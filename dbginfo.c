/* dbginfo - parse ELF64 + DWARF 4/5 debug info and print a readable dump.
 *
 * No libelf, no libdwarf, no zlib: every byte is decoded here. The input is
 * untrusted (a truncated or hostile object file is a normal case, not an
 * exception), so the whole file is read into one buffer and every read goes
 * through a bounds-checked cursor that latches an error flag instead of
 * trapping. A parse failure must print a diagnostic and exit nonzero; it must
 * never crash, read out of bounds, or spin.
 *
 * C11, gcc, x86-64 little-endian only.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <stdarg.h>

/* ------------------------------------------------------------------ */
/* bounds-checked cursor                                              */
/* ------------------------------------------------------------------ */

/* Every DWARF read goes through this. `err` is sticky: once a read runs off
 * the end we keep returning zeros, so callers can decode a whole structure
 * and check err once at the end instead of after every field. That is what
 * keeps the error paths short enough to actually be correct. */
typedef struct {
	const uint8_t *buf;
	size_t len;
	size_t pos;
	int err;
} Rd;

static Rd rd_at(const uint8_t *buf, size_t len, size_t pos)
{
	Rd r = { buf, len, pos, 0 };
	if (pos > len)
		r.err = 1;
	return r;
}

static int rd_left(const Rd *r, size_t n)
{
	return !r->err && r->pos <= r->len && r->len - r->pos >= n;
}

static const uint8_t *rd_take(Rd *r, size_t n)
{
	if (!rd_left(r, n)) {
		r->err = 1;
		return NULL;
	}
	const uint8_t *p = r->buf + r->pos;
	r->pos += n;
	return p;
}

static uint64_t rd_fixed(Rd *r, unsigned n)
{
	const uint8_t *p = rd_take(r, n);
	if (!p)
		return 0;
	uint64_t v = 0;
	for (unsigned i = 0; i < n; i++)	/* little-endian only */
		v |= (uint64_t)p[i] << (8 * i);
	return v;
}

static uint8_t rd_u8(Rd *r) { return (uint8_t)rd_fixed(r, 1); }
static uint16_t rd_u16(Rd *r) { return (uint16_t)rd_fixed(r, 2); }
static uint32_t rd_u32(Rd *r) { return (uint32_t)rd_fixed(r, 4); }
static uint64_t rd_u64(Rd *r) { return rd_fixed(r, 8); }

/* LEB128: the spec (DWARF5 section 7.6) stores integers 7 bits per byte,
 * low group first, with bit 7 set on every byte but the last. Unsigned is a
 * plain base-128 accumulation. We stop accumulating after 64 bits of payload
 * but keep consuming continuation bytes, because the byte length of the field
 * is what the rest of the parse depends on - silently stopping early would
 * desynchronise the cursor and turn one bad value into a cascade. */
static uint64_t rd_uleb(Rd *r)
{
	uint64_t v = 0;
	unsigned shift = 0;
	for (;;) {
		if (!rd_left(r, 1)) {
			r->err = 1;
			return 0;
		}
		uint8_t b = rd_u8(r);
		if (shift < 64)
			v |= (uint64_t)(b & 0x7f) << shift;
		shift += 7;
		if (!(b & 0x80))
			return v;
		if (shift > 128) {	/* absurd: malformed, not just large */
			r->err = 1;
			return 0;
		}
	}
}

/* Signed LEB128 is the same framing, but the last byte's bit 6 is the sign
 * bit and the value must be sign-extended from the final shift position. */
static int64_t rd_sleb(Rd *r)
{
	uint64_t v = 0;
	unsigned shift = 0;
	uint8_t b = 0;
	for (;;) {
		if (!rd_left(r, 1)) {
			r->err = 1;
			return 0;
		}
		b = rd_u8(r);
		if (shift < 64)
			v |= (uint64_t)(b & 0x7f) << shift;
		shift += 7;
		if (!(b & 0x80))
			break;
		if (shift > 128) {
			r->err = 1;
			return 0;
		}
	}
	if (shift < 64 && (b & 0x40))
		v |= ~(uint64_t)0 << shift;
	return (int64_t)v;
}

/* ------------------------------------------------------------------ */
/* name tables                                                        */
/* ------------------------------------------------------------------ */

typedef struct { uint64_t code; const char *name; } NameEnt;

static const char *lookup(const NameEnt *t, size_t n, uint64_t code,
                          char *scratch, size_t slen, const char *pfx)
{
	for (size_t i = 0; i < n; i++)
		if (t[i].code == code)
			return t[i].name;
	snprintf(scratch, slen, "%s_unknown_0x%" PRIx64, pfx, code);
	return scratch;
}

#define DW_TAG_array_type 0x01
#define DW_TAG_class_type 0x02
#define DW_TAG_entry_point 0x03
#define DW_TAG_enumeration_type 0x04
#define DW_TAG_formal_parameter 0x05
#define DW_TAG_imported_declaration 0x08
#define DW_TAG_label 0x0a
#define DW_TAG_lexical_block 0x0b
#define DW_TAG_member 0x0d
#define DW_TAG_pointer_type 0x0f
#define DW_TAG_reference_type 0x10
#define DW_TAG_compile_unit 0x11
#define DW_TAG_string_type 0x12
#define DW_TAG_structure_type 0x13
#define DW_TAG_subroutine_type 0x15
#define DW_TAG_typedef 0x16
#define DW_TAG_union_type 0x17
#define DW_TAG_unspecified_parameters 0x18
#define DW_TAG_variant 0x19
#define DW_TAG_common_block 0x1a
#define DW_TAG_common_inclusion 0x1b
#define DW_TAG_inheritance 0x1c
#define DW_TAG_inlined_subroutine 0x1d
#define DW_TAG_module 0x1e
#define DW_TAG_ptr_to_member_type 0x1f
#define DW_TAG_set_type 0x20
#define DW_TAG_subrange_type 0x21
#define DW_TAG_with_stmt 0x22
#define DW_TAG_access_declaration 0x23
#define DW_TAG_base_type 0x24
#define DW_TAG_catch_block 0x25
#define DW_TAG_const_type 0x26
#define DW_TAG_constant 0x27
#define DW_TAG_enumerator 0x28
#define DW_TAG_file_type 0x29
#define DW_TAG_friend 0x2a
#define DW_TAG_namelist 0x2b
#define DW_TAG_namelist_item 0x2c
#define DW_TAG_packed_type 0x2d
#define DW_TAG_subprogram 0x2e
#define DW_TAG_template_type_parameter 0x2f
#define DW_TAG_template_value_parameter 0x30
#define DW_TAG_thrown_type 0x31
#define DW_TAG_try_block 0x32
#define DW_TAG_variant_part 0x33
#define DW_TAG_variable 0x34
#define DW_TAG_volatile_type 0x35
#define DW_TAG_dwarf_procedure 0x36
#define DW_TAG_restrict_type 0x37
#define DW_TAG_interface_type 0x38
#define DW_TAG_namespace 0x39
#define DW_TAG_imported_module 0x3a
#define DW_TAG_unspecified_type 0x3b
#define DW_TAG_partial_unit 0x3c
#define DW_TAG_imported_unit 0x3d
#define DW_TAG_condition 0x3f
#define DW_TAG_shared_type 0x40
#define DW_TAG_type_unit 0x41
#define DW_TAG_rvalue_reference_type 0x42
#define DW_TAG_template_alias 0x43
#define DW_TAG_coarray_type 0x44
#define DW_TAG_generic_subrange 0x45
#define DW_TAG_dynamic_type 0x46
#define DW_TAG_atomic_type 0x47
#define DW_TAG_call_site 0x48
#define DW_TAG_call_site_parameter 0x49
#define DW_TAG_skeleton_unit 0x4a
#define DW_TAG_immutable_type 0x4b
#define DW_TAG_GNU_call_site 0x4109
#define DW_TAG_GNU_call_site_parameter 0x410a

#define N(x) { x, #x }
static const NameEnt tags[] = {
	N(DW_TAG_array_type), N(DW_TAG_class_type), N(DW_TAG_entry_point),
	N(DW_TAG_enumeration_type), N(DW_TAG_formal_parameter),
	N(DW_TAG_imported_declaration), N(DW_TAG_label), N(DW_TAG_lexical_block),
	N(DW_TAG_member), N(DW_TAG_pointer_type), N(DW_TAG_reference_type),
	N(DW_TAG_compile_unit), N(DW_TAG_string_type), N(DW_TAG_structure_type),
	N(DW_TAG_subroutine_type), N(DW_TAG_typedef), N(DW_TAG_union_type),
	N(DW_TAG_unspecified_parameters), N(DW_TAG_variant), N(DW_TAG_common_block),
	N(DW_TAG_common_inclusion), N(DW_TAG_inheritance),
	N(DW_TAG_inlined_subroutine), N(DW_TAG_module),
	N(DW_TAG_ptr_to_member_type), N(DW_TAG_set_type), N(DW_TAG_subrange_type),
	N(DW_TAG_with_stmt), N(DW_TAG_access_declaration), N(DW_TAG_base_type),
	N(DW_TAG_catch_block), N(DW_TAG_const_type), N(DW_TAG_constant),
	N(DW_TAG_enumerator), N(DW_TAG_file_type), N(DW_TAG_friend),
	N(DW_TAG_namelist), N(DW_TAG_namelist_item), N(DW_TAG_packed_type),
	N(DW_TAG_subprogram), N(DW_TAG_template_type_parameter),
	N(DW_TAG_template_value_parameter), N(DW_TAG_thrown_type),
	N(DW_TAG_try_block), N(DW_TAG_variant_part), N(DW_TAG_variable),
	N(DW_TAG_volatile_type), N(DW_TAG_dwarf_procedure),
	N(DW_TAG_restrict_type), N(DW_TAG_interface_type), N(DW_TAG_namespace),
	N(DW_TAG_imported_module), N(DW_TAG_unspecified_type),
	N(DW_TAG_partial_unit), N(DW_TAG_imported_unit), N(DW_TAG_condition),
	N(DW_TAG_shared_type), N(DW_TAG_type_unit),
	N(DW_TAG_rvalue_reference_type), N(DW_TAG_template_alias),
	N(DW_TAG_coarray_type), N(DW_TAG_generic_subrange),
	N(DW_TAG_dynamic_type), N(DW_TAG_atomic_type), N(DW_TAG_call_site),
	N(DW_TAG_call_site_parameter), N(DW_TAG_skeleton_unit),
	N(DW_TAG_immutable_type), N(DW_TAG_GNU_call_site),
	N(DW_TAG_GNU_call_site_parameter),
};
#undef N

#define DW_AT_sibling 0x01
#define DW_AT_location 0x02
#define DW_AT_name 0x03
#define DW_AT_ordering 0x09
#define DW_AT_byte_size 0x0b
#define DW_AT_bit_offset 0x0c
#define DW_AT_bit_size 0x0d
#define DW_AT_stmt_list 0x10
#define DW_AT_low_pc 0x11
#define DW_AT_high_pc 0x12
#define DW_AT_language 0x13
#define DW_AT_discr 0x15
#define DW_AT_discr_value 0x16
#define DW_AT_visibility 0x17
#define DW_AT_import 0x18
#define DW_AT_string_length 0x19
#define DW_AT_common_reference 0x1a
#define DW_AT_comp_dir 0x1b
#define DW_AT_const_value 0x1c
#define DW_AT_containing_type 0x1d
#define DW_AT_default_value 0x1e
#define DW_AT_inline 0x20
#define DW_AT_is_optional 0x21
#define DW_AT_lower_bound 0x22
#define DW_AT_producer 0x25
#define DW_AT_prototyped 0x27
#define DW_AT_return_addr 0x2a
#define DW_AT_start_scope 0x2c
#define DW_AT_bit_stride 0x2e
#define DW_AT_upper_bound 0x2f
#define DW_AT_abstract_origin 0x31
#define DW_AT_accessibility 0x32
#define DW_AT_address_class 0x33
#define DW_AT_artificial 0x34
#define DW_AT_base_types 0x35
#define DW_AT_calling_convention 0x36
#define DW_AT_count 0x37
#define DW_AT_data_member_location 0x38
#define DW_AT_decl_column 0x39
#define DW_AT_decl_file 0x3a
#define DW_AT_decl_line 0x3b
#define DW_AT_declaration 0x3c
#define DW_AT_discr_list 0x3d
#define DW_AT_encoding 0x3e
#define DW_AT_external 0x3f
#define DW_AT_frame_base 0x40
#define DW_AT_friend 0x41
#define DW_AT_identifier_case 0x42
#define DW_AT_macro_info 0x43
#define DW_AT_namelist_item 0x44
#define DW_AT_priority 0x45
#define DW_AT_segment 0x46
#define DW_AT_specification 0x47
#define DW_AT_static_link 0x48
#define DW_AT_type 0x49
#define DW_AT_use_location 0x4a
#define DW_AT_variable_parameter 0x4b
#define DW_AT_virtuality 0x4c
#define DW_AT_vtable_elem_location 0x4d
#define DW_AT_allocated 0x4e
#define DW_AT_associated 0x4f
#define DW_AT_data_location 0x50
#define DW_AT_byte_stride 0x51
#define DW_AT_entry_pc 0x52
#define DW_AT_use_UTF8 0x53
#define DW_AT_extension 0x54
#define DW_AT_ranges 0x55
#define DW_AT_trampoline 0x56
#define DW_AT_call_column 0x57
#define DW_AT_call_file 0x58
#define DW_AT_call_line 0x59
#define DW_AT_description 0x5a
#define DW_AT_binary_scale 0x5b
#define DW_AT_decimal_scale 0x5c
#define DW_AT_small 0x5d
#define DW_AT_decimal_sign 0x5e
#define DW_AT_digit_count 0x5f
#define DW_AT_picture_string 0x60
#define DW_AT_mutable 0x61
#define DW_AT_threads_scaled 0x62
#define DW_AT_explicit 0x63
#define DW_AT_object_pointer 0x64
#define DW_AT_endianity 0x65
#define DW_AT_elemental 0x66
#define DW_AT_pure 0x67
#define DW_AT_recursive 0x68
#define DW_AT_signature 0x69
#define DW_AT_main_subprogram 0x6a
#define DW_AT_data_bit_offset 0x6b
#define DW_AT_const_expr 0x6c
#define DW_AT_enum_class 0x6d
#define DW_AT_linkage_name 0x6e
#define DW_AT_string_length_bit_size 0x6f
#define DW_AT_string_length_byte_size 0x70
#define DW_AT_rank 0x71
#define DW_AT_str_offsets_base 0x72
#define DW_AT_addr_base 0x73
#define DW_AT_rnglists_base 0x74
#define DW_AT_dwo_name 0x76
#define DW_AT_reference 0x77
#define DW_AT_rvalue_reference 0x78
#define DW_AT_macros 0x79
#define DW_AT_call_all_calls 0x7a
#define DW_AT_call_all_source_calls 0x7b
#define DW_AT_call_all_tail_calls 0x7c
#define DW_AT_call_return_pc 0x7d
#define DW_AT_call_value 0x7e
#define DW_AT_call_origin 0x7f
#define DW_AT_call_parameter 0x80
#define DW_AT_call_pc 0x81
#define DW_AT_call_tail_call 0x82
#define DW_AT_call_target 0x83
#define DW_AT_call_target_clobbered 0x84
#define DW_AT_call_data_location 0x85
#define DW_AT_call_data_value 0x86
#define DW_AT_noreturn 0x87
#define DW_AT_alignment 0x88
#define DW_AT_export_symbols 0x89
#define DW_AT_deleted 0x8a
#define DW_AT_defaulted 0x8b
#define DW_AT_loclists_base 0x8c
#define DW_AT_GNU_call_site_value 0x2111
#define DW_AT_GNU_dwo_name 0x2130
#define DW_AT_GNU_dwo_id 0x2131
#define DW_AT_GNU_ranges_base 0x2132
#define DW_AT_GNU_addr_base 0x2133
#define DW_AT_GNU_pubnames 0x2134
#define DW_AT_GNU_pubtypes 0x2135
#define DW_AT_GNU_all_tail_call_sites 0x2116
#define DW_AT_GNU_all_call_sites 0x2117
#define DW_AT_GNU_macros 0x2119
#define DW_AT_GNU_locviews 0x2137
#define DW_AT_GNU_entry_view 0x2138

#define N(x) { x, #x }
static const NameEnt attrs[] = {
	N(DW_AT_sibling), N(DW_AT_location), N(DW_AT_name), N(DW_AT_ordering),
	N(DW_AT_byte_size), N(DW_AT_bit_offset), N(DW_AT_bit_size),
	N(DW_AT_stmt_list), N(DW_AT_low_pc), N(DW_AT_high_pc), N(DW_AT_language),
	N(DW_AT_discr), N(DW_AT_discr_value), N(DW_AT_visibility), N(DW_AT_import),
	N(DW_AT_string_length), N(DW_AT_common_reference), N(DW_AT_comp_dir),
	N(DW_AT_const_value), N(DW_AT_containing_type), N(DW_AT_default_value),
	N(DW_AT_inline), N(DW_AT_is_optional), N(DW_AT_lower_bound),
	N(DW_AT_producer), N(DW_AT_prototyped), N(DW_AT_return_addr),
	N(DW_AT_start_scope), N(DW_AT_bit_stride), N(DW_AT_upper_bound),
	N(DW_AT_abstract_origin), N(DW_AT_accessibility), N(DW_AT_address_class),
	N(DW_AT_artificial), N(DW_AT_base_types), N(DW_AT_calling_convention),
	N(DW_AT_count), N(DW_AT_data_member_location), N(DW_AT_decl_column),
	N(DW_AT_decl_file), N(DW_AT_decl_line), N(DW_AT_declaration),
	N(DW_AT_discr_list), N(DW_AT_encoding), N(DW_AT_external),
	N(DW_AT_frame_base), N(DW_AT_friend), N(DW_AT_identifier_case),
	N(DW_AT_macro_info), N(DW_AT_namelist_item), N(DW_AT_priority),
	N(DW_AT_segment), N(DW_AT_specification), N(DW_AT_static_link),
	N(DW_AT_type), N(DW_AT_use_location), N(DW_AT_variable_parameter),
	N(DW_AT_virtuality), N(DW_AT_vtable_elem_location), N(DW_AT_allocated),
	N(DW_AT_associated), N(DW_AT_data_location), N(DW_AT_byte_stride),
	N(DW_AT_entry_pc), N(DW_AT_use_UTF8), N(DW_AT_extension), N(DW_AT_ranges),
	N(DW_AT_trampoline), N(DW_AT_call_column), N(DW_AT_call_file),
	N(DW_AT_call_line), N(DW_AT_description), N(DW_AT_binary_scale),
	N(DW_AT_decimal_scale), N(DW_AT_small), N(DW_AT_decimal_sign),
	N(DW_AT_digit_count), N(DW_AT_picture_string), N(DW_AT_mutable),
	N(DW_AT_threads_scaled), N(DW_AT_explicit), N(DW_AT_object_pointer),
	N(DW_AT_endianity), N(DW_AT_elemental), N(DW_AT_pure), N(DW_AT_recursive),
	N(DW_AT_signature), N(DW_AT_main_subprogram), N(DW_AT_data_bit_offset),
	N(DW_AT_const_expr), N(DW_AT_enum_class), N(DW_AT_linkage_name),
	N(DW_AT_string_length_bit_size), N(DW_AT_string_length_byte_size),
	N(DW_AT_rank), N(DW_AT_str_offsets_base), N(DW_AT_addr_base),
	N(DW_AT_rnglists_base), N(DW_AT_dwo_name), N(DW_AT_reference),
	N(DW_AT_rvalue_reference), N(DW_AT_macros), N(DW_AT_call_all_calls),
	N(DW_AT_call_all_source_calls), N(DW_AT_call_all_tail_calls),
	N(DW_AT_call_return_pc), N(DW_AT_call_value), N(DW_AT_call_origin),
	N(DW_AT_call_parameter), N(DW_AT_call_pc), N(DW_AT_call_tail_call),
	N(DW_AT_call_target), N(DW_AT_call_target_clobbered),
	N(DW_AT_call_data_location), N(DW_AT_call_data_value), N(DW_AT_noreturn),
	N(DW_AT_alignment), N(DW_AT_export_symbols), N(DW_AT_deleted),
	N(DW_AT_defaulted), N(DW_AT_loclists_base), N(DW_AT_GNU_call_site_value),
	N(DW_AT_GNU_dwo_name), N(DW_AT_GNU_dwo_id), N(DW_AT_GNU_ranges_base),
	N(DW_AT_GNU_addr_base), N(DW_AT_GNU_pubnames), N(DW_AT_GNU_pubtypes),
	N(DW_AT_GNU_all_tail_call_sites), N(DW_AT_GNU_all_call_sites),
	N(DW_AT_GNU_macros), N(DW_AT_GNU_locviews), N(DW_AT_GNU_entry_view),
};
#undef N

#define DW_FORM_addr 0x01
#define DW_FORM_block2 0x03
#define DW_FORM_block4 0x04
#define DW_FORM_data2 0x05
#define DW_FORM_data4 0x06
#define DW_FORM_data8 0x07
#define DW_FORM_string 0x08
#define DW_FORM_block 0x09
#define DW_FORM_block1 0x0a
#define DW_FORM_data1 0x0b
#define DW_FORM_flag 0x0c
#define DW_FORM_sdata 0x0d
#define DW_FORM_strp 0x0e
#define DW_FORM_udata 0x0f
#define DW_FORM_ref_addr 0x10
#define DW_FORM_ref1 0x11
#define DW_FORM_ref2 0x12
#define DW_FORM_ref4 0x13
#define DW_FORM_ref8 0x14
#define DW_FORM_ref_udata 0x15
#define DW_FORM_indirect 0x16
#define DW_FORM_sec_offset 0x17
#define DW_FORM_exprloc 0x18
#define DW_FORM_flag_present 0x19
#define DW_FORM_strx 0x1a
#define DW_FORM_addrx 0x1b
#define DW_FORM_ref_sup4 0x1c
#define DW_FORM_strp_sup 0x1d
#define DW_FORM_data16 0x1e
#define DW_FORM_line_strp 0x1f
#define DW_FORM_ref_sig8 0x20
#define DW_FORM_implicit_const 0x21
#define DW_FORM_loclistx 0x22
#define DW_FORM_rnglistx 0x23
#define DW_FORM_ref_sup8 0x24
#define DW_FORM_strx1 0x25
#define DW_FORM_strx2 0x26
#define DW_FORM_strx3 0x27
#define DW_FORM_strx4 0x28
#define DW_FORM_addrx1 0x29
#define DW_FORM_addrx2 0x2a
#define DW_FORM_addrx3 0x2b
#define DW_FORM_addrx4 0x2c

#define N(x) { x, #x }
static const NameEnt forms[] = {
	N(DW_FORM_addr), N(DW_FORM_block2), N(DW_FORM_block4), N(DW_FORM_data2),
	N(DW_FORM_data4), N(DW_FORM_data8), N(DW_FORM_string), N(DW_FORM_block),
	N(DW_FORM_block1), N(DW_FORM_data1), N(DW_FORM_flag), N(DW_FORM_sdata),
	N(DW_FORM_strp), N(DW_FORM_udata), N(DW_FORM_ref_addr), N(DW_FORM_ref1),
	N(DW_FORM_ref2), N(DW_FORM_ref4), N(DW_FORM_ref8), N(DW_FORM_ref_udata),
	N(DW_FORM_indirect), N(DW_FORM_sec_offset), N(DW_FORM_exprloc),
	N(DW_FORM_flag_present), N(DW_FORM_strx), N(DW_FORM_addrx),
	N(DW_FORM_ref_sup4), N(DW_FORM_strp_sup), N(DW_FORM_data16),
	N(DW_FORM_line_strp), N(DW_FORM_ref_sig8), N(DW_FORM_implicit_const),
	N(DW_FORM_loclistx), N(DW_FORM_rnglistx), N(DW_FORM_ref_sup8),
	N(DW_FORM_strx1), N(DW_FORM_strx2), N(DW_FORM_strx3), N(DW_FORM_strx4),
	N(DW_FORM_addrx1), N(DW_FORM_addrx2), N(DW_FORM_addrx3),
	N(DW_FORM_addrx4),
};
#undef N

/* ------------------------------------------------------------------ */
/* ELF                                                                */
/* ------------------------------------------------------------------ */

typedef struct {
	const char *name;
	const uint8_t *data;
	size_t size;
	uint64_t flags;
	uint32_t type;
	int truncated;		/* header claims bytes the file does not contain */
} Sec;

typedef struct {
	uint8_t *file;
	size_t flen;
	Sec *sec;
	size_t nsec;
	/* the sections we decode; NULL when absent */
	const Sec *info, *abbrev, *str, *line_str, *line, *str_off, *addr;
} Elf;

static void die(const char *fmt, ...)
	__attribute__((format(printf, 1, 2), noreturn));
static void die(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fputs("dbginfo: ", stderr);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	exit(1);
}

static void *xmalloc(size_t n)
{
	void *p = malloc(n ? n : 1);
	if (!p)
		die("out of memory");
	return p;
}

static uint8_t *read_file(const char *path, size_t *out_len)
{
	FILE *f = fopen(path, "rb");
	if (!f)
		die("%s: %s", path, strerror(errno));
	size_t cap = 1 << 16, len = 0;
	uint8_t *buf = xmalloc(cap);
	for (;;) {
		if (len == cap) {
			if (cap > (size_t)1 << 31)
				die("%s: file too large", path);
			cap *= 2;
			uint8_t *nb = realloc(buf, cap);
			if (!nb)
				die("out of memory");
			buf = nb;
		}
		size_t got = fread(buf + len, 1, cap - len, f);
		len += got;
		if (got == 0) {
			if (ferror(f))
				die("%s: read error", path);
			break;
		}
	}
	fclose(f);
	*out_len = len;
	return buf;
}

/* A string table lookup that refuses to walk off the end: a corrupt
 * sh_name/strp offset is the single most common way a DWARF reader turns into
 * an out-of-bounds read, so the only way to get a char* out of a section is
 * through here. */
static const char *sec_str(const Sec *s, uint64_t off)
{
	if (!s || off >= s->size)
		return NULL;
	const uint8_t *p = s->data + off;
	size_t left = s->size - off;
	for (size_t i = 0; i < left; i++)
		if (p[i] == 0)
			return (const char *)p;
	return NULL;		/* unterminated: refuse rather than over-read */
}

static const Sec *find_sec(Elf *e, const char *name)
{
	for (size_t i = 0; i < e->nsec; i++)
		if (e->sec[i].name && strcmp(e->sec[i].name, name) == 0)
			return &e->sec[i];
	return NULL;
}

#define SHF_COMPRESSED 0x800

static void elf_load(Elf *e, const char *path)
{
	memset(e, 0, sizeof *e);
	e->file = read_file(path, &e->flen);
	Rd r = rd_at(e->file, e->flen, 0);
	const uint8_t *id = rd_take(&r, 16);
	if (!id)
		die("%s: too short to be an ELF file", path);
	if (memcmp(id, "\177ELF", 4) != 0)
		die("%s: not an ELF file (bad magic)", path);
	/* shortcut: ELFCLASS64 little-endian only. 32-bit and big-endian ELF
	 * need a second set of header offsets and a byte-swapping reader;
	 * upgrade path is to parameterise rd_fixed and the shdr offsets. */
	if (id[4] != 2)
		die("%s: only 64-bit ELF supported (EI_CLASS=%u)", path, id[4]);
	if (id[5] != 1)
		die("%s: only little-endian ELF supported (EI_DATA=%u)", path, id[5]);

	r.pos = 0x28;
	uint64_t shoff = rd_u64(&r);
	r.pos = 0x3a;
	uint16_t shentsize = rd_u16(&r);
	uint64_t shnum = rd_u16(&r);
	uint64_t shstrndx = rd_u16(&r);
	if (r.err)
		die("%s: truncated ELF header", path);
	if (shoff == 0 || shnum == 0)
		die("%s: no section headers", path);
	if (shentsize < 64)
		die("%s: implausible e_shentsize %u", path, shentsize);

	/* Extended numbering: when the real counts exceed 16 bits they live in
	 * section header 0 (ELF gABI). Rare, but cheap to honour. */
	Rd s0 = rd_at(e->file, e->flen, shoff);
	if (shnum == 0xffff || shstrndx == 0xffff) {
		s0.pos = shoff + 0x20;
		uint64_t real_n = rd_u64(&s0);
		s0.pos = shoff + 0x28;
		uint32_t real_link = rd_u32(&s0);
		if (s0.err)
			die("%s: truncated section header 0", path);
		if (shnum == 0xffff)
			shnum = real_n;
		if (shstrndx == 0xffff)
			shstrndx = real_link;
	}
	if (shnum > (1u << 20))
		die("%s: implausible section count %" PRIu64, path, shnum);

	e->nsec = shnum;
	e->sec = xmalloc(shnum * sizeof *e->sec);
	memset(e->sec, 0, shnum * sizeof *e->sec);
	for (uint64_t i = 0; i < shnum; i++) {
		Rd h = rd_at(e->file, e->flen, shoff + i * shentsize);
		uint32_t nameoff = rd_u32(&h);
		uint32_t type = rd_u32(&h);
		uint64_t flags = rd_u64(&h);
		(void)rd_u64(&h);	/* sh_addr */
		uint64_t off = rd_u64(&h);
		uint64_t size = rd_u64(&h);
		if (h.err)
			die("%s: truncated section header %" PRIu64, path, i);
		e->sec[i].type = type;
		e->sec[i].flags = flags;
		e->sec[i].data = NULL;
		e->sec[i].size = 0;
		e->sec[i].name = NULL;
		/* SHT_NOBITS (8) occupies no file bytes; everything else must fit.
		 * A header pointing past EOF is the normal shape of a truncated
		 * file: treat the section as empty and say so rather than
		 * trusting sh_size. */
		if (type != 8 && off <= e->flen && size <= e->flen - off) {
			e->sec[i].data = e->file + off;
			e->sec[i].size = size;
		} else if (type != 8 && size != 0) {
			e->sec[i].truncated = 1;
		}
		e->sec[i].name = (const char *)(uintptr_t)nameoff;	/* fixed below */
	}
	/* Resolve names only after the table exists, since shstrndx points into
	 * it and we must bounds-check that too. */
	const Sec *shstr = (shstrndx < shnum) ? &e->sec[shstrndx] : NULL;
	for (uint64_t i = 0; i < shnum; i++) {
		uint64_t nameoff = (uint64_t)(uintptr_t)e->sec[i].name;
		e->sec[i].name = shstr ? sec_str(shstr, nameoff) : NULL;
	}

	e->info = find_sec(e, ".debug_info");
	e->abbrev = find_sec(e, ".debug_abbrev");
	e->str = find_sec(e, ".debug_str");
	e->line_str = find_sec(e, ".debug_line_str");
	e->line = find_sec(e, ".debug_line");
	e->str_off = find_sec(e, ".debug_str_offsets");
	e->addr = find_sec(e, ".debug_addr");

	/* shortcut: SHF_COMPRESSED / .zdebug_* sections would need zlib or
	 * zstd, which we refuse to link. Say so instead of printing garbage.
	 * Upgrade path: shell out to objcopy --decompress-debug-sections. */
	const Sec *check[] = { e->info, e->abbrev, e->str, e->line_str, e->line };
	for (size_t i = 0; i < sizeof check / sizeof *check; i++)
		if (check[i] && check[i]->truncated)
			fprintf(stderr, "dbginfo: %s: %s extends past end of file,"
			        " treating as empty\n", path, check[i]->name);
	for (size_t i = 0; i < sizeof check / sizeof *check; i++)
		if (check[i] && (check[i]->flags & SHF_COMPRESSED))
			die("%s: %s is SHF_COMPRESSED; "
			    "run objcopy --decompress-debug-sections first",
			    path, check[i]->name);
}

/* ------------------------------------------------------------------ */
/* abbreviation tables                                                */
/* ------------------------------------------------------------------ */

typedef struct {
	uint64_t at, form;
	int64_t iconst;		/* only meaningful for DW_FORM_implicit_const */
} AbbrevAttr;

typedef struct {
	uint64_t code, tag;
	int children;
	AbbrevAttr *attr;
	size_t nattr;
} Abbrev;

typedef struct {
	Abbrev *v;
	size_t n, cap;
	uint64_t off;		/* section offset this table was parsed from */
} AbbrevTab;

static void abbrev_free(AbbrevTab *t)
{
	for (size_t i = 0; i < t->n; i++)
		free(t->v[i].attr);
	free(t->v);
	t->v = NULL;
	t->n = t->cap = 0;
}

/* Abbreviation codes are ULEB128 and in practice dense from 1, but the spec
 * does not require that, so lookup is a linear scan rather than an index.
 * With the handful of abbrevs a real CU declares this is faster than a hash
 * and immune to a hostile table that claims code 2^60. */
static const Abbrev *abbrev_find(const AbbrevTab *t, uint64_t code)
{
	for (size_t i = 0; i < t->n; i++)
		if (t->v[i].code == code)
			return &t->v[i];
	return NULL;
}

/* One table runs from `off` to the first abbreviation with code 0; each
 * declaration ends with an all-zero (attribute, form) pair. */
static int abbrev_parse(AbbrevTab *t, const Sec *sec, uint64_t off)
{
	abbrev_free(t);
	t->off = off;
	if (!sec)
		return 0;
	Rd r = rd_at(sec->data, sec->size, off);
	for (;;) {
		uint64_t code = rd_uleb(&r);
		if (r.err)
			return 0;
		if (code == 0)
			return 1;	/* end of this table */
		uint64_t tag = rd_uleb(&r);
		int children = rd_u8(&r) != 0;
		if (r.err)
			return 0;
		if (t->n == t->cap) {
			t->cap = t->cap ? t->cap * 2 : 16;
			Abbrev *nv = realloc(t->v, t->cap * sizeof *nv);
			if (!nv)
				die("out of memory");
			t->v = nv;
		}
		Abbrev *a = &t->v[t->n];
		memset(a, 0, sizeof *a);
		a->code = code;
		a->tag = tag;
		a->children = children;
		size_t cap = 0;
		for (;;) {
			uint64_t at = rd_uleb(&r);
			uint64_t form = rd_uleb(&r);
			int64_t ic = 0;
			/* DWARF5: implicit_const carries its value in the abbrev, and
			 * contributes zero bytes to the DIE. Forgetting this is an
			 * instant desync on gcc-14 output, which uses it heavily. */
			if (form == DW_FORM_implicit_const)
				ic = rd_sleb(&r);
			if (r.err) {
				free(a->attr);
				a->attr = NULL;
				a->nattr = 0;
				return 0;
			}
			if (at == 0 && form == 0)
				break;
			if (a->nattr == cap) {
				cap = cap ? cap * 2 : 8;
				AbbrevAttr *na = realloc(a->attr, cap * sizeof *na);
				if (!na)
					die("out of memory");
				a->attr = na;
			}
			a->attr[a->nattr].at = at;
			a->attr[a->nattr].form = form;
			a->attr[a->nattr].iconst = ic;
			a->nattr++;
		}
		t->n++;		/* only count it once fully parsed */
	}
}

/* ------------------------------------------------------------------ */
/* attribute values                                                   */
/* ------------------------------------------------------------------ */

typedef struct {
	uint64_t version;
	unsigned addr_size;
	unsigned off_size;	/* 4 for 32-bit DWARF, 8 for 64-bit DWARF */
	uint64_t cu_off;	/* .debug_info offset of this CU header */
	uint64_t str_off_base;
	uint64_t addr_base;
} Cu;

enum { V_NONE, V_U, V_S, V_STR, V_BLOCK, V_REF, V_UNRES };

typedef struct {
	int kind;
	uint64_t form;
	uint64_t u;
	int64_t s;
	const char *str;
	const uint8_t *blk;
	size_t blklen;
	const char *why;	/* set when kind == V_UNRES */
} Val;

/* An index into .debug_str_offsets (DW_FORM_strx*) is relative to the CU's
 * DW_AT_str_offsets_base. We default the base to 8, the size of a 32-bit
 * DWARF5 str_offsets header, for the case where the CU declares no base.
 * shortcut: a two-pass DIE read would get this exactly right; the default is
 * shortcut: a CU whose root DIE declares no base at all (split DWARF skeleton
 * units) still falls back to 8. The root DIE is prescanned for the real base
 * before any attribute is decoded, so the fallback only bites producers that
 * omit the attribute entirely. */
static const char *strx_lookup(Elf *e, const Cu *cu, uint64_t idx,
                               const char **why)
{
	if (!e->str_off) {
		*why = "no .debug_str_offsets";
		return NULL;
	}
	uint64_t base = cu->str_off_base ? cu->str_off_base : 8;
	Rd r = rd_at(e->str_off->data, e->str_off->size,
	             base + idx * cu->off_size);
	uint64_t off = rd_fixed(&r, cu->off_size);
	if (r.err) {
		*why = "str_offsets index out of range";
		return NULL;
	}
	const char *s = sec_str(e->str, off);
	if (!s)
		*why = "bad .debug_str offset";
	return s;
}

static int addrx_lookup(Elf *e, const Cu *cu, uint64_t idx, uint64_t *out,
                        const char **why)
{
	if (!e->addr) {
		*why = "no .debug_addr";
		return 0;
	}
	uint64_t base = cu->addr_base ? cu->addr_base : 8;
	Rd r = rd_at(e->addr->data, e->addr->size, base + idx * cu->addr_size);
	uint64_t v = rd_fixed(&r, cu->addr_size);
	if (r.err) {
		*why = "addr index out of range";
		return 0;
	}
	*out = v;
	return 1;
}

static int read_form(Rd *r, Elf *e, const Cu *cu, uint64_t form, int64_t ic,
                     Val *v, int depth)
{
	memset(v, 0, sizeof *v);
	v->form = form;
	switch (form) {
	case DW_FORM_addr:
		v->kind = V_U;
		v->u = rd_fixed(r, cu->addr_size);
		break;
	case DW_FORM_data1: v->kind = V_U; v->u = rd_u8(r); break;
	case DW_FORM_data2: v->kind = V_U; v->u = rd_u16(r); break;
	case DW_FORM_data4: v->kind = V_U; v->u = rd_u32(r); break;
	case DW_FORM_data8: v->kind = V_U; v->u = rd_u64(r); break;
	case DW_FORM_udata: v->kind = V_U; v->u = rd_uleb(r); break;
	case DW_FORM_sdata: v->kind = V_S; v->s = rd_sleb(r); break;
	case DW_FORM_flag: v->kind = V_U; v->u = rd_u8(r); break;
	case DW_FORM_flag_present: v->kind = V_U; v->u = 1; break;
	case DW_FORM_implicit_const: v->kind = V_S; v->s = ic; break;
	case DW_FORM_sec_offset:
		v->kind = V_U;
		v->u = rd_fixed(r, cu->off_size);
		break;
	case DW_FORM_ref_sig8: v->kind = V_U; v->u = rd_u64(r); break;
	case DW_FORM_data16: {
		v->kind = V_BLOCK;
		v->blk = rd_take(r, 16);
		v->blklen = 16;
		break;
	}
	case DW_FORM_string: {
		/* Inline NUL-terminated string living in .debug_info itself. */
		size_t start = r->pos;
		for (;;) {
			if (!rd_left(r, 1)) {
				r->err = 1;
				return 0;
			}
			if (rd_u8(r) == 0)
				break;
		}
		v->kind = V_STR;
		v->str = (const char *)r->buf + start;
		break;
	}
	case DW_FORM_strp: {
		uint64_t off = rd_fixed(r, cu->off_size);
		v->str = sec_str(e->str, off);
		v->kind = v->str ? V_STR : V_UNRES;
		v->u = off;
		v->why = e->str ? "bad .debug_str offset" : "no .debug_str";
		break;
	}
	case DW_FORM_line_strp: {
		uint64_t off = rd_fixed(r, cu->off_size);
		v->str = sec_str(e->line_str, off);
		v->kind = v->str ? V_STR : V_UNRES;
		v->u = off;
		v->why = e->line_str ? "bad .debug_line_str offset"
		                     : "no .debug_line_str";
		break;
	}
	case DW_FORM_strx: case DW_FORM_strx1: case DW_FORM_strx2:
	case DW_FORM_strx3: case DW_FORM_strx4: {
		uint64_t idx = (form == DW_FORM_strx) ? rd_uleb(r)
		             : rd_fixed(r, (unsigned)(form - DW_FORM_strx1 + 1));
		const char *why = "unresolved";
		v->u = idx;
		v->str = r->err ? NULL : strx_lookup(e, cu, idx, &why);
		v->kind = v->str ? V_STR : V_UNRES;
		v->why = why;
		break;
	}
	case DW_FORM_addrx: case DW_FORM_addrx1: case DW_FORM_addrx2:
	case DW_FORM_addrx3: case DW_FORM_addrx4: {
		uint64_t idx = (form == DW_FORM_addrx) ? rd_uleb(r)
		             : rd_fixed(r, (unsigned)(form - DW_FORM_addrx1 + 1));
		const char *why = "unresolved";
		uint64_t a = 0;
		v->u = idx;
		if (!r->err && addrx_lookup(e, cu, idx, &a, &why)) {
			v->kind = V_U;
			v->u = a;
		} else {
			v->kind = V_UNRES;
			v->why = why;
		}
		break;
	}
	case DW_FORM_ref1: v->kind = V_REF; v->u = cu->cu_off + rd_u8(r); break;
	case DW_FORM_ref2: v->kind = V_REF; v->u = cu->cu_off + rd_u16(r); break;
	case DW_FORM_ref4: v->kind = V_REF; v->u = cu->cu_off + rd_u32(r); break;
	case DW_FORM_ref8: v->kind = V_REF; v->u = cu->cu_off + rd_u64(r); break;
	case DW_FORM_ref_udata:
		v->kind = V_REF;
		v->u = cu->cu_off + rd_uleb(r);
		break;
	case DW_FORM_ref_addr:
		/* Section-relative, not CU-relative. */
		v->kind = V_REF;
		v->u = rd_fixed(r, cu->off_size);
		break;
	case DW_FORM_ref_sup4: v->kind = V_U; v->u = rd_u32(r); break;
	case DW_FORM_ref_sup8: v->kind = V_U; v->u = rd_u64(r); break;
	case DW_FORM_strp_sup:
		/* String in a supplementary object file we do not have. */
		v->kind = V_UNRES;
		v->u = rd_fixed(r, cu->off_size);
		v->why = "supplementary file not loaded";
		break;
	case DW_FORM_loclistx: case DW_FORM_rnglistx:
		/* We read the index but do not expand the list. */
		v->kind = V_U;
		v->u = rd_uleb(r);
		break;
	case DW_FORM_exprloc: case DW_FORM_block: {
		uint64_t n = rd_uleb(r);
		v->kind = V_BLOCK;
		v->blk = rd_take(r, (size_t)n);
		v->blklen = v->blk ? (size_t)n : 0;
		break;
	}
	case DW_FORM_block1: case DW_FORM_block2: case DW_FORM_block4: {
		unsigned w = form == DW_FORM_block1 ? 1
		           : form == DW_FORM_block2 ? 2 : 4;
		uint64_t n = rd_fixed(r, w);
		v->kind = V_BLOCK;
		v->blk = rd_take(r, (size_t)n);
		v->blklen = v->blk ? (size_t)n : 0;
		break;
	}
	case DW_FORM_indirect: {
		/* The DIE names its own form at runtime. Recurse exactly once;
		 * a chain of indirects is malformed and we refuse it rather than
		 * recursing on attacker-controlled depth. */
		uint64_t real = rd_uleb(r);
		if (r->err)
			return 0;
		if (depth > 0 || real == DW_FORM_indirect) {
			r->err = 1;
			return 0;
		}
		return read_form(r, e, cu, real, 0, v, depth + 1);
	}
	default:
		/* Unknown form: we cannot know its length, so the rest of this CU
		 * is unparseable. Say so loudly instead of guessing. */
		return 0;
	}
	return !r->err;
}

static void print_block(const uint8_t *b, size_t n)
{
	printf("%zu byte block:", n);
	for (size_t i = 0; i < n; i++)
		printf(" %02x", b[i]);
}

static void print_val(const Val *v, uint64_t at)
{
	switch (v->kind) {
	case V_STR:
		printf("\"%s\"", v->str);
		break;
	case V_BLOCK:
		print_block(v->blk, v->blklen);
		break;
	case V_REF:
		printf("<0x%" PRIx64 ">", v->u);
		break;
	case V_S:
		printf("%" PRId64, v->s);
		break;
	case V_UNRES: {
		char sb[64];
		printf("<unresolved %s 0x%" PRIx64 ": %s>",
		       lookup(forms, sizeof forms / sizeof *forms, v->form, sb,
		              sizeof sb, "DW_FORM"), v->u, v->why);
		break;
	}
	case V_U:
	default:
		/* Addresses and section offsets read better in hex; counts,
		 * line numbers and flags in decimal. */
		if (at == DW_AT_low_pc || at == DW_AT_high_pc ||
		    at == DW_AT_entry_pc || at == DW_AT_stmt_list ||
		    at == DW_AT_ranges || at == DW_AT_str_offsets_base ||
		    at == DW_AT_addr_base || at == DW_AT_rnglists_base ||
		    at == DW_AT_loclists_base || at == DW_AT_macros ||
		    v->form == DW_FORM_addr || v->form == DW_FORM_ref_sig8)
			printf("0x%" PRIx64, v->u);
		else
			printf("%" PRIu64, v->u);
		break;
	}
}

/* ------------------------------------------------------------------ */
/* .debug_info                                                        */
/* ------------------------------------------------------------------ */

static const char *ut_name(uint64_t ut)
{
	switch (ut) {
	case 1: return "DW_UT_compile";
	case 2: return "DW_UT_type";
	case 3: return "DW_UT_partial";
	case 4: return "DW_UT_skeleton";
	case 5: return "DW_UT_split_compile";
	case 6: return "DW_UT_split_type";
	default: return "DW_UT_unknown";
	}
}

/* Returns 0 on a parse error (message already printed). */
static int dump_cu(Elf *e, Rd *r, uint64_t cu_off, int *bad)
{
	Cu cu = { 0 };
	cu.cu_off = cu_off;
	cu.off_size = 4;

	uint64_t len = rd_u32(r);
	if (r->err)
		return 0;
	/* 0xfffffff0..0xffffffff are reserved; 0xffffffff selects 64-bit DWARF
	 * where the real length and all section offsets become 8 bytes. */
	if (len == 0xffffffffu) {
		cu.off_size = 8;
		len = rd_u64(r);
	} else if (len >= 0xfffffff0u) {
		fprintf(stderr, "dbginfo: CU @0x%" PRIx64
		        ": reserved length 0x%" PRIx64 "\n", cu_off, len);
		return 0;
	}
	if (r->err)
		return 0;
	size_t body = r->pos;
	if (len > r->len - body) {
		fprintf(stderr, "dbginfo: CU @0x%" PRIx64 ": length 0x%" PRIx64
		        " runs past end of .debug_info\n", cu_off, len);
		return 0;
	}
	size_t cu_end = body + (size_t)len;

	cu.version = rd_u16(r);
	uint64_t ut = 1, abbrev_off = 0;
	if (cu.version >= 5) {
		/* DWARF5 reordered the header and added unit_type. */
		ut = rd_u8(r);
		cu.addr_size = rd_u8(r);
		abbrev_off = rd_fixed(r, cu.off_size);
		if (ut == 2 || ut == 6) {	/* type units carry a signature */
			(void)rd_u64(r);
			(void)rd_fixed(r, cu.off_size);
		} else if (ut == 4 || ut == 5) {	/* split units carry a dwo_id */
			(void)rd_u64(r);
		}
	} else if (cu.version >= 2) {
		abbrev_off = rd_fixed(r, cu.off_size);
		cu.addr_size = rd_u8(r);
	} else {
		fprintf(stderr, "dbginfo: CU @0x%" PRIx64
		        ": DWARF version %" PRIu64 " not supported "
		        "(we handle 2-5)\n", cu_off, cu.version);
		r->pos = cu_end;
		*bad = 1;
		return 1;
	}
	if (r->err)
		return 0;
	if (cu.addr_size == 0 || cu.addr_size > 8) {
		fprintf(stderr, "dbginfo: CU @0x%" PRIx64
		        ": implausible address size %u\n", cu_off, cu.addr_size);
		return 0;
	}

	printf("CU @0x%" PRIx64 " len=0x%" PRIx64 " version=%" PRIu64
	       " unit_type=%s abbrev_off=0x%" PRIx64 " addr_size=%u"
	       " dwarf%u\n", cu_off, len, cu.version,
	       cu.version >= 5 ? ut_name(ut) : "DW_UT_compile",
	       abbrev_off, cu.addr_size, cu.off_size == 8 ? 64 : 32);

	AbbrevTab tab = { 0 };
	if (!abbrev_parse(&tab, e->abbrev, abbrev_off)) {
		fprintf(stderr, "dbginfo: CU @0x%" PRIx64
		        ": bad abbrev table at 0x%" PRIx64 "\n",
		        cu_off, abbrev_off);
		abbrev_free(&tab);
		return 0;
	}

	/* The DIE tree is flattened: a DIE whose abbrev says it has children is
	 * followed by its children, and the child list is terminated by a null
	 * DIE (abbrev code 0). Depth is therefore derivable from the stream, no
	 * recursion needed - which also means a hostile file cannot blow the
	 * C stack here. */
	int depth = 0;
	int rc = 1;
	int first_die = 1;
	while (r->pos < cu_end) {
		uint64_t die_off = r->pos;
		uint64_t code = rd_uleb(r);
		if (r->err) {
			fprintf(stderr, "dbginfo: CU @0x%" PRIx64
			        ": truncated DIE at 0x%" PRIx64 "\n",
			        cu_off, die_off);
			rc = 0;
			break;
		}
		if (code == 0) {
			if (depth > 0)
				depth--;
			continue;
		}
		const Abbrev *a = abbrev_find(&tab, code);
		if (!a) {
			fprintf(stderr, "dbginfo: CU @0x%" PRIx64 ": DIE at 0x%"
			        PRIx64 " uses undeclared abbrev code %" PRIu64 "\n",
			        cu_off, die_off, code);
			rc = 0;
			break;
		}
		if (first_die) {
			first_die = 0;
			/* DW_AT_str_offsets_base and DW_AT_addr_base live on the root
			 * DIE, but nothing requires them to come first: clang emits
			 * DW_AT_name as DW_FORM_strx1 *before* declaring the base, so a
			 * single forward pass resolves the second CU's strings against
			 * CU 1's base. readelf caught us doing exactly that. So scan the
			 * root DIE's attributes once for the bases, then rewind and
			 * decode for real. read_form only reads, so the dry pass is
			 * free of side effects. */
			Rd pre = *r;
			Cu tmp = cu;
			for (size_t i = 0; i < a->nattr; i++) {
				Val v;
				if (!read_form(&pre, e, &tmp, a->attr[i].form,
				               a->attr[i].iconst, &v, 0))
					break;	/* malformed; the real pass will report it */
				if (a->attr[i].at == DW_AT_str_offsets_base)
					cu.str_off_base = v.u;
				else if (a->attr[i].at == DW_AT_addr_base)
					cu.addr_base = v.u;
			}
		}
		char tb[64];
		printf("<%d><0x%" PRIx64 "> %s (abbrev %" PRIu64 ")%s\n", depth,
		       die_off, lookup(tags, sizeof tags / sizeof *tags, a->tag,
		                       tb, sizeof tb, "DW_TAG"),
		       code, a->children ? " [children]" : "");
		for (size_t i = 0; i < a->nattr; i++) {
			Val v;
			if (!read_form(r, e, &cu, a->attr[i].form,
			               a->attr[i].iconst, &v, 0)) {
				char fb[64];
				fprintf(stderr, "dbginfo: CU @0x%" PRIx64 ": DIE 0x%"
				        PRIx64 ": cannot decode %s (0x%" PRIx64
				        "); rest of CU skipped\n", cu_off, die_off,
				        lookup(forms, sizeof forms / sizeof *forms,
				               a->attr[i].form, fb, sizeof fb, "DW_FORM"),
				        a->attr[i].form);
				rc = 0;
				goto done;
			}
			/* Bases must be captured as we go: later strx/addrx
			 * attributes in this same CU resolve through them. */
			if (a->attr[i].at == DW_AT_str_offsets_base)
				cu.str_off_base = v.u;
			else if (a->attr[i].at == DW_AT_addr_base)
				cu.addr_base = v.u;
			char ab[64];
			printf("    %s = ",
			       lookup(attrs, sizeof attrs / sizeof *attrs,
			              a->attr[i].at, ab, sizeof ab, "DW_AT"));
			print_val(&v, a->attr[i].at);
			putchar('\n');
		}
		if (a->children)
			depth++;
	}
done:
	abbrev_free(&tab);
	if (rc)
		r->pos = cu_end;	/* trailing padding is legal */
	return rc;
}

static int dump_info(Elf *e)
{
	if (!e->info)
		die("no .debug_info section (compile with -g?)");
	printf("== .debug_info (%zu bytes) ==\n", e->info->size);
	Rd r = rd_at(e->info->data, e->info->size, 0);
	int bad = 0;
	while (r.pos + 4 <= e->info->size) {
		uint64_t off = r.pos;
		if (!dump_cu(e, &r, off, &bad))
			return 0;
		if (r.pos <= off) {	/* belt and braces against a zero-length CU */
			fprintf(stderr, "dbginfo: CU @0x%" PRIx64
			        " made no progress\n", off);
			return 0;
		}
	}
	return !bad;
}

static int dump_abbrev(Elf *e)
{
	if (!e->abbrev)
		die("no .debug_abbrev section");
	printf("== .debug_abbrev (%zu bytes) ==\n", e->abbrev->size);
	/* Tables are concatenated with no index, so we walk offset to offset:
	 * each table ends at a zero code, and the next starts right after. */
	uint64_t off = 0;
	while (off < e->abbrev->size) {
		AbbrevTab t = { 0 };
		if (!abbrev_parse(&t, e->abbrev, off)) {
			fprintf(stderr, "dbginfo: bad abbrev table at 0x%" PRIx64
			        "\n", off);
			abbrev_free(&t);
			return 0;
		}
		printf("table @0x%" PRIx64 " (%zu abbrevs)\n", off, t.n);
		for (size_t i = 0; i < t.n; i++) {
			char tb[64];
			printf("  [%" PRIu64 "] %s %s\n", t.v[i].code,
			       lookup(tags, sizeof tags / sizeof *tags, t.v[i].tag,
			              tb, sizeof tb, "DW_TAG"),
			       t.v[i].children ? "[children]" : "[no children]");
			for (size_t j = 0; j < t.v[i].nattr; j++) {
				char ab[64], fb[64];
				printf("      %s %s", lookup(attrs,
				       sizeof attrs / sizeof *attrs, t.v[i].attr[j].at,
				       ab, sizeof ab, "DW_AT"),
				       lookup(forms, sizeof forms / sizeof *forms,
				              t.v[i].attr[j].form, fb, sizeof fb,
				              "DW_FORM"));
				if (t.v[i].attr[j].form == DW_FORM_implicit_const)
					printf(": %" PRId64, t.v[i].attr[j].iconst);
				putchar('\n');
			}
		}
		/* Re-walk to find where this table ended. abbrev_parse consumed it
		 * but does not report the end position, so recompute cheaply by
		 * scanning for the terminator the same way. */
		Rd r = rd_at(e->abbrev->data, e->abbrev->size, off);
		for (;;) {
			uint64_t code = rd_uleb(&r);
			if (r.err || code == 0)
				break;
			(void)rd_uleb(&r);
			(void)rd_u8(&r);
			for (;;) {
				uint64_t at = rd_uleb(&r), form = rd_uleb(&r);
				if (form == DW_FORM_implicit_const)
					(void)rd_sleb(&r);
				if (r.err || (at == 0 && form == 0))
					break;
			}
			if (r.err)
				break;
		}
		abbrev_free(&t);
		if (r.err || r.pos <= off)
			break;
		off = r.pos;
	}
	return 1;
}

/* ------------------------------------------------------------------ */
/* .debug_line                                                        */
/* ------------------------------------------------------------------ */

#define DW_LNCT_path 1
#define DW_LNCT_directory_index 2
#define DW_LNCT_timestamp 3
#define DW_LNCT_size 4
#define DW_LNCT_MD5 5

typedef struct {
	const char *name;
	uint64_t dir;
} FileEnt;

static void fv_push(FileEnt **v, size_t *n, size_t *cap, FileEnt f)
{
	if (*n == *cap) {
		*cap = *cap ? *cap * 2 : 8;
		FileEnt *nv = realloc(*v, *cap * sizeof **v);
		if (!nv)
			die("out of memory");
		*v = nv;
	}
	(*v)[(*n)++] = f;
}

/* Read one entry value from a DWARF5 directory/file table using the
 * format description. Only the forms the spec permits here are meaningful;
 * anything else we still have to skip by length, which read_form does. */
static int line_entry_val(Rd *r, Elf *e, const Cu *cu, uint64_t form, Val *v)
{
	return read_form(r, e, cu, form, 0, v, 0);
}

static int dump_line_prog(Elf *e, Rd *r, uint64_t unit_off, int verbose)
{
	Cu cu = { 0 };
	cu.off_size = 4;
	cu.addr_size = 8;

	uint64_t ulen = rd_u32(r);
	if (r->err)
		return 0;
	if (ulen == 0xffffffffu) {
		cu.off_size = 8;
		ulen = rd_u64(r);
	} else if (ulen >= 0xfffffff0u) {
		fprintf(stderr, "dbginfo: line unit @0x%" PRIx64
		        ": reserved length\n", unit_off);
		return 0;
	}
	if (r->err || ulen > r->len - r->pos) {
		fprintf(stderr, "dbginfo: line unit @0x%" PRIx64
		        ": length runs past end of .debug_line\n", unit_off);
		return 0;
	}
	size_t unit_end = r->pos + (size_t)ulen;

	uint64_t ver = rd_u16(r);
	if (r->err)
		return 0;
	if (ver < 2 || ver > 5) {
		fprintf(stderr, "dbginfo: line unit @0x%" PRIx64 ": version %"
		        PRIu64 " not supported (we handle 2-5)\n", unit_off, ver);
		return 0;
	}
	cu.version = ver;
	unsigned seg_sel = 0;
	if (ver >= 5) {
		cu.addr_size = rd_u8(r);
		seg_sel = rd_u8(r);
	}
	uint64_t hlen = rd_fixed(r, cu.off_size);
	size_t prog_start = r->pos + (size_t)hlen;	/* header_length is from here */
	unsigned min_inst = rd_u8(r);
	unsigned max_ops = (ver >= 4) ? rd_u8(r) : 1;
	unsigned default_is_stmt = rd_u8(r);
	int64_t line_base = (int8_t)rd_u8(r);
	unsigned line_range = rd_u8(r);
	unsigned opcode_base = rd_u8(r);
	if (r->err)
		return 0;
	if (min_inst == 0 || line_range == 0 || opcode_base == 0 ||
	    max_ops == 0 || cu.addr_size == 0 || cu.addr_size > 8) {
		fprintf(stderr, "dbginfo: line unit @0x%" PRIx64
		        ": implausible header (min_inst=%u line_range=%u "
		        "opcode_base=%u max_ops=%u addr_size=%u)\n", unit_off,
		        min_inst, line_range, opcode_base, max_ops, cu.addr_size);
		return 0;
	}
	uint8_t std_len[256] = { 0 };
	for (unsigned i = 1; i < opcode_base; i++)
		std_len[i] = rd_u8(r);
	if (r->err)
		return 0;

	printf("line unit @0x%" PRIx64 " len=0x%" PRIx64 " version=%" PRIu64
	       " addr_size=%u seg_sel=%u min_inst=%u max_ops=%u"
	       " default_is_stmt=%u line_base=%" PRId64 " line_range=%u"
	       " opcode_base=%u\n", unit_off, ulen, ver, cu.addr_size, seg_sel,
	       min_inst, max_ops, default_is_stmt, line_base, line_range,
	       opcode_base);

	char **dirs = NULL;
	size_t ndirs = 0, cdirs = 0;
	FileEnt *files = NULL;
	size_t nfiles = 0, cfiles = 0;
	int rc = 1;
	/* DWARF5 numbers files from 0 and entry 0 is the primary source file;
	 * DWARF2-4 number from 1 with entry 0 meaning "the CU's own name".
	 * The state machine's initial `file` register is 1 in both, which is
	 * why the off-by-one here is the classic place to get this wrong. */

	if (ver >= 5) {
		unsigned dfc = rd_u8(r);
		uint64_t *dforms = xmalloc((dfc ? dfc : 1) * 2 * sizeof(uint64_t));
		for (unsigned i = 0; i < dfc; i++) {
			dforms[2 * i] = rd_uleb(r);
			dforms[2 * i + 1] = rd_uleb(r);
		}
		uint64_t dcount = rd_uleb(r);
		if (r->err || dcount > unit_end) { free(dforms); rc = 0; goto out; }
		for (uint64_t i = 0; i < dcount && rc; i++) {
			const char *nm = NULL;
			for (unsigned j = 0; j < dfc; j++) {
				Val v;
				if (!line_entry_val(r, e, &cu, dforms[2 * j + 1], &v)) {
					rc = 0;
					break;
				}
				if (dforms[2 * j] == DW_LNCT_path && v.kind == V_STR)
					nm = v.str;
			}
			if (!rc)
				break;
			if (ndirs == cdirs) {
				cdirs = cdirs ? cdirs * 2 : 8;
				char **nv = realloc(dirs, cdirs * sizeof *nv);
				if (!nv) die("out of memory");
				dirs = nv;
			}
			dirs[ndirs++] = (char *)(uintptr_t)nm;
		}
		free(dforms);
		if (!rc) goto out;

		unsigned ffc = rd_u8(r);
		uint64_t *fforms = xmalloc((ffc ? ffc : 1) * 2 * sizeof(uint64_t));
		for (unsigned i = 0; i < ffc; i++) {
			fforms[2 * i] = rd_uleb(r);
			fforms[2 * i + 1] = rd_uleb(r);
		}
		uint64_t fcount = rd_uleb(r);
		if (r->err || fcount > unit_end) { free(fforms); rc = 0; goto out; }
		for (uint64_t i = 0; i < fcount && rc; i++) {
			FileEnt f = { NULL, 0 };
			for (unsigned j = 0; j < ffc; j++) {
				Val v;
				if (!line_entry_val(r, e, &cu, fforms[2 * j + 1], &v)) {
					rc = 0;
					break;
				}
				if (fforms[2 * j] == DW_LNCT_path && v.kind == V_STR)
					f.name = v.str;
				else if (fforms[2 * j] == DW_LNCT_directory_index)
					f.dir = v.u;
			}
			if (!rc)
				break;
			fv_push(&files, &nfiles, &cfiles, f);
		}
		free(fforms);
		if (!rc) goto out;
	} else {
		/* DWARF2-4: two NUL-terminated-string lists, each ended by an
		 * empty string. */
		for (;;) {
			Val v;
			if (!read_form(r, e, &cu, DW_FORM_string, 0, &v, 0)) {
				rc = 0;
				goto out;
			}
			if (!v.str || !*v.str)
				break;
			if (ndirs == cdirs) {
				cdirs = cdirs ? cdirs * 2 : 8;
				char **nv = realloc(dirs, cdirs * sizeof *nv);
				if (!nv) die("out of memory");
				dirs = nv;
			}
			dirs[ndirs++] = (char *)(uintptr_t)v.str;
		}
		fv_push(&files, &nfiles, &cfiles, (FileEnt){ NULL, 0 });	/* index 0 */
		for (;;) {
			Val v;
			if (!read_form(r, e, &cu, DW_FORM_string, 0, &v, 0)) {
				rc = 0;
				goto out;
			}
			if (!v.str || !*v.str)
				break;
			FileEnt f = { v.str, rd_uleb(r) };
			(void)rd_uleb(r);	/* mtime */
			(void)rd_uleb(r);	/* length */
			if (r->err) {
				rc = 0;
				goto out;
			}
			fv_push(&files, &nfiles, &cfiles, f);
		}
	}

	if (verbose) {
		printf("  directories:\n");
		for (size_t i = 0; i < ndirs; i++)
			printf("    [%zu] %s\n", i, dirs[i] ? dirs[i] : "(none)");
		printf("  files:\n");
		for (size_t i = 0; i < nfiles; i++)
			printf("    [%zu] dir=%" PRIu64 " %s\n", i, files[i].dir,
			       files[i].name ? files[i].name : "(none)");
	}

	if (prog_start > unit_end || prog_start < r->pos) {
		fprintf(stderr, "dbginfo: line unit @0x%" PRIx64
		        ": header_length 0x%" PRIx64 " inconsistent\n",
		        unit_off, hlen);
		rc = 0;
		goto out;
	}
	r->pos = prog_start;

	/* The line program is a bytecode over a row register set (DWARF5
	 * 6.2.2). Registers reset to these values at the start of every
	 * sequence and again after DW_LNE_end_sequence. */
	uint64_t addr = 0, op_index = 0, file = 1, line = 1, col = 0, isa = 0,
	         disc = 0;
	int is_stmt = default_is_stmt != 0, basic_block = 0, end_seq = 0,
	    prologue_end = 0, epilogue_begin = 0;
#define LINE_RESET() do { \
		addr = 0; op_index = 0; file = 1; line = 1; col = 0; isa = 0; \
		disc = 0; is_stmt = default_is_stmt != 0; basic_block = 0; \
		end_seq = 0; prologue_end = 0; epilogue_begin = 0; \
	} while (0)
#define ROW() do { \
		const char *fn = NULL; \
		size_t fi = (size_t)file; \
		if (fi < nfiles) fn = files[fi].name; \
		printf("  row file=%s line=", fn ? fn : "?"); \
		if (end_seq) printf("-"); else printf("%" PRIu64, line); \
		printf(" addr=0x%" PRIx64 " col=%" PRIu64 " stmt=%d%s%s%s\n", \
		       addr, col, is_stmt, \
		       basic_block ? " basic_block" : "", \
		       prologue_end ? " prologue_end" : "", \
		       end_seq ? " end_sequence" : ""); \
	} while (0)

	/* Address advance for VLIW targets: the operation advance is divided by
	 * max_ops to get whole instruction-bundle steps. On x86-64 max_ops is 1
	 * and this degenerates to addr += min_inst * advance. */
#define ADVANCE(opadv) do { \
		uint64_t _oa = (opadv); \
		addr += (uint64_t)min_inst * ((op_index + _oa) / max_ops); \
		op_index = (op_index + _oa) % max_ops; \
	} while (0)

	while (r->pos < unit_end) {
		uint8_t op = rd_u8(r);
		if (r->err)
			break;
		if (op >= opcode_base) {
			/* Special opcode: one byte encodes both an address and a line
			 * advance, and emits a row. This is where the compression in
			 * the line table comes from. */
			unsigned adj = op - opcode_base;
			ADVANCE(adj / line_range);
			line += line_base + (int64_t)(adj % line_range);
			ROW();
			basic_block = prologue_end = epilogue_begin = 0;
			disc = 0;
			continue;
		}
		if (op == 0) {
			/* Extended opcode: length-prefixed, so unknown ones are
			 * skippable - which is exactly why the length is there. */
			uint64_t elen = rd_uleb(r);
			if (r->err || elen == 0 || elen > unit_end - r->pos)
				break;
			size_t eend = r->pos + (size_t)elen;
			uint8_t sub = rd_u8(r);
			switch (sub) {
			case 1:	/* DW_LNE_end_sequence */
				end_seq = 1;
				ROW();
				LINE_RESET();
				break;
			case 2:	/* DW_LNE_set_address */
				addr = rd_fixed(r, cu.addr_size);
				op_index = 0;
				break;
			case 3:	/* DW_LNE_define_file (DWARF<=4) */
				if (ver <= 4) {
					Val v;
					if (read_form(r, e, &cu, DW_FORM_string, 0, &v, 0)) {
						FileEnt f = { v.str, rd_uleb(r) };
						(void)rd_uleb(r);
						(void)rd_uleb(r);
						fv_push(&files, &nfiles, &cfiles, f);
					}
				}
				break;
			case 4:	/* DW_LNE_set_discriminator */
				disc = rd_uleb(r);
				break;
			default:
				if (verbose)
					printf("  (unknown extended opcode %u, %" PRIu64
					       " bytes, skipped)\n", sub, elen);
				break;
			}
			if (eend > unit_end)
				break;
			r->pos = eend;	/* trust the length, not our own decoding */
			continue;
		}
		switch (op) {
		case 1:	/* DW_LNS_copy */
			ROW();
			disc = 0;
			basic_block = prologue_end = epilogue_begin = 0;
			break;
		case 2:	/* DW_LNS_advance_pc */
			ADVANCE(rd_uleb(r));
			break;
		case 3:	/* DW_LNS_advance_line */
			line = (uint64_t)((int64_t)line + rd_sleb(r));
			break;
		case 4: file = rd_uleb(r); break;	/* DW_LNS_set_file */
		case 5: col = rd_uleb(r); break;	/* DW_LNS_set_column */
		case 6: is_stmt = !is_stmt; break;	/* DW_LNS_negate_stmt */
		case 7: basic_block = 1; break;
		case 8:	/* DW_LNS_const_add_pc: advance as special opcode 255 */
			ADVANCE((255u - opcode_base) / line_range);
			break;
		case 9:	/* DW_LNS_fixed_advance_pc: uhalf, not LEB, and not scaled */
			addr += rd_u16(r);
			op_index = 0;
			break;
		case 10: prologue_end = 1; break;
		case 11: epilogue_begin = 1; break;
		case 12: isa = rd_uleb(r); break;
		default:
			/* A vendor standard opcode below opcode_base: the header told
			 * us how many LEB operands it takes, so we can skip it. */
			for (unsigned i = 0; i < std_len[op]; i++)
				(void)rd_uleb(r);
			break;
		}
		if (r->err)
			break;
	}
	(void)isa;
	(void)disc;
	(void)epilogue_begin;
	if (r->err) {
		fprintf(stderr, "dbginfo: line unit @0x%" PRIx64
		        ": truncated line program\n", unit_off);
		rc = 0;
	}
out:
	free(dirs);
	free(files);
	if (rc)
		r->pos = unit_end;
	return rc;
#undef ROW
#undef LINE_RESET
#undef ADVANCE
}

static int dump_line(Elf *e, int verbose)
{
	if (!e->line)
		die("no .debug_line section");
	printf("== .debug_line (%zu bytes) ==\n", e->line->size);
	Rd r = rd_at(e->line->data, e->line->size, 0);
	while (r.pos + 4 <= e->line->size) {
		uint64_t off = r.pos;
		if (!dump_line_prog(e, &r, off, verbose))
			return 0;
		if (r.pos <= off) {
			fprintf(stderr, "dbginfo: line unit @0x%" PRIx64
			        " made no progress\n", off);
			return 0;
		}
	}
	return 1;
}

static int dump_sections(Elf *e)
{
	printf("== sections (%zu) ==\n", e->nsec);
	for (size_t i = 0; i < e->nsec; i++)
		printf("  [%2zu] %-24s type=0x%-4x flags=0x%-4" PRIx64 " size=%zu\n",
		       i, e->sec[i].name ? e->sec[i].name : "(bad name)",
		       e->sec[i].type, e->sec[i].flags, e->sec[i].size);
	return 1;
}

/* ------------------------------------------------------------------ */

static void usage(FILE *f)
{
	fputs("usage: dbginfo [--sections] [--abbrev] [--info] [--line]\n"
	      "                 [--line-headers] [--all] FILE\n"
	      "\n"
	      "  --sections      ELF section header table\n"
	      "  --abbrev        .debug_abbrev abbreviation tables\n"
	      "  --info          .debug_info CU headers and DIE tree\n"
	      "  --line          .debug_line decoded line table rows\n"
	      "  --line-headers  --line plus directory and file tables\n"
	      "  --all           --sections --abbrev --info --line-headers\n"
	      "\n"
	      "default is --info. DWARF 2-5, 64-bit little-endian ELF.\n", f);
}

int main(int argc, char **argv)
{
	int want_sec = 0, want_abbrev = 0, want_info = 0, want_line = 0,
	    line_verbose = 0;
	const char *path = NULL;
	for (int i = 1; i < argc; i++) {
		const char *a = argv[i];
		if (strcmp(a, "--sections") == 0) want_sec = 1;
		else if (strcmp(a, "--abbrev") == 0) want_abbrev = 1;
		else if (strcmp(a, "--info") == 0) want_info = 1;
		else if (strcmp(a, "--line") == 0) want_line = 1;
		else if (strcmp(a, "--line-headers") == 0) want_line = line_verbose = 1;
		else if (strcmp(a, "--all") == 0)
			want_sec = want_abbrev = want_info = want_line = line_verbose = 1;
		else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
			usage(stdout);
			return 0;
		} else if (a[0] == '-' && a[1]) {
			fprintf(stderr, "dbginfo: unknown option %s\n", a);
			usage(stderr);
			return 2;
		} else if (!path) {
			path = a;
		} else {
			fprintf(stderr, "dbginfo: only one FILE allowed\n");
			return 2;
		}
	}
	if (!path) {
		usage(stderr);
		return 2;
	}
	if (!want_sec && !want_abbrev && !want_info && !want_line)
		want_info = 1;

	Elf e;
	elf_load(&e, path);
	int ok = 1;
	if (want_sec) ok &= dump_sections(&e);
	if (want_abbrev) ok &= dump_abbrev(&e);
	if (want_info) ok &= dump_info(&e);
	if (want_line) ok &= dump_line(&e, line_verbose);
	/* Free so ASan's leak checker can police the parse paths. */
	free(e.sec);
	free(e.file);
	return ok ? 0 : 1;
}
