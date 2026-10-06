# PLAN

## Contract

`dbginfo [--sections] [--abbrev] [--info] [--line] [--line-headers] [--all] FILE`
reads a 64-bit little-endian ELF file, finds `.debug_info`, `.debug_abbrev`,
`.debug_str`, `.debug_line_str`, `.debug_line` (plus `.debug_str_offsets` and
`.debug_addr` when present), and prints:

- the ELF section header table (`--sections`),
- every abbreviation table, with tags, attributes, forms and
  `DW_FORM_implicit_const` values (`--abbrev`),
- every compilation unit header and its full DIE tree with decoded attribute
  values (`--info`, the default),
- the line-number program run to completion as `row file=... line=... addr=...`
  (`--line`), optionally with the directory and file tables (`--line-headers`).

Pure C11 in one file, built by gcc with no libraries beyond libc: no libelf, no
libdwarf, no zlib. Exit 0 on a clean parse, 1 on a parse error or unreadable
input, 2 on a usage error.

## Hard invariant

Every fact we print agrees with `readelf`, and malformed input errors rather
than crashes.

Concretely, and checked by `make test`:

- For every test binary, the set of compilation-unit names, the multiset of
  (`DW_TAG_*`, `DW_AT_name`) pairs over the whole DIE tree, and the multiset of
  (file, line, address, is_stmt) line-table rows are *identical* to the ones
  extracted from `readelf --debug-dump=info` and
  `readelf --debug-dump=decodedline`. Not "similar", identical.
- No input - truncated, byte-corrupted, non-ELF, or a directory - may make
  dbginfo exit with a status above 1, which means no SIGSEGV, no SIGABRT, no
  timeout. Verified over ~2000 mutants per run, and again under
  `-fsanitize=address,undefined`.
- A construct we cannot decode is named in the output (`DW_FORM_unknown_0x...`,
  `<unresolved ... : no .debug_str_offsets>`, "rest of CU skipped"), never
  silently dropped.

## Oracle

Ranked, strongest first:

1. **`readelf --debug-dump=info` and `readelf --debug-dump=decodedline`** on
   binaries we compile here with `gcc -g`, `gcc -gdwarf-4`, `gcc -gdwarf-3`,
   `gcc -gdwarf64`, `g++ -g` and `clang -g`, at `-O0` and `-O2`. binutils'
   DWARF reader is 25 years old and independently written; where we disagree,
   we are wrong. Facts are extracted from both dumps with python and compared
   as multisets - the two text formats have nothing in common and diffing them
   would only measure formatting.
2. **The same oracle on a binary from the wild** - the harness looks for a
   system binary with `.debug_info` (here, a Go program with 80 CUs, 41409
   named DIEs and 122180 line rows, decompressed with objcopy first). Our own
   fixtures are all small C; a foreign producer at scale is where the
   assumptions break.
3. **The mutation sweeps.** Whole-file truncation, 3-byte corruption at strided
   offsets *inside* the `.debug_*` sections, and in-place `sh_size` shrinking of
   each debug section. Each sweep asserts it is non-vacuous (some mutants must
   be rejected) as well as non-fatal.
4. **ASan + UBSan** (`make test-asan`) running the entire suite, with
   `exitcode=42` so a sanitiser report cannot be mistaken for our own exit 1.
5. **valgrind**, spot-checked by hand on the C++ and Go binaries.

## Non-goals

- Linking libelf, libdwarf, zlib or anything else. Compressed sections get a
  diagnostic naming `objcopy --decompress-debug-sections`, not a decompressor.
- 32-bit ELF, big-endian ELF, non-ELF containers (Mach-O, PE).
- Following `DW_AT_dwo_name` into `.dwo` files, or `.gnu_debuglink` into
  separate debug files. readelf does; we print the skeleton unit and stop.
- Expanding `.debug_loclists`, `.debug_rnglists`, `.debug_loc`,
  `.debug_ranges`, `.debug_frame`, `.debug_macro`, `.debug_names`,
  `.debug_pubnames`. We print the index or section offset that points at them.
- Disassembling DWARF expressions. `DW_AT_location` prints its bytes; readelf
  prints `DW_OP_addr: 4010`.
- Rendering enumerated attribute values (`DW_AT_language = 29`, not `(C11)`).
- Being a library. It is a program that prints text.

## Commit sequence

- [x] ELF64 reader: the bounds-checked cursor and section lookup
      why: every later stage reads untrusted bytes, so the cursor with its
      sticky error flag has to exist before anything that uses it, or the
      error handling gets retrofitted and misses cases.
- [x] LEB128, the DWARF code name tables, and the abbreviation reader
      why: .debug_abbrev is a stream of LEB128 integers and the integers mean
      nothing without the tag/attribute/form tables, so all three land
      together or none of them is testable.
- [x] CU headers (DWARF 2-4), the DIE tree walk, and the constant forms
      why: the tree is flat in the byte stream, so an iterative depth counter
      is both simpler than recursion and immune to a file that nests a
      million DIEs deep.
- [x] String forms: inline, `.debug_str`, `.debug_line_str`
      why: gcc 14 puts the CU name in `.debug_line_str`, so a reader with
      only `DW_FORM_strp` gets no compilation unit name at all.
- [x] Reference forms: CU-relative, section-relative, type signatures
      why: `DW_FORM_ref4` and `DW_FORM_ref_addr` are indistinguishable on a
      single-CU binary and differ on every multi-CU link.
- [x] Block forms: `exprloc`, `block1/2/4`, `block`, `data16`
      why: every subprogram has a `DW_AT_location`, so until these exist
      every CU containing a function ends early.
- [x] DWARF 5 unit headers, unit types, and 64-bit DWARF
      why: gcc 14 emits DWARF 5 by default, so without this the tool refuses
      the output of the compiler it was written with.
- [x] The line-number program: state machine and DWARF 2-4 file tables
      why: the file/line mapping is the half of DWARF people actually use,
      and it has a completely separate oracle.
- [x] DWARF 5 line-table headers: format-described entry tables
      why: DWARF 5 also changed file numbering from 1-based to 0-based, which
      misattributes every row in a multi-file unit without crashing.
- [x] The oracle: extract facts and compare against readelf as multisets
      why: without it, "it looks right" is the only standard available, and
      that standard is how DWARF readers stay quietly wrong for years.
- [x] Indexed and exotic forms: `strx*`, `addrx*`, `loclistx`, `indirect`
      why: clang emits indexed strings by default, so its output has no
      names in it until these exist.
- [x] Oracle: add the clang fixture - **red**, 52 passed, 2 failed
      why: left as its own commit so the bug the oracle found is visible to
      anyone who bisects here, and so the suite has demonstrated it can fail.
- [x] Fix: prescan the root DIE for `DW_AT_str_offsets_base` / `addr_base`
      why: clang declares the bases *after* the `DW_FORM_strx1` attributes
      that need them, so a single forward pass cannot be correct.
- [x] Robustness sweeps and the ASan/UBSan target
      why: the robustness half of the invariant is not testable by
      inspection, and a sweep that rejects nothing passes while proving
      nothing - hence the non-vacuity assertions.
- [x] Oracle: a binary from the wild, plus the GNU split-DWARF attributes
      why: our fixtures can only contain constructs we thought to write; a
      foreign producer at scale is where the unknown assumption breaks.
- [x] README, then PLAN
      why: written last so the limitations list is observed rather than
      guessed at.

### Milestone 1 - the facts we print but do not yet check

- [ ] Compare `DW_AT_low_pc` / `DW_AT_high_pc` per subprogram against readelf
      why: addresses are the other half of what a debugger needs, and we print
      them today with nothing checking them.
- [ ] Compare the decoded `--abbrev` output against `readelf --debug-dump=abbrev`
      why: the abbrev table is the one structure every other check depends on,
      and it is currently only tested indirectly.
- [ ] Compare `DW_AT_type` reference targets, by resolving each reference and
      checking both tools name the same DIE
      why: a CU-relative vs section-relative mix-up in `DW_FORM_ref4` would
      pass every test we have now.
- [ ] Compare file *paths* (directory joined to file name), not just basenames
      why: readelf prints basenames in `decodedline`, so our directory-index
      handling is currently unverified, and DWARF 5 changed the indexing base.

### Milestone 2 - constructs we currently decline

- [ ] Disassemble DWARF expressions in `DW_AT_location` / `DW_AT_frame_base`
      why: raw bytes are honest but useless, and `DW_OP_addr`/`DW_OP_fbreg`
      cover the overwhelming majority of real operations.
- [ ] Render enumerated attribute values (`DW_AT_language`, `DW_AT_encoding`,
      `DW_AT_inline`, `DW_AT_virtuality`)
      why: cheap name tables, and it makes the dump readable without the spec
      open beside it.
- [ ] Expand `.debug_rnglists` / `.debug_ranges` for `DW_AT_ranges`
      why: optimised and inlined code has discontiguous address ranges, so
      `--O2` output today hides where a function actually lives.
- [ ] Follow `DW_AT_dwo_name` into `.dwo` files for split DWARF
      why: `-gsplit-dwarf` currently yields a skeleton unit and nothing else,
      which is the one case where readelf prints facts we cannot.

### Milestone 3 - inputs we reject

- [ ] 32-bit and big-endian ELF
      why: the only blockers are the hardcoded `Elf64_Shdr` offsets and the
      little-endian `rd_fixed`; both are parameterisable in an afternoon.
- [ ] `SHF_COMPRESSED` sections via a bundled inflate
      why: Go and Rust binaries ship compressed debug info by default, so the
      most interesting real-world input is the one we currently refuse.
- [ ] A seeded structure-aware fuzzer over `.debug_info` and `.debug_line`
      why: truncation and strided corruption are blunt; a fuzzer that mutates
      length fields and abbrev codes specifically would find the loop or
      over-read the sweeps have not.
