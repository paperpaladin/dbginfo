# dbginfo

A single-file C11 program that parses ELF64 section headers and decodes DWARF 2
through 5 debug information - compilation units, abbreviation tables, the DIE
tree with attribute values, and the line-number program - with no libelf, no
libdwarf and no zlib.

```
$ cat hello.c
int gv = 3;
int add(int a, int b) { return a + b; }
int main(void) { return add(gv, 1); }

$ gcc -g -O0 -o hello hello.c && dbginfo --info hello | head -12
== .debug_info (158 bytes) ==
CU @0x0 len=0x9a version=5 unit_type=DW_UT_compile abbrev_off=0x0 addr_size=8 dwarf32
<0><0xc> DW_TAG_compile_unit (abbrev 2) [children]
    DW_AT_producer = "GNU C17 14.2.0 -mtune=generic -march=x86-64 -g -O0 -fasynchronous-unwind-tables"
    DW_AT_language = 29
    DW_AT_name = "hello.c"
    DW_AT_comp_dir = "/tmp"
    DW_AT_low_pc = 0x1129
    DW_AT_high_pc = 0x2c
    DW_AT_stmt_list = 0x0
<1><0x2e> DW_TAG_variable (abbrev 3)
    DW_AT_name = "gv"
    DW_AT_decl_file = 1

$ dbginfo --line hello
== .debug_line (89 bytes) ==
line unit @0x0 len=0x55 version=5 addr_size=8 seg_sel=0 min_inst=1 max_ops=1 default_is_stmt=1 line_base=-5 line_range=14 opcode_base=13
  row file=hello.c line=2 addr=0x1129 col=23 stmt=1
  row file=hello.c line=2 addr=0x1133 col=34 stmt=1
  row file=hello.c line=2 addr=0x113b col=39 stmt=1
  row file=hello.c line=3 addr=0x113d col=16 stmt=1
  row file=hello.c line=3 addr=0x1141 col=25 stmt=1
  row file=hello.c line=3 addr=0x1153 col=37 stmt=1
  row file=hello.c line=- addr=0x1155 col=37 stmt=1 end_sequence
```

```
usage: dbginfo [--sections] [--abbrev] [--info] [--line]
                 [--line-headers] [--all] FILE
```

## Why this exists

DWARF is the format every debugger, profiler and crash reporter on Linux
depends on, and it is usually consumed through libdwarf or gdb, which means
very few people have ever watched the bytes. Writing the decoder is the only
way to find out which parts of the format are genuinely hard (the line-number
state machine, DWARF 5's indirect string tables) and which only look hard (the
DIE tree, a flat stream with an implicit depth counter).

It is also an exercise in parsing hostile input. A debug section is
attacker-controlled data in any tool that reads crash dumps from strangers, and
"I added a bounds check where it seemed necessary" is not a defence. So every
read in this program goes through one cursor with a sticky error flag, and
`make test` throws ~2000 truncated and corrupted mutants at it per run.

## The oracle

`readelf` is the authority. binutils' DWARF reader is decades old and was
written independently. Where we disagree, we are wrong.

`t/run.sh` compiles fixtures with `gcc -g`, `gcc -gdwarf-4`, `gcc -gdwarf-3`,
`gcc -gdwarf64`, `g++ -g` and `clang -g` at `-O0` and `-O2`, finds a system
binary with debug info if one exists, then for each one extracts and compares:

| fact | from readelf | from us |
|---|---|---|
| compilation unit names | `--debug-dump=info` | `--info` |
| (`DW_TAG_*`, `DW_AT_name`) over the whole DIE tree | `--debug-dump=info` | `--info` |
| (name, `DW_AT_low_pc`, `DW_AT_high_pc`) per subprogram | `--debug-dump=info` | `--info` |
| every abbreviation declaration: offset, code, tag, children, (attribute, form, implicit value) | `--debug-dump=abbrev` | `--abbrev` |

2778 abbreviation declaration lines across the eleven binaries agree with
binutils. The number is here because the commit that added the comparison
claimed 2673 in its message, a figure written down rather than measured; the
suite prints the per-binary counts and they add up to 2778.
| (file, line, address) per line-table row | `--debug-dump=decodedline` | `--line` |
| is_stmt per row | `--debug-dump=decodedline` | `--line` |

The comparison is on extracted facts as multisets, never on raw text. Those
two formats share nothing, and diffing them would measure formatting. The
abbreviation comparison is the one ordered list rather than a multiset,
because the order of codes within a table and of tables within the section
are facts in themselves.

Two normalisations are applied, neither about a byte. Binutils still prints
the DWARF 3 short form for two tags (`DW_TAG_template_type_param` for
`DW_TAG_template_type_parameter`). And where a code has no name, readelf
writes three words with a different first one for the vendor range
(`Unknown AT value: 3f01`, `User TAG value: 0x4201`) against our
`DW_AT_unknown_0x3f01`. The fold runs in one direction only: a code we name
and readelf does not is a disagreement and fails.

The oracle has already earned its keep. It caught dbginfo resolving clang's
*second* compilation unit's strings against the *first* unit's
`DW_AT_str_offsets_base`, because clang emits `DW_AT_name` as
`DW_FORM_strx1` before it declares the base. Every function and variable name
in that CU was wrong, and nothing about the output looked wrong - the strings
were real strings, just the neighbouring ones. The fix is a prescan of the root
DIE for the bases before decoding any attribute.

```
$ make test
cc -std=c11 -O2 -g -Wall -Wextra -Wshadow -Wpedantic -o dbginfo dbginfo.c
./t/run.sh
--- wild binary: /usr/bin/host-spawn
--- oracle: readelf --debug-dump=info / =decodedline
ok   g5 info_exit
ok   g5 line_exit
ok   g5 cu_names (2 CUs)
ok   g5 die_names (42 named DIEs)
ok   g5 line_rows (42 rows)
ok   g5 line_stmt (40 rows)
ok   g4 info_exit
ok   g4 line_exit
ok   g4 cu_names (2 CUs)
ok   g4 die_names (42 named DIEs)
ok   g4 line_rows (42 rows)
ok   g4 line_stmt (40 rows)
ok   g5opt info_exit
ok   g5opt line_exit
ok   g5opt cu_names (2 CUs)
ok   g5opt die_names (42 named DIEs)
ok   g5opt line_rows (40 rows)
ok   g5opt line_stmt (38 rows)
ok   g4opt info_exit
ok   g4opt line_exit
ok   g4opt cu_names (2 CUs)
ok   g4opt die_names (42 named DIEs)
ok   g4opt line_rows (40 rows)
ok   g4opt line_stmt (38 rows)
ok   g3 info_exit
ok   g3 line_exit
ok   g3 cu_names (2 CUs)
ok   g3 die_names (42 named DIEs)
ok   g3 line_rows (42 rows)
ok   g3 line_stmt (40 rows)
ok   tiny info_exit
ok   tiny line_exit
ok   tiny cu_names (1 CUs)
ok   tiny die_names (3 named DIEs)
ok   tiny line_rows (4 rows)
ok   tiny line_stmt (3 rows)
ok   d64 info_exit
ok   d64 line_exit
ok   d64 cu_names (2 CUs)
ok   d64 die_names (42 named DIEs)
ok   d64 line_rows (42 rows)
ok   d64 line_stmt (40 rows)
ok   cpp5 info_exit
ok   cpp5 line_exit
ok   cpp5 cu_names (1 CUs)
ok   cpp5 die_names (1213 named DIEs)
ok   cpp5 line_rows (354 rows)
ok   cpp5 line_stmt (301 rows)
ok   c5 info_exit
ok   c5 line_exit
ok   c5 cu_names (2 CUs)
ok   c5 die_names (40 named DIEs)
ok   c5 line_rows (41 rows)
ok   c5 line_stmt (39 rows)
ok   wild info_exit
ok   wild line_exit
ok   wild cu_names (80 CUs)
ok   wild die_names (41409 named DIEs)
ok   wild line_rows (122180 rows)
ok   wild line_stmt (119084 rows)
--- robustness: truncation / corruption / non-ELF
ok   truncation sweep (804 runs over 201 prefixes, 804 rejected, 0 crashed or hung)
ok   corruption sweep (840 runs inside .debug_* sections, 196 rejected, 0 crashed or hung)
ok   section-shrink sweep (410 runs over 5 sections, 197 rejected, 0 crashed or hung)
ok   non-ELF and missing-debug-info inputs error cleanly
ok   directory argument errors cleanly

85 passed, 0 failed
```

The block above shows 65 of the 118 `ok` lines the suite now prints, and its
total line is two revisions out of date. The 20 missing from it first were the
`subprogram_pcs` and `subprogram_pcs_nonempty` pairs, one of each per fixture;
the 33 after that are the `abbrev_exit`, `abbrev` and `abbrev_nonempty` triple
for the ten fixtures, plus the three the `abbrevsyn` fixture contributes on
its own. Said here instead of quietly regenerated, because the gap is the
useful fact: a transcript is evidence only for as long as someone re-pastes
it, and ten fixtures times eleven checks, plus three, plus five, is the
arithmetic a reader should be able to do.

`make test-asan` reruns all 118 under `-fsanitize=address,undefined` (also
clean). `ASAN_OPTIONS=exitcode=42` is load-bearing there: ASan's default exit
status on a report is 1, also our own "malformed input" status, so
without it the harness would wave a real memory error through as a clean
diagnostic.

The `wild` row depends on what the machine happens to have installed. Here it
is a Go binary (`/usr/bin/host-spawn`, 80 CUs, 41409 named DIEs, 122180 line
rows), decompressed with `objcopy --decompress-debug-sections` first because its
debug sections are `SHF_COMPRESSED`. On a machine with no such binary the row is
skipped and the suite reports 107: each fixture contributes 11 checks.

One fixture is not compiled from C at all. `abbrevsyn` is a hand-assembled
`.debug_abbrev` section with nothing else in the file, and it exists because
of a mutant that survived everything else: gcc and clang both number their
abbreviation codes 1..n in declaration order, so a reader that printed the
index of a declaration instead of the code it read agreed with readelf on all
ten real binaries. DWARF imposes no such numbering. The fixture declares code
5 before code 2, and carries the other constructs no compiler will emit on
request: an attribute and a tag in the vendor ranges, a form that is not
allocated at all, and a negative `DW_FORM_implicit_const`. It contributes 3
checks and is the only place the unknown-code paths are reached when no wild
binary is installed.

## Status

Works, and agrees with readelf on every fact it prints.

Until recently that sentence was weaker than it sounded. The comparison covered
tag and name pairs and line-table rows, and nothing at all checked an address:
every `DW_AT_low_pc` and `DW_AT_high_pc` was printed unverified. Adding one
to every printed address above `0x10` used to pass all 65 assertions. It now
fails 10 of 85.

`high_pc` is compared as the raw value both tools print, which in DWARF 4 and
later is a *length*, not an address. Comparing a computed end address
would have been comparing two sums of the same two numbers, a longer
way of checking nothing.

The abbreviation tables were in the same position until the check above was
written. They are read by everything, so the argument was that a defect there
shows up downstream, and for part of the structure that is true: an abbrev
code read wrongly picks the wrong declaration and the DIE names go wrong.
It is not true of what the table says about attributes nothing else compares.
Printing `[no children]` for every declaration, adding one to every
`DW_FORM_implicit_const` value, and printing a negative implicit value as
unsigned were each invisible to all 85 earlier checks and each fail now.

Supported. DWARF 2, 3, 4 and 5 in `.debug_info` and `.debug_line`. 32-bit
and 64-bit DWARF (`-gdwarf64` verified). `DW_UT_compile`, `DW_UT_partial`,
`DW_UT_type`, `DW_UT_skeleton` headers. All 43 `DW_FORM` codes in DWARF 5,
including `DW_FORM_implicit_const` (which gcc 14 leans on heavily),
`DW_FORM_strx1..4` and `DW_FORM_addrx1..4` resolved through
`.debug_str_offsets` / `.debug_addr`, and `DW_FORM_indirect`. 70 tags and 133
attributes by name. The full line-number program: special opcodes, all twelve
standard opcodes, the four extended opcodes, DWARF 5's `directory_entry_format`
tables, and VLIW `max_ops_per_instruction` address advance. `gcc` and `clang`,
C and C++, `-O0` and `-O2`.

What does not work.

- Compressed debug sections. `SHF_COMPRESSED` and `.zdebug_*` are refused
  with a diagnostic naming `objcopy --decompress-debug-sections`, because
  linking zlib is off the table. This is the common case for Go and Rust
  binaries, so the most interesting input in the wild needs a preprocessing
  step.
- Split DWARF. `-gsplit-dwarf` gives you the skeleton unit and nothing
  else. We do not follow `DW_AT_dwo_name` into the `.dwo` file, and we do not
  follow `.gnu_debuglink` either. readelf does both, so this is the one case
  where it prints facts we cannot, and the one case excluded from the test
  matrix for that reason.
- 32-bit ELF and big-endian ELF are rejected at the magic check. The
  blockers are the hardcoded `Elf64_Shdr` field offsets and a little-endian-only
  `rd_fixed`.
- DWARF expressions are not disassembled. `DW_AT_location` prints
  `9 byte block: 03 10 40 00 ...` where readelf prints `(DW_OP_addr: 4010)`.
  Honest, but less useful.
- Enumerated attribute values are printed as numbers. `DW_AT_language = 29`,
  not `(C11)`; likewise `DW_AT_encoding`, `DW_AT_inline`, `DW_AT_virtuality`.
- Location and range lists are not expanded. `DW_FORM_loclistx`,
  `DW_FORM_rnglistx`, `DW_AT_ranges` and `DW_AT_location` section offsets print
  the index or offset; `.debug_loclists`, `.debug_rnglists`, `.debug_loc` and
  `.debug_ranges` are never read. On `-O2` output this hides the real address
  ranges of inlined code.
- Sections we never look at: `.debug_frame`/`.eh_frame` (no CFI
  decoding at all), `.debug_macro`, `.debug_names`, `.debug_pubnames`,
  `.debug_aranges`, `.debug_types`.
- `DW_FORM_strp_sup` / `DW_FORM_ref_sup4` / `DW_FORM_ref_sup8` are skipped
  by the right number of bytes and printed as unresolved: supplementary object
  files are not loaded.
- Unknown codes are named, not hidden. An unrecognised tag, attribute or
  form prints as `DW_TAG_unknown_0x4109` / `DW_FORM_unknown_0x2d`. An unknown
  *form* is fatal for the rest of that CU - we cannot know its length, so we
  print a diagnostic saying the remainder is skipped instead of guessing and
  emitting plausible rubbish. None of the fixtures or the Go binary hit this
  path.
- `DW_AT_str_offsets_base` is assumed to be 8 when a CU declares no base at
  all. The root DIE is prescanned for a real base first, so this only affects
  producers that omit the attribute entirely.
- The line table's file column prints the file-table name, not the directory
  joined to it - matching readelf's `decodedline`, which means our
  directory-index handling is printed but not yet verified by the oracle.

## Design

One file, 1831 lines, of which the tag/attribute/form name tables and their `#define`s
are about a fifth (lines 148-494, 347 lines), this said half, four
layers, each depending only on the one below.

The cursor (`Rd`). A buffer, a length, a position and a sticky error flag.
Every single read of the file goes through it; `rd_take` is the only thing that
turns an offset into a pointer. The flag is sticky so a caller can decode a
whole structure and check once at the end - which is what keeps the error paths
short enough to be right. Nothing in the program indexes the file buffer
directly, and `sec_str` is the only way to obtain a `char *` from a section
(refusing an unterminated string, not over-reading it). That single
chokepoint is why ~2000 mutants per test run produce diagnostics instead of
segfaults.

ELF. The whole file is read into one `malloc` buffer, not `mmap`ed,
specifically so that a truncated file yields our error message instead of
`SIGBUS`. Section headers whose contents fall outside the file are recorded as
empty with a warning, since that is the normal shape of a truncated object.

DWARF structure. LEB128, abbreviation tables (parsed per CU, looked up by
linear scan - a real CU declares a handful, and a scan is immune to a hostile
table claiming code 2^60), CU headers for both the DWARF 4 and the reshuffled
DWARF 5 layouts, and one `read_form` covering every form. The DIE tree is
walked iteratively with a depth counter, because the tree is already flat in the
byte stream: a hostile file therefore cannot recurse us off the stack.

The line program. A register set and a bytecode interpreter, kept
deliberately close to the spec's own prose so the two can be read side by side.

Every loop advances the cursor by at least one byte or sets the error flag,
which is the invariant that makes "no timeout" provable.

Deliberate shortcuts are marked `shortcut:` in the source, each naming its
ceiling and its upgrade path.

## License

GPL-3.0. See `LICENSE`.
