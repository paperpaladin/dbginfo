#!/bin/sh
# Oracle harness. readelf is the authority; we compare extracted facts, never
# raw text, because the two output formats have nothing in common.
#
# Checks per test binary:
#   cu_names   - the DW_AT_name of every compilation unit
#   die_names  - the multiset of (DW_TAG_*, DW_AT_name) over the whole DIE tree
#   line_rows  - the multiset of (file, line, address) from the line program
#   line_stmt  - the is_stmt flag per row (end_sequence rows excluded, see below)
# Then a robustness sweep: truncations, byte corruption, and non-ELF input must
# exit cleanly rather than crash, hang, or read out of bounds.
set -u

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
DD=${DD:-$root/dbginfo}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM

pass=0
fail=0
ok()   { pass=$((pass+1)); printf 'ok   %s\n' "$*"; }
bad()  { fail=$((fail+1)); printf 'FAIL %s\n' "$*"; }

[ -x "$DD" ] || { echo "no dbginfo binary at $DD (run make)"; exit 1; }
command -v readelf >/dev/null || { echo "readelf not found; no oracle"; exit 1; }

# ---------------------------------------------------------------- fixtures
mkdir -p "$work/src"
cat > "$work/src/pt.h" <<'EOF'
struct Pt { int x, y; };
static inline int pt_sum(struct Pt p) { return p.x + p.y; }
EOF
cat > "$work/src/lib.c" <<'EOF'
#include "pt.h"
int helper(struct Pt *p, double d) { return pt_sum(*p) + (int)d; }
EOF
cat > "$work/src/main.c" <<'EOF'
#include "pt.h"
extern int helper(struct Pt *, double);
enum Colour { RED, GREEN, BLUE };
typedef struct Pt Point;
union U { long l; char c[8]; };
static const char *msg = "hello";
int arr[4] = { 1, 2, 3, 4 };
unsigned long long big = 1ULL << 40;
static int bump(int *p) { return ++*p; }
int main(void)
{
	Point p = { 1, 2 };
	enum Colour c = BLUE;
	union U u = { .l = 7 };
	int n = 0;
	for (int i = 0; i < 3; i++)
		n += bump(&i) + arr[i];
	return helper(&p, 2.5) + c + (int)u.c[0] + (int)msg[0] + n + (int)big;
}
EOF
cat > "$work/src/tiny.c" <<'EOF'
int main(void) { return 0; }
EOF

# build is always called as `add "$(build ...)"`, and command substitution
# runs in a SUBSHELL -- so `fail=$((fail+1))` here incremented a copy and was
# discarded. A compiler that could not build a fixture printed FAIL to stderr
# and the suite exited 0 with that producer silently untested, its name
# missing from $bins and skipped by the `[ -n "$b" ] || continue` below.
#
# The filesystem crosses the subshell boundary, so the failure is recorded
# there and the parent checks it after all the builds.
: > "$work/build.failures"

build() {   # build NAME CC FLAGS...
	name=$1; shift
	if "$@" -o "$work/$name" 2>"$work/$name.cc.log"; then
		echo "$name"
	else
		printf 'FAIL could not build %s:\n' "$name" >&2
		sed 's/^/    /' "$work/$name.cc.log" >&2
		echo "$name" >> "$work/build.failures"
	fi
}

bins=""
add() { bins="$bins $1"; }
S="$work/src"
add "$(build g5     gcc -g        -O0 "$S/main.c" "$S/lib.c")"
add "$(build g4     gcc -gdwarf-4 -O0 "$S/main.c" "$S/lib.c")"
add "$(build g5opt  gcc -g        -O2 "$S/main.c" "$S/lib.c")"
add "$(build g4opt  gcc -gdwarf-4 -O2 "$S/main.c" "$S/lib.c")"
add "$(build g3     gcc -gdwarf-3 -O0 "$S/main.c" "$S/lib.c")"
add "$(build tiny   gcc -g        -O0 "$S/tiny.c")"
# -gdwarf64 (gcc 11+) is the only easy way to get 64-bit DWARF, where every
# unit length and section offset widens to 8 bytes. Skip it if gcc is older.
if gcc -gdwarf64 -c -o /dev/null -x c /dev/null 2>/dev/null; then
	add "$(build d64 gcc -g -gdwarf64 -O0 "$S/main.c" "$S/lib.c")"
fi
if command -v g++ >/dev/null; then
	# C++ is the stress case: ~1200 named DIEs, templates, namespaces,
	# inheritance, DW_AT_specification, and a line table spanning headers.
	cat > "$work/src/cls.cpp" <<'CPP'
#include <string>
#include <vector>
namespace N { template <class T> struct Box { T v; T get() const { return v; } }; }
struct Base { virtual ~Base() {} virtual int f() { return 1; } };
struct Der : Base { int f() override { return 2; } };
int main()
{
	N::Box<int> b{3};
	std::vector<int> v{1, 2};
	std::string s = "x";
	Der d;
	return b.get() + v[0] + (int)s.size() + d.f();
}
CPP
	add "$(build cpp5 g++ -g -O0 "$S/cls.cpp")"
fi
if command -v clang >/dev/null; then
	# clang is worth a row of its own: it is the producer that actually uses
	# DW_FORM_strx*/addrx*, which gcc only emits for split DWARF.
	add "$(build c5 clang -g -O0 "$S/main.c" "$S/lib.c")"
fi

# ---------------------------------------------------------------- extractor
cat > "$work/cmp.py" <<'PY'
import re, subprocess, sys
from collections import Counter

elf = sys.argv[1]
name = sys.argv[2]
dd = sys.argv[3]

def run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.stdout, p.returncode

# ---- readelf --debug-dump=info
# binutils still prints the DWARF3-era short spellings for two tags. That is a
# naming difference between two renderers of the same byte, not a disagreement
# about a fact, so normalise it and keep comparing the facts.
TAG_ALIAS = {
    "DW_TAG_template_type_param": "DW_TAG_template_type_parameter",
    "DW_TAG_template_value_param": "DW_TAG_template_value_parameter",
}

def readelf_info():
    out, rc = run(["readelf", "--debug-dump=info", elf])
    dies, cus = [], []
    tag = None
    for ln in out.splitlines():
        m = re.match(r"\s*<\d+><[0-9a-f]+>:\s+Abbrev Number:\s+\d+\s+\((\S+)\)", ln)
        if m:
            tag = TAG_ALIAS.get(m.group(1), m.group(1))
            continue
        m = re.match(r"\s*<[0-9a-f]+>\s+(DW_AT_\w+)\s*:\s*(.*)$", ln)
        if m and m.group(1) == "DW_AT_name" and tag:
            v = m.group(2).strip()
            # strp/line_strp/strx values are prefixed with their provenance,
            # e.g. "(indirect string, offset: 0x4c): main".
            if v.startswith("("):
                v = v.split("): ", 1)[1] if "): " in v else v
            dies.append((tag, v))
            if tag == "DW_TAG_compile_unit":
                cus.append(v)
    return cus, dies, rc

# ---- our own --info
def mine_info():
    out, rc = run([dd, "--info", elf])
    dies, cus = [], []
    tag = None
    for ln in out.splitlines():
        m = re.match(r"<\d+><0x[0-9a-f]+> (\S+)", ln)
        if m:
            tag = m.group(1)
            continue
        m = re.match(r"\s+(DW_AT_\w+) = (.*)$", ln)
        if m and m.group(1) == "DW_AT_name" and tag:
            v = m.group(2)
            if v.startswith('"') and v.endswith('"'):
                v = v[1:-1]
            dies.append((tag, v))
            if tag == "DW_TAG_compile_unit":
                cus.append(v)
    return cus, dies, rc

# ---- subprogram address ranges, from both tools
#
# low_pc/high_pc is the other half of what a debugger needs from .debug_info,
# and until now we printed it with nothing checking it. Both tools render the
# raw value, and in DWARF 4 and later high_pc is a *length* rather than an
# address, so what is compared is what both of them actually print rather than
# a sum one of us computed.
#
# A subprogram with no address -- a declaration, or the abstract root of an
# inlined function -- is recorded as "-" rather than skipped. Dropping them
# would let a tool that invents an address for a declaration pass.
def addr_triples(text, die_re, attr_re, unquote):
    out = []
    tag = None
    cur = {}

    def flush():
        if tag == "DW_TAG_subprogram":
            out.append("%s %s %s" % (cur.get("DW_AT_name", "-"),
                                     cur.get("DW_AT_low_pc", "-"),
                                     cur.get("DW_AT_high_pc", "-")))

    for ln in text.splitlines():
        m = re.match(die_re, ln)
        if m:
            flush()
            tag = TAG_ALIAS.get(m.group(1), m.group(1))
            cur = {}
            continue
        m = re.match(attr_re, ln)
        if m and tag:
            k, v = m.group(1), m.group(2).strip()
            if k in ("DW_AT_name", "DW_AT_low_pc", "DW_AT_high_pc"):
                cur[k] = unquote(v)
    flush()
    return sorted(out)

RE_DIE = r"\s*<\d+><[0-9a-f]+>:\s+Abbrev Number:\s+\d+\s+\((\S+)\)"
RE_ATTR = r"\s*<[0-9a-f]+>\s+(DW_AT_\w+)\s*:\s*(.*)$"
MY_DIE = r"<\d+><0x[0-9a-f]+> (\S+)"
MY_ATTR = r"\s+(DW_AT_\w+) = (.*)$"

def strip_readelf(v):
    # strp/line_strp/strx values carry their provenance: "(indirect string,
    # offset: 0x57): main".
    if v.startswith("(") and "): " in v:
        v = v.split("): ", 1)[1]
    return v.strip()

def strip_ours(v):
    return v[1:-1] if v.startswith('"') and v.endswith('"') else v

def readelf_subs():
    out, _ = run(["readelf", "--debug-dump=info", elf])
    return addr_triples(out, RE_DIE, RE_ATTR, strip_readelf)

def mine_subs():
    out, _ = run([dd, "--info", elf])
    return addr_triples(out, MY_DIE, MY_ATTR, strip_ours)

# ---- readelf --debug-dump=decodedline
# Row layout: "file  line  0xaddr  [view]  [x]". The trailing x is the Stmt
# column; a numeric last field is the View column, meaning is_stmt is clear.
def readelf_lines():
    out, rc = run(["readelf", "--debug-dump=decodedline", elf])
    rows, stmt = [], []
    for ln in out.splitlines():
        m = re.match(r"^(\S+)\s+(\d+|-)\s+(0x[0-9a-f]+)", ln)
        if not m:
            continue
        f, l, a = m.group(1), m.group(2), m.group(3)
        rows.append((f, l, int(a, 16)))
        if l != "-":
            stmt.append((f, l, int(a, 16), ln.split()[-1] == "x"))
    return rows, stmt, rc

def mine_lines():
    out, rc = run([dd, "--line", elf])
    rows, stmt = [], []
    for ln in out.splitlines():
        m = re.match(r"\s+row file=(\S+) line=(\S+) addr=(0x[0-9a-f]+) col=\d+ stmt=(\d)", ln)
        if not m:
            continue
        f, l, a, s = m.group(1), m.group(2), int(m.group(3), 16), m.group(4) == "1"
        rows.append((f, l, a))
        # readelf leaves the Stmt column blank on end_sequence rows regardless
        # of the register, so comparing it there would compare formatting, not
        # facts. We still print the register; we just do not score it.
        if l != "-":
            stmt.append((f, l, a, s))
    return rows, stmt, rc

def report(check, a, b, kind="set"):
    if a == b:
        print("ok   %s %s (%d %s)" % (name, check, len(a) if hasattr(a, "__len__") else 0, kind))
        return 0
    print("FAIL %s %s" % (name, check))
    if isinstance(a, list) and isinstance(b, list):
        ca, cb = Counter(a), Counter(b)
        miss = list((ca - cb).elements())[:8]
        extra = list((cb - ca).elements())[:8]
        if miss:
            print("       readelf has, we do not: %r" % (miss,))
        if extra:
            print("       we have, readelf does not: %r" % (extra,))
        print("       counts: readelf=%d ours=%d" % (len(a), len(b)))
    else:
        print("       readelf=%r" % (a,))
        print("       ours   =%r" % (b,))
    return 1

rcus, rdies, rrc = readelf_info()
mcus, mdies, mrc = mine_info()
rrows, rstmt, _ = readelf_lines()
mrows, mstmt, mlrc = mine_lines()
rsubs, msubs = readelf_subs(), mine_subs()

bad = 0
if mrc != 0:
    print("FAIL %s info_exit (dbginfo --info exited %d)" % (name, mrc)); bad += 1
else:
    print("ok   %s info_exit" % name)
if mlrc != 0:
    print("FAIL %s line_exit (dbginfo --line exited %d)" % (name, mlrc)); bad += 1
else:
    print("ok   %s line_exit" % name)
bad += report("cu_names", rcus, mcus, "CUs")
bad += report("die_names", sorted(rdies), sorted(mdies), "named DIEs")
bad += report("subprogram_pcs", rsubs, msubs, "subprograms")
# A comparison of two empty lists agrees and proves nothing. Every fixture
# here is compiled from C with at least a main, so zero subprograms means the
# extractor stopped working rather than that the binary has none.
if not rsubs:
    print("FAIL %s subprogram_pcs_nonempty (readelf found no subprograms)" % name)
    bad += 1
else:
    print("ok   %s subprogram_pcs_nonempty (%d)" % (name, len(rsubs)))
bad += report("line_rows", rrows, mrows, "rows")
bad += report("line_stmt", rstmt, mstmt, "rows")
sys.exit(1 if bad else 0)
PY

# One binary from the wild, if the system ships one: our own fixtures are all
# gcc/clang on tiny C, and a third-party producer at scale (Go, Rust, a
# distro package) exercises tag/attribute codes and line tables we would never
# generate ourselves. It is the strongest oracle here -- on this machine it is
# a Go binary with 80 CUs and 41409 named DIEs, against 85 assertions total --
# and it used to be skipped SILENTLY when nothing suitable was installed,
# which meant the output looked the same whether the best test in the suite
# ran or not. Said out loud now, either way.
wild=""
for cand in $(grep -lsa -m1 '\.debug_info' /usr/bin/* /usr/lib/debug/* 2>/dev/null | head -20); do
	[ -f "$cand" ] || continue
	line=$(readelf -S -W "$cand" 2>/dev/null | grep ' \.debug_info ') || continue
	[ -n "$line" ] || continue
	# "C" in the flags column means SHF_COMPRESSED; we deliberately refuse to
	# link zlib, so hand it to objcopy first - the upgrade path our own error
	# message names.
	if printf '%s' "$line" | grep -q ' C  '; then
		command -v objcopy >/dev/null || continue
		objcopy --decompress-debug-sections "$cand" "$work/wild" 2>/dev/null \
			|| continue
	else
		cp "$cand" "$work/wild" 2>/dev/null || continue
	fi
	wild="wild"
	echo "--- wild binary: $cand"
	break
done
if [ -z "$wild" ]; then
	printf 'SKIP no third-party binary with an uncompressed .debug_info found\n'
	printf '     under /usr/bin or /usr/lib/debug, so the only oracle that is\n'
	printf '     not our own gcc/clang output did not run.\n'
fi

echo "--- oracle: readelf --debug-dump=info / =decodedline"
# Every fixture that failed to build, counted in the parent where the
# counter survives.
nbuildfail=$(wc -l < "$work/build.failures")
if [ "$nbuildfail" -gt 0 ]; then
	printf 'FAIL %s fixture(s) did not build: %s\n' "$nbuildfail" \
		"$(tr '\n' ' ' < "$work/build.failures")"
	fail=$((fail + nbuildfail))
fi

for b in $bins $wild; do
	[ -n "$b" ] || continue
	out=$(python3 "$work/cmp.py" "$work/$b" "$b" "$DD" 2>"$work/cmp.err")
	rc=$?
	echo "$out"
	nok=$(printf '%s\n' "$out" | grep -c '^ok  ')
	nbad=$(printf '%s\n' "$out" | grep -c '^FAIL')
	pass=$((pass + nok))
	fail=$((fail + nbad))
	# cmp.py's status was discarded and its traceback goes to stderr, so a
	# Python exception -- readelf absent, a regex that stopped matching a
	# format change, an IndexError -- produced empty stdout, added ZERO
	# passes and ZERO failures, and the whole 8-check block for that binary
	# vanished with the suite still green.
	if [ "$rc" -ne 0 ] || [ "$((nok + nbad))" -eq 0 ]; then
		printf 'FAIL cmp.py on %s exited %s and produced %s checks\n' \
			"$b" "$rc" "$((nok + nbad))"
		sed 's/^/    /' "$work/cmp.err" | head -5
		fail=$((fail + 1))
	fi
done

# ------------------------------------------------------- robustness sweep
# Truncation is the cheapest fuzzer there is and it hits every length field in
# the format. A clean run means: exit status 0 or 1 (our own diagnostics), no
# signal (>=128 would be SIGSEGV/SIGABRT), and no timeout (124 would mean we
# found a loop that does not advance).
echo "--- robustness: truncation / corruption / non-ELF"
victim="$work/g5"
[ -f "$victim" ] || victim="$work/tiny"
size=$(wc -c < "$victim")
crashes=0
tried=0
errored=0
step=$(( size / 200 ))
[ "$step" -lt 1 ] && step=1
n=1
while [ "$n" -lt "$size" ]; do
	head -c "$n" "$victim" > "$work/trunc.bin"
	for flag in --info --line-headers --abbrev --all; do
		tried=$((tried+1))
		timeout 10 "$DD" $flag "$work/trunc.bin" >/dev/null 2>&1
		rc=$?
		[ "$rc" -eq 1 ] && errored=$((errored+1))
		if [ "$rc" -gt 1 ]; then
			crashes=$((crashes+1))
			[ "$crashes" -le 5 ] && \
			  echo "       trunc $n bytes $flag -> exit $rc"
		fi
	done
	n=$((n + step))
done
if [ "$crashes" -ne 0 ]; then
	bad "truncation sweep: $crashes of $tried runs crashed or hung"
elif [ "$errored" -eq 0 ]; then
	# A sweep where nothing is rejected is a sweep that proves nothing.
	bad "truncation sweep: no prefix was rejected; the sweep is vacuous"
else
	ok "truncation sweep ($tried runs over $((size / step + 1)) prefixes, \
$errored rejected, 0 crashed or hung)"
fi

# Byte corruption. Random file offsets mostly land in machine code the parser
# never reads, so the offsets come from inside the DWARF sections themselves:
# that reliably produces absurd unit lengths, undeclared abbrev codes, bogus
# string offsets and nonsense line opcodes.
offs=$(python3 - "$victim" <<'PY'
import re, subprocess, sys
out = subprocess.run(["readelf", "-S", "-W", sys.argv[1]],
                     capture_output=True, text=True).stdout
res = []
for name, _addr, off, size in re.findall(
        r"\[\s*\d+\]\s+(\.debug_\w+)\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)",
        out):
    o, n = int(off, 16), int(size, 16)
    if n:
        res += [o + (i * 7919) % n for i in range(70)]
print(" ".join(str(x) for x in res))
PY
)
corrupt=0
ctried=0
cerr=0
for off in $offs; do
	python3 -c '
import sys
d = bytearray(open(sys.argv[1], "rb").read())
o = int(sys.argv[2])
for k in range(o, min(o + 3, len(d))):
    d[k] = 0xff
open(sys.argv[3], "wb").write(d)' "$victim" "$off" "$work/corrupt.bin"
	for flag in --info --all; do
		ctried=$((ctried+1))
		timeout 10 "$DD" $flag "$work/corrupt.bin" >/dev/null 2>&1
		rc=$?
		[ "$rc" -eq 1 ] && cerr=$((cerr+1))
		if [ "$rc" -gt 1 ]; then
			corrupt=$((corrupt+1))
			[ "$corrupt" -le 5 ] && echo "       corrupt @$off $flag -> exit $rc"
		fi
	done
done
if [ "$ctried" -eq 0 ]; then
	bad "corruption sweep produced no mutants (readelf -S parse failed?)"
elif [ "$corrupt" -eq 0 ] && [ "$cerr" -eq 0 ]; then
	bad "corruption sweep: no mutant was rejected; the sweep is vacuous"
elif [ "$corrupt" -eq 0 ]; then
	ok "corruption sweep ($ctried runs inside .debug_* sections, \
$cerr rejected, 0 crashed or hung)"
else
	bad "corruption sweep: $corrupt of $ctried runs crashed or hung"
fi

# Truncating the whole file never reaches the DWARF decoders, because the
# section header table lives at EOF and every prefix dies in the ELF layer
# first. To actually exercise "unit length runs past the end of the section",
# "truncated DIE" and "truncated line program", shrink sh_size in place and
# leave the rest of the file intact.
cat > "$work/shrink.py" <<'PY'
import struct, sys
# argv: FILE SECTION (size | NEWSIZE OUT). "size" just reports sh_size, so the
# shell does not have to parse readelf -S (whose field layout shifts with the
# section index width, and whose hex sizes mawk cannot convert).
path, want = sys.argv[1], sys.argv[2]
report = sys.argv[3] == "size"
newsize = 0 if report else int(sys.argv[3])
out = None if report else sys.argv[4]
d = bytearray(open(path, "rb").read())
shoff, = struct.unpack_from("<Q", d, 0x28)
shentsize, shnum, shstrndx = struct.unpack_from("<HHH", d, 0x3a)
def shdr(i):
    return struct.unpack_from("<IIQQQQ", d, shoff + i * shentsize)
stroff = shdr(shstrndx)[4]
for i in range(shnum):
    nameoff, _t, _f, _a, off, size = shdr(i)
    end = d.index(b"\0", stroff + nameoff)
    if d[stroff + nameoff:end].decode() == want:
        if report:
            print(size)
        else:
            struct.pack_into("<Q", d, shoff + i * shentsize + 0x20, newsize)  # sh_size
            open(out, "wb").write(d)
        sys.exit(0)
sys.exit(2)   # section absent: caller skips
PY
secs=0
serr=0
scrash=0
stried=0
for sec in .debug_info .debug_abbrev .debug_line .debug_str .debug_line_str; do
	orig=$(python3 "$work/shrink.py" "$victim" "$sec" size) || continue
	[ -n "$orig" ] && [ "$orig" -gt 0 ] || continue
	secs=$((secs+1))
	k=0
	while [ "$k" -le 40 ]; do
		ns=$(( orig * k / 40 ))
		python3 "$work/shrink.py" "$victim" "$sec" "$ns" "$work/shrunk.bin" || break
		for flag in --info --all; do
			stried=$((stried+1))
			timeout 10 "$DD" $flag "$work/shrunk.bin" >/dev/null 2>&1
			rc=$?
			[ "$rc" -eq 1 ] && serr=$((serr+1))
			if [ "$rc" -gt 1 ]; then
				scrash=$((scrash+1))
				[ "$scrash" -le 5 ] && \
				  echo "       $sec shrunk to $ns $flag -> exit $rc"
			fi
		done
		k=$((k+1))
	done
done
if [ "$stried" -eq 0 ]; then
	bad "section-shrink sweep found no .debug_* sections to shrink"
elif [ "$scrash" -ne 0 ]; then
	bad "section-shrink sweep: $scrash of $stried runs crashed or hung"
elif [ "$serr" -eq 0 ]; then
	bad "section-shrink sweep: nothing was rejected; the sweep is vacuous"
else
	ok "section-shrink sweep ($stried runs over $secs sections, \
$serr rejected, 0 crashed or hung)"
fi

# Garbage that is not an ELF file at all, plus an ELF with no debug info.
: > "$work/empty"
printf 'not an elf, just text\n' > "$work/text"
head -c 4096 /dev/urandom > "$work/random"
printf '\177ELF\002\001\001' > "$work/stub"
gcc -x c -o "$work/nodebug" - <<'EOF' 2>/dev/null
int main(void) { return 0; }
EOF
junk_ok=1
for j in empty text random stub nodebug; do
	[ -f "$work/$j" ] || continue
	timeout 10 "$DD" --all "$work/$j" >/dev/null 2>&1
	rc=$?
	if [ "$rc" -gt 1 ]; then
		echo "       $j -> exit $rc"
		junk_ok=0
	fi
done
timeout 10 "$DD" --all "$work/does-not-exist" >/dev/null 2>&1
[ $? -eq 1 ] || junk_ok=0
if [ "$junk_ok" -eq 1 ]; then
	ok "non-ELF and missing-debug-info inputs error cleanly"
else
	bad "non-ELF input did not error cleanly"
fi

# A directory and /dev/zero-ish input: no reason to crash on either.
timeout 10 "$DD" --info "$root" >/dev/null 2>&1
rc=$?
if [ "$rc" -le 1 ]; then ok "directory argument errors cleanly"
else bad "directory argument -> exit $rc"; fi

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
