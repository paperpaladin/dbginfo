#!/bin/sh
# Oracle harness. readelf is the authority; we compare extracted facts, never
# raw text, because the two output formats have nothing in common.
#
# Checks per test binary:
#   cu_names   - the DW_AT_name of every compilation unit
#   die_names  - the multiset of (DW_TAG_*, DW_AT_name) over the whole DIE tree
#   line_rows  - the multiset of (file, line, address) from the line program
#   line_stmt  - the is_stmt flag per row (end_sequence rows excluded, see below)
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

build() {   # build NAME CC FLAGS...
	name=$1; shift
	if "$@" -o "$work/$name" 2>"$work/$name.cc.log"; then
		echo "$name"
	else
		printf 'FAIL could not build %s:\n' "$name" >&2
		sed 's/^/    /' "$work/$name.cc.log" >&2
		fail=$((fail+1))
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
bad += report("line_rows", rrows, mrows, "rows")
bad += report("line_stmt", rstmt, mstmt, "rows")
sys.exit(1 if bad else 0)
PY

echo "--- oracle: readelf --debug-dump=info / =decodedline"
for b in $bins; do
	[ -n "$b" ] || continue
	out=$(python3 "$work/cmp.py" "$work/$b" "$b" "$DD")
	echo "$out"
	pass=$((pass + $(printf '%s\n' "$out" | grep -c '^ok  ')))
	fail=$((fail + $(printf '%s\n' "$out" | grep -c '^FAIL')))
done

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
