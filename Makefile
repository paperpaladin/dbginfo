CC      ?= gcc
CFLAGS  ?= -std=c11 -O2 -g -Wall -Wextra -Wshadow -Wpedantic -ffile-prefix-map=$(CURDIR)=.
# Input is untrusted binary data, so the sanitiser build is a first-class
# target, not an afterthought: ASan catches the out-of-bounds read a missing
# length check would otherwise hide, UBSan catches the shift/overflow paths in
# LEB128 and the line-program arithmetic.
ASAN    = -fsanitize=address,undefined -fno-omit-frame-pointer -O1 -g

all: dbginfo

dbginfo: dbginfo.c
	$(CC) $(CFLAGS) -o $@ $<

dbginfo-asan: dbginfo.c
	$(CC) -std=c11 -Wall -Wextra $(ASAN) -o $@ $<

test: dbginfo
	./t/run.sh

# exitcode=42 is load-bearing: ASan's default exit status on a report is 1,
# which is also our own "malformed input" status, so without it the harness
# would wave a real memory error through as a clean diagnostic.
test-asan: dbginfo-asan
	ASAN_OPTIONS=detect_leaks=1:exitcode=42 \
	UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
	DD=$(CURDIR)/dbginfo-asan ./t/run.sh

clean:
	rm -f dbginfo dbginfo-asan

.PHONY: all test test-asan clean
