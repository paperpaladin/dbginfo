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

# The gate runs BEFORE the suite, so that make stops on it rather than running
# 118 checks whose sanitizer coverage is in doubt, and so that the suite's own
# total is still the last line of the output: commitq reports the last line.
test: dbginfo
	@$(MAKE) --no-print-directory overread
	./t/run.sh

# A buffer larger than its data turns the sanitizer off. read_file trims the
# whole-file buffer down to the exact length for exactly that reason, and this
# target asserts the consequence instead of trusting it: the same source with a
# deliberate read one byte past the end of the file must be REPORTED. Untrimmed
# the buffer doubles, so that read lands tens of kilobytes inside a live
# allocation, ASan is silent, and a clean test-asan run would say nothing about
# any of the lengths this program takes out of the DWARF sections themselves.
overread: dbginfo.c dbginfo
	@$(CC) -std=c11 -Wall -Wextra $(ASAN) -DDBGINFO_PLANT_OVERREAD \
	  -o dbginfo-probe dbginfo.c
	@if ASAN_OPTIONS=detect_leaks=0 ./dbginfo-probe --sections ./dbginfo 2>&1 \
	    | grep -q 'runtime error\|Sanitizer'; then \
	  echo '[overread] the sanitizer sees the end of the file buffer'; \
	else \
	  echo 'FAIL [overread] a read one byte past the end of the file is'; \
	  echo '      invisible: read_file returned a buffer larger than the'; \
	  echo '      file, so the sanitizer is switched off over every length'; \
	  echo '      this program reads out of the DWARF sections'; \
	  rm -f dbginfo-probe; exit 1; \
	fi
	@rm -f dbginfo-probe

# exitcode=42 is load-bearing: ASan's default exit status on a report is 1,
# which is also our own "malformed input" status, so without it the harness
# would wave a real memory error through as a clean diagnostic.
test-asan: dbginfo-asan
	ASAN_OPTIONS=detect_leaks=1:exitcode=42 \
	UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
	DD=$(CURDIR)/dbginfo-asan ./t/run.sh

clean:
	rm -f dbginfo dbginfo-asan dbginfo-probe

.PHONY: all test test-asan overread clean
