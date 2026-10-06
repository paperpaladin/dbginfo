CC      ?= gcc
CFLAGS  ?= -std=c11 -O2 -g -Wall -Wextra -Wshadow -Wpedantic

all: dbginfo

dbginfo: dbginfo.c
	$(CC) $(CFLAGS) -o $@ $<

test: dbginfo
	./t/run.sh

clean:
	rm -f dbginfo

.PHONY: all test clean
