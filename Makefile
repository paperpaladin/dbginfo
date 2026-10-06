CC      ?= gcc
CFLAGS  ?= -std=c11 -O2 -g -Wall -Wextra -Wshadow -Wpedantic

all: dbginfo

dbginfo: dbginfo.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f dbginfo

.PHONY: all clean
