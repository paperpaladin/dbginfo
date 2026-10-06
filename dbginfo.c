/* dbginfo - parse ELF64 section headers and locate the DWARF sections.
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

static uint16_t rd_u16(Rd *r) { return (uint16_t)rd_fixed(r, 2); }
static uint32_t rd_u32(Rd *r) { return (uint32_t)rd_fixed(r, 4); }
static uint64_t rd_u64(Rd *r) { return rd_fixed(r, 8); }

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
	const Sec *info, *abbrev, *str, *line_str, *line;
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
	fputs("usage: dbginfo [--sections] FILE\n"
	      "\n"
	      "  --sections      ELF section header table\n"
	      "\n"
	      "Locates the .debug_* sections; decoding them comes next.\n"
	      "64-bit little-endian ELF.\n", f);
}

int main(int argc, char **argv)
{
	int want_sec = 0;
	const char *path = NULL;
	for (int i = 1; i < argc; i++) {
		const char *a = argv[i];
		if (strcmp(a, "--sections") == 0) want_sec = 1;
		else if (strcmp(a, "--all") == 0) want_sec = 1;
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
	if (!want_sec)
		want_sec = 1;

	Elf e;
	elf_load(&e, path);
	int ok = 1;
	if (want_sec) ok &= dump_sections(&e);
	/* Free so ASan's leak checker can police the parse paths. */
	free(e.sec);
	free(e.file);
	return ok ? 0 : 1;
}
