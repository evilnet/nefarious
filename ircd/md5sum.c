/*
 * IRC - Internet Relay Chat, ircd/md5sum.c
 * Copyright (C) 1993 Branko Lankester
 *               1993 Colin Plumb
 *
 * $Id$
 */

#include <getopt.h>
#include <stdlib.h>    /* Added RKNOP 960111 */
#include <stdio.h>
#include <string.h>
#include "md5.h"

#ifdef UNIX
#define	FOPRTXT	"r"
#define	FOPRBIN	"r"
#else
#ifdef VMS
#define	FOPRTXT	"r","ctx=stm"
#define	FOPRBIN	"rb","ctx=stm"
#else
#define	FOPRTXT	"r"
#define	FOPRBIN	"rb"
#endif
#endif

extern char *optarg;
extern int optind;

void usage();
void print_digest();
int mdfile(FILE *fp, unsigned char *digest);
int do_check(FILE *chkf);

char *progname;
int verbose = 0;
int bin_mode = 0;

int
main(int argc, char **argv)
{
	int opt, rc = 0;
	int check = 0;
	FILE *fp = NULL;
	unsigned char digest[16];

	progname = *argv;
	while ((opt = getopt(argc, argv, "cbvp:h")) != EOF) {
		switch (opt) {
			case 'c': check = 1; break;
			case 'v': verbose = 1; break;
			case 'b': bin_mode = 1; break;
			default: usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (check) {
		switch (argc) {
			case 0: fp = stdin; break;
			case 1: if ((fp = fopen(*argv, FOPRTXT)) == NULL) {
					perror(*argv);
					exit(2);
				}
				break;
			default: usage();
		}
		exit(do_check(fp));
	}
	if (argc == 0) {
		if (mdfile(stdin, digest)) {
			fprintf(stderr, "%s: read error on stdin\n", progname);
			exit(2);
		}
		print_digest(digest);
		printf("\n");
		exit(0);
	}
	for ( ; argc > 0; --argc, ++argv) {
		if (bin_mode)
			fp = fopen(*argv, FOPRBIN);
		else
			fp = fopen(*argv, FOPRTXT);
		if (fp == NULL) {
			perror(*argv);
			rc = 2;
			continue;
		}
		if (mdfile(fp, digest)) {
			fprintf(stderr, "%s: error reading %s\n", progname, *argv);
			rc = 2;
		} else {
			print_digest(digest);
			printf(" %c%s\n", bin_mode ? '*' : ' ', *argv);
		}
		fclose(fp);
	}
	exit(rc);
}

void
usage()
{
	fprintf(stderr, "usage: md5sum [-bv] [-c [file]] | [file...]\n");
	fprintf(stderr, "Generates or checks MD5 Message Digests\n");
	fprintf(stderr, "    -c  check message digests (default is generate)\n");
	fprintf(stderr, "    -v  verbose, print file names when checking\n");
	fprintf(stderr, "    -b  read files in binary mode\n");
	fprintf(stderr, "The input for -c should be the list of message digests and file names\n");
	fprintf(stderr, "that is printed on stdout by this program when it generates digests.\n");
	exit(2);
}

int
mdfile(FILE *fp, unsigned char *digest)
{
	unsigned char buf[1024];
	MD5_CTX ctx;
	int n;

	MD5Init(&ctx);
	while ((n = fread(buf, 1, sizeof(buf), fp)) > 0)
		MD5Update(&ctx, buf, n);
	MD5Final(digest, &ctx);
	if (ferror(fp))
		return -1;
	return 0;
}

void
print_digest(unsigned char *p)
{
	int i;

	for (i = 0; i < 16; ++i)
		printf("%02x", *p++);
}

int
hex_digit(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	return -1;
}

int
get_md5_line(FILE *fp, unsigned char *digest, char *file)
{
	char buf[1024];
	int i, d1, d2, rc;
	char *p = buf;

	if (fgets(buf, sizeof(buf), fp) == NULL)
		return -1;

	for (i = 0; i < 16; ++i) {
		if ((d1 = hex_digit(*p++)) == -1)
			return 0;
		if ((d2 = hex_digit(*p++)) == -1)
			return 0;
		*digest++ = d1*16 + d2;
	}
	if (*p++ != ' ')
		return 0;
	/*
	 * next char is an attribute char, space means text file
	 * if it's a '*' the file should be checked in binary mode.
	 */
	if (*p == ' ')
		rc = 1;
	else if (*p == '*')
		rc = 2;
	else {
		fprintf(stderr, "%s: unrecognized line: %s", progname, buf);
		return 0;
	}
	++p;
	i = strlen(p);
	if (i < 2 || i > 255)
		return 0;
	p[i-1] = '\0';
	strcpy(file, p);
	return rc;
}

int
do_check(FILE *chkf)
{
	int rc, ex = 0, failed = 0, checked = 0;
	unsigned char chk_digest[16], file_digest[16];
	char filename[256];
	FILE *fp;
	int flen = 14;

	while ((rc = get_md5_line(chkf, chk_digest, filename)) >= 0) {
		if (rc == 0)	/* not an md5 line */
			continue;
		if (verbose) {
			if (strlen(filename) > flen)
				flen = strlen(filename);
			fprintf(stderr, "%-*s ", flen, filename);
		}
		if (bin_mode || rc == 2)
			fp = fopen(filename, FOPRBIN);
		else
			fp = fopen(filename, FOPRTXT);
		if (fp == NULL) {
			fprintf(stderr, "%s: can't open %s\n", progname, filename);
			ex = 2;
			continue;
		}
		if (mdfile(fp, file_digest)) {
			fprintf(stderr, "%s: error reading %s\n", progname, filename);
			ex = 2;
			fclose(fp);
			continue;
		}
		fclose(fp);
		if (memcmp(chk_digest, file_digest, 16) != 0) {
			if (verbose)
				fprintf(stderr, "FAILED\n");
			else
				fprintf(stderr, "%s: MD5 check failed for '%s'\n", progname, filename);
			++failed;
		} else if (verbose)
			fprintf(stderr, "OK\n");
		++checked;
	}
	if (verbose && failed)
		fprintf(stderr, "%s: %d of %d file(s) failed MD5 check\n", progname, failed, checked);
	if (!checked) {
		fprintf(stderr, "%s: no files checked\n", progname);
		return 3;
	}
	if (!ex && failed)
		ex = 1;
	return ex;
}

#ifndef HIGHFIRST
#define byteReverse(buf, len)	/* Nothing */
#else
void byteReverse(unsigned char *buf, unsigned longs);

#ifndef ASM_MD5
/*
 * Note: this code is harmless on little-endian machines.
 */
void byteReverse(unsigned char *buf, unsigned longs)
{
    uint32 t;
    do {
	t = (uint32) ((unsigned) buf[3] << 8 | buf[2]) << 16 |
	    ((unsigned) buf[1] << 8 | buf[0]);
	*(uint32 *) buf = t;
	buf += 4;
    } while (--longs);
}
#endif
#endif

/*
 * Start MD5 accumulation.  Set bit count to 0 and buffer to mysterious
 * initialization constants.
 */
void MD5Init(struct MD5Context *ctx)
{
    ctx->buf[0] = 0x67452301;
    ctx->buf[1] = 0xefcdab89;
    ctx->buf[2] = 0x98badcfe;
    ctx->buf[3] = 0x10325476;

    ctx->bits[0] = 0;
    ctx->bits[1] = 0;
}

/*
 * Update context to reflect the concatenation of another buffer full
 * of bytes.
 */
void MD5Update(struct MD5Context *ctx, unsigned char const *buf, unsigned len)
{
    uint32 t;

    /* Update bitcount */

    t = ctx->bits[0];
    if ((ctx->bits[0] = t + ((uint32) len << 3)) < t)
	ctx->bits[1]++;		/* Carry from low to high */
    ctx->bits[1] += len >> 29;

    t = (t >> 3) & 0x3f;	/* Bytes already in shsInfo->data */

    /* Handle any leading odd-sized chunks */

    if (t) {
	unsigned char *p = (unsigned char *) ctx->in + t;

	t = 64 - t;
	if (len < t) {
	    memcpy(p, buf, len);
	    return;
	}
	memcpy(p, buf, t);
	byteReverse(ctx->in, 16);
	MD5Transform(ctx->buf, (uint32 *) ctx->in);
	buf += t;
	len -= t;
    }
    /* Process data in 64-byte chunks */

    while (len >= 64) {
	memcpy(ctx->in, buf, 64);
	byteReverse(ctx->in, 16);
	MD5Transform(ctx->buf, (uint32 *) ctx->in);
	buf += 64;
	len -= 64;
    }

    /* Handle any remaining bytes of data. */

    memcpy(ctx->in, buf, len);
}

/*
 * Final wrapup - pad to 64-byte boundary with the bit pattern 
 * 1 0* (64-bit count of bits processed, MSB-first)
 */
void MD5Final(unsigned char digest[16], struct MD5Context *ctx)
{
    unsigned count;
    unsigned char *p;

    /* Compute number of bytes mod 64 */
    count = (ctx->bits[0] >> 3) & 0x3F;

    /* Set the first char of padding to 0x80.  This is safe since there is
       always at least one byte free */
    p = ctx->in + count;
    *p++ = 0x80;

    /* Bytes of padding needed to make 64 bytes */
    count = 64 - 1 - count;

    /* Pad out to 56 mod 64 */
    if (count < 8) {
	/* Two lots of padding:  Pad the first block to 64 bytes */
	memset(p, 0, count);
	byteReverse(ctx->in, 16);
	MD5Transform(ctx->buf, (uint32 *) ctx->in);

	/* Now fill the next block with 56 bytes */
	memset(ctx->in, 0, 56);
    } else {
	/* Pad block to 56 bytes */
	memset(p, 0, count - 8);
    }
    byteReverse(ctx->in, 14);

    /* Append length in bits and transform */
    ((uint32 *) ctx->in)[14] = ctx->bits[0];
    ((uint32 *) ctx->in)[15] = ctx->bits[1];

    MD5Transform(ctx->buf, (uint32 *) ctx->in);
    byteReverse((unsigned char *) ctx->buf, 4);
    memcpy(digest, ctx->buf, 16);
    memset(ctx, 0, sizeof(ctx));	/* In case it's sensitive */
}

#ifndef ASM_MD5

/* The four core functions - F1 is optimized somewhat */

/* #define F1(x, y, z) (x & y | ~x & z) */
#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))

/* This is the central step in the MD5 algorithm. */
#ifdef __PUREC__
#define MD5STEP(f, w, x, y, z, data, s) \
	( w += f /*(x, y, z)*/ + data,  w = w<<s | w>>(32-s),  w += x )
#else
#define MD5STEP(f, w, x, y, z, data, s) \
	( w += f(x, y, z) + data,  w = w<<s | w>>(32-s),  w += x )
#endif

/*
 * The core of the MD5 algorithm, this alters an existing MD5 hash to
 * reflect the addition of 16 longwords of new data.  MD5Update blocks
 * the data and converts bytes into longwords for this routine.
 */
void MD5Transform(uint32 buf[4], uint32 const in[16])
{
    register uint32 a, b, c, d;

    a = buf[0];
    b = buf[1];
    c = buf[2];
    d = buf[3];

#ifdef __PUREC__	/* PureC Weirdness... (GG) */
    MD5STEP(F1(b,c,d), a, b, c, d, in[0] + 0xd76aa478L, 7);
    MD5STEP(F1(a,b,c), d, a, b, c, in[1] + 0xe8c7b756L, 12);
    MD5STEP(F1(d,a,b), c, d, a, b, in[2] + 0x242070dbL, 17);
    MD5STEP(F1(c,d,a), b, c, d, a, in[3] + 0xc1bdceeeL, 22);
    MD5STEP(F1(b,c,d), a, b, c, d, in[4] + 0xf57c0fafL, 7);
    MD5STEP(F1(a,b,c), d, a, b, c, in[5] + 0x4787c62aL, 12);
    MD5STEP(F1(d,a,b), c, d, a, b, in[6] + 0xa8304613L, 17);
    MD5STEP(F1(c,d,a), b, c, d, a, in[7] + 0xfd469501L, 22);
    MD5STEP(F1(b,c,d), a, b, c, d, in[8] + 0x698098d8L, 7);
    MD5STEP(F1(a,b,c), d, a, b, c, in[9] + 0x8b44f7afL, 12);
    MD5STEP(F1(d,a,b), c, d, a, b, in[10] + 0xffff5bb1L, 17);
    MD5STEP(F1(c,d,a), b, c, d, a, in[11] + 0x895cd7beL, 22);
    MD5STEP(F1(b,c,d), a, b, c, d, in[12] + 0x6b901122L, 7);
    MD5STEP(F1(a,b,c), d, a, b, c, in[13] + 0xfd987193L, 12);
    MD5STEP(F1(d,a,b), c, d, a, b, in[14] + 0xa679438eL, 17);
    MD5STEP(F1(c,d,a), b, c, d, a, in[15] + 0x49b40821L, 22);

    MD5STEP(F2(b,c,d), a, b, c, d, in[1] + 0xf61e2562L, 5);
    MD5STEP(F2(a,b,c), d, a, b, c, in[6] + 0xc040b340L, 9);
    MD5STEP(F2(d,a,b), c, d, a, b, in[11] + 0x265e5a51L, 14);
    MD5STEP(F2(c,d,a), b, c, d, a, in[0] + 0xe9b6c7aaL, 20);
    MD5STEP(F2(b,c,d), a, b, c, d, in[5] + 0xd62f105dL, 5);
    MD5STEP(F2(a,b,c), d, a, b, c, in[10] + 0x02441453L, 9);
    MD5STEP(F2(d,a,b), c, d, a, b, in[15] + 0xd8a1e681L, 14);
    MD5STEP(F2(c,d,a), b, c, d, a, in[4] + 0xe7d3fbc8L, 20);
    MD5STEP(F2(b,c,d), a, b, c, d, in[9] + 0x21e1cde6L, 5);
    MD5STEP(F2(a,b,c), d, a, b, c, in[14] + 0xc33707d6L, 9);
    MD5STEP(F2(d,a,b), c, d, a, b, in[3] + 0xf4d50d87L, 14);
    MD5STEP(F2(c,d,a), b, c, d, a, in[8] + 0x455a14edL, 20);
    MD5STEP(F2(b,c,d), a, b, c, d, in[13] + 0xa9e3e905L, 5);
    MD5STEP(F2(a,b,c), d, a, b, c, in[2] + 0xfcefa3f8L, 9);
    MD5STEP(F2(d,a,b), c, d, a, b, in[7] + 0x676f02d9L, 14);
    MD5STEP(F2(c,d,a), b, c, d, a, in[12] + 0x8d2a4c8aL, 20);

    MD5STEP(F3(b,c,d), a, b, c, d, in[5] + 0xfffa3942L, 4);
    MD5STEP(F3(a,b,c), d, a, b, c, in[8] + 0x8771f681L, 11);
    MD5STEP(F3(d,a,b), c, d, a, b, in[11] + 0x6d9d6122L, 16);
    MD5STEP(F3(c,d,a), b, c, d, a, in[14] + 0xfde5380cL, 23);
    MD5STEP(F3(b,c,d), a, b, c, d, in[1] + 0xa4beea44L, 4);
    MD5STEP(F3(a,b,c), d, a, b, c, in[4] + 0x4bdecfa9L, 11);
    MD5STEP(F3(d,a,b), c, d, a, b, in[7] + 0xf6bb4b60L, 16);
    MD5STEP(F3(c,d,a), b, c, d, a, in[10] + 0xbebfbc70L, 23);
    MD5STEP(F3(b,c,d), a, b, c, d, in[13] + 0x289b7ec6L, 4);
    MD5STEP(F3(a,b,c), d, a, b, c, in[0] + 0xeaa127faL, 11);
    MD5STEP(F3(d,a,b), c, d, a, b, in[3] + 0xd4ef3085L, 16);
    MD5STEP(F3(c,d,a), b, c, d, a, in[6] + 0x04881d05L, 23);
    MD5STEP(F3(b,c,d), a, b, c, d, in[9] + 0xd9d4d039L, 4);
    MD5STEP(F3(a,b,c), d, a, b, c, in[12] + 0xe6db99e5L, 11);
    MD5STEP(F3(d,a,b), c, d, a, b, in[15] + 0x1fa27cf8L, 16);
    MD5STEP(F3(c,d,a), b, c, d, a, in[2] + 0xc4ac5665L, 23);

    MD5STEP(F4(b,c,d), a, b, c, d, in[0] + 0xf4292244L, 6);
    MD5STEP(F4(a,b,c), d, a, b, c, in[7] + 0x432aff97L, 10);
    MD5STEP(F4(d,a,b), c, d, a, b, in[14] + 0xab9423a7L, 15);
    MD5STEP(F4(c,d,a), b, c, d, a, in[5] + 0xfc93a039L, 21);
    MD5STEP(F4(b,c,d), a, b, c, d, in[12] + 0x655b59c3L, 6);
    MD5STEP(F4(a,b,c), d, a, b, c, in[3] + 0x8f0ccc92L, 10);
    MD5STEP(F4(d,a,b), c, d, a, b, in[10] + 0xffeff47dL, 15);
    MD5STEP(F4(c,d,a), b, c, d, a, in[1] + 0x85845dd1L, 21);
    MD5STEP(F4(b,c,d), a, b, c, d, in[8] + 0x6fa87e4fL, 6);
    MD5STEP(F4(a,b,c), d, a, b, c, in[15] + 0xfe2ce6e0L, 10);
    MD5STEP(F4(d,a,b), c, d, a, b, in[6] + 0xa3014314L, 15);
    MD5STEP(F4(c,d,a), b, c, d, a, in[13] + 0x4e0811a1L, 21);
    MD5STEP(F4(b,c,d), a, b, c, d, in[4] + 0xf7537e82L, 6);
    MD5STEP(F4(a,b,c), d, a, b, c, in[11] + 0xbd3af235L, 10);
    MD5STEP(F4(d,a,b), c, d, a, b, in[2] + 0x2ad7d2bbL, 15);
    MD5STEP(F4(c,d,a), b, c, d, a, in[9] + 0xeb86d391L, 21);
#else
    MD5STEP(F1, a, b, c, d, in[0] + 0xd76aa478, 7);
    MD5STEP(F1, d, a, b, c, in[1] + 0xe8c7b756, 12);
    MD5STEP(F1, c, d, a, b, in[2] + 0x242070db, 17);
    MD5STEP(F1, b, c, d, a, in[3] + 0xc1bdceee, 22);
    MD5STEP(F1, a, b, c, d, in[4] + 0xf57c0faf, 7);
    MD5STEP(F1, d, a, b, c, in[5] + 0x4787c62a, 12);
    MD5STEP(F1, c, d, a, b, in[6] + 0xa8304613, 17);
    MD5STEP(F1, b, c, d, a, in[7] + 0xfd469501, 22);
    MD5STEP(F1, a, b, c, d, in[8] + 0x698098d8, 7);
    MD5STEP(F1, d, a, b, c, in[9] + 0x8b44f7af, 12);
    MD5STEP(F1, c, d, a, b, in[10] + 0xffff5bb1, 17);
    MD5STEP(F1, b, c, d, a, in[11] + 0x895cd7be, 22);
    MD5STEP(F1, a, b, c, d, in[12] + 0x6b901122, 7);
    MD5STEP(F1, d, a, b, c, in[13] + 0xfd987193, 12);
    MD5STEP(F1, c, d, a, b, in[14] + 0xa679438e, 17);
    MD5STEP(F1, b, c, d, a, in[15] + 0x49b40821, 22);

    MD5STEP(F2, a, b, c, d, in[1] + 0xf61e2562, 5);
    MD5STEP(F2, d, a, b, c, in[6] + 0xc040b340, 9);
    MD5STEP(F2, c, d, a, b, in[11] + 0x265e5a51, 14);
    MD5STEP(F2, b, c, d, a, in[0] + 0xe9b6c7aa, 20);
    MD5STEP(F2, a, b, c, d, in[5] + 0xd62f105d, 5);
    MD5STEP(F2, d, a, b, c, in[10] + 0x02441453, 9);
    MD5STEP(F2, c, d, a, b, in[15] + 0xd8a1e681, 14);
    MD5STEP(F2, b, c, d, a, in[4] + 0xe7d3fbc8, 20);
    MD5STEP(F2, a, b, c, d, in[9] + 0x21e1cde6, 5);
    MD5STEP(F2, d, a, b, c, in[14] + 0xc33707d6, 9);
    MD5STEP(F2, c, d, a, b, in[3] + 0xf4d50d87, 14);
    MD5STEP(F2, b, c, d, a, in[8] + 0x455a14ed, 20);
    MD5STEP(F2, a, b, c, d, in[13] + 0xa9e3e905, 5);
    MD5STEP(F2, d, a, b, c, in[2] + 0xfcefa3f8, 9);
    MD5STEP(F2, c, d, a, b, in[7] + 0x676f02d9, 14);
    MD5STEP(F2, b, c, d, a, in[12] + 0x8d2a4c8a, 20);

    MD5STEP(F3, a, b, c, d, in[5] + 0xfffa3942, 4);
    MD5STEP(F3, d, a, b, c, in[8] + 0x8771f681, 11);
    MD5STEP(F3, c, d, a, b, in[11] + 0x6d9d6122, 16);
    MD5STEP(F3, b, c, d, a, in[14] + 0xfde5380c, 23);
    MD5STEP(F3, a, b, c, d, in[1] + 0xa4beea44, 4);
    MD5STEP(F3, d, a, b, c, in[4] + 0x4bdecfa9, 11);
    MD5STEP(F3, c, d, a, b, in[7] + 0xf6bb4b60, 16);
    MD5STEP(F3, b, c, d, a, in[10] + 0xbebfbc70, 23);
    MD5STEP(F3, a, b, c, d, in[13] + 0x289b7ec6, 4);
    MD5STEP(F3, d, a, b, c, in[0] + 0xeaa127fa, 11);
    MD5STEP(F3, c, d, a, b, in[3] + 0xd4ef3085, 16);
    MD5STEP(F3, b, c, d, a, in[6] + 0x04881d05, 23);
    MD5STEP(F3, a, b, c, d, in[9] + 0xd9d4d039, 4);
    MD5STEP(F3, d, a, b, c, in[12] + 0xe6db99e5, 11);
    MD5STEP(F3, c, d, a, b, in[15] + 0x1fa27cf8, 16);
    MD5STEP(F3, b, c, d, a, in[2] + 0xc4ac5665, 23);

    MD5STEP(F4, a, b, c, d, in[0] + 0xf4292244, 6);
    MD5STEP(F4, d, a, b, c, in[7] + 0x432aff97, 10);
    MD5STEP(F4, c, d, a, b, in[14] + 0xab9423a7, 15);
    MD5STEP(F4, b, c, d, a, in[5] + 0xfc93a039, 21);
    MD5STEP(F4, a, b, c, d, in[12] + 0x655b59c3, 6);
    MD5STEP(F4, d, a, b, c, in[3] + 0x8f0ccc92, 10);
    MD5STEP(F4, c, d, a, b, in[10] + 0xffeff47d, 15);
    MD5STEP(F4, b, c, d, a, in[1] + 0x85845dd1, 21);
    MD5STEP(F4, a, b, c, d, in[8] + 0x6fa87e4f, 6);
    MD5STEP(F4, d, a, b, c, in[15] + 0xfe2ce6e0, 10);
    MD5STEP(F4, c, d, a, b, in[6] + 0xa3014314, 15);
    MD5STEP(F4, b, c, d, a, in[13] + 0x4e0811a1, 21);
    MD5STEP(F4, a, b, c, d, in[4] + 0xf7537e82, 6);
    MD5STEP(F4, d, a, b, c, in[11] + 0xbd3af235, 10);
    MD5STEP(F4, c, d, a, b, in[2] + 0x2ad7d2bb, 15);
    MD5STEP(F4, b, c, d, a, in[9] + 0xeb86d391, 21);
#endif

    buf[0] += a;
    buf[1] += b;
    buf[2] += c;
    buf[3] += d;
}

#endif
