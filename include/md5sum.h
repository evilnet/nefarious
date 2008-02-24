#ifndef INCLUDED_md5sum_h
#define INCLUDED_md5sum_h
/*
 * IRC - Internet Relay Chat, include/md5sum.h
 * Copyright (C) 1993 Branko Lankester
 *               1993 Colin Plumb
 *
 * $Id: md5.h 1652 2006-07-11 00:07:07Z rubin $
 */

#ifdef __alpha
typedef unsigned int uint32;
#else
typedef unsigned long uint32;
#endif

struct MD5Context {
	uint32 buf[4];
	uint32 bits[2];
	unsigned char in[64];
};

void MD5Init(struct MD5Context *context);
void MD5Update(struct MD5Context *context, unsigned char const *buf,
	       unsigned len);
void MD5Final(unsigned char digest[16], struct MD5Context *context);
void MD5Transform(uint32 buf[4], uint32 const in[16]);

typedef struct MD5Context MD5_CTX;

#endif

