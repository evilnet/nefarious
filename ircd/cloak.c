/*
 * IRC - Internet Relay Chat, ircd/cloak.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 *
 * See file AUTHORS in IRC package for additional names of
 * the programmers.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * $Id$
 */


#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_chattr.h"
#include "ircd_defs.h"
#include "ircd_features.h"
#include "ircd_string.h"
#include "ircd_snprintf.h"
#include "match.h"
#include "md5.h"
#include "s_bsd.h"
#include "s_debug.h"
#include "ircd_struct.h"

#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#define KEY1 feature_str(FEAT_HOST_HIDING_KEY1)
#define KEY2 feature_str(FEAT_HOST_HIDING_KEY2)
#define KEY3 feature_str(FEAT_HOST_HIDING_KEY3)

static inline unsigned int downsample(unsigned char *i)
{
char r[4];

	r[0] = i[0] ^ i[1] ^ i[2] ^ i[3];
	r[1] = i[4] ^ i[5] ^ i[6] ^ i[7];
	r[2] = i[8] ^ i[9] ^ i[10] ^ i[11];
	r[3] = i[12] ^ i[13] ^ i[14] ^ i[15];
	
	return ( ((unsigned int)r[0] << 24) +
	         ((unsigned int)r[1] << 16) +
	         ((unsigned int)r[2] << 8) +
	         (unsigned int)r[3]);
}

char *hidehost_ipv4(char *host)
{
unsigned int a, b, c, d;
static char buf[512], result[128];
unsigned char res[512], res2[512];
unsigned long n;
unsigned int alpha, beta, gamma;

	/* 
	 * Output: ALPHA.BETA.GAMMA.IP
	 * ALPHA is unique for a.b.c.d
	 * BETA  is unique for a.b.c.*
	 * GAMMA is unique for a.b.*
	 * We cloak like this:
	 * ALPHA = downsample(md5(md5("KEY2:A.B.C.D:KEY3")+"KEY1"));
	 * BETA  = downsample(md5(md5("KEY3:A.B.C:KEY1")+"KEY2"));
	 * GAMMA = downsample(md5(md5("KEY1:A.B:KEY2")+"KEY3"));
	 */
	sscanf(host, "%u.%u.%u.%u", &a, &b, &c, &d);

	/* ALPHA... */
	ircd_snprintf(0, buf, HOSTLEN, "%s:%s:%s", KEY2, host, KEY3);
	DoMD5(res, (unsigned char*) buf, strlen(buf));
	strcpy((char *)res+16, KEY1); 
	n = strlen((char *)res+16) + 16;
	DoMD5(res2, res, n);
	alpha = downsample(res2);

	/* BETA... */
	ircd_snprintf(0, buf, HOSTLEN, "%s:%d.%d.%d:%s", KEY3, a, b, c, KEY1); 
	DoMD5(res, (unsigned char*) buf, strlen(buf));
	strcpy((char *) res+16, KEY2);
	n = strlen((char *)res+16) + 16;
	DoMD5(res2, res, n);
	beta = downsample(res2);

	/* GAMMA... */
	ircd_snprintf(0, buf, HOSTLEN, "%s:%d.%d:%s", KEY1, a, b, KEY2); 
	DoMD5(res, (unsigned char*) buf, strlen(buf));
 	strcpy((char *) res+16, KEY3);
	n = strlen((char *)res+16) + 16;
	DoMD5(res2, res, n);
	gamma = downsample(res2);

	/* lower case X? */
 	ircd_snprintf(0, result, HOSTLEN, "%X.%X.%X.IP", alpha, beta, gamma);
	return result;
}


char *hidehost_normalhost(char *host)
{
char *p;
static char buf[512], result[HOSTLEN+1];
unsigned char res[512], res2[512];
unsigned int alpha, n;

	ircd_snprintf(0, buf, HOSTLEN, "%s:%s:%s", KEY1, host, KEY2);
	DoMD5(res, (unsigned char*) buf, strlen(buf));
        strcpy((char *) res+16, KEY3);
	n = strlen((char *)res+16) + 16;
	DoMD5(res2, res, n);
	alpha = downsample(res2);

	for (p = host; *p; p++)
		if (*p == '.')
			if (IsAlpha(*(p + 1)))
				break;

	if (*p)
	{
		unsigned int len;
		p++;

		ircd_snprintf(0, result, HOSTLEN, "%s-%X.",  feature_str(FEAT_HOST_HIDING_PREFIX), alpha);
		len = strlen(result) + strlen(p);
		if (len <= HOSTLEN)
			strcat(result, p);
		else
			strcat(result, p + (len - HOSTLEN));
	} else
		ircd_snprintf(0, result, HOSTLEN, "%s-%X",  feature_str(FEAT_HOST_HIDING_PREFIX), alpha);

	return result;
}

