#ifndef INCLUDED_zline_h
#define INCLUDED_zline_h
/*
 * IRC - Internet Relay Chat, include/zline.h
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 * Copyright (C) 1996 -1997 Carlo Wood
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
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
#ifndef INCLUDED_config_h
#include "config.h"
#endif
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif

#include <netinet/in.h>

struct Client;
struct StatDesc;

#define ZLINE_MAX_EXPIRE 604800	/* max expire: 7 days */

struct Zline {
  struct Zline *zl_next;
  struct Zline**zl_prev_p;
  char	       *zl_host;
  char	       *zl_reason;
  time_t	zl_expire;
  time_t	zl_lastmod;
  struct in_addr ipnum;  /* We store the IP in binary for ip zlines */
  char 		bits;
  unsigned int	zl_flags;
};

#define ZLINE_ACTIVE	0x0001
#define ZLINE_IPMASK	0x0002
#define ZLINE_LOCAL	0x0002
#define ZLINE_ANY	0x0008
#define ZLINE_FORCE	0x0010
#define ZLINE_EXACT	0x0020
#define ZLINE_LDEACT	0x0040	/* locally deactivated */
#define ZLINE_GLOBAL	0x0080	/* find only global zlines */
#define ZLINE_LASTMOD	0x0100	/* find only zlines with non-zero lastmod */
#define ZLINE_OPERFORCE	0x0200	/* oper forcing zline to be set */

#define ZLINE_MASK	(ZLINE_ACTIVE | ZLINE_LOCAL )
#define ZLINE_ACTMASK	(ZLINE_ACTIVE | ZLINE_LDEACT)

#define ZlineIsActive(g)	(((g)->zl_flags & ZLINE_ACTMASK) == \
				 ZLINE_ACTIVE)
#define ZlineIsRemActive(g)	((g)->zl_flags & ZLINE_ACTIVE)
#define ZlineIsIpMask(g)	((g)->zl_flags & ZLINE_IPMASK)
#define ZlineIsLocal(g)		((g)->zl_flags & ZLINE_LOCAL)

#define ZlineHost(g)		((g)->zl_host)
#define ZlineReason(g)		((g)->zl_reason)
#define ZlineLastMod(g)		((g)->zl_lastmod)

extern int zline_propagate(struct Client *cptr, struct Client *sptr,
			   struct Zline *zline);
extern int zline_add(struct Client *cptr, struct Client *sptr, char *userhost,
		     char *reason, time_t expire, time_t lastmod,
		     unsigned int flags);
extern int zline_activate(struct Client *cptr, struct Client *sptr,
			  struct Zline *zline, time_t lastmod,
			  unsigned int flags);
extern int zline_deactivate(struct Client *cptr, struct Client *sptr,
			    struct Zline *zline, time_t lastmod,
			    unsigned int flags);
extern struct Zline *zline_find(char *userhost, unsigned int flags);
extern struct Zline *zline_lookup(struct Client *cptr, unsigned int flags);
extern struct Zline *zline_lookup_oc(struct Client *cptr, unsigned int flags);
extern void zline_free(struct Zline *zline);
extern void zline_burst(struct Client *cptr);
extern int zline_resend(struct Client *cptr, struct Zline *zline);
extern int zline_list(struct Client *sptr, char *userhost);
extern void zline_stats(struct Client *sptr, struct StatDesc *sd, int stat,
			char *param);
extern int zline_memory_count(size_t *zl_size);

#endif /* INCLUDED_zline_h */
