#ifndef INCLUDED_shun_h
#define INCLUDED_shun_h
/*
 * IRC - Internet Relay Chat, include/shun.h
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 * Copyright (C) 1996 -1997 Carlo Wood
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

#define SHUN_MAX_EXPIRE 604800	/* max expire: 7 days */

struct Shun {
  struct Shun *sh_next;
  struct Shun **sh_prev_p;
  char	       *sh_user;
  char	       *sh_host;
  char	       *sh_reason;
  time_t	sh_expire;
  time_t	sh_lastmod;
  struct in_addr ipnum;  /* We store the IP in binary for ip shuns */
  char 		bits;
  unsigned int	sh_flags;
};

#define SHUN_ACTIVE	0x0001
#define SHUN_IPMASK	0x0002
#define SHUN_LOCAL	0x0008
#define SHUN_ANY	0x0010
#define SHUN_FORCE	0x0020
#define SHUN_EXACT	0x0040
#define SHUN_LDEACT	0x0080	/* locally deactivated */
#define SHUN_GLOBAL	0x0100	/* find only global shun */
#define SHUN_LASTMOD	0x0200	/* find only shuns with non-zero lastmod */
#define SHUN_OPERFORCE	0x0400	/* oper forcing shun to be set */
#define SHUN_REALNAME	0x0800	/* shun matches only the realname field */

#define SHUN_MASK	(SHUN_ACTIVE | SHUN_LOCAL | SHUN_REALNAME )
#define SHUN_ACTMASK	(SHUN_ACTIVE | SHUN_LDEACT)

#define ShunIsActive(s)		(((s)->sh_flags & SHUN_ACTMASK) == \
				 SHUN_ACTIVE)
#define ShunIsRemActive(s)	((s)->sh_flags & SHUN_ACTIVE)
#define ShunIsIpMask(s)		((s)->sh_flags & SHUN_IPMASK)
#define ShunIsRealName(s)	((s)->sh_flags & SHUN_REALNAME)
#define ShunIsLocal(s)		((s)->sh_flags & SHUN_LOCAL)

#define ShunUser(s)		((s)->sh_user)
#define ShunHost(s)		((s)->sh_host)
#define ShunReason(s)		((s)->sh_reason)
#define ShunLastMod(s)		((s)->sh_lastmod)

extern int shun_propagate(struct Client *cptr, struct Client *sptr,
			  struct Shun *shun);
extern int shun_add(struct Client *cptr, struct Client *sptr, char *userhost,
		    char *reason, time_t expire, time_t lastmod,
		    unsigned int flags);
extern int shun_activate(struct Client *cptr, struct Client *sptr,
		 	 struct Shun *shun, time_t lastmod,
			 unsigned int flags);
extern int shun_deactivate(struct Client *cptr, struct Client *sptr,
			    struct Shun *shun, time_t lastmod,
			    unsigned int flags);
extern struct Shun *shun_find(char *userhost, unsigned int flags);
extern struct Shun *shun_lookup(struct Client *cptr, unsigned int flags);
extern void shun_free(struct Shun *shun);
extern void shun_burst(struct Client *cptr);
extern int shun_resend(struct Client *cptr, struct Shun *shun);
extern int shun_list(struct Client *sptr, char *userhost);
extern void shun_stats(struct Client *sptr, const struct StatDesc *sd,
		       char *param);
extern int shun_memory_count(size_t *sh_size);
extern int expire_shuns();
extern int count_affected(char* mask);

#endif /* INCLUDED_shun_h */

