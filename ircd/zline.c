/*
 * IRC - Internet Relay Chat, ircd/zline.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Finland
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
#include "config.h"

#include "zline.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "match.h"
#include "numeric.h"
#include "s_bsd.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_stats.h"
#include "send.h"
#include "ircd_struct.h"
#include "support.h"
#include "msg.h"
#include "numnicks.h"
#include "numeric.h"
#include "sys.h"    /* FALSE bleah */
#include "whocmds.h"

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h> /* for inet_ntoa */

#define CHECK_APPROVED	   0	/* Mask is acceptable */
#define CHECK_OVERRIDABLE  1	/* Mask is acceptable, but not by default */
#define CHECK_REJECTED	   2	/* Mask is totally unacceptable */

#define MASK_WILD_0	0x01	/* Wildcards in the last position */
#define MASK_WILD_1	0x02	/* Wildcards in the next-to-last position */

#define MASK_WILD_MASK	0x03	/* Mask out the positional wildcards */

#define MASK_WILDS	0x10	/* Mask contains wildcards */
#define MASK_IP		0x20	/* Mask is an IP address */
#define MASK_HALT	0x40	/* Finished processing mask */

struct Zline* GlobalZlineList  = 0;

static struct Zline *
make_zline(char *userhost, char *reason, time_t expire, time_t lastmod,
	   unsigned int flags)
{
  struct Zline *zline, *szline, *after = 0;
  char *host = userhost;

  for (zline = GlobalZlineList; zline; zline = szline) {
    szline = zline->zl_next;

    if (zline->zl_expire <= CurrentTime)
      zline_free(zline);
    else if (((zline->zl_flags & ZLINE_LOCAL) != (flags & ZLINE_LOCAL)) ||
            (zline->zl_host && !host) || (!zline->zl_host && host))
      continue;
    else if (zline->zl_host == NULL || !mmatch(zline->zl_host, host)) {
      if (expire <= zline->zl_expire) /* will expire before wider zline */
        return 0;
      else
        after = zline; /* stick new zline after this one */
    } else if ((zline->zl_host==NULL || !mmatch(host, zline->zl_host))  /* new mask contains zline */
              && zline->zl_expire <= expire) /* old expires before new */
      zline_free(zline); /* save some memory */
  }

  zline = (struct Zline *)MyMalloc(sizeof(struct Zline)); /* alloc memory */
  assert(0 != zline);

  DupString(zline->zl_reason, reason); /* initialize zline... */
  zline->zl_expire = expire;
  zline->zl_lastmod = lastmod;
  zline->zl_flags = flags & ZLINE_MASK;

  DupString(zline->zl_host, host);

  if (check_if_ipmask(host)) { /* mark if it's an IP mask */
    int class;
    char ipname[16];
    int ad[4] = { 0 };
    int bits2 = 0;
    char *ch;
    int seenwild;
    int badmask=0;
      
    /* Sanity check for dodgy IP masks 
     * Any mask featuring a digit after a wildcard will 
     * not behave as expected. */
    for (seenwild=0,ch=host;*ch;ch++) {
      if (*ch=='*' || *ch=='?') 
        seenwild=1;
      if (IsDigit(*ch) && seenwild) {
        badmask=1;
        break;
      }
    }
      
    if (badmask) {
      /* It's bad - let's make it match 0.0.0.0/32 */
      zline->bits=32;
      zline->ipnum.s_addr=0;
    } else {

      class = sscanf(host,"%d.%d.%d.%d/%d",
                     &ad[0],&ad[1],&ad[2],&ad[3], &bits2);
      if (class!=5) {
        zline->bits=class*8;
      } else {
        zline->bits=bits2;
      }
      ircd_snprintf(0, ipname, sizeof(ipname), "%d.%d.%d.%d", ad[0], ad[1],
                    ad[2], ad[3]);
      zline->ipnum.s_addr = inet_addr(ipname);
    }      
    Debug((DEBUG_DEBUG,"IP zline: %08x/%i",zline->ipnum.s_addr,zline->bits));
    zline->zl_flags |= ZLINE_IPMASK;
  }

  if (after) {
    zline->zl_next = after->zl_next;
    zline->zl_prev_p = &after->zl_next;
    if (after->zl_next)
      after->zl_next->zl_prev_p = &zline->zl_next;
    after->zl_next = zline;
  } else {
    zline->zl_next = GlobalZlineList; /* then link it into list */
    zline->zl_prev_p = &GlobalZlineList;
    if (GlobalZlineList)
      GlobalZlineList->zl_prev_p = &zline->zl_next;
    GlobalZlineList = zline;
  }

  return zline;
}

static int
do_mangle_zline(struct Client* cptr, struct Client* acptr,
               struct Client* sptr, const char* orig_reason)
{
  char reason[BUFSIZE];
  char* endanglebracket;
  char* space;

  if (!feature_bool(FEAT_HIS_ZLINE))
    return exit_client_msg(cptr, acptr, &me, "Z-lined (%s)", orig_reason);

  endanglebracket = strchr(orig_reason, '>');
  space = strchr(orig_reason, ' ');

  if (IsService(sptr))
  {
    if (orig_reason[0] == '<' && endanglebracket && endanglebracket < space)
    {
      strcpy(reason, "Z-lined by ");
      strncat(reason, orig_reason + 1, endanglebracket - orig_reason - 1);
    } else {
      ircd_snprintf(0, reason, sizeof(reason), "Z-lined (%s)",
                   orig_reason);
    }
  } else {
    ircd_snprintf(0, reason, sizeof(reason), "Z-lined (<%s> %s)",
                 sptr->cli_name, orig_reason);
  }
  return exit_client_msg(cptr, acptr, &me, reason);
}

static int
do_zline(struct Client *cptr, struct Client *sptr, struct Zline *zline)
{
  struct Client *acptr;
  int fd, retval = 0, tval;

  if (!ZlineIsActive(zline)) /* no action taken on inactive zlines */
    return 0;

  for (fd = HighestFd; fd >= 0; --fd) {
    /*
     * get the users!
     */
    if ((acptr = LocalClientArray[fd])) {
      if (!cli_user(acptr))
        continue;

      if (ZlineIsIpMask(zline)) {
        Debug((DEBUG_DEBUG,"IP zline: %08x %08x/%i",(cli_ip(cptr)).s_addr,
        zline->ipnum.s_addr,zline->bits));
        if (((cli_ip(acptr)).s_addr & NETMASK(zline->bits)) != zline->ipnum.s_addr)
          continue;
      } else {
        if (match(zline->zl_host, cli_sockhost(acptr)) != 0)
          continue;
      }

      /* ok, here's one that got Z-lined */
      send_reply(acptr, SND_EXPLICIT | ERR_YOUREBANNEDCREEP, ":%s",
      	   zline->zl_reason);

      /* let the ops know about it */
      sendto_allops(&me, SNO_GLINE, "Z-line active for %s",
      		     get_client_name(acptr, TRUE));

      /* and get rid of him */
      if ((tval = do_mangle_zline(cptr, acptr, sptr, zline->zl_reason)))
        retval = tval; /* retain killed status */
    }
  }
  return retval;
}

/*
 * This routine implements the mask checking applied to local
 * Z-lines.  Basically, host masks must have a minimum of two non-wild
 * domain fields, and IP masks must have a minimum of 16 bits.  If the
 * mask has even one wild-card, OVERRIDABLE is returned, assuming the
 * other check doesn't fail.
 */
static int
zline_checkmask(char *mask)
{
  unsigned int flags = MASK_IP;
  unsigned int dots = 0;
  unsigned int ipmask = 0;

  for (; *mask; mask++) { /* go through given mask */
    if (*mask == '.') { /* it's a separator; advance positional wilds */
      flags = (flags & ~MASK_WILD_MASK) | ((flags << 1) & MASK_WILD_MASK);
      dots++;

      if ((flags & (MASK_IP | MASK_WILDS)) == MASK_IP)
	ipmask += 8; /* It's an IP with no wilds, count bits */
    } else if (*mask == '*' || *mask == '?')
      flags |= MASK_WILD_0 | MASK_WILDS; /* found a wildcard */
    else if (*mask == '/') { /* n.n.n.n/n notation; parse bit specifier */
      mask++;
      ipmask = strtoul(mask, &mask, 10);

      if (*mask || dots != 3 || ipmask > 32 || /* sanity-check to date */
	  (flags & (MASK_WILDS | MASK_IP)) != MASK_IP)
	return CHECK_REJECTED; /* how strange... */

      if (ipmask < 32) /* it's a masked address; mark wilds */
	flags |= MASK_WILDS;

      flags |= MASK_HALT; /* Halt the ipmask calculation */

      break; /* get out of the loop */
    } else if (!IsDigit(*mask)) {
      flags &= ~MASK_IP; /* not an IP anymore! */
      ipmask = 0;
    }
  }

  /* Sanity-check quads */
  if (dots > 3 || (!(flags & MASK_WILDS) && dots < 3)) {
    flags &= ~MASK_IP;
    ipmask = 0;
  }

  /* update bit count if necessary */
  if ((flags & (MASK_IP | MASK_WILDS | MASK_HALT)) == MASK_IP)
    ipmask += 8;

  /* Check to see that it's not too wide of a mask */
  if (flags & MASK_WILDS &&
      ((!(flags & MASK_IP) && (dots < 2 || flags & MASK_WILD_MASK)) ||
       (flags & MASK_IP && ipmask < 16)))
    return CHECK_REJECTED; /* to wide, reject */

  /* Ok, it's approved; require override if it has wildcards, though */
  return flags & MASK_WILDS ? CHECK_OVERRIDABLE : CHECK_APPROVED;
}

int
zline_propagate(struct Client *cptr, struct Client *sptr, struct Zline *zline)
{
  if (ZlineIsLocal(zline) || (IsUser(sptr) && !zline->zl_lastmod))
    return 0;

  if (zline->zl_lastmod)
    sendcmdto_serv_butone(sptr, CMD_ZLINE, cptr, "* %c%s %Tu %Tu :%s",
			  ZlineIsRemActive(zline) ? '+' : '-',
			  zline->zl_host ? zline->zl_host : "",
			  zline->zl_expire - CurrentTime, zline->zl_lastmod,
			  zline->zl_reason);
  else
    sendcmdto_serv_butone(sptr, CMD_ZLINE, cptr,
			  (ZlineIsRemActive(zline) ?
			   "* +%s %Tu :%s" : "* -%s"),
			  zline->zl_host ? zline->zl_host : "",
			  zline->zl_expire - CurrentTime, zline->zl_reason);

  return 0;
}

int 
zline_add(struct Client *cptr, struct Client *sptr, char *userhost,
	  char *reason, time_t expire, time_t lastmod, unsigned int flags)
{
  struct Zline *azline;
  char fmask[HOSTLEN+3];
  int tmp;

  assert(0 != reason);

  ircd_snprintf(0, fmask, sizeof(fmask), "FAKE@%s", userhost);

  if (MyUser(sptr) || (IsUser(sptr) && flags & ZLINE_LOCAL)) {
    switch (zline_checkmask(fmask)) {
    case CHECK_OVERRIDABLE: /* oper overrided restriction */
      if (flags & ZLINE_OPERFORCE)
        break;
      /*FALLTHROUGH*/
    case CHECK_REJECTED:
      return send_reply(sptr, ERR_MASKTOOWIDE, userhost);
      break;
    }

    if ((tmp = count_users(fmask)) >= feature_int(FEAT_ZLINEMAXUSERCOUNT) && !(flags & ZLINE_OPERFORCE))
      return send_reply(sptr, ERR_TOOMANYUSERS, tmp);
  }

  if (!check_if_ipmask(userhost))
    return send_reply(sptr, ERR_INVALIDMASK);

  /*
   * You cannot set a negative (or zero) expire time, nor can you set an
   * expiration time for greater than ZLINE_MAX_EXPIRE.
   */
  if (!(flags & ZLINE_FORCE) && (expire <= 0 || expire > ZLINE_MAX_EXPIRE)) {
    if (!IsServer(sptr) && MyConnect(sptr))
      send_reply(sptr, ERR_BADEXPIRE, expire);
    return 0;
  }

  expire += CurrentTime; /* convert from lifetime to timestamp */

  /* Inform ops... */
  sendto_opmask_butone(0, ircd_strncmp(reason, "AUTO", 4) ? SNO_GLINE :
		       SNO_AUTO, "%s adding %s ZLINE for %s, expiring at "
		       "%Tu: %s",
		       feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr) ?
		       cli_name(sptr) : cli_name((cli_user(sptr))->server),
		       flags & ZLINE_LOCAL ? "local" : "global", userhost,
		       expire + TSoffset, reason);

  /* and log it */
  log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
	    "%#C adding %s ZLINE for %s, expiring at %Tu: %s", sptr,
	    flags & ZLINE_LOCAL ? "local" : "global", userhost,
	    expire + TSoffset, reason);

  /* make the zline */
  azline = make_zline(userhost, reason, expire, lastmod, flags);

  if (!azline) /* if it overlapped, silently return */
    return 0;

  zline_propagate(cptr, sptr, azline);

  return do_zline(cptr, sptr, azline); /* knock off users if necessary */
}

int
zline_activate(struct Client *cptr, struct Client *sptr, struct Zline *zline,
	       time_t lastmod, unsigned int flags)
{
  unsigned int saveflags = 0;

  assert(0 != zline);

  saveflags = zline->zl_flags;

  if (flags & ZLINE_LOCAL)
    zline->zl_flags &= ~ZLINE_LDEACT;
  else {
    zline->zl_flags |= ZLINE_ACTIVE;

    if (zline->zl_lastmod) {
      if (zline->zl_lastmod >= lastmod) /* force lastmod to increase */
	zline->zl_lastmod++;
      else
	zline->zl_lastmod = lastmod;
    }
  }

  if ((saveflags & ZLINE_ACTMASK) == ZLINE_ACTIVE)
    return 0; /* was active to begin with */

  /* Inform ops and log it */
  sendto_opmask_butone(0, SNO_GLINE, "%s activating global ZLINE for %s, "
		       "expiring at %Tu: %s",
		       feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr) ?
		       cli_name(sptr) : cli_name((cli_user(sptr))->server),
		       zline->zl_host ? zline->zl_host : "",
		       zline->zl_expire + TSoffset, zline->zl_reason);

  log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
	    "%#C activating global ZLINE for %s, expiring at %Tu: %s", sptr,
	    zline->zl_host ? zline->zl_host : "",
	    zline->zl_expire + TSoffset, zline->zl_reason);

  if (!(flags & ZLINE_LOCAL)) /* don't propagate local changes */
    zline_propagate(cptr, sptr, zline);

  return do_zline(cptr, sptr, zline);
}

int
zline_deactivate(struct Client *cptr, struct Client *sptr, struct Zline *zline,
		 time_t lastmod, unsigned int flags)
{
  unsigned int saveflags = 0;
  char *msg;

  assert(0 != zline);

  saveflags = zline->zl_flags;

  if (ZlineIsLocal(zline))
    msg = "removing local";
  else if (!zline->zl_lastmod && !(flags & ZLINE_LOCAL)) {
    msg = "removing global";
    zline->zl_flags &= ~ZLINE_ACTIVE; /* propagate a -<mask> */
  } else {
    msg = "deactivating global";

    if (flags & ZLINE_LOCAL)
      zline->zl_flags |= ZLINE_LDEACT;
    else {
      zline->zl_flags &= ~ZLINE_ACTIVE;

      if (zline->zl_lastmod) {
	if (zline->zl_lastmod >= lastmod)
	  zline->zl_lastmod++;
	else
	  zline->zl_lastmod = lastmod;
      }
    }

    if ((saveflags & ZLINE_ACTMASK) != ZLINE_ACTIVE)
      return 0; /* was inactive to begin with */
  }

  /* Inform ops and log it */
  sendto_opmask_butone(0, SNO_GLINE, "%s %s ZLINE for %s, expiring at %Tu: "
		       "%s",
		       feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr) ?
		       cli_name(sptr) : cli_name((cli_user(sptr))->server),
		       msg, zline->zl_host ? zline->zl_host : "",
		       zline->zl_expire + TSoffset, zline->zl_reason);

  log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
	    "%#C %s ZLINE for %s, expiring at %Tu: %s", sptr, msg,
	    zline->zl_host ? zline->zl_host : "",
	    zline->zl_expire + TSoffset, zline->zl_reason);

  if (!(flags & ZLINE_LOCAL)) /* don't propagate local changes */
    zline_propagate(cptr, sptr, zline);

  /* if it's a local zline or a Uworld zline (and not locally deactivated).. */
  if (ZlineIsLocal(zline) || (!zline->zl_lastmod && !(flags & ZLINE_LOCAL)))
    zline_free(zline); /* get rid of it */

  return 0;
}

struct Zline *
zline_find(char *userhost, unsigned int flags)
{
  struct Zline *zline;
  struct Zline *szline;

  for (zline = GlobalZlineList; zline; zline = szline) {
    szline = zline->zl_next;

    if (zline->zl_expire <= CurrentTime) {
      zline_free(zline);
    } else if ((flags & ZLINE_GLOBAL && zline->zl_flags & ZLINE_LOCAL) || (flags & ZLINE_LASTMOD && !zline->zl_lastmod)) {
      continue;
    } else {
      if ((zline->zl_host && userhost && (ircd_strcmp(zline->zl_host,userhost) == 0)) || (!zline->zl_host && !userhost)) {
        break;
      }
    } 
  }

  return zline;
}

struct Zline *
zline_lookup(struct Client *cptr, unsigned int flags)
{
  struct Zline *zline;
  struct Zline *szline;

  for (zline = GlobalZlineList; zline; zline = szline) {
    szline = zline->zl_next;

    if (zline->zl_expire <= CurrentTime) {
      zline_free(zline);
      continue;
    }
    
    if ((flags & ZLINE_GLOBAL && zline->zl_flags & ZLINE_LOCAL) ||
	     (flags & ZLINE_LASTMOD && !zline->zl_lastmod))
      continue;

    if (ZlineIsIpMask(zline)) {
      Debug((DEBUG_DEBUG,"IP zline: %08x %08x/%i",(cli_ip(cptr)).s_addr,zline->ipnum.s_addr,zline->bits));
      if (((cli_ip(cptr)).s_addr & NETMASK(zline->bits)) != zline->ipnum.s_addr)
        continue;
    } else
      continue;

    if (ZlineIsActive(zline))
      return zline;
  }
  /*
   * No Zlines matched
   */
  return 0;
}

struct Zline *
zline_lookup_oc(struct Client *cptr, unsigned int flags)
{
  struct Zline *zline;
  struct Zline *szline;

  for (zline = GlobalZlineList; zline; zline = szline) {
    szline = zline->zl_next;

    if (zline->zl_expire <= CurrentTime) {
      zline_free(zline);
      continue;
    }
    
    if ((flags & ZLINE_GLOBAL && zline->zl_flags & ZLINE_LOCAL) ||
	     (flags & ZLINE_LASTMOD && !zline->zl_lastmod))
      continue;

    if (ZlineIsIpMask(zline)) {
      Debug((DEBUG_DEBUG,"IP zline: %08x %08x/%i",(cli_ip(cptr)).s_addr,zline->ipnum.s_addr,zline->bits));
      if (((cli_ip(cptr)).s_addr & NETMASK(zline->bits)) != zline->ipnum.s_addr)
        continue;
    }    
    else {
      if (match(zline->zl_host, (cli_user(cptr))->realhost) != 0) 
        continue;
    }

    if (ZlineIsActive(zline))
      return zline;
  }
  /*
   * No Zlines matched
   */
  return 0;
}

void
zline_free(struct Zline *zline)
{
  assert(0 != zline);

  *zline->zl_prev_p = zline->zl_next; /* squeeze this zline out */
  if (zline->zl_next)
    zline->zl_next->zl_prev_p = zline->zl_prev_p;

  if (zline->zl_host)
    MyFree(zline->zl_host);
  MyFree(zline->zl_reason);
  MyFree(zline);
}

void
zline_burst(struct Client *cptr)
{
  struct Zline *zline;
  struct Zline *szline;

  for (zline = GlobalZlineList; zline; zline = szline) { /* all zlines */
    szline = zline->zl_next;

    if (zline->zl_expire <= CurrentTime) /* expire any that need expiring */
      zline_free(zline);
    else if (!ZlineIsLocal(zline) && zline->zl_lastmod)
      sendcmdto_one(&me, CMD_ZLINE, cptr, "* %c%s %Tu %Tu :%s",
		    ZlineIsRemActive(zline) ? '+' : '-',
		    zline->zl_host ? zline->zl_host : "", 
		    zline->zl_expire - CurrentTime, zline->zl_lastmod, 
		    zline->zl_reason);
  }
}

int
zline_resend(struct Client *cptr, struct Zline *zline)
{
  if (ZlineIsLocal(zline) || !zline->zl_lastmod)
    return 0;

  sendcmdto_one(&me, CMD_ZLINE, cptr, "* %c%s %Tu %Tu :%s",
		ZlineIsRemActive(zline) ? '+' : '-',
		zline->zl_host ? zline->zl_host : "",
		zline->zl_expire - CurrentTime, zline->zl_lastmod,
		zline->zl_reason);

  return 0;
}

int
zline_list(struct Client *sptr, char *userhost)
{
  struct Zline *zline;
  struct Zline *szline;

  if (userhost) {
    if (!(zline = zline_find(userhost, ZLINE_ANY))) /* no such zline */
      return send_reply(sptr, ERR_NOSUCHZLINE, userhost);

    /* send zline information along */
    send_reply(sptr, RPL_ZLIST,
	       zline->zl_host ? zline->zl_host : "",
	       zline->zl_expire + TSoffset,
               zline->zl_lastmod + TSoffset,
	       ZlineIsLocal(zline) ? cli_name(&me) : "*",
	       ZlineIsActive(zline) ? '+' : '-', zline->zl_reason);
  } else {
    for (zline = GlobalZlineList; zline; zline = szline) {
      szline = zline->zl_next;

      if (zline->zl_expire <= CurrentTime)
	zline_free(zline);
      else
	send_reply(sptr, RPL_ZLIST,
		   zline->zl_host ? zline->zl_host : "",
		   zline->zl_expire + TSoffset,
                   zline->zl_lastmod + TSoffset,
		   ZlineIsLocal(zline) ? cli_name(&me) : "*",
		   ZlineIsActive(zline) ? '+' : '-', zline->zl_reason);
    }
  }

  /* end of zline information */
  return send_reply(sptr, RPL_ENDOFZLIST);
}

void
zline_stats(struct Client *sptr, struct StatDesc *sd, int stat, char *param)
{
  struct Zline *zline;
  struct Zline *szline;

  for (zline = GlobalZlineList; zline; zline = szline) {
    szline = zline->zl_next;

    if (zline->zl_expire <= CurrentTime)
      zline_free(zline);
    else
      send_reply(sptr, RPL_STATSZLINE, 'Z',
		 zline->zl_host ? zline->zl_host : "",
		 zline->zl_expire + TSoffset,
                 zline->zl_lastmod + TSoffset, zline->zl_reason);
  }
}

int
zline_memory_count(size_t *zl_size)
{
  struct Zline *zline;
  unsigned int gl = 0;

  for (zline = GlobalZlineList; zline; zline = zline->zl_next) {
    gl++;
    *zl_size += sizeof(struct Zline);
    *zl_size += zline->zl_host ? (strlen(zline->zl_host) + 1) : 0;
    *zl_size += zline->zl_reason ? (strlen(zline->zl_reason) + 1) : 0;
  }
  return gl;
}
