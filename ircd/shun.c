/*
 * IRC - Internet Relay Chat, ircd/shun.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Finland
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
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

#include "shun.h"
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

struct Shun* GlobalShunList  = 0;

static void
canon_userhost(char *userhost, char **user_p, char **host_p, char *def_user)
{
  char *tmp;
  if (*userhost == '$') {
    *user_p = userhost;
    *host_p = NULL;
    return;
  }

  if (!(tmp = strchr(userhost, '@'))) {
    *user_p = def_user;
    *host_p = userhost;
  } else {
    *user_p = userhost;
    *(tmp++) = '\0';
    *host_p = tmp;
  }
}

static struct Shun *
make_shun(char *user, char *host, char *reason, time_t expire, time_t lastmod,
	   unsigned int flags)
{
  struct Shun *shun, *sshun, *after = 0;

  for (shun = GlobalShunList; shun; shun = sshun) {
    sshun = shun->sh_next;

    if (shun->sh_expire <= CurrentTime)
      shun_free(shun);
    else if (((shun->sh_flags & SHUN_LOCAL) != (flags & SHUN_LOCAL)) ||
             (shun->sh_host && !host) || (!shun->sh_host && host))
      continue;
    else if (!mmatch(shun->sh_user, user) /* shun contains new mask */
             && (shun->sh_host == NULL || !mmatch(shun->sh_host, host))) {
      if (expire <= shun->sh_expire) /* will expire before wider shun */
        return 0;
      else
        after = shun; /* stick new shun after this one */
    } else if (!mmatch(user, shun->sh_user) /* new mask contains shun */
               && (shun->sh_host==NULL || !mmatch(host, shun->sh_host))
               && shun->sh_expire <= expire) /* old expires before new */
      shun_free(shun); /* save some memory */
  }

  shun = (struct Shun *)MyMalloc(sizeof(struct Shun)); /* alloc memory */
  assert(0 != shun);

  DupString(shun->sh_reason, reason); /* initialize shun... */
  shun->sh_expire = expire;
  shun->sh_lastmod = lastmod;
  shun->sh_flags = flags & SHUN_MASK;

  DupString(shun->sh_user, user); /* remember them... */
  if (*user!='$')
    DupString(shun->sh_host, host);
  else
    shun->sh_host = 0;

  if (*user!='$' && check_if_ipmask(host)) { /* mark if it's an IP mask */
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
      shun->bits=32;
      shun->ipnum.s_addr=0;
    } else {

      class = sscanf(host,"%d.%d.%d.%d/%d",
                     &ad[0],&ad[1],&ad[2],&ad[3], &bits2);
      if (class!=5) {
        shun->bits=class*8;
      }
      else {
        shun->bits=bits2;
      }
      ircd_snprintf(0, ipname, sizeof(ipname), "%d.%d.%d.%d", ad[0], ad[1],
                    ad[2], ad[3]);
      shun->ipnum.s_addr = inet_addr(ipname);
    }      
    Debug((DEBUG_DEBUG,"IP shun: %08x/%i",shun->ipnum.s_addr,shun->bits));
    shun->sh_flags |= SHUN_IPMASK;
  }

  if (after) {
    shun->sh_next = after->sh_next;
    shun->sh_prev_p = &after->sh_next;
    if (after->sh_next)
      after->sh_next->sh_prev_p = &shun->sh_next;
    after->sh_next = shun;
  } else {
    shun->sh_next = GlobalShunList; /* then link it into list */
    shun->sh_prev_p = &GlobalShunList;
    if (GlobalShunList)
      GlobalShunList->sh_prev_p = &shun->sh_next;
    GlobalShunList = shun;
  }

  return shun;
}

static int
do_shun(struct Client *cptr, struct Client *sptr, struct Shun *shun)
{
  struct Client *acptr;
  int fd, tval = 0;

  if (!ShunIsActive(shun)) /* no action taken on inactive shuns */
    return 0;

  for (fd = HighestFd; fd >= 0; --fd) {
    /*
     * get the users!
     */
    if ((acptr = LocalClientArray[fd])) {
      if (!cli_user(acptr))
        continue;


      if (shun->sh_flags & SHUN_REALNAME) { /* Realname Shun */
	Debug((DEBUG_DEBUG,"Realname Shun: %s %s",(cli_info(acptr)),
					shun->sh_user+2));
        if (match(shun->sh_user+2, cli_info(acptr)) != 0)
            continue;
        Debug((DEBUG_DEBUG,"Matched!"));
      } else { /* Host/IP shun */
	      if (cli_user(acptr)->username && 
			      match (shun->sh_user, cli_user(acptr)->realusername ? cli_user(acptr)->realusername : cli_user(acptr)->username ) != 0)
		      continue;

	      if (ShunIsIpMask(shun)) {
		      Debug((DEBUG_DEBUG,"IP shun: %08x %08x/%i",(cli_ip(cptr)).s_addr,
                 shun->ipnum.s_addr,shun->bits));
		      if (((cli_ip(acptr)).s_addr & NETMASK(shun->bits)) 
              != shun->ipnum.s_addr)
			      continue;
	      }
	      else {
		      if (match(shun->sh_host, cli_sockhost(acptr)) != 0)
			      continue;
	      }
      } /* of Host/IP Shun */


      /* ok, here's one that got Shunned */
      if (!feature_bool(FEAT_HIS_SHUN_REASON))
        sendcmdto_one(&me, CMD_NOTICE, acptr, "%C :You are shunned: %s", acptr,
   	     shun->sh_reason);

      /* let the ops know about it */
      sendto_opmask_butone(0, SNO_GLINE, "Shun active for %s",
      		     get_client_name(acptr, TRUE));

      /* and mark him */
      ircd_snprintf(0, cli_user(acptr)->shunreason, sizeof(cli_user(acptr)->shunreason), "%s", shun->sh_reason);
      tval = 1;
    }
  }
  return tval;
}

/*
 * This routine implements the mask checking applied to local
 * Shuns.  Basically, host masks must have a minimum of two non-wild
 * domain fields, and IP masks must have a minimum of 16 bits.  If the
 * mask has even one wild-card, OVERRIDABLE is returned, assuming the
 * other check doesn't fail.
 */
static int
shun_checkmask(char *mask)
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
shun_propagate(struct Client *cptr, struct Client *sptr, struct Shun *shun)
{
  if (ShunIsLocal(shun) || (IsUser(sptr) && !shun->sh_lastmod))
    return 0;

  if (shun->sh_lastmod)
    sendcmdto_serv_butone(sptr, CMD_SHUN, cptr, "* %c%s%s%s %Tu %Tu :%s",
			  ShunIsRemActive(shun) ? '+' : '-', shun->sh_user,
			  shun->sh_host ? "@" : "",
			  shun->sh_host ? shun->sh_host : "",
			  shun->sh_expire - CurrentTime, shun->sh_lastmod,
			  shun->sh_reason);
  else
    sendcmdto_serv_butone(sptr, CMD_SHUN, cptr,
			  (ShunIsRemActive(shun) ?
			   "* +%s%s%s %Tu :%s" : "* -%s%s%s"),
			  shun->sh_user, 
			  shun->sh_host ? "@" : "",
			  shun->sh_host ? shun->sh_host : "",
			  shun->sh_expire - CurrentTime, shun->sh_reason);

  return 0;
}

int 
shun_add(struct Client *cptr, struct Client *sptr, char *userhost,
	  char *reason, time_t expire, time_t lastmod, unsigned int flags)
{
  struct Shun *ashun;
  char uhmask[USERLEN + HOSTLEN + 2];
  char *user, *host;
  int tmp;

  assert(0 != userhost);
  assert(0 != reason);

  if (*userhost == '$' || userhost[2] == '$') {
    switch (*userhost == '$' ? userhost[1] : userhost[3]) {
      case 'R': flags |= SHUN_REALNAME; break;
      default:
        /* uh, what to do here? */
        /* The answer, my dear Watson, is we throw a protocol_violation()
           -- hikari */
        return protocol_violation(sptr,"%s has sent an incorrect shun.",cli_name(sptr));
        break;
    }
     user = (*userhost =='$' ? userhost : userhost+2);
     host = 0;
  } else {
    canon_userhost(userhost, &user, &host, "*");
    if (sizeof(uhmask) <
	ircd_snprintf(0, uhmask, sizeof(uhmask), "%s@%s", user, host))
      return send_reply(sptr, ERR_LONGMASK);
    else if (MyUser(sptr) || (IsUser(sptr) && flags & SHUN_LOCAL)) {
      switch (shun_checkmask(host)) {
      case CHECK_OVERRIDABLE: /* oper overrided restriction */
	if (flags & SHUN_OPERFORCE)
	  break;
	/*FALLTHROUGH*/
      case CHECK_REJECTED:
	return send_reply(sptr, ERR_MASKTOOWIDE, uhmask);
	break;
      }

      if ((tmp = count_users(uhmask)) >=
	  feature_int(FEAT_SHUNMAXUSERCOUNT) && !(flags & SHUN_OPERFORCE))
	return send_reply(sptr, ERR_TOOMANYUSERS, tmp);
    }
  }

  /*
   * You cannot set a negative (or zero) expire time, nor can you set an
   * expiration time for greater than SHUN_MAX_EXPIRE.
   */
  if (!(flags & SHUN_FORCE) && (expire <= 0 || expire > SHUN_MAX_EXPIRE)) {
    if (!IsServer(sptr) && MyConnect(sptr))
      send_reply(sptr, ERR_BADEXPIRE, expire);
    return 0;
  }

  expire += CurrentTime; /* convert from lifetime to timestamp */

  /* Inform ops... */
  sendto_opmask_butone(0, ircd_strncmp(reason, "AUTO", 4) ? SNO_GLINE :
		       SNO_AUTO, "%s adding %s SHUN for %s%s%s, expiring at "
		       "%Tu: %s",
		       feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr) ?
		       cli_name(sptr) : cli_name((cli_user(sptr))->server),
		       flags & SHUN_LOCAL ? "local" : "global", user,
		       flags & (SHUN_REALNAME) ? "" : "@",
		       flags & (SHUN_REALNAME) ? "" : host,
		       expire + TSoffset, reason);

  /* and log it */
  log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
	    "%#C adding %s %s for %s%s%s, expiring at %Tu: %s", sptr,
	    flags & SHUN_LOCAL ? "local" : "global", user,
	    flags & (SHUN_REALNAME) ? "" : "@",
	    flags & (SHUN_REALNAME) ? "" : host,
	    expire + TSoffset, reason);

  /* make the shun */
  ashun = make_shun(user, host, reason, expire, lastmod, flags);

  if (!ashun) /* if it overlapped, silently return */
    return 0;

  shun_propagate(cptr, sptr, ashun);

  return do_shun(cptr, sptr, ashun); /* knock off users if necessary */
}

int
shun_activate(struct Client *cptr, struct Client *sptr, struct Shun *shun,
	       time_t lastmod, unsigned int flags)
{
  unsigned int saveflags = 0;

  assert(0 != shun);

  saveflags = shun->sh_flags;

  if (flags & SHUN_LOCAL)
    shun->sh_flags &= ~SHUN_LDEACT;
  else {
    shun->sh_flags |= SHUN_ACTIVE;

    if (shun->sh_lastmod) {
      if (shun->sh_lastmod >= lastmod) /* force lastmod to increase */
	shun->sh_lastmod++;
      else
	shun->sh_lastmod = lastmod;
    }
  }

  if ((saveflags & SHUN_ACTMASK) == SHUN_ACTIVE)
    return 0; /* was active to begin with */

  /* Inform ops and log it */
  sendto_opmask_butone(0, SNO_GLINE, "%s activating global SHUN for %s%s%s, "
		       "expiring at %Tu: %s",
		       feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr) ?
		       cli_name(sptr) : cli_name((cli_user(sptr))->server),
		       shun->sh_user, shun->sh_host ? "@" : "",
		       shun->sh_host ? shun->sh_host : "",
		       shun->sh_expire + TSoffset, shun->sh_reason);

  log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
	    "%#C activating global SHUN for %s%s%s, expiring at %Tu: %s", sptr,
	    shun->sh_user,
	    shun->sh_host ? "@" : "",
	    shun->sh_host ? shun->sh_host : "",
	    shun->sh_expire + TSoffset, shun->sh_reason);

  if (!(flags & SHUN_LOCAL)) /* don't propagate local changes */
    shun_propagate(cptr, sptr, shun);

  return do_shun(cptr, sptr, shun);
}

int
shun_deactivate(struct Client *cptr, struct Client *sptr, struct Shun *shun,
		 time_t lastmod, unsigned int flags)
{
  unsigned int saveflags = 0;
  char *msg;

  assert(0 != shun);

  saveflags = shun->sh_flags;

  if (ShunIsLocal(shun))
    msg = "removing local";
  else if (!shun->sh_lastmod && !(flags & SHUN_LOCAL)) {
    msg = "removing global";
    shun->sh_flags &= ~SHUN_ACTIVE; /* propagate a -<mask> */
  } else {
    msg = "deactivating global";

    if (flags & SHUN_LOCAL)
      shun->sh_flags |= SHUN_LDEACT;
    else {
      shun->sh_flags &= ~SHUN_ACTIVE;

      if (shun->sh_lastmod) {
	if (shun->sh_lastmod >= lastmod)
	  shun->sh_lastmod++;
	else
	  shun->sh_lastmod = lastmod;
      }
    }

    if ((saveflags & SHUN_ACTMASK) != SHUN_ACTIVE)
      return 0; /* was inactive to begin with */
  }

  /* Inform ops and log it */
  sendto_opmask_butone(0, SNO_GLINE, "%s %s %s for %s%s%s, expiring at %Tu: "
		       "%s",
		       feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr) ?
		       cli_name(sptr) : cli_name((cli_user(sptr))->server),
		       msg, "SHUN",
		       shun->sh_user, shun->sh_host ? "@" : "",
		       shun->sh_host ? shun->sh_host : "",
		       shun->sh_expire + TSoffset, shun->sh_reason);

  log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
	    "%#C %s %s for %s%s%s, expiring at %Tu: %s", sptr, msg,
	    "SHUN", shun->sh_user,
	    shun->sh_host ? "@" : "",
	    shun->sh_host ? shun->sh_host : "",
	    shun->sh_expire + TSoffset, shun->sh_reason);

  if (!(flags & SHUN_LOCAL)) /* don't propagate local changes */
    shun_propagate(cptr, sptr, shun);

  /* if it's a local shun or a Uworld shun (and not locally deactivated).. */
  if (ShunIsLocal(shun) || (!shun->sh_lastmod && !(flags & SHUN_LOCAL)))
    shun_free(shun); /* get rid of it */

  return 0;
}

struct Shun *
shun_find(char *userhost, unsigned int flags)
{
  struct Shun *shun;
  struct Shun *sshun;
  char *user, *host, *t_uh;

  DupString(t_uh, userhost);
  canon_userhost(t_uh, &user, &host, 0);

  if(BadPtr(user))
    return 0;

  for (shun = GlobalShunList; shun; shun = sshun) {
    sshun = shun->sh_next;

    if (shun->sh_expire <= CurrentTime)
      shun_free(shun);
    else if ((flags & SHUN_GLOBAL && shun->sh_flags & SHUN_LOCAL) ||
	     (flags & SHUN_LASTMOD && !shun->sh_lastmod))
      continue;
    else if (flags & SHUN_EXACT) {
      if (((shun->sh_host && host && ircd_strcmp(shun->sh_host,host) == 0)
	 ||(!shun->sh_host && !host)) &&
	  ((!user && ircd_strcmp(shun->sh_user, "*") == 0) ||
	   ircd_strcmp(shun->sh_user, user) == 0))
	break;
    } else {
      if (((shun->sh_host && host && ircd_strcmp(shun->sh_host,host) == 0)
	 ||(!shun->sh_host && !host)) &&
	  ((!user && ircd_strcmp(shun->sh_user, "*") == 0) ||
	   match(shun->sh_user, user) == 0))
      break;
    }
  }

  if (!BadPtr(t_uh))
    MyFree(t_uh);

  return shun;
}

struct Shun *
shun_lookup(struct Client *cptr, unsigned int flags)
{
  struct Shun *shun;
  struct Shun *sshun;

  for (shun = GlobalShunList; shun; shun = sshun) {
    sshun = shun->sh_next;

    if (shun->sh_expire <= CurrentTime) {
      shun_free(shun);
      continue;
    }
    
    if ((flags & SHUN_GLOBAL && shun->sh_flags & SHUN_LOCAL) ||
	     (flags & SHUN_LASTMOD && !shun->sh_lastmod))
      continue;

    if (ShunIsRealName(shun)) {
      Debug((DEBUG_DEBUG,"realname shun: '%s' '%s'",shun->sh_user,cli_info(cptr)));

      if (match(shun->sh_user+2, cli_info(cptr)) != 0)
	continue;

      if (!ShunIsActive(shun))
        continue;

      return shun;
    }
    else {
      if (match(shun->sh_user,
          (cli_user(cptr)->realusername ? cli_user(cptr)->realusername : cli_user(cptr)->username)) != 0)
        continue;
    	 
      if (ShunIsIpMask(shun)) {
        Debug((DEBUG_DEBUG,"IP shun: %08x %08x/%i",(cli_ip(cptr)).s_addr,shun->ipnum.s_addr,shun->bits));
        if (((cli_ip(cptr)).s_addr & NETMASK(shun->bits)) != shun->ipnum.s_addr)
          continue;
      }    
      else {
        if (match(shun->sh_host,
            (cli_user(cptr)->realhost ? cli_user(cptr)->realhost : cli_user(cptr)->host)) != 0) 
          continue;
      }
    }
    if (ShunIsActive(shun))
      return shun;
  }
  /*
   * No Shuns matched
   */
  return 0;
}

void
shun_free(struct Shun *shun)
{
  assert(0 != shun);

  *shun->sh_prev_p = shun->sh_next; /* squeeze this shun out */
  if (shun->sh_next)
    shun->sh_next->sh_prev_p = shun->sh_prev_p;

  MyFree(shun->sh_user); /* free up the memory */
  if (shun->sh_host)
    MyFree(shun->sh_host);
  MyFree(shun->sh_reason);
  MyFree(shun);
}

void
shun_burst(struct Client *cptr)
{
  struct Shun *shun;
  struct Shun *sshun;

  for (shun = GlobalShunList; shun; shun = sshun) { /* all shuns */
    sshun = shun->sh_next;

    if (shun->sh_expire <= CurrentTime) /* expire any that need expiring */
      shun_free(shun);
    else if (!ShunIsLocal(shun) && shun->sh_lastmod)
      sendcmdto_one(&me, CMD_SHUN, cptr, "* %c%s%s%s %Tu %Tu :%s",
		    ShunIsRemActive(shun) ? '+' : '-', shun->sh_user,
		    shun->sh_host ? "@" : "",
		    shun->sh_host ? shun->sh_host : "", 
		    shun->sh_expire - CurrentTime, shun->sh_lastmod, 
		    shun->sh_reason);
  }

}

int
shun_resend(struct Client *cptr, struct Shun *shun)
{
  if (ShunIsLocal(shun) || !shun->sh_lastmod)
    return 0;

  sendcmdto_one(&me, CMD_SHUN, cptr, "* %c%s%s%s %Tu %Tu :%s",
		ShunIsRemActive(shun) ? '+' : '-', shun->sh_user,
		shun->sh_host ? "@" : "",
		shun->sh_host ? shun->sh_host : "",
		shun->sh_expire - CurrentTime, shun->sh_lastmod,
		shun->sh_reason);

  return 0;
}

int
shun_list(struct Client *sptr, char *userhost)
{
  struct Shun *shun;
  struct Shun *sshun;

  if (userhost) {
    if (!(shun = shun_find(userhost, SHUN_ANY))) /* no such shun */
      return send_reply(sptr, ERR_NOSUCHSHUN, userhost);

    /* send shun information along */
    send_reply(sptr, RPL_SLIST, shun->sh_user, "",
	       shun->sh_host ? shun->sh_host : "",
	       shun->sh_expire + TSoffset,
	       ShunIsLocal(shun) ? cli_name(&me) : "*",
	       ShunIsActive(shun) ? '+' : '-', shun->sh_reason);
  } else {
    for (shun = GlobalShunList; shun; shun = sshun) {
      sshun = shun->sh_next;

      if (shun->sh_expire <= CurrentTime)
	shun_free(shun);
      else
	send_reply(sptr, RPL_SLIST, shun->sh_user, 
		   shun->sh_host ? "@" : "", 
		   shun->sh_host ? shun->sh_host : "",
		   shun->sh_expire + TSoffset,
		   ShunIsLocal(shun) ? cli_name(&me) : "*",
		   ShunIsActive(shun) ? '+' : '-', shun->sh_reason);
    }
  }

  /* end of shun information */
  return send_reply(sptr, RPL_ENDOFSLIST);
}

void
shun_stats(struct Client *sptr, struct StatDesc *sd, int stat, char *param)
{
  struct Shun *shun;
  struct Shun *sshun;

  for (shun = GlobalShunList; shun; shun = sshun) {
    sshun = shun->sh_next;

    if (shun->sh_expire <= CurrentTime)
      shun_free(shun);
    else
      send_reply(sptr, RPL_STATSSHUN, 'S', shun->sh_user, 
		 shun->sh_host ? "@" : "",
		 shun->sh_host ? shun->sh_host : "",
		 shun->sh_expire + TSoffset, shun->sh_reason);
  }
}

int
shun_memory_count(size_t *sh_size)
{
  struct Shun *shun;
  unsigned int sh = 0;

  for (shun = GlobalShunList; shun; shun = shun->sh_next) {
    sh++;
    *sh_size += sizeof(struct Shun);
    *sh_size += shun->sh_user ? (strlen(shun->sh_user) + 1) : 0;
    *sh_size += shun->sh_host ? (strlen(shun->sh_host) + 1) : 0;
    *sh_size += shun->sh_reason ? (strlen(shun->sh_reason) + 1) : 0;
  }
  return sh;
}

int expire_shuns()
{
  struct Shun *shun;
  struct Shun *sshun;

  for (shun = GlobalShunList; shun; shun = sshun) { /* all shuns */
    sshun = shun->sh_next;

    if (shun->sh_expire <= CurrentTime) /* expire any that need expiring */
      shun_free(shun);
  }
  return 0;
}

