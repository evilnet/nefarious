/*
 * IRC - Internet Relay Chat, ircd/m_account.c
 * Copyright (C) 2002 Kevin L. Mitchell <klmitch@mit.edu>
 *
 * See file AUTHORS in IRC package for additional names of
 * the programmers.
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

/*
 * m_functions execute protocol messages on this server:
 *
 *    cptr    is always NON-NULL, pointing to a *LOCAL* client
 *            structure (with an open socket connected!). This
 *            identifies the physical socket where the message
 *            originated (or which caused the m_function to be
 *            executed--some m_functions may call others...).
 *
 *    sptr    is the source of the message, defined by the
 *            prefix part of the message if present. If not
 *            or prefix not found, then sptr==cptr.
 *
 *            (!IsServer(cptr)) => (cptr == sptr), because
 *            prefixes are taken *only* from servers...
 *
 *            (IsServer(cptr))
 *                    (sptr == cptr) => the message didn't
 *                    have the prefix.
 *
 *                    (sptr != cptr && IsServer(sptr) means
 *                    the prefix specified servername. (?)
 *
 *                    (sptr != cptr && !IsServer(sptr) means
 *                    that message originated from a remote
 *                    user (not local).
 *
 *            combining
 *
 *            (!IsServer(sptr)) means that, sptr can safely
 *            taken as defining the target structure of the
 *            message in this server.
 *
 *    *Always* true (if 'parse' and others are working correct):
 *
 *    1)      sptr->from == cptr  (note: cptr->from == cptr)
 *
 *    2)      MyConnect(sptr) <=> sptr == cptr (e.g. sptr
 *            *cannot* be a local connection, unless it's
 *            actually cptr!). [MyConnect(x) should probably
 *            be defined as (x == x->from) --msa ]
 *
 *    parc    number of variable parameter strings (if zero,
 *            parv is allowed to be NULL)
 *
 *    parv    a NULL terminated list of parameter pointers,
 *
 *                    parv[0], sender (prefix string), if not present
 *                            this points to an empty string.
 *                    parv[1]...parv[parc-1]
 *                            pointers to additional parameters
 *                    parv[parc] == NULL, *always*
 *
 *            note:   it is guaranteed that parv[0]..parv[parc-1] are all
 *                    non-NULL pointers.
 */
#include "config.h"

#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numnicks.h"
#include "querycmds.h"
#include "s_debug.h"
#include "s_bsd.h"
#include "s_user.h"
#include "send.h"
#include "support.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

/*
 * decode the request id, as encoded in s_user.c (register_user):
 * request-id ::= <period> <fd> <period> <cookie>
 */
static struct Client *decode_auth_id(const char *id)
{
  const char *cookiestr;
  unsigned int fd, cookie;
  struct Client *cptr;

  if (id[0] != '.')
    return NULL;
  if (!(cookiestr = strchr(id + 1, '.')))
    return NULL;
  fd = atoi(id + 1);
  cookie = atoi(cookiestr + 1);
  Debug((DEBUG_DEBUG, "ACCOUNT auth id fd=%u cookie=%u", fd, cookie));

#if 1
  if (!(cptr = LocalClientArray[fd]))
    return NULL;
  Debug((DEBUG_DEBUG, "ACCOUNT auth client %s", cli_name(cptr)));
  if (!cli_loc(cptr))
    return NULL;
  Debug((DEBUG_DEBUG, "ACCOUNT auth client %s: cookie %u", cli_name(cptr), cli_loc(cptr)->cookie));
#endif

  if (!(cptr = LocalClientArray[fd]) || !cli_loc(cptr) || cli_loc(cptr)->cookie != cookie)
    return NULL;
  return cptr;
}

/*
 * ms_account - server message handler
 *
 * parv[0] = sender prefix
 * parv[1] = numeric of client to act on
 * parv[2] = account name (12 characters or less)
 * parv[3] = message sub-type
 *
 * for parv[4] == 'R' (remote auth):
 * parv[4] = account name (12 characters or less)
 * parv[5] = account TS (optional)
 *
 * for parv[4] == 'C' (auth check):
 * parv[4] = request id (transparent, uninterpreted string)
 * parv[5] = username
 * parv[parc-1] = password
 *
 * for parv[3] == 'A' (auth ok) or
 * for parv[3] == 'D' (auth denied):
 * parv[4] = request id (transparent, uninterpreted string)
 *
 * for parv[3] == 'U' (unregister)
 * no extra parms
 *
 * for parv[3] == 'M' (account renaming)
 * parv[3] = new account name
 *
 */
int ms_account(struct Client* cptr, struct Client* sptr, int parc,
	       char* parv[])
{
  struct Client *acptr;
  int hidden;
  char type;

  if (parc < 3)
    return need_more_params(sptr, "ACCOUNT");

  if (!IsServer(sptr))
    return protocol_violation(cptr, "ACCOUNT from non-server %s",
			      cli_name(sptr));

  if (parv[2][0] != 'U' && parv[2][0] != 'M') {
    if (parc < 4) {
      /* old-school message, remap it to 'R' */
      parv[4] = NULL;
      parv[3] = parv[2];
      parv[2] = "R";
      parc = 4;
    } else if (parc == 4 && atoi(parv[3])) {
      /* old-school message with timestamp, remap it to 'R' */
      parv[5] = NULL;
      parv[4] = parv[3];
      parv[3] = parv[2];
      parv[2] = "R";
      parc = 5;
    }
  }

  type = parv[2][0];

  if (type == 'U') { /* account removal */
    if (!(acptr = findNUser(parv[1])))
      return 0; /* Ignore ACCOUNT for a user that QUIT; probably crossed */

    if (!IsAccount(acptr))
      return protocol_violation(cptr, "User %s does not have an account set (ACCOUNT Removal)", cli_name(acptr));

    assert(0 != cli_user(acptr)->account[0]);

    ircd_strncpy(cli_user(acptr)->account, "", ACCOUNTLEN);

    hidden = HasHiddenHost(acptr);
    if (hidden && (feature_int(FEAT_HOST_HIDING_STYLE) == 1))
      unhide_hostmask(acptr);

    ClearAccount(acptr);
    --UserStats.authed;

    sendcmdto_serv_butone(sptr, CMD_ACCOUNT, cptr, "%C U", acptr);
    return 0;
  } else if (type == 'M') { /* account renaming */

    if (!(acptr = findNUser(parv[1])))
      return 0; /* Ignore ACCOUNT for a user that QUIT; probably crossed */

    if (!IsAccount(acptr)) {
      parv[2] = "R";
    } else {
      if (strlen(parv[3]) > ACCOUNTLEN) {
	return protocol_violation(cptr, "Received account (%s) longer than %d for %s; ignoring. (rename)",
                                  parv[3], ACCOUNTLEN, cli_name(acptr));
      }

      ircd_strncpy(cli_user(acptr)->account, parv[3], ACCOUNTLEN);

      hidden = HasHiddenHost(acptr);
      if (hidden && (feature_int(FEAT_HOST_HIDING_STYLE) == 1))
        hide_hostmask(acptr);

      sendcmdto_serv_butone(sptr, CMD_ACCOUNT, cptr, "%C M %s", acptr, parv[3]);
      return 0;
    }
  }

  /* Ended here just in case an account rename was remapped to a R */

  if (type == 'R') { /* account login */
    if (!(acptr = findNUser(parv[1])))
      return 0; /* Ignore ACCOUNT for a user that QUIT; probably crossed */

    if (IsAccount(acptr))
      return protocol_violation(cptr, "ACCOUNT for already registered user %s "
			        "(%s -> %s)", cli_name(acptr),
			        cli_user(acptr)->account, parv[3]);

    assert(0 == cli_user(acptr)->account[0]);

    if (strlen(parv[3]) > ACCOUNTLEN)
      return protocol_violation(cptr, "Received account (%s) longer than %d for %s; ignoring.",
                                parv[3], ACCOUNTLEN, cli_name(acptr));

    if (parc > 4) {
      cli_user(acptr)->acc_create = atoi(parv[4]);
      Debug((DEBUG_DEBUG, "Received timestamped account: account \"%s\", "
	     "timestamp %Tu", parv[3], cli_user(acptr)->acc_create));
    }

    Debug((DEBUG_DEBUG, "ACC TEST: hf: %s fh %s dh %s id %s dmf %s", HasFakeHost(acptr) ? "1" : "0",
                       cli_user(acptr)->fakehost, cli_user(acptr)->dnsblhost, IsDNSBLMarked(acptr) ? "1" : "0",
                       feature_bool(FEAT_DNSBL_MARK_FAKEHOST) ? "1" : "0"));

    if (HasFakeHost(acptr) && !ircd_strcmp(cli_user(acptr)->fakehost, cli_user(acptr)->dnsblhost) &&
        IsDNSBLMarked(acptr) && feature_bool(FEAT_DNSBL_MARK_FAKEHOST))
      ClearFakeHost(acptr);

    hidden = HasHiddenHost(acptr);
    SetAccount(acptr);
    ircd_strncpy(cli_user(acptr)->account, parv[3], ACCOUNTLEN);
    ++UserStats.authed;

    /* Fake hosts have precedence over account-based hidden hosts,
       so, if the user was already hidden, don't do it again */
    if (!hidden && (feature_int(FEAT_HOST_HIDING_STYLE) == 1))
       hide_hostmask(acptr);

    sendcmdto_serv_butone(sptr, CMD_ACCOUNT, cptr,
			  cli_user(acptr)->acc_create ? "%C R %s %Tu" : "%C R %s",
			  acptr, cli_user(acptr)->account,
			  cli_user(acptr)->acc_create);
  } else {
    if (type == 'C' && parc < 6)
      return need_more_params(sptr, "ACCOUNT");

    /* findNUser("AB") seems to return Sirvulcan, whois numnick is ABAAB.. 
     * This is a bug with findNUser no? 
     * so you cant do this, because acptr is the user not the server. 
     * Hopefully reversing them will be ok.
     *    if (!(acptr = findNUser(parv[1])) && !(acptr = FindNServer(parv[1])))
    */
    if(!(acptr = FindNServer(parv[1])) && !(acptr = findNUser(parv[1])))
      return 0; /* target not online, ignore */
    
    if (!IsMe(acptr)) {
      /* in-transit message, forward it */
      sendcmdto_one(sptr, CMD_ACCOUNT, acptr,
                   type == 'C' ? "%s %s %s %s :%s" : "%s %s %s",
                   parv[1], parv[2], parv[3], parv[4], parv[parc-1]);
      return 0;
    }
    
    /* the message is for &me, process it */
    if (type == 'C')
      /* auth checks are for services, not servers */
      return protocol_violation(cptr, "ACCOUNT check (%s %s %s)", parv[3], parv[4], parv[5]);
    else if (type != 'A' && type != 'D' && type != 'U' && type != 'M')
      return protocol_violation(cptr, "ACCOUNT sub-type '%s' not implemented", parv[2]);
    
    if (!(acptr = decode_auth_id(parv[3])))
      return 0; /* most probably, user disconnected */

    if (type == 'A') {
      SetAccount(acptr);
      ircd_strncpy(cli_user(acptr)->account, cli_loc(acptr)->account, ACCOUNTLEN);
      if (feature_int(FEAT_HOST_HIDING_STYLE) == 1) {
        SetHiddenHost(acptr);
        hide_hostmask(acptr);
      }
    }
    
    sendcmdto_one(&me, CMD_NOTICE, acptr, "%C :AUTHENTICATION %s as %s", acptr,
                 type == 'A' ? "SUCCESSFUL" : "FAILED",
                 cli_loc(acptr)->account);
    MyFree(cli_loc(acptr));

    if (type == 'D') {
      sendcmdto_one(&me, CMD_NOTICE, acptr, "%C :Type \002/QUOTE PASS\002 to connect anyway", acptr);
      return 0;
    }
    
    return register_user(acptr, acptr, cli_name(acptr), cli_user(acptr)->username);
  }

  return 0;
}


