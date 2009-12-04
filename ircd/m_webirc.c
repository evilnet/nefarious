/*
 * IRC - Internet Relay Chat, ircd/m_webirc.c
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

#include "handlers.h"
#include "client.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "match.h"
#include "numeric.h"
#include "numnicks.h"
#include "opercmds.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "send.h"
#include "IPcheck.h"

#include <arpa/inet.h>
/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int wline_flags[] = {
  WFLAG_MARK,       'm',
  WFLAG_SIDENT,     's',
  WFLAG_UIDENT,     'u',
  WFLAG_STRIPSSLFP, 'f'
};

char wflagstr(const char* wflags)
{
  unsigned int  *flag_p;
  unsigned int   x_flag = 0;
  const    char *flagstr;

  flagstr = wflags;

  /* This should never happen... */
  assert(flagstr != 0);

  for (; *flagstr; flagstr++) {
    for (flag_p = (unsigned int*)wline_flags; flag_p[0]; flag_p += 2) {
      if (flag_p[1] == *flagstr)
        break;
    }

    if (!flag_p[0])
      continue;

    x_flag |= flag_p[0];
  }

  return x_flag;
}


/*
 * m_webirc
 *
 * parv[0] = sender prefix
 * parv[1] = password           (W:Line pass)
 * parv[2] = "cgiirc"           (ignored)
 * parv[3] = hostname           (Real host)
 * parv[4] = ip                 (Real IP in ASCII)
 */
int m_webirc(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  char*         hostname = NULL;
  char*         ipaddr = NULL;
  char*         password = NULL;
  char          i_host[SOCKIPLEN + USERLEN + 2];
  char          s_host[HOSTLEN + USERLEN + 2];
  int           invalidauth = 1, invalidpass = 0, mark = 0;
  unsigned int  w_flag = 0;
  time_t        next_target = 0;

  struct in_addr webirc_addr;
  struct wline *wline;
 
  assert(0 != cptr);
  assert(cptr == sptr);

  if (IsServerPort(cptr))
    return exit_client(cptr, cptr, &me, "Use a different port");

  if (parc < 5)
    return need_more_params(sptr, "WEBIRC");

  if (!EmptyString(parv[1])) {
    password = parv[1];
  }

  ircd_snprintf(0, i_host, USERLEN+SOCKIPLEN+2, "%s@%s", cli_username(sptr), ircd_ntoa((const char*) &(cli_ip(sptr))));
  ircd_snprintf(0, s_host, USERLEN+HOSTLEN+2, "%s@%s", cli_username(sptr), cli_sockhost(sptr));

  for (wline = GlobalWList; wline; wline = wline->next) {
    w_flag = wflagstr(wline->flags);
    if (w_flag & WFLAG_MARK)
      mark = 1;
    else
      mark = 0;

    if ((match(wline->mask, s_host) == 0) || (match(wline->mask, i_host) == 0)) {
      invalidauth = 0;
      if (!oper_password_match(password, wline->passwd))
        invalidpass = 1;
      else
        invalidpass = 0;
    }

    if (!invalidauth && !invalidpass)
      break;
  }

  if (invalidauth)
    return exit_client(cptr, cptr, &me, "WEBIRC Not authorized from your host");

  if (invalidpass)
    return exit_client(cptr, cptr, &me, "WEBIRC Password invalid for your host");

  /* assume success and continue */

  if (mark && !EmptyString(wline->desc))
    ircd_strncpy(cli_webirc(cptr), wline->desc, BUFSIZE);

  /* 
   * Copy parameters into better documenting variables
   *
   * ignore host part if u@h
   */
  if (!EmptyString(parv[3])) {
    hostname = parv[3];
  }

  if (!EmptyString(parv[4])) {
    ipaddr = parv[4];
  }

  inet_aton(ipaddr, &webirc_addr);

  if (feature_bool(FEAT_IPCHECK) && !find_eline(cptr, EFLAG_IPCHECK)) {
    IPcheck_connect_fail(cptr);
    IPcheck_disconnect(cptr);
    ClearIPChecked(cptr);
  }

  if (IsIPCheckExempted(cptr))
    ClearIPCheckExempted(cptr);

  if (IsNotIPCheckExempted(cptr))
    ClearNotIPCheckExempted(cptr);

  cli_ip(cptr).s_addr = webirc_addr.s_addr;

  if (feature_bool(FEAT_IPCHECK) && !find_eline(cptr, EFLAG_IPCHECK)) {
    if (!IPcheck_local_connect(cli_ip(cptr), &next_target)) {
      return exit_client(cptr, sptr, &me, "Your host is trying to (re)connect too fast -- throttled");
    }

    SetIPChecked(cptr);
    if (next_target)
      cli_nexttarget(cptr) = next_target;
  }

  if (find_eline(cptr, EFLAG_IPCHECK))
    SetIPCheckExempted(cptr);

  ircd_strncpy(cli_sock_ip(cptr), ipaddr, SOCKIPLEN);
  ircd_strncpy(cli_sockhost(cptr), hostname, HOSTLEN);

  if (cli_user(sptr)) {
    if (!HasHiddenHost(sptr) && (feature_int(FEAT_HOST_HIDING_STYLE) == 1))
      ircd_strncpy(cli_user(sptr)->host, cli_sockhost(sptr), HOSTLEN);
    ircd_strncpy(cli_user(sptr)->realhost, cli_sockhost(sptr), HOSTLEN);
  }

  SetWebIRC(cptr);

  if (w_flag & WFLAG_STRIPSSLFP)
    ircd_strncpy(cli_sslclifp(cptr), "", BUFSIZE + 1);

  if (w_flag & WFLAG_UIDENT)
    SetWebIRCUserIdent(cptr);

  if (w_flag & WFLAG_SIDENT) {
    if (!EmptyString(wline->ident)) {
      ircd_strncpy(cli_username(cptr), wline->ident, USERLEN);
      SetGotId(cptr);
    }
  }

  return 0;
}

