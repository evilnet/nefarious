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
 * $Id: m_webirc.c 1969 2007-06-30 10:09:22Z sirvulcan $
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
#include "ircd_reply.h"
#include "ircd_string.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "send.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
  char*        hostname;
  char*        ipaddr;
  char*        password;

  struct in_addr webirc_addr;
  struct ConfItem *aconf;
 
  assert(0 != cptr);
  assert(cptr == sptr);

  if (IsServerPort(cptr))
    return exit_client(cptr, cptr, &me, "Use a different port");

  if (parc < 5)
    return need_more_params(sptr, "WEBIRC");

  if (!EmptyString(parv[1])) {
    password = parv[1];
  }

  /* Find W:Lines */

  aconf = find_conf_exact("*", cli_username(sptr),
                          cli_sockhost(sptr), CONF_WEBIRC);
  if (!aconf)
    aconf = find_conf_exact("*", cli_username(sptr),
                            ircd_ntoa((const char*) &(cli_ip(sptr))), CONF_WEBIRC);

  if (!aconf)
    aconf = find_conf_cidr("*", cli_username(sptr),
                            cli_ip(sptr), CONF_WEBIRC);

  if (!aconf || IsIllegal(aconf))
    return exit_client(cptr, cptr, &me, "WEBIRC Not authorized from your host");
   assert(0 != (aconf->status & CONF_WEBIRC));

  /* do validation */

  if (!oper_password_match(password, aconf->passwd)) {
    return exit_client(cptr, cptr, &me, "WEBIRC Password invalid for your host");
  }

  /* assume success and continue */

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

  cli_ip(sptr).s_addr = webirc_addr.s_addr;

  ircd_strncpy(cli_sock_ip(sptr), ipaddr, SOCKIPLEN);
  ircd_strncpy(cli_sockhost(cptr), hostname, HOSTLEN);

  SetWebIRC(cptr);

  if ( feature_bool(FEAT_WEBIRC_SPOOFIDENT) ) {
    ircd_strncpy(cli_username(cptr), (char*)feature_str(FEAT_WEBIRC_FAKEIDENT), USERLEN);
    SetGotId(cptr);
  }

  return 0;
}

