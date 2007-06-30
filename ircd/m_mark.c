/*
 * IRC - Internet Relay Chat, ircd/m_mark.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 * Copyright (C) 2005 Neil Spierling <sirvulcan@sirvulcan.co.nz>
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

#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "mark.h"
#include "msg.h"
#include "numnicks.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_bsd.h"
#include "s_user.h"
#include "send.h"
#include "support.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>


int ms_mark(struct Client* cptr, struct Client* sptr, int parc,
	  char* parv[])
{

  if (!IsServer(sptr))
    return protocol_violation(sptr, "MARK from non-server %s", cli_name(sptr));

  if (!strcmp(parv[2], MARK_DNSBL)) {
    unsigned int x_flag = 0;
    struct Client* acptr;

    if(parc < 5)
        return protocol_violation(sptr, "MARK DNSBL received too few parameters (%u)", parc);;

    Debug((DEBUG_DEBUG, "Receiving DNSBL MARK"));
    if ((acptr = FindUser(parv[1]))) {
      log_write(LS_DNSBL, L_INFO, 0, "Received DNSBL Mark %s flags: %s host: %s",
                cli_name(acptr), parv[3], parv[4]);

      x_flag = dflagstr(parv[3]);

      SetDNSBL(acptr);

      if (x_flag & DFLAG_MARK)
        SetDNSBLMarked(acptr);

      if (x_flag & DFLAG_ALLOW)
        SetDNSBLAllowed(acptr);

      ircd_strncpy(cli_user(acptr)->dnsblhost, parv[4], HOSTLEN);

      sendcmdto_serv_butone(sptr, CMD_MARK, cptr, "%s %s %s %s", cli_name(acptr), MARK_DNSBL,
                            parv[3], cli_user(acptr)->dnsblhost);
    } else
      Debug((DEBUG_DEBUG, "MARK cannot find user %s", parv[1]));

    return 0;

  } else if (!strcmp(parv[2], MARK_DNSBL_DATA)) {
    struct Client* acptr;

    if(parc < 4)
        return protocol_violation(sptr, "MARK DNSBL Data received too few parameters (%u)", parc);

    Debug((DEBUG_DEBUG, "Receiving MARK DNSBL Data"));
    if ((acptr = FindUser(parv[1]))) {
      log_write(LS_DNSBL, L_INFO, 0, "Received DNSBL Mark Data %s d: %s",
                cli_name(acptr), parv[3]);

      add_dnsbl(acptr, parv[3]);

      sendcmdto_serv_butone(sptr, CMD_MARK, cptr, "%s %s %s", cli_name(acptr), MARK_DNSBL_DATA,
                            parv[3]);
    } else
      Debug((DEBUG_DEBUG, "MARK cannot find user %s", parv[1]));

    return 0;
  } else if (!strcmp(parv[2], MARK_EXEMPT_UPDATE)) {
    struct Client* acptr;

    if(parc < 4)
      return protocol_violation(sptr, "MARK Exempt Update received too few parameters (%u)", parc);

    Debug((DEBUG_DEBUG, "Receiving MARK Exempt Update"));

    if ((acptr = FindNServer(parv[1]))) {
      process_exempts(acptr, parv[3], atoi(parv[4]));

      sendcmdto_serv_butone(sptr, CMD_MARK, cptr, "%s %s %s %s", cli_name(acptr), MARK_EXEMPT_UPDATE,
                            parv[3], parv[4]);

    } else
      Debug((DEBUG_DEBUG, "MARK cannot find server %s", parv[1]));

    return 0;
  } else
    return protocol_violation(sptr, "Unknown MARK received [%s]", parv[2]);

  return 0;
}
