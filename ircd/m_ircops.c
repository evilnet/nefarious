/*
 * IRC - Internet Relay Chat, ircd/m_ircops.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
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

#include "channel.h"
#include "client.h"
#include "handlers.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_defs.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "ircd_snprintf.h"
#include "list.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"
#include "s_conf.h"
#include "s_user.h"
#include "s_debug.h"

#include <string.h>
#include <ctype.h>
#include <stdlib.h>

/*
 * m_ircops - generic message handler
 *
 * parv[0]        = sender prefix
 * parv[1]        = servername
 */
int m_ircops(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Client *acptr;
  struct Client *server = 0;
  char buf[BUFSIZE] = NULL;
  int ircops = 0;

  if (!MyUser(sptr))
    return 0;

  /*
   * If user is only looking for opers on a specific server, we need 
   * to find that server.
   */
  if (parc > 1)
  {
    if (!string_has_wildcards(parv[1]))
      server = FindServer(parv[1]);
    else
      server = find_match_server(parv[1]);

    if (!server || IsService(server) ||
	!ircd_strrcmp(cli_name(server), feature_str(FEAT_SERVICES_TLD)))
      return send_reply(sptr, ERR_NOSUCHSERVER, parv[1]);
  }   

  send_reply(sptr, RPL_IRCOPSHEADER, (parc > 1) ? cli_name(server) :
	     feature_str(FEAT_NETWORK));

  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr))
  {
    if (acptr->cli_user && !IsChannelService(acptr) && IsOper(acptr) &&
	!IsService(acptr->cli_user->server) &&
	ircd_strrcmp(cli_name(acptr->cli_user->server), feature_str(FEAT_SERVICES_TLD)))
    {
      if ((parc == 2) && !ircd_strcmp(cli_name(acptr->cli_user->server), cli_name(server)))
      {
	ircd_snprintf(0, buf, sizeof(buf), "* %s%s - Idle: %d",
		      acptr->cli_name ? acptr->cli_name : "<Unknown>",
		      acptr->cli_user->away ? " (AWAY)" : "",
		      (feature_bool(FEAT_ASUKA_HIDEIDLE) &&
		       IsNoIdle(acptr)) ? 0 :
		       CurrentTime - acptr->cli_user->last);
	ircops++;
	send_reply(sptr, RPL_IRCOPS, buf);
      } else if (parc == 1) {
	ircd_snprintf(0, buf, sizeof(buf), "* %s%s [%s] - Idle: %d",
		      acptr->cli_name ? acptr->cli_name : "<Unknown>",
		      acptr->cli_user->away ? " (AWAY)" : "",
		      cli_name(acptr->cli_user->server),
		      (feature_bool(FEAT_ASUKA_HIDEIDLE) &&
		       IsNoIdle(acptr)) ? 0 :
		       CurrentTime - acptr->cli_user->last);
	ircops++;
	send_reply(sptr, RPL_IRCOPS, buf);
      }
    }
  }

  ircd_snprintf(0, buf, sizeof(buf), "Total: %d IRCop%s connected",
		ircops, (ircops != 1) ? "s" : "");
  send_reply(sptr, RPL_ENDOFIRCOPS, buf);
  return 0;
}

/*
 * ms_ircops - server message handler
 *
 * parv[0]        = sender prefix
 * parv[1]        = servername
 */
int ms_ircops(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
/**
 *  if (hunt_server_cmd(sptr, CMD_IRCOPS, cptr, 0, "%C", 1, parc, parv) !=
 *    HUNTED_ISME)
 *  return 0;
 *
 *  return m_ircops(cptr, sptr, parc, parv);
 */
  return 0;
}
