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
 *
 * m_ircops (Ported From Ultimate IRCd)
 *
 */
int m_ircops(struct Client *cptr, struct Client *sptr, int parc, char *parv[]) {
  struct Client *acptr;
  struct Client *server = 0;
  char buf[BUFSIZE];
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

    if (!server || !ircd_strrcmp(cli_name(server), ".Services"))
      return send_reply(sptr, ERR_NOSUCHSERVER, parv[1]);
  }   

  send_reply(sptr, RPL_IRCOPSHEADER, (parc > 1) ? cli_name(server) :
	     feature_str(FEAT_NETWORK));

  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr))
  {
    if (acptr->cli_user && !IsChannelService(acptr) && IsOper(acptr) &&
	ircd_strrcmp(cli_name(acptr->cli_user->server), ".Services"))
    {
      if ((parc > 1) && (ircd_strcmp(cli_name(acptr->cli_user->server), cli_name(server)) == 0))
	ircd_snprintf(0, buf, sizeof(buf), "* %s%s - Idle: %d",
			acptr->cli_name ? acptr->cli_name : "<Unknown>",
			acptr->cli_user->away ? " (AWAY)" : "",
			CurrentTime - acptr->cli_user->last);
      else
	ircd_snprintf(0, buf, sizeof(buf), "* %s%s [%s] - Idle: %d",
			acptr->cli_name ? acptr->cli_name : "<Unknown>",
			acptr->cli_user->away ? " (AWAY)" : "",
			cli_name(acptr->cli_user->server),
			CurrentTime - acptr->cli_user->last);
      send_reply(sptr, RPL_IRCOPS, buf);
      ircops++;
    }
  }

  ircd_snprintf(0, buf, sizeof(buf), "Total: %d IRCop%s connected",
		ircops, (ircops != 1) ? "s" : "");
  send_reply(sptr, RPL_ENDOFIRCOPS, buf);
  return 0;
}
