/*
 * IRC - Internet Relay Chat, ircd/m_rules.c
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

#include "config.h"

#include "class.h"
#include "client.h"
#include "handlers.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_conf.h"
#include "s_serv.h"
#include "s_user.h"
#include "send.h"

#include <stdlib.h>
#include <assert.h>

/*
 * m_rules - generic message handler
 *
 * parv[0] - sender prefix
 * parv[1] - servername
 *
 */
int m_rules(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  if (hunt_server_cmd(sptr, CMD_RULES, cptr, feature_int(FEAT_HIS_REMOTE),
		      "%C", 1, parc, parv) != HUNTED_ISME)
    return 0;

  return rules_send(sptr);
}

/*
 * ms_rules - server message handler
 *
 * parv[0] - sender prefix
 * parv[1] - servername
 *
 */
int ms_rules(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  if (hunt_server_cmd(sptr, CMD_RULES, cptr, 0, "%C", 1, parc, parv) !=
      HUNTED_ISME)
    return 0;

  return rules_send(sptr);
}
