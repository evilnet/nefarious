/*
 * IRC - Internet Relay Chat, ircd/m_svsnoop.c
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
#include "config.h"

#include "client.h"
#include "handlers.h"
#include "ircd.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "send.h"
#include "s_conf.h"
#include "s_user.h"

/*
 *  ms_svsnoop
 *
 *  parv[0] = sender prefix
 *  parv[1] = server
 *  parv[2] = +/-
 *
 *  Ported From Ultimate IRCd
 */

int ms_svsnoop(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct ConfItem *aconf;
  char           c;
  char*          cp;

  if (!IsServer(sptr) || parc < 3)
    return 0;

  if (hunt_server_cmd(sptr, CMD_SVSNOOP, cptr, 0, "%C", 1, parc, parv) != HUNTED_ISME) {
     cp = parv[2];
     c = *cp;
     if (c == '+') {
        for(aconf = GlobalConfList; aconf; aconf = aconf->next) {
            if (aconf->status & CONF_OPERATOR || aconf->status & CONF_LOCOP)
               aconf->status = CONF_ILLEGAL;
	}
      } else {
        rehash (&me, 2);
      }
  }

  sendcmdto_serv_butone(sptr, CMD_SVSNOOP, cptr, "%C %s %s", sptr, parv[2], parv[3]);
  return 0;
}
