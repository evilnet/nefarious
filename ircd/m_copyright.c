/*
 * IRC - Internet Relay Chat, ircd/m_copyright.c
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

#include "client.h"
#include "handlers.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "s_serv.h"
#include "s_user.h"
#include "version.h"

/*
 * m_copyright - generic message handler
 *
 * parv[0] - sender prefix
 * parv[1] - servername
 *
 */

int m_copyright(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  const char **text = copyrighttext;

  if (hunt_server_cmd(sptr, CMD_COPYRIGHT, cptr, 1, ":%C", 1, parc, parv) !=
      HUNTED_ISME)
        return 0;

  while (text[0])
  {
    send_reply(sptr, RPL_INFO, *text);
    text++;
  }

  send_reply(sptr, RPL_INFO, "");
  send_reply(sptr, RPL_ENDOFINFO);

  return 0;
}


/*
 * ms_copyright - server message handler
 *
 * parv[0] = sender prefix
 * parv[1] = servername
 */
int ms_copyright(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  const char **text = copyrighttext;

  if (IsServer(sptr))
    return 0;

  if (hunt_server_cmd(sptr, CMD_COPYRIGHT, cptr, 1, ":%C", 1, parc, parv) !=
      HUNTED_ISME)
    return 0;

  while (text[2])
  {
    send_reply(sptr, RPL_INFO, *text++);
    text++;
  }

  send_reply(sptr, RPL_INFO, "");
  send_reply(sptr, RPL_ENDOFINFO);

  return 0;
}
