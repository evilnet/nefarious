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
#include "config.h"
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
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "querycmds.h"
#include "send.h"
#include "s_conf.h"
#include "s_user.h"
#include "s_debug.h"
#include "userload.h"
#include "patchlevel.h"

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
  char buf[BUFSIZE];
  int locals = 0, globals = 0;

  if (!MyUser(sptr))
  return 0;


  strcpy(buf, "==========================================================================");
  send_reply(sptr, RPL_IRCOPS, buf);
  strcpy(buf, "\2Nick                            Status            Server\2");
  send_reply(sptr, RPL_IRCOPS, buf);
  strcpy(buf, "--------------------------------------------------------------------------");
  send_reply(sptr, RPL_IRCOPS, buf);
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr))
  {
        if (!IsChannelService(acptr) && IsAnOper(acptr))
        {
          if (!acptr->cli_user) continue;
          ircd_snprintf(0, buf, sizeof(buf), "\2%-30s\2  %s  %-8s  %s",
			acptr->cli_name ? acptr->cli_name : "<Desconhecido>",
			IsOper(acptr) ? "Global" : "Local",
			acptr->cli_user->away ? "(AWAY)" : "",
			cli_name(acptr->cli_user->server));
          send_reply(sptr, RPL_IRCOPS, buf);
          send_reply(sptr, RPL_IRCOPS, "-");
          if (IsOper(acptr)) globals++;
          else locals++;
        }
  }
  ircd_snprintf(0, buf, sizeof(buf), "Total: \2%d\2 IRCop%s connected - \2%d\2 Globa%s, \2%d\2 Loca%s", globals+locals,
                        (globals+locals) > 1 ? "s" : "", globals, globals > 1 ? "ls" : "l", locals, 
                         locals > 1 ? "ls" : "l");  send_reply(sptr, RPL_IRCOPS, buf);  
  strcpy(buf, "==========================================================================");
  send_reply(sptr, RPL_IRCOPS, buf);
  send_reply(sptr, RPL_ENDOFIRCOPS, buf);
  return 0;

}
