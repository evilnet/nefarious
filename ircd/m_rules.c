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

#include "handlers.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "s_serv.h"
#include "s_user.h"
#include "support.h"

#include <fcntl.h>
#include <unistd.h>

/*
 * rules_send()
 * - Ported from Ultimate IRCd
 */
static int rules_send(struct Client* cptr) {
  int fd, nr;
  char line[100], s_rules[1024], *tmp;

  alarm(3);
  ircd_snprintf(0, s_rules, sizeof(s_rules), "%s/%s", DPATH,
		feature_str(FEAT_EPATH));
  fd = open(s_rules, O_RDONLY);
  alarm(0);

  if (fd == -1) {
    send_reply(cptr, ERR_NORULES);
    return 0;
  }

  send_reply(cptr, RPL_RULESSTART, feature_str(FEAT_NETWORK));

  dgets(-1, NULL, 0);
  while ((nr = dgets (fd, line, sizeof (line) - 1)) > 0)
    {
      line[nr] = '\0';
      if ((tmp = (char *) index (line, '\n')))
        *tmp = '\0';
      if ((tmp = (char *) index (line, '\r')))
        *tmp = '\0';
      send_reply(cptr, RPL_RULES, line);
    }
  dgets (-1, NULL, 0);
  send_reply(cptr, RPL_ENDOFRULES);
  close(fd);
  return 0;
}

/*
 * m_rules - generic message handler
 *
 * parv[0] - sender prefix
 * parv[1] - servername
 *
 */
int m_rules(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  if (!feature_bool(FEAT_RULES))
    return 0;

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
