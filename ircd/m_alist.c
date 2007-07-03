/*
 * IRC - Internet Relay Chat, ircd/m_alist.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 * Copyright (C) 2007 Neil Spierling <sirvulcan@sirvulcan.co.nz>
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

#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_bsd.h"
#include "s_debug.h"
#include "send.h"
#include "support.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>


/*      
 * m_alist - generic message handler
 *
 * parv[0] = sender prefix
 * parv[1] = timestamp
 * parv[2] = limit
 */
int m_alist(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel *chptr;
  char modebuf[MODEBUFLEN];
  char parabuf[MODEBUFLEN];
  char modestuff[MODEBUFLEN + TOPICLEN + 5];
  time_t btime, itime;
  int limit, l = 0;

  if (parc < 2)
    return need_more_params(sptr, "ALIST");

  
  if (is_timestamp(parv[1])) {
      btime = atoi(parv[1]);
  } else {
     itime = ParseInterval(parv[1]);
     btime = CurrentTime - itime;
  }

  if (parc > 2) {
     if (IsDigit(*parv[2])) {
       limit = atoi(parv[2]);
       Debug((DEBUG_DEBUG, "Limit: %i Max: %i", limit, feature_int(FEAT_DEF_ALIST_LIMIT)));
       if (limit > feature_int(FEAT_DEF_ALIST_LIMIT))
         limit = feature_int(FEAT_DEF_ALIST_LIMIT);
     } else
       limit = feature_int(FEAT_DEF_ALIST_LIMIT);
  } else
    limit = feature_int(FEAT_DEF_ALIST_LIMIT);


  send_reply(sptr, RPL_LISTSTART);
  for (chptr = GlobalChannelList; chptr; chptr = chptr->next) {
    l++;
    if (chptr->last_message > btime) {
      if (ShowChannel(sptr, chptr)) { 
        modebuf[0] = parabuf[0] = modestuff[0] = 0;
        if (!(chptr->mode.mode & MODE_NOLISTMODES) || (IsOper(sptr))) {
          channel_modes(sptr, modebuf, parabuf, sizeof(modebuf), chptr);
          if (modebuf[1] != '\0') {
            strcat(modestuff, "[");
            strcat(modestuff, modebuf);
            if (parabuf[0]) {
              strcat(modestuff, " ");
              strcat(modestuff, parabuf);
            }
            strcat(modestuff, "] ");
          }
        }
        strcat(modestuff, chptr->topic);
        send_reply(cptr, RPL_LIST, chptr->chname, chptr->users, modestuff);
      }
    }
    if (limit == l)
      break;
  }
  send_reply(sptr, RPL_LISTEND);
  return 0;
}


/*      
 * ms_alist - generic message handler
 *
 * parv[0] = sender prefix
 * parv[1] = channel
 * parv[2] = timestamp
 */
int ms_alist(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel *chptr = 0;

  if (!IsChannelName(parv[1]) || !(chptr = FindChannel(parv[1])))
    return 0;

  chptr->last_message = atoi(parv[2]);

  sendcmdto_serv_butone(sptr, CMD_ALIST, cptr, "%s %s", parv[1], parv[2]);
  return 0;
}
