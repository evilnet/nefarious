/*
 * IRC - Internet Relay Chat, ircd/m_sajoin.c
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
#include "ircd_chattr.h"
#include "ircd_defs.h"
#include "ircd_features.h"
#include "ircd_relay.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "ircd_snprintf.h"
#include "ircd_alloc.h"
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


int ms_sajoin(struct Client* cptr, struct Client* sptr, int parc, char* parv[]) {
  struct Client *acptr;
  struct Channel *chptr;
  struct JoinBuf join;
  struct JoinBuf create;
  unsigned int flags = 0;
  char *name;

  if (parc < 3)
    return need_more_params(sptr, "SAJOIN");

  if(!(acptr = FindClient(parv[1])))
    return 0;

  acptr = FindUser(parv[1]);

  if (IsChannelService(acptr))
    return 0;

  if (!FindChannel(parv[2])) {
    chptr = get_channel(acptr, parv[2], CGT_CREATE);
  } else {
    chptr = get_channel(acptr, parv[2], CGT_NO_CREATE);
  }

  if (find_member_link(chptr, acptr))
    return 0;

  joinbuf_init(&join, acptr, acptr, JOINBUF_TYPE_JOIN, 0, 0);  
  joinbuf_init(&create, acptr, acptr, JOINBUF_TYPE_CREATE, 0, TStime());

  name = chptr->chname;
  clean_channelname(name);

  /* bad channel name */
  if ((!IsChannelName(name)) || (IsColor(name))) {
    return 0;
  }

  if (chptr->users == 0) {
    flags = CHFL_CHANOP;
  } else {
    flags = CHFL_DEOPPED;
  }

 if (chptr) {
    joinbuf_join(&join, chptr, flags);
 } else if (!(chptr = get_channel(acptr, name, CGT_CREATE)))
     return 0;
   else if (check_target_limit(acptr, chptr, chptr->chname, 1)) {
    sub1_from_channel(chptr); /* created it... */
     return 0;
  } else
      joinbuf_join(&create, chptr, flags);

  if (chptr->topic[0]) {
    send_reply(acptr, RPL_TOPIC, chptr->chname, chptr->topic);
    send_reply(acptr, RPL_TOPICWHOTIME, chptr->chname, chptr->topic_nick,
      chptr->topic_time);
  }

  do_names(acptr, chptr, NAMES_ALL|NAMES_EON); /* send /names list */

  joinbuf_flush(&join); /* must be first, if there's a JOIN 0 */  
  joinbuf_flush(&create);

  return 0;

}
