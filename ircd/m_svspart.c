/*
 * IRC - Internet Relay Chat, ircd/m_sapart.c
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

#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <assert.h>

int ms_sapart(struct Client* cptr, struct Client* sptr, int parc, char* parv[]) {
  struct Client *acptr;
  struct Channel *chptr;
  struct Membership *member;
  struct JoinBuf parts;
  char *name;

  if(!(acptr = FindClient(parv[1])))
    return 0;

  acptr = FindUser(parv[1]);

  if (IsChannelService(acptr))
    return 0;

  ClrFlag(acptr, FLAG_TS8);

  /* check number of arguments */
  if (parc < 3)
    return need_more_params(sptr, "SAPART");

  /* init join/part buffer */
  joinbuf_init(&parts, acptr, acptr, JOINBUF_TYPE_PART, 0, 0);

  chptr = get_channel(acptr, parv[2], CGT_NO_CREATE); /* look up channel */ 
  name = chptr->chname;

  if (!chptr) { /* complain if there isn't such a channel */
    return 0;
  }

  if (!(member = find_member_link(chptr, acptr))) { /* complain if not on */
    return 0;
  }

  assert(!IsZombie(member)); /* Local users should never zombie */

  joinbuf_join(&parts, chptr, /* part client from channel */
  member_can_send_to_channel(member) ? 0 : CHFL_BANNED);

  return joinbuf_flush(&parts);
}
