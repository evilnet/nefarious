/*
 * IRC - Internet Relay Chat, ircd/m_mkpasswd.c
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

#include <crypt.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char saltChars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";


static char *make_salt(void)
{
  static char salt[3];
  salt[0] = saltChars[random() % 64];
  salt[1] = saltChars[random() % 64];
  salt[2] = '\0';
  return salt;
}

static char *make_md5_salt(void)
{
  static char salt[13];
  int i;
  salt[0] = '$';
  salt[1] = '1';
  salt[2] = '$';
  for (i=3; i<11; i++)
    salt[i] = saltChars[random() % 64];
  salt[11] = '$';
  salt[12] = '\0';
  return salt;
}

int mo_mkpasswd(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  int is_md5 = 0;

  if (parc == 3) {
    if (!strcasecmp(parv[2], "MD5")) {
      is_md5 = 1;
    } else if (!strcasecmp(parv[2], "DES")) {
      is_md5 = 0;
    } else {
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :MKPASSWD syntax error:  MKPASSWD pass [DES|MD5]", &me);
      return 0;
    }
  }

  if (parc == 1)
    send_reply(sptr, ERR_NEEDMOREPARAMS, "MKPASSWD");
  else
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C: Encryption for [%s]:  %s", &me, parv[1],
                  crypt(parv[1], is_md5 ? make_md5_salt() : make_salt()));

  return 0;
}
