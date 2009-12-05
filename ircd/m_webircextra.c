/*
 * IRC - Internet Relay Chat, ircd/m_webircextra.c
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
 * $Id: m_webirc.c 2720 2009-12-04 10:52:57Z jobe1986 $
 */

#include "config.h"

#include "handlers.h"
#include "client.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "match.h"
#include "numeric.h"
#include "numnicks.h"
#include "opercmds.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "send.h"
#include "IPcheck.h"

#include <arpa/inet.h>
/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * m_webircextra
 *
 * parv[0] = sender prefix
 * parv[1] = password           (W:Line pass)
 * parv[2] = type               (Extra Type)
 * parv[-1] = data              (Extra Data)
 */
int m_webircextra(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  char*         password = NULL;
  char*         key = NULL;
  char*         data = NULL;

  assert(0 != cptr);
  assert(cptr == sptr);

  if (IsServerPort(cptr))
    return exit_client(cptr, cptr, &me, "Use a different port");

  if (parc < 4)
    return need_more_params(sptr, "WEBIRCEXTRA");

  if (!IsWebIRC(cptr))
    return send_reply(cptr, ERR_NOTWEBIRC, "WEBIRCEXTRA");

  if (!EmptyString(parv[1])) {
    password = parv[1];
  }

  if (!oper_password_match(password, cli_webircpass(sptr)))
    return exit_client(cptr, cptr, &me, "WEBIRCEXTRA Password invalid for your host");

  /* assume success and continue */

  if (!EmptyString(parv[2])) {
    key = parv[2];
  }

  data = parv[parc - 1];

  if (!key)
    return 0;

  if (ircd_strcmp(key, "SSLFP") == 0) {
    if (!EmptyString(data))
      ircd_strncpy(cli_sslclifp(cptr), data, BUFSIZE);
  } else if (ircd_strcmp(key, "IDENT") == 0) {
    if (EmptyString(data))
      ClrFlag(cptr, FLAG_GOTID);
    else {
      ircd_strncpy(cli_username(cptr), data, USERLEN);
      SetGotId(cptr);
    }
  }

  return 0;
}

