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

#include "handlers.h"
#include "ircd.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "send.h"

#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char saltChars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";

static char *make_salt(void)
{
  static char salt[3];
  srandom(CurrentTime); /* may not be the BEST salt, but its close */
  salt[0] = saltChars[random() % 64];
  salt[1] = saltChars[random() % 64];
  salt[2] = '\0';
  return salt;
}

static char *make_md5_salt(void)
{
  static char salt[13];
  int i;
  srandom(CurrentTime); /* may not be the BEST salt, but its close */
  salt[0] = '$';
  salt[1] = '1';
  salt[2] = '$';
  for (i=3; i<11; i++)
    salt[i] = saltChars[random() % 64];
  salt[11] = '$';
  salt[12] = '\0';
  return salt;
}

/*
 * mo_mkpasswd - oper message handler
 *
 * parv[0]        = sender prefix
 * parv[1]        = password to encrypt
 * parv[2]        = MD5/DES (optional)
 */
int mo_mkpasswd(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  int is_md5 = 0;

  if (parc < 2)
    return need_more_params(sptr, "MKPASSWD");

  if (parc == 3) {
    if (!ircd_strcmp(parv[2], "MD5")) {
      is_md5 = 1;
    } else if (!ircd_strcmp(parv[2], "DES")) {
      is_md5 = 0;
    } else {
      sendcmdto_one(&me, CMD_NOTICE, sptr,
		    "%C :MKPASSWD syntax error: MKPASSWD <pass> [DES|MD5]",
		    sptr);
      return 0;
    }
  }

  sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Encryption for [%s]: %s",
		sptr, parv[1], crypt(parv[1], is_md5 ?
				    make_md5_salt() : make_salt()));

  return 0;
}
