/*
 * IRC - Internet Relay Chat, ircd/m_privmsg.c
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

#include "client.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_relay.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "send.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <string.h>
#include <stdio.h>
#ifdef _GNU_SOURCE
#include <strings.h>
#endif

/*
 * m_privmsg - generic message handler
 */
int m_privmsg(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char*           name;
  char*           server;
  int             i;
  int             count;
  int             ret = 0;
  int             isdcc = 0;
  char*           vector[MAXTARGETS];
  char*           temp;

  assert(0 != cptr);
  assert(cptr == sptr);
  assert(0 != cli_user(sptr));

  ClrFlag(sptr, FLAG_TS8);

  if (feature_bool(FEAT_IDLE_FROM_MSG))
    cli_user(sptr)->last = CurrentTime;

  if (parc < 2 || EmptyString(parv[1]))
    return send_reply(sptr, ERR_NORECIPIENT, MSG_PRIVATE);

  if (parc < 3 || EmptyString(parv[parc - 1]))
    return send_reply(sptr, ERR_NOTEXTTOSEND);

  count = unique_name_vector(parv[1], ',', vector, MAXTARGETS);

  for (i = 0; i < count; ++i) {
    name = vector[i];
    if (IsChannelPrefix(*name)) {
      ret = find_fline(cptr, sptr, parv[parc-1], WFFLAG_CHANMSG, name);
      if (ret != 0) {
        if (ret == 2)
          return CPTR_KILLED;
        else
          return 0;
      }
    } else {
      #ifdef _GNU_SOURCE
      if ((temp = strcasestr(parv[2], "\001DCC"))) {
        temp = strchrnul(parv[2], ' ');
      #else
      if ((temp = strstr(parv[2], "\001DCC")) || (temp = strstr(parv[2], "\001dcc"))) {
        temp = strchr(parv[2], ' ');
      #endif
        isdcc = 1;
        ret = find_fline(cptr, sptr, parv[parc-1], WFFLAG_DCC, name);
        if (ret != 0) {
          if (ret == 2)
            return CPTR_KILLED;
          else
            return 0;
        }
      }

      if (!isdcc) {
        ret = find_fline(cptr, sptr, parv[parc-1], WFFLAG_PRIVMSG, name);
        if (ret != 0) {
          if (ret == 2)
            return CPTR_KILLED;
          else
            return 0;
        }
      }
    }
  }
  i = 0;

  for (i = 0; i < count; ++i) {
    name = vector[i];
    /*
     * channel msg?
     */
    if (IsChannelPrefix(*name)) {
      relay_channel_message(sptr, name, parv[parc - 1], count);
    }
    /*
     * we have to check for the '@' at least once no matter what we do
     * handle it first so we don't have to do it twice
    */
    else if ((server = strchr(name, '@')))
      relay_directed_message(sptr, name, server, parv[parc - 1]);
    else 
      relay_private_message(sptr, name, parv[parc - 1]);
  }

  return 0;
}

/*
 * ms_privmsg - server message handler
 */
int ms_privmsg(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char* name;
  char* server;

  ClrFlag(sptr, FLAG_TS8);

  if (parc < 3) {
    /*
     * we can't deliver it, sending an error back is pointless
     */
    return 0;
  }
  name = parv[1];
  /*
   * channel msg?
   */
  if (IsChannelPrefix(*name)) {
    server_relay_channel_message(sptr, name, parv[parc - 1]);
  }
  /*
   * coming from another server, we have to check this here
   */
  else if ('$' == *name && IsOper(sptr)) {
    server_relay_masked_message(sptr, name, parv[parc - 1]);
  }
  else if ((server = strchr(name, '@'))) {
    /*
     * XXX - can't get away with not doing everything
     * relay_directed_message has to do
     */
    relay_directed_message(sptr, name, server, parv[parc - 1]);
  }
  else {
    server_relay_private_message(sptr, name, parv[parc - 1]);
  }
  return 0;
}


/*
 * mo_privmsg - oper message handler
 */
int mo_privmsg(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char*           name;
  char*           server;
  int             i;
  int             count;
  char*           vector[MAXTARGETS];
  assert(0 != cptr);
  assert(cptr == sptr);
  assert(0 != cli_user(sptr));

  ClrFlag(sptr, FLAG_TS8);

  if (feature_bool(FEAT_IDLE_FROM_MSG))
    cli_user(sptr)->last = CurrentTime;

  if (parc < 2 || EmptyString(parv[1]))
    return send_reply(sptr, ERR_NORECIPIENT, MSG_PRIVATE);

  if (parc < 3 || EmptyString(parv[parc - 1]))
    return send_reply(sptr, ERR_NOTEXTTOSEND);

  count = unique_name_vector(parv[1], ',', vector, MAXTARGETS);

  for (i = 0; i < count; ++i) {
    name = vector[i];
    /*
     * channel msg?
     */
    if (IsChannelPrefix(*name))
      relay_channel_message(sptr, name, parv[parc - 1], count);

    else if (*name == '$')
      relay_masked_message(sptr, name, parv[parc - 1]);

    else if ((server = strchr(name, '@')))
      relay_directed_message(sptr, name, server, parv[parc - 1]);

    else 
      relay_private_message(sptr, name, parv[parc - 1]);
  }
  return 0;
}
