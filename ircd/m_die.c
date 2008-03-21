/*
 * IRC - Internet Relay Chat, ircd/m_die.c
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
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "opercmds.h"
#include "s_bsd.h"
#include "s_user.h"
#include "send.h"

/*
 * mo_die - oper message handler
 */
int mo_die(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  int i;
  time_t when = 0;
  const char *reason = 0;
  char* password;
  char *diepass = (char *)feature_str(FEAT_DIEPASS);

  if (!HasPriv(sptr, PRIV_DIE))
    return send_reply(sptr, ERR_NOPRIVILEGES);

  if (!EmptyString(diepass)) {
    password = parc > 1 ? parv[1] : 0;
    if (!oper_password_match(password, diepass))
      return send_reply(sptr, ERR_PASSWDMISMATCH);
  }

  if (!EmptyString(diepass)) {
    if (parc > 2 && !ircd_strcmp(parv[2], "cancel")) {
      exit_cancel(sptr); /* cancel a pending exit */
      return 0;
    } else if (parc > 3) { /* have both time and reason */
      when = atoi(parv[2]);
      reason = parv[parc - 1];
    } else if (parc > 2 && !(when = atoi(parv[2])))
      reason = parv[parc - 1];
  } else {
    if (parc > 1 && !ircd_strcmp(parv[1], "cancel")) {
      exit_cancel(sptr); /* cancel a pending exit */
      return 0;
    } else if (parc > 2) { /* have both time and reason */
      when = atoi(parv[1]);
      reason = parv[parc - 1];
    } else if (parc > 1 && !(when = atoi(parv[1])))
      reason = parv[parc - 1];
  }

  /* now, let's schedule the exit */
  exit_schedule(0, when, sptr, reason);

  return 0;
}


/** Handle a DIE message from a server connection.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the target server, or "*" for all.
 * \li \a parv[2] is either "cancel" or a time interval in seconds
 * \li \a parv[\a parc - 1] is the reason
 *
 * All fields must be present.  Additionally, the time interval should
 * not be 0 for messages sent to "*", as that may not function
 * reliably due to buffering in the server.
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_die(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  const char *target, *when, *reason;

  if (parc < 4)
    return need_more_params(sptr, "DIE");

  target = parv[1];
  when = parv[2];
  reason = parv[parc - 1];

  /* is it a message we should pay attention to? */
  if (target[0] != '*' || target[1] != '\0') {
    if (hunt_server_cmd(sptr, CMD_DIE, cptr, 0, "%C %s :%s", 1, parc, parv)
       != HUNTED_ISME)
      return 0;
  } else /* must forward the message */
    sendcmdto_serv_butone(sptr, CMD_DIE, cptr, "* %s :%s", when, reason);

  /* OK, the message has been forwarded, but before we can act... */
  if (!feature_bool(FEAT_NETWORK_DIE))
    return 0;

  /* is it a cancellation? */
  if (!ircd_strcmp(when, "cancel"))
    exit_cancel(sptr); /* cancel a pending exit */
  else /* schedule an exit */
    exit_schedule(0, atoi(when), sptr, reason);

  return 0;
}
