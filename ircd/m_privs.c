/*
 * IRC - Internet Relay Chat, ircd/m_privs.c
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
#include "hash.h"
#include "ircd.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"
#include "msg.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */

/*
 * mo_privs - report operator privileges
 */
int mo_privs(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  char *name;
  char *p = 0;
  int i;

  if (parc < 2)
    return client_report_privs(sptr, sptr);

  for (i = 1; i < parc; i++) {
    for (name = ircd_strtok(&p, parv[i], " "); name;
	 name = ircd_strtok(&p, 0, " ")) {
      if (!(acptr = FindUser(name)))
        send_reply(sptr, ERR_NOSUCHNICK, name);
      else if (MyUser(acptr))
        client_report_privs(sptr, acptr);
      else
        sendcmdto_one(cptr, CMD_PRIVS, acptr, "%s%s", NumNick(acptr));
    }
  }

  return 0;
}


int ms_privs(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  char *numnick, *p = 0;
  char buf[512] = "";
  int i;
  int what = PRIV_ADD;
  int modified = 0;
  char *tmp;

  if (IsServer(sptr)) {
    if (parc < 3)
      return 0;

    acptr = parc > 1 ? findNUser(parv[1]) : NULL;

    for (i=1; i<parc; i++) {
      strcat(buf, parv[i]);
      strcat(buf, " ");
    }

    for (i = 2; i < parc; i++) {
      if (*parv[i] == '+') { what = PRIV_ADD; parv[i]++; }
      if (*parv[i] == '-') { what = PRIV_DEL; parv[i]++; }
      for (tmp = ircd_strtok(&p, parv[i], ","); tmp;
           tmp = ircd_strtok(&p, NULL, ",")) {
        if (!strcmp(tmp, "PRIV_NONE")) {
          memset(cli_privs(acptr), 0, sizeof(struct Privs));
          break;
        } else
          client_modify_priv_by_name(acptr, tmp, what);
        if (!modified)
          modified = 1;
      }
    }

    if (MyConnect(acptr) && modified)
      sendcmdto_one(&me, CMD_NOTICE, acptr, "%C :Your privileges were modified", acptr);

    sendcmdto_serv_butone(sptr, CMD_PRIVS, cptr, "%s", buf);
  } else {
    if (parc < 2)
      return protocol_violation(cptr, "PRIVS (from remote oper) with no arguments");

    for (i = 1; i < parc; i++) {
      for (numnick = ircd_strtok(&p, parv[i], " "); numnick;
           numnick = ircd_strtok(&p, 0, " ")) {
        if (!(acptr = findNUser(numnick)))
          continue;
        else if (MyUser(acptr))
          client_report_privs(sptr, acptr);
        else
          sendcmdto_one(sptr, CMD_PRIVS, acptr, "%s%s", NumNick(acptr));
      }
    }
  }

  return 0;
}
