/*
 * IRC - Internet Relay Chat, ircd/m_help.c
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
#include "fileio.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_debug.h"
#include "send.h"

#include <sys/stat.h>
#include <assert.h>

#define HPATH  DPATH "/help/opers"
#define UHPATH DPATH "/help/users"
#define HELPLEN 400

static void
sendhelpfile(struct Client *sptr, const char *path, const char *topic)
{
  FBFILE *file;
  char line[HELPLEN];
  char started = 0;
  int type;

  if ((file = fbopen(path, "r")) == NULL)
  {
    send_reply(sptr, ERR_HELPNOTFOUND, topic);
    return;
  }

  if (fbgets(line, sizeof(line), file) == NULL)
  {
    send_reply(sptr, ERR_HELPNOTFOUND, topic);
    return;
  }

  else if (line[0] != '#')
  {
    line[strlen(line) - 1] = '\0';
    send_reply(sptr, RPL_HELPSTART, topic);
    started = 1;
  }

  while (fbgets(line, sizeof(line), file))
  {
    line[strlen(line) - 1] = '\0';
    if(line[0] != '#')
    {
      if (!started)
      {
        type = RPL_HELPSTART;
        started = 1;
      }
      else
        type = RPL_HELPTXT;

      send_reply(sptr, RPL_HELPTXT, topic, line);
    }
  }

  fbclose(file);
  send_reply(sptr, RPL_HELPTXT, topic, "");
  send_reply(sptr, RPL_ENDOFHELP, topic);
}

dohelp(struct Client *sptr, const char *hpath, char *topic)
{
  char path[PATH_MAX + 1];
  const char *tmppath;
  const char *tmptopic;
  struct stat sb;
  int i;

  if (topic != NULL)
  {
    if (*topic == '\0')
      topic = "index";
    else
    {
      /* convert to lower case */
      for (i = 0; topic[i] != '\0'; i++)
        topic[i] = ToLower(topic[i]);
    }
  }
  else
    topic = "index"; /* list available help topics */

  if (strpbrk(topic, "/\\"))
  {
    send_reply(sptr, ERR_HELPNOTFOUND, topic);
    return;
  }

  if (strlen(hpath) + strlen(topic) + 1 > PATH_MAX)
  {
    send_reply(sptr, ERR_HELPNOTFOUND, topic);
    return;
  }

  ircd_snprintf(0, path, sizeof(path), "%s/%s", hpath, topic);

  if (stat(path, &sb) < 0)
  {
    Debug((DEBUG_DEBUG, "help file %s not found", path));
    send_reply(sptr, ERR_HELPNOTFOUND, topic);
    return;
  }

  tmptopic = strdup(topic);
  tmppath = strdup(path);
  sendhelpfile(sptr, path, topic);
}

int m_help(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  static time_t last_used = 0;

  /* HELP is always local */
  if ((last_used + feature_int(FEAT_HELP_PACE)) > CurrentTime)
  {
    send_reply(sptr, RPL_LOAD2HI);
    return;
  }

  last_used = CurrentTime;

  dohelp(sptr, UHPATH, parv[1]);
}


int mo_help(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  dohelp(sptr, HPATH, parv[1]);
}

int mo_uhelp(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  dohelp(sptr, UHPATH, parv[1]);
}
