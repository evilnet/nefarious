/*
 * IRC - Internet Relay Chat, ircd/m_notice.c
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
#include "ircd_chattr.h"
#include "ircd_log.h"
#include "ircd_relay.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "mark.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "send.h"
#include "ircd_features.h" /* FEAT_CTCP_VERSIONING - added by Vadtec 02/25/2008 */
#include "ircd.h" /* &me - added by Vadtec 02/26/2008 */
#include "s_bsd.h" /* HighestFd, LocalClientArray[] - added by Vadtec 02/26/2008 */
#include "s_conf.h"
#include "s_misc.h" /* CPTR_KILLED - added by Vadtec 02/26/2008 */
#include "hash.h" /* FindChannel() - added by Vadtec 02/26/2008 */

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <string.h>
#include <stdio.h> /* snprintf - added by Vadtec 02/25/2008 */
#ifdef _GNU_SOURCE
#include <strings.h> /* strncasecmp() - added by Vadtec 02/25/2008 */
#endif

#if !defined(XXX_BOGUS_TEMP_HACK)
#include "handlers.h"
#endif

/*
 * m_notice - generic message handler
 */
int m_notice(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char*           name;
  char*           server;
  int             ret = 0;
  int             i;
  int             j;
  int             fd = 0;
  int             count;
  char            *clean;
  char*           vector[MAXTARGETS];
  char*           temp; /* added by Vadtec 02/25/2008 */
  char*           parv_temp; /* added by Vadtec 02/26/2008 */
  int             found_g = 0; /* added by Vadtec 02/26/2008 */
  int             sent = 0; /* added by Vadtec 03/13/2008 */
  struct Client*  acptr; /* added by Vadtec 02/26/2008 */
  struct Channel* chptr; /* added by Vadtec 02/27/2008 */
  int             isdcc = 0;

  assert(0 != cptr);
  assert(cptr == sptr);

  ClrFlag(sptr, FLAG_TS8);

  if (parc < 2 || EmptyString(parv[1]))
    return send_reply(sptr, ERR_NORECIPIENT, MSG_NOTICE);

  if (parc < 3 || EmptyString(parv[parc - 1]))
    return send_reply(sptr, ERR_NOTEXTTOSEND);

  if (parv[1][0] == '@' && IsChannelPrefix(parv[1][1])) {
    parv[1]++;                        /* Get rid of '@' */
    return m_wallchops(cptr, sptr, parc, parv);
  }

  count = unique_name_vector(parv[1], ',', vector, MAXTARGETS);

  /* Check here to make sure that the client is ours so we dont respond to NOTICES from other server's users. - Vadtec 02/25/2008 */
  /* Also, check to make sure that the notice is actually destined for the *server* and not another user. That way we don't process
     some user saying "what version do you use" to another user via notice. - Vadtec 03/13/2008 */
  if (feature_bool(FEAT_CTCP_VERSIONING) && MyConnect(sptr) && !strcmp(parv[1], cli_name(&me))) {
    /*
     Added by Vadtec 02/25/2008.
     This is so that we can do version checking (and banning) of connecting clients.
     Rules: Only one really. CTCP VERSION is not part of the RFC and therefore clients are not required to respond to
     a request for their version.
     NOTE: If we are lucky enough to have _GNU_SOURCE, we will use it over the standard strstr because its case insensetive.
           This should help against clients that like to send lower case CTCPs from slipping through as easily with only one
           function call.
    */
    for (fd = HighestFd; fd >= 0 && !sent; --fd) { /* Added the "sent" check here so that if we have already sent the notice
                                                      we don't needlessly loop through *all* the users - Vadtec 03/13/2008 */
      if ((acptr = LocalClientArray[fd])) {
        if (!cli_user(acptr))
          continue;

        #ifdef _GNU_SOURCE
        if ((temp = strcasestr(parv[2], "\x01VERSION"))) { /* added \x01 to the string so that it will *only* respond to CTCP version
                                                              replies. Seems redundant, but we dont want the users doing
                                                              /notice <server> version (and getting away with it) - Vadtec 03/13/2008 */
          temp = strchrnul(parv[2], ' '); /* Moved this here to take advantage of strchrnul - added by Vadtec 03/13/2008 */
        #else
        if ((temp = strstr(parv[2], "\x01VERSION")) || (temp = strstr(parv[2], "\x01version"))) { /* See above comment about \x01 - Vadtec */
          temp = strchr(parv[2], ' '); /* Moved this here to take advantage of strchrnul - added by Vadtec 03/13/2008 */
          if (temp == 0)
            temp = parv[2] + strlen(parv[2]); /* This does the same thing as strchrnul - Vadtec */
        #endif
          parv_temp = parv[2];
          j = 0;
          while (j <= (temp - parv[2])) { parv_temp++; j++; }

          clean = normalizeBuffer(parv_temp);
          doCleanBuffer((char *) clean);

          ircd_strncpy(cli_version(sptr), normalizeBuffer(clean), VERSIONLEN);
          sendcmdto_serv_butone(&me, CMD_MARK, cptr, "%s %s :%s", cli_name(sptr), MARK_CVERSION, cli_version(sptr));

          if (feature_bool(FEAT_CTCP_VERSIONING_CHAN)) {
            sprintf(temp, "%s has version \002%s\002", cli_name(sptr), cli_version(sptr));
            /* Announce to channel. */
            if ((chptr = FindChannel(feature_str(FEAT_CTCP_VERSIONING_CHANNAME)))) {
              if (feature_bool(FEAT_CTCP_VERSIONING_USEMSG))
                sendcmdto_channel_butone(&me, CMD_PRIVATE, chptr, cptr, SKIP_DEAF | SKIP_BURST, '\0', "%H :%s", chptr, temp);
              else
                sendcmdto_channel_butone(&me, CMD_NOTICE, chptr, cptr, SKIP_DEAF | SKIP_BURST, '\0', "%H :%s", chptr, temp);
              sent = 1;
            }
          }

          if (feature_bool(FEAT_CTCP_VERSIONING_KILL)) {
            if ((found_g = find_kill(acptr))) {
              sendto_opmask_butone(0, found_g == -2 ? SNO_GLINE : SNO_OPERKILL,
                                   found_g == -2 ? "G-line active for %s%s" :
                                   "K-line active for %s%s",
                                   IsUnknown(sptr) ? "Unregistered Client ":"",
                                   get_client_name(sptr, SHOW_IP));
              return exit_client_msg(cptr, acptr, &me, "Banned Client: %s", cli_version(acptr));
            }
          }
          else
            return 0;
        }
      }
    }
  }

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
      if (strcmp(parv[2], "DCC")) {
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
      relay_channel_notice(sptr, name, parv[parc - 1], count);
    }
    /*
     * we have to check for the '@' at least once no matter what we do
     * handle it first so we don't have to do it twice
     */
    else if ((server = strchr(name, '@')))
      relay_directed_notice(sptr, name, server, parv[parc - 1]);
    else 
      relay_private_notice(sptr, name, parv[parc - 1]);
  }
  return 0;
}

/*
 * ms_notice - server message handler
 */
int ms_notice(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char* name;
  char* server;

  ClrFlag(sptr, FLAG_TS8);

  if (parc < 3) {
    /*
     * we can't deliver it, sending an error back is pointless
     */
    return protocol_violation(sptr,"Not enough params for NOTICE");
  }
  name = parv[1];
  /*
   * channel msg?
   */
  if (IsChannelPrefix(*name)) {
    server_relay_channel_notice(sptr, name, parv[parc - 1]);
  }
  /*
   * coming from another server, we have to check this here
   */
  else if ('$' == *name && IsOper(sptr)) {
    server_relay_masked_notice(sptr, name, parv[parc - 1]);
  }
  else if ((server = strchr(name, '@'))) {
    /*
     * XXX - can't get away with not doing everything
     * relay_directed_notice has to do
     */
    relay_directed_notice(sptr, name, server, parv[parc - 1]);
  }
  else {
    server_relay_private_notice(sptr, name, parv[parc - 1]);
  }
  return 0;
}

/*
 * mo_notice - oper message handler
 */
int mo_notice(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char*           name;
  char*           server;
  int             i;
  int             count;
  char*           vector[MAXTARGETS];
  assert(0 != cptr);
  assert(cptr == sptr);

  ClrFlag(sptr, FLAG_TS8);

  if (parc < 2 || EmptyString(parv[1]))
    return send_reply(sptr, ERR_NORECIPIENT, MSG_NOTICE);

  if (parc < 3 || EmptyString(parv[parc - 1]))
    return send_reply(sptr, ERR_NOTEXTTOSEND);

  if (parv[1][0] == '@' && IsChannelPrefix(parv[1][1])) {
    parv[1]++;                        /* Get rid of '@' */
    return m_wallchops(cptr, sptr, parc, parv);
  }

  count = unique_name_vector(parv[1], ',', vector, MAXTARGETS);

  for (i = 0; i < count; ++i) {
    name = vector[i];
    /*
     * channel msg?
     */
    if (IsChannelPrefix(*name))
      relay_channel_notice(sptr, name, parv[parc - 1], count);

    else if (*name == '$')
      relay_masked_notice(sptr, name, parv[parc - 1]);

    else if ((server = strchr(name, '@')))
      relay_directed_notice(sptr, name, server, parv[parc - 1]);

    else 
      relay_private_notice(sptr, name, parv[parc - 1]);
  }
  return 0;
}
