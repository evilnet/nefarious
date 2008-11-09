/*
 * IRC - Internet Relay Chat, ircd/m_exempt.c
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

#include "config.h"

#include "ircd_struct.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "ircd_struct.h"
#include "list.h"
#include "mark.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_user.h"
#include "send.h"
#include "support.h"
#include "sys.h"
#include "msg.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdlib.h>
#include <string.h>

struct dnsblexempts*    DNSBLExemptList = 0;

char* find_dnsblexempt(const char* host)
{
  struct dnsblexempts *dnsblexempts;

  for (dnsblexempts = DNSBLExemptList; dnsblexempts; dnsblexempts = dnsblexempts->next)
    if (!match(dnsblexempts->host, host))
      return dnsblexempts->host;

  return 0;
}

char* process_exempts(struct Client* sptr, char* host, time_t lseen)
{
  struct dnsblexempts *pdnsblexempts;
  int m = 0;

  for (pdnsblexempts = DNSBLExemptList; pdnsblexempts; pdnsblexempts = pdnsblexempts->next) {
    Debug((DEBUG_DEBUG, "[PROCESS][SEARCH] %s (%s)", pdnsblexempts->host, host));
    if (!match(pdnsblexempts->host, host)) {
      Debug((DEBUG_DEBUG, "[PROCESS][UPDATE] Match"));
      pdnsblexempts->lastseen = IsServer(sptr) ? lseen : CurrentTime;
      if (!IsServer(sptr)) {
        sendcmdto_serv_butone(sptr, CMD_MARK, sptr, "%C %s %s %Tu", &me, MARK_EXEMPT_UPDATE, pdnsblexempts->host,
                              pdnsblexempts->lastseen);
        m = 1;
      }
    }

    if (!IsServer(sptr)) {
      if ((m == 0) && (pdnsblexempts->lastseen+feature_int(FEAT_EXEMPT_EXPIRE) <= CurrentTime)) {
        Debug((DEBUG_DEBUG, "[PROCESS][EXPIRE] Match %C %s", &me, host));
        sendcmdto_serv_butone(&me, CMD_EXEMPT, &me, "%C -%s %Tu nm", &me, pdnsblexempts->host, pdnsblexempts->lastseen);
        *pdnsblexempts->prev = pdnsblexempts->next;

        if (pdnsblexempts->next)
          pdnsblexempts->next->prev = pdnsblexempts->prev;

        MyFree(pdnsblexempts->host);
      }

      m = 0;
    }

  }

  return 0;
}

int add_exempt(struct Client* sptr, char* host, char* netburst, time_t lseen)
{
  struct dnsblexempts *dnsblexempts;
  char *dhost;

  if ((dhost = find_dnsblexempt(host))) {
    if ((0 != ircd_strcmp(netburst, "nb")) && MyConnect(sptr))
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :DNSBL Exemption for %s already exists", sptr, host);
    return 0;
  }

  if (!IsServer(sptr) && (0 != ircd_strcmp(netburst, "nb")))
    sendto_opmask_butone(0, SNO_GLINE, "%C adding DNSBL Exemption for %s", sptr, host);

  log_write(LS_DNSBL, L_INFO, 0, "%C adding DNSBL Exemption for %s", sptr, host);

  dnsblexempts = (struct dnsblexempts *)MyMalloc(sizeof(struct dnsblexempts));

  DupString(dnsblexempts->host, host);

  if (lseen == 0)
    dnsblexempts->lastseen = CurrentTime;
  else
    dnsblexempts->lastseen = lseen;

  dnsblexempts->next = DNSBLExemptList;
  dnsblexempts->prev = &DNSBLExemptList;
  if (DNSBLExemptList)
    DNSBLExemptList->prev = &dnsblexempts->next;
  DNSBLExemptList = dnsblexempts;

  return 1;
}

int del_exempt(struct Client* sptr, char* host)
{
  struct dnsblexempts *dnsblexempts;
  char *dhost;

  if (!(dhost = find_dnsblexempt(host))) {
    if (MyConnect(sptr))
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :DNSBL Exemption for %s does not exist", sptr, host);
    return 0;
  }

  for (dnsblexempts = DNSBLExemptList; dnsblexempts; dnsblexempts = dnsblexempts->next) {
    if (!match(dnsblexempts->host, host)) {
      sendto_opmask_butone(0, SNO_GLINE, "%C removing DNSBL Exemption for %s", sptr, host);

      log_write(LS_DNSBL, L_INFO, 0, "%C Removing DNSBL Exemption for %s", sptr, host);

      *dnsblexempts->prev = dnsblexempts->next;

      if (dnsblexempts->next)
        dnsblexempts->next->prev = dnsblexempts->prev;

      MyFree(dnsblexempts->host);
      MyFree(dnsblexempts);
      return 1;
    }
  }

  return 0;
}

int mo_exempt(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char	c;
  char*	cp;

  struct dnsblexempts *dnsblexempts;

  if (!feature_bool(FEAT_DNSBL_CHECKS))
    return send_reply(sptr, ERR_DISABLED, "EXEMPT");

  if (parc < 2 || EmptyString(parv[1]) || (strlen(parv[1]) <= 4)) {
    for (dnsblexempts = DNSBLExemptList; dnsblexempts; dnsblexempts = dnsblexempts->next)
      send_reply(sptr, RPL_DNSBLEXEMPTLIST, dnsblexempts->host, dnsblexempts->lastseen);

    send_reply(sptr, RPL_ENDOFEXEMPTLIST, cli_name(sptr));
    return 0;
  }
  cp = parv[1];
  c = *cp;
  if (c == '-' || c == '+')
    cp++;
  else if (!(strchr(cp, '@') || strchr(cp, '.') || strchr(cp, '*'))) {
    return 0;
  }
  else
    c = '+';

  cp = pretty_mask(cp);

  if ((c == '-' && del_exempt(sptr, cp)) || (c != '-' && add_exempt(sptr, cp, "nm", 0)))
    sendcmdto_serv_butone(sptr, CMD_EXEMPT, sptr, "%C %c%s", sptr, c, cp);

  return 0;
}

int ms_exempt(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char	c;
  char*	cp;

  cp = parv[2];
  c = *cp;
  if (c == '-' || c == '+')
    cp++;
  else if (!(strchr(cp, '@') || strchr(cp, '.') || strchr(cp, '*'))) {
    return 0;
  }
  else
    c = '+';

  if ((c == '-' && del_exempt(sptr, cp)) || (c != '-' && add_exempt(sptr, cp, parv[4] ? parv[4] : "nm", parv[3] ?
      atoi(parv[3]) : 0)))
      sendcmdto_serv_butone(sptr, CMD_EXEMPT, sptr, "%C %s %d %s", sptr, parv[2], parv[3] ? atoi(parv[3]) : 0,
                            parv[4] ? parv[4] : "nm");

  return 0;
}
