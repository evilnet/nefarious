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

#include "config.h"

#include "ircd_struct.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "list.h"
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

#include <assert.h>
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

int add_exempt(struct Client* sptr, char* host, char* netburst)
{
  struct dnsblexempts *dnsblexempts;
  char *dhost;

  if ((dhost = find_dnsblexempt(host))) {
    if ((0 != ircd_strcmp(netburst, "nb")) && MyConnect(sptr))
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :DNSBL Exemption %s already exists", sptr, host);

    return 0;
  }

  if (!IsServer(sptr) && (0 != ircd_strcmp(netburst, "nb")))
    sendto_opmask_butone(0, SNO_GLINE, "%C Adding DNSBL Exemption on %s", sptr, host);

  dnsblexempts = (struct dnsblexempts *)MyMalloc(sizeof(struct dnsblexempts));

  DupString(dnsblexempts->host, host);

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
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :DNSBL Exemption %s does not exist", sptr, host);

    return 0;
  }

  for (dnsblexempts = DNSBLExemptList; dnsblexempts; dnsblexempts = dnsblexempts->next) {
    if (!match(dnsblexempts->host, host)) {
      sendto_opmask_butone(0, SNO_GLINE, "%C Removing DNSBL Exemption on %s", sptr, host);

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
  char           c;
  char*          cp;

  struct dnsblexempts *dnsblexempts;

  if (!feature_bool(FEAT_DNSBL_CHECKS))
    return send_reply(sptr, ERR_DISABLED, "EXEMPT");


  if (parc < 2 || EmptyString(parv[1]) || (strlen(parv[1]) <= 4)) {
    for (dnsblexempts = DNSBLExemptList; dnsblexempts; dnsblexempts = dnsblexempts->next)
      send_reply(sptr, RPL_DNSBLEXEMPTLIST, dnsblexempts->host);

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

  if ((c == '-' && del_exempt(sptr, cp)) || (c != '-' && add_exempt(sptr, cp, "nm")))
    sendcmdto_serv_butone(sptr, CMD_EXEMPT, sptr, "%C %c%s", sptr, c, cp);

  return 0;
}

int ms_exempt(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char           c;
  char*          cp;

  cp = parv[2];
  c = *cp;
  if (c == '-' || c == '+')
    cp++;
  else if (!(strchr(cp, '@') || strchr(cp, '.') || strchr(cp, '*'))) {
    return 0;
  }
  else
    c = '+';

  if ((c == '-' && !del_exempt(sptr, cp)) || (c != '-' && !add_exempt(sptr, cp, parv[3] ? parv[3] : "nm")))
    sendcmdto_serv_butone(sptr, CMD_EXEMPT, sptr, "%C %s", sptr, parv[2]);

  return 0;
}
