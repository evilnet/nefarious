/*
 * IRC - Internet Relay Chat, ircd/m_zline.c
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
#include "zline.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "send.h"
#include "support.h"

#include <stdlib.h>
#include <string.h>

/*
 * ms_zline - server message handler
 *
 * parv[0] = Sender prefix
 * parv[1] = Target: server numeric
 * parv[2] = (+|-)<G-line mask>
 * parv[3] = G-line lifetime
 *
 * From Uworld:
 *
 * parv[4] = Comment
 *
 * From somewhere else:
 *
 * parv[4] = Last modification time
 * parv[5] = Comment
 *
 */
int
ms_zline(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Client *acptr = 0;
  struct Zline *azline;
  unsigned int flags = 0;
  time_t expire_off, lastmod = 0;
  char *mask = parv[2], *target = parv[1], *reason = "No reason";

  if (*mask == '!') {
    mask++;

    flags |= ZLINE_OPERFORCE; /* assume oper had WIDE_ZLINE */
  }

  if ((parc == 3 && *mask == '-') || parc == 5) {
    if (!find_conf_byhost(cli_confs(cptr), cli_name(sptr), CONF_UWORLD))
      return need_more_params(sptr, "ZLINE");

    if (parc > 4)
      reason = parv[4];
    flags |= ZLINE_FORCE;
  } else if (parc > 5) {
    lastmod = atoi(parv[4]);
    reason = parv[5];
  } else
    return need_more_params(sptr, "ZLINE");

  if (IsServer(sptr))
    flags |= ZLINE_FORCE;

  if (!(target[0] == '*' && target[1] == '\0')) {
    if (!(acptr = FindNServer(target)))
      return 0; /* no such server */

    if (!IsMe(acptr)) { /* manually propagate */
      if (!lastmod)
	sendcmdto_one(sptr, CMD_ZLINE, acptr,
		      (parc == 3) ? "%C %s" : "%C %s %s :%s", acptr, mask,
		      parv[3], reason);
      else
	sendcmdto_one(sptr, CMD_ZLINE, acptr, "%C %s%s %s %s :%s", acptr,
		      flags & ZLINE_OPERFORCE ? "!" : "", mask, parv[3],
		      parv[4], reason);

      return 0;
    }

    flags |= ZLINE_LOCAL;
  }

  if (feature_bool(FEAT_LASTMOD_TWEAK) && !lastmod) /* must have a lastmod parameter by now */
    lastmod = CurrentTime;

  if (*mask == '-')
    mask++;
  else if (*mask == '+') {
    flags |= ZLINE_ACTIVE;
    mask++;
  } else
    flags |= ZLINE_ACTIVE;

  expire_off = parc < 5 ? 0 : atoi(parv[3]);

  azline = zline_find(mask, ZLINE_ANY | ZLINE_EXACT);

  if (azline) {
    if (ZlineIsLocal(azline) && !(flags & ZLINE_LOCAL)) /* global over local */
      zline_free(azline);
    else if (!lastmod && ((flags & ZLINE_ACTIVE) == ZlineIsRemActive(azline)))
      return zline_propagate(cptr, sptr, azline);
    else if (!lastmod || ZlineLastMod(azline) < lastmod) { /* new mod */
      if (flags & ZLINE_ACTIVE)
	return zline_activate(cptr, sptr, azline, lastmod, flags);
      else
	return zline_deactivate(cptr, sptr, azline, lastmod, flags);
    } else if (ZlineLastMod(azline) == lastmod || IsBurstOrBurstAck(cptr))
      return 0;
    else
      return zline_resend(cptr, azline); /* other server desynched WRT zline */
  } else if (parc == 3 && !(flags & ZLINE_ACTIVE)) {
    /* U-lined server removing a G-line we don't have; propagate the removal
     * anyway.
     */
    if (!(flags & ZLINE_LOCAL))
      sendcmdto_serv_butone(sptr, CMD_ZLINE, cptr, "* -%s", mask);
    return 0;
  } else if (parc < 5)
    return need_more_params(sptr, "ZLINE");

  return zline_add(cptr, sptr, mask, reason, expire_off, lastmod, flags);
}

/*
 * mo_zline - oper message handler
 *
 * parv[0] = Sender prefix
 * parv[1] = [[+|-]<G-line mask>]
 *
 * Local (to me) style:
 *
 * parv[2] = [Expiration offset]
 * parv[3] = [Comment]
 *
 * Global (or remote local) style:
 *
 * parv[2] = [target]
 * parv[3] = [Expiration offset]
 * parv[4] = [Comment]
 *
 */
int
mo_zline(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Client *acptr = 0;
  struct Zline *azline;
  unsigned int flags = 0;
  time_t expire_off;
  char *mask = parv[1], *target = 0, *reason;

  if (parc < 2)
    return zline_list(sptr, 0);

  if (*mask == '!') {
    mask++;

    if (HasPriv(sptr, PRIV_WIDE_ZLINE))
      flags |= ZLINE_OPERFORCE;
  }

  if (*mask == '+') {
    flags |= ZLINE_ACTIVE;
    mask++;

  } else if (*mask == '-')
    mask++;
  else
    return zline_list(sptr, mask);

  if (parc == 4) {
    if (is_timestamp(parv[2])) {
      expire_off = atoi(parv[2]);
    } else {
      expire_off = ParseInterval(parv[2]);
    }
    reason = parv[3];
    flags |= ZLINE_LOCAL;
  } else if (parc > 4) {
    target = parv[2];
    if (is_timestamp(parv[3])) {
      expire_off = atoi(parv[3]);
    } else {
      expire_off = ParseInterval(parv[3]);
    }
    reason = parv[4];
  } else
    return need_more_params(sptr, "ZLINE");

  if (target) {
    if (!(target[0] == '*' && target[1] == '\0')) {
      if (!(acptr = find_match_server(target)))
	return send_reply(sptr, ERR_NOSUCHSERVER, target);

      if (!IsMe(acptr)) { /* manually propagate, since we don't set it */
	if (!feature_bool(FEAT_CONFIG_OPERCMDS))
	  return send_reply(sptr, ERR_DISABLED, "ZLINE");

	if (!HasPriv(sptr, PRIV_ZLINE))
	  return send_reply(sptr, ERR_NOPRIVILEGES);

	sendcmdto_one(sptr, CMD_ZLINE, acptr, "%C %s%c%s %s %Tu :%s", acptr,
		      flags & ZLINE_OPERFORCE ? "!" : "",
		      flags & ZLINE_ACTIVE ? '+' : '-', mask, parv[3],
		      TStime(), reason);
	return 0;
      }

      flags |= ZLINE_LOCAL;
    }
  }

  if (!(flags & ZLINE_LOCAL) && !feature_bool(FEAT_CONFIG_OPERCMDS))
    return send_reply(sptr, ERR_DISABLED, "ZLINE");

  if (!HasPriv(sptr, (flags & ZLINE_LOCAL ? PRIV_LOCAL_ZLINE : PRIV_ZLINE)))
    return send_reply(sptr, ERR_NOPRIVILEGES);

  azline = zline_find(mask, ZLINE_ANY | ZLINE_EXACT);

  if (azline) {
    if (ZlineIsLocal(azline) && !(flags & ZLINE_LOCAL)) /* global over local */
      zline_free(azline);
    else {
      if (!ZlineLastMod(azline)) /* force mods to Uworld-set G-lines local */
	flags |= ZLINE_LOCAL;

      if (flags & ZLINE_ACTIVE)
	return zline_activate(cptr, sptr, azline,
			      ZlineLastMod(azline) ? TStime() : 0, flags);
      else
	return zline_deactivate(cptr, sptr, azline,
				ZlineLastMod(azline) ? TStime() : 0, flags);
    }
  }

  return zline_add(cptr, sptr, mask, reason, expire_off, TStime(), flags);
}

/*
 * m_zline - user message handler
 *
 * parv[0] = Sender prefix
 * parv[1] = [<server name>]
 *
 */
int
m_zline(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  if (parc < 2)
    return send_reply(sptr, ERR_NOSUCHZLINE, "");

  if (feature_bool(FEAT_HIS_USERZLINE))
    return send_reply(sptr, ERR_DISABLED, "ZLINE");

  return zline_list(sptr, parv[1]);
}
