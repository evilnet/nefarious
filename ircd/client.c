/*
 * IRC - Internet Relay Chat, ircd/client.c
 * Copyright (C) 1990 Darren Reed
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
 */
/** @file
 * @brief Implementation of functions for handling local clients.
 * @version $Id$
 */

#include "config.h"

#include "client.h"
#include "class.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "list.h"
#include "msg.h"
#include "msgq.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_debug.h"
#include "send.h"
#include "ircd_struct.h"
#include "ircd_string.h"

#include <assert.h>
#include <string.h>

#define BAD_PING                ((unsigned int)-2)

char privbufp[512] = "";

/** Find the shortest non-zero ping time attached to a client.
 * If all attached ping times are zero, return the value for
 * FEAT_PINGFREQUENCY.
 * @param[in] acptr Client to find ping time for.
 * @return Ping time in seconds.
 */
int client_get_ping(const struct Client* acptr)
{
  int     ping = 0;
  struct ConfItem* aconf;
  struct SLink*    link;

  assert(cli_verify(acptr));

  for (link = cli_confs(acptr); link; link = link->next) {
    aconf = link->value.aconf;
    if (aconf->status & (CONF_CLIENT | CONF_SERVER)) {
      int tmp = get_conf_ping(aconf);
      if (0 < tmp && (ping > tmp || !ping))
        ping = tmp;
    }
  }
  if (0 == ping)
    ping = feature_int(FEAT_PINGFREQUENCY);

  Debug((DEBUG_DEBUG, "Client %s Ping %d", cli_name(acptr), ping));

  return ping;
}

/** Remove a connection from the list of connections with queued data.
 * @param[in] con Connection with no queued data.
 */
void client_drop_sendq(struct Connection* con)
{
  if (con_prev_p(con)) { /* on the queued data list... */
    if (con_next(con))
      con_prev_p(con_next(con)) = con_prev_p(con);
    *(con_prev_p(con)) = con_next(con);

    con_next(con) = 0;
    con_prev_p(con) = 0;
  }
}

/** Add a connection to the list of connections with queued data.
 * @param[in] con Connection with queued data.
 * @param[in,out] con_p Previous pointer to next connection.
 */
void client_add_sendq(struct Connection* con, struct Connection** con_p)
{
  if (!con_prev_p(con)) { /* not on the queued data list yet... */
    con_prev_p(con) = con_p;
    con_next(con) = *con_p;

    if (*con_p)
      con_prev_p(*con_p) = &(con_next(con));
    *con_p = con;
  }
}

/** Array mapping privilege values to names and vice versa. */
static struct {
  enum Priv priv;
  enum Feature feat;
  enum {
    FEATFLAG_DISABLES_PRIV,
    FEATFLAG_ENABLES_PRIV,
    FEATFLAG_ADMIN_OPERS,
    FEATFLAG_GLOBAL_OPERS,
    FEATFLAG_LOCAL_OPERS,
    FEATFLAG_ALL_OPERS
  } flag;
} feattab[] = {
  { PRIV_WHOX, FEAT_LAST_F, FEATFLAG_ALL_OPERS },
  { PRIV_DISPLAY, FEAT_LAST_F, FEATFLAG_ALL_OPERS },
  { PRIV_CHAN_LIMIT, FEAT_OPER_NO_CHAN_LIMIT, FEATFLAG_ALL_OPERS },
  { PRIV_MODE_LCHAN, FEAT_OPER_MODE_LCHAN, FEATFLAG_ALL_OPERS },
  { PRIV_LOCAL_OPMODE, FEAT_OPER_MODE_LCHAN, FEATFLAG_ALL_OPERS },
  { PRIV_WALK_LCHAN, FEAT_OPER_WALK_THROUGH_LMODES, FEATFLAG_ALL_OPERS },
  { PRIV_DEOP_LCHAN, FEAT_NO_OPER_DEOP_LCHAN, FEATFLAG_ALL_OPERS },
  { PRIV_SHOW_INVIS, FEAT_SHOW_INVISIBLE_USERS, FEATFLAG_ALL_OPERS },
  { PRIV_SHOW_ALL_INVIS, FEAT_SHOW_ALL_INVISIBLE_USERS, FEATFLAG_ALL_OPERS },
  { PRIV_UNLIMIT_QUERY, FEAT_UNLIMIT_OPER_QUERY, FEATFLAG_ALL_OPERS },

  { PRIV_KILL, FEAT_LOCAL_KILL_ONLY, FEATFLAG_DISABLES_PRIV },
  { PRIV_GLINE, FEAT_CONFIG_OPERCMDS, FEATFLAG_ENABLES_PRIV },
  { PRIV_ZLINE, FEAT_CONFIG_OPERCMDS, FEATFLAG_ENABLES_PRIV },
  { PRIV_SHUN, FEAT_CONFIG_OPERCMDS, FEATFLAG_ENABLES_PRIV },
  { PRIV_JUPE, FEAT_CONFIG_OPERCMDS, FEATFLAG_ENABLES_PRIV },
  { PRIV_OPMODE, FEAT_CONFIG_OPERCMDS, FEATFLAG_ENABLES_PRIV },
  { PRIV_BADCHAN, FEAT_CONFIG_OPERCMDS, FEATFLAG_ENABLES_PRIV },

  /* 
   * if OPERFLAGS is disabled then any priv below will be given to global
   * opers (assuming the feature for the priv is enabled)
   */
  { PRIV_RESTART, FEAT_OPER_RESTART, FEATFLAG_ADMIN_OPERS },
  { PRIV_JUPE, FEAT_OPER_JUPE, FEATFLAG_ADMIN_OPERS },
  { PRIV_DIE, FEAT_OPER_DIE, FEATFLAG_ADMIN_OPERS },
  { PRIV_SET, FEAT_OPER_SET, FEATFLAG_ADMIN_OPERS },
  { PRIV_REMOTEREHASH, FEAT_OPER_REHASH, FEATFLAG_ADMIN_OPERS },
  { PRIV_CHECK, FEAT_CHECK, FEATFLAG_ADMIN_OPERS },
  { PRIV_SEE_SECRET_CHAN, FEAT_OPER_WHOIS_SECRET, FEATFLAG_ADMIN_OPERS },
  { PRIV_LIST_CHAN, FEAT_OPER_LIST_CHAN, FEATFLAG_ADMIN_OPERS },

  { PRIV_PROPAGATE, FEAT_LAST_F, FEATFLAG_GLOBAL_OPERS },
  { PRIV_SEE_OPERS, FEAT_LAST_F, FEATFLAG_GLOBAL_OPERS },
  { PRIV_KILL, FEAT_OPER_KILL, FEATFLAG_GLOBAL_OPERS },
  { PRIV_LOCAL_KILL, FEAT_OPER_KILL, FEATFLAG_GLOBAL_OPERS },
  { PRIV_REHASH, FEAT_OPER_REHASH, FEATFLAG_GLOBAL_OPERS },
  { PRIV_GLINE, FEAT_OPER_GLINE, FEATFLAG_GLOBAL_OPERS },
  { PRIV_LOCAL_GLINE, FEAT_OPER_LGLINE, FEATFLAG_GLOBAL_OPERS },
  { PRIV_ZLINE, FEAT_OPER_ZLINE, FEATFLAG_GLOBAL_OPERS },
  { PRIV_LOCAL_ZLINE, FEAT_OPER_LZLINE, FEATFLAG_GLOBAL_OPERS },
  { PRIV_SHUN, FEAT_OPER_SHUN, FEATFLAG_GLOBAL_OPERS },
  { PRIV_LOCAL_SHUN, FEAT_OPER_LSHUN, FEATFLAG_GLOBAL_OPERS },
  { PRIV_LOCAL_JUPE, FEAT_OPER_LJUPE, FEATFLAG_GLOBAL_OPERS },
  { PRIV_OPMODE, FEAT_OPER_OPMODE, FEATFLAG_GLOBAL_OPERS },
  { PRIV_LOCAL_OPMODE, FEAT_OPER_LOPMODE, FEATFLAG_GLOBAL_OPERS },
  { PRIV_FORCE_OPMODE, FEAT_OPER_FORCE_OPMODE, FEATFLAG_GLOBAL_OPERS },
  { PRIV_FORCE_LOCAL_OPMODE, FEAT_OPER_FORCE_LOPMODE, FEATFLAG_GLOBAL_OPERS },
  { PRIV_BADCHAN, FEAT_OPER_BADCHAN, FEATFLAG_GLOBAL_OPERS },
  { PRIV_LOCAL_BADCHAN, FEAT_OPER_LBADCHAN, FEATFLAG_GLOBAL_OPERS },
  { PRIV_SEE_CHAN, FEAT_OPERS_SEE_IN_SECRET_CHANNELS, FEATFLAG_GLOBAL_OPERS },
  { PRIV_WIDE_GLINE, FEAT_OPER_WIDE_GLINE, FEATFLAG_GLOBAL_OPERS },
  { PRIV_WIDE_ZLINE, FEAT_OPER_WIDE_ZLINE, FEATFLAG_GLOBAL_OPERS },
  { PRIV_WIDE_SHUN, FEAT_OPER_WIDE_SHUN, FEATFLAG_GLOBAL_OPERS },

  { PRIV_LOCAL_KILL, FEAT_LOCOP_KILL, FEATFLAG_LOCAL_OPERS },
  { PRIV_REHASH, FEAT_LOCOP_REHASH, FEATFLAG_LOCAL_OPERS },
  { PRIV_RESTART, FEAT_LOCOP_RESTART, FEATFLAG_LOCAL_OPERS },
  { PRIV_DIE, FEAT_LOCOP_DIE, FEATFLAG_LOCAL_OPERS },
  { PRIV_LOCAL_GLINE, FEAT_LOCOP_LGLINE, FEATFLAG_LOCAL_OPERS },
  { PRIV_LOCAL_ZLINE, FEAT_LOCOP_LZLINE, FEATFLAG_LOCAL_OPERS },
  { PRIV_LOCAL_SHUN, FEAT_LOCOP_LSHUN, FEATFLAG_LOCAL_OPERS },
  { PRIV_LOCAL_JUPE, FEAT_LOCOP_LJUPE, FEATFLAG_LOCAL_OPERS },
  { PRIV_LOCAL_OPMODE, FEAT_LOCOP_LOPMODE, FEATFLAG_LOCAL_OPERS },
  { PRIV_FORCE_LOCAL_OPMODE, FEAT_LOCOP_FORCE_LOPMODE, FEATFLAG_LOCAL_OPERS },
  { PRIV_LOCAL_BADCHAN, FEAT_LOCOP_LBADCHAN, FEATFLAG_LOCAL_OPERS },
  { PRIV_SET, FEAT_LOCOP_SET, FEATFLAG_LOCAL_OPERS },
  { PRIV_SEE_CHAN, FEAT_LOCOP_SEE_IN_SECRET_CHANNELS, FEATFLAG_LOCAL_OPERS },
  { PRIV_WIDE_GLINE, FEAT_LOCOP_WIDE_GLINE, FEATFLAG_LOCAL_OPERS },
  { PRIV_WIDE_ZLINE, FEAT_LOCOP_WIDE_ZLINE, FEATFLAG_LOCAL_OPERS },
  { PRIV_WIDE_SHUN, FEAT_LOCOP_WIDE_SHUN, FEATFLAG_LOCAL_OPERS },

  { PRIV_LAST_PRIV, FEAT_LAST_F, 0 }
};

/** Array mapping privilege values to names and vice versa. */
static struct {
  char        *name;
  unsigned int priv;
} privtab[] = {
#define P(priv)		{ #priv, PRIV_ ## priv }
  P(CHAN_LIMIT),     P(MODE_LCHAN),     P(WALK_LCHAN),    P(DEOP_LCHAN),
  P(SHOW_INVIS),     P(SHOW_ALL_INVIS), P(UNLIMIT_QUERY), P(KILL),
  P(LOCAL_KILL),     P(REHASH),         P(RESTART),       P(DIE),
  P(GLINE),          P(LOCAL_GLINE),    P(JUPE),          P(LOCAL_JUPE),
  P(OPMODE),         P(LOCAL_OPMODE),   P(SET),           P(WHOX),
  P(BADCHAN),        P(LOCAL_BADCHAN),  P(SEE_CHAN),      P(PROPAGATE),
  P(DISPLAY),        P(SEE_OPERS),      P(WIDE_GLINE),    P(FORCE_OPMODE),
  P(FORCE_LOCAL_OPMODE), P(REMOTEREHASH), P(CHECK), P(SEE_SECRET_CHAN),
  P(SHUN),           P(LOCAL_SHUN),     P(WIDE_SHUN),     P(ZLINE),
  P(LOCAL_ZLINE),    P(WIDE_ZLINE),     P(LIST_CHAN),
#undef P
  { 0, 0 }
};


/** Set privileges on \a client.
 * @param[in] client Client whos privileges are being set.
 * @return Zero.
 */
void
client_set_privs(struct Client* client)
{
  struct Privs privs;
  struct Privs antiprivs;
  char privbuf[512] = "";
  int i;

  memset(&privs, 0, sizeof(struct Privs));
  memset(&antiprivs, 0, sizeof(struct Privs));

  if (!IsAnOper(client)) { /* clear privilege mask */
    memset(&(cli_privs(client)), 0, sizeof(struct Privs));
    return;
  } else if (!MyConnect(client) && !IsRemoteOper(client)) {
    memset(&(cli_privs(client)), 255, sizeof(struct Privs));
    PrivClr(&(cli_privs(client)), PRIV_SET);
    return;
  }

  /* This sequence is temporary until the .conf is carefully rewritten */

  for (i = 0; feattab[i].priv != PRIV_LAST_PRIV; i++) {
    if (feattab[i].flag == FEATFLAG_ENABLES_PRIV) {
      if (!feature_bool(feattab[i].feat))
	PrivSet(&antiprivs, feattab[i].priv);
    } else if (feattab[i].feat == FEAT_LAST_F || feature_bool(feattab[i].feat)) {
      if (feattab[i].flag == FEATFLAG_DISABLES_PRIV) {
	PrivSet(&antiprivs, feattab[i].priv);
      } else if (feattab[i].flag == FEATFLAG_ALL_OPERS) {
	if (IsAnOper(client))
	  PrivSet(&privs, feattab[i].priv);
      } else if (feattab[i].flag == FEATFLAG_GLOBAL_OPERS) {
	if (IsOper(client))
	  PrivSet(&privs, feattab[i].priv);
      } else if (feattab[i].flag == FEATFLAG_ADMIN_OPERS) {
        if (feature_bool(FEAT_OPERFLAGS)) {
          if (IsAdmin(client))
            PrivSet(&privs, feattab[i].priv);
        } else {
          if (IsOper(client))
            PrivSet(&privs, feattab[i].priv);
        }
      } else if (feattab[i].flag == FEATFLAG_LOCAL_OPERS) {
	if (IsLocOp(client))
	  PrivSet(&privs, feattab[i].priv);
      }
    }
  }
       
  /* This is the end of the gross section */

  if (PrivHas(&privs, PRIV_PROPAGATE))
    PrivSet(&privs, PRIV_DISPLAY); /* force propagating opers to display */
  else { /* if they don't propagate oper status, prevent desyncs */
    PrivSet(&antiprivs, PRIV_KILL);
    PrivSet(&antiprivs, PRIV_GLINE);
    PrivSet(&antiprivs, PRIV_SHUN);
    PrivSet(&antiprivs, PRIV_JUPE);
    PrivSet(&antiprivs, PRIV_OPMODE);
    PrivSet(&antiprivs, PRIV_BADCHAN);
  }

  for (i = 0; i <= _PRIV_IDX(PRIV_LAST_PRIV); i++)
    privs.priv_mask[i] &= ~antiprivs.priv_mask[i];

  cli_privs(client) = privs;

  /* Send privileges */
  for (i = 0; privtab[i].name; i++)
  if (HasPriv(client, privtab[i].priv)) {
	strcat(privbuf, privtab[i].name);
	strcat(privbuf, ",");
  }
  privbuf[strlen(privbuf)] = 0;
  if (IsRemoteOper(client)) {
    ClearRemoteOper(client);
    sendcmdto_one(&me, CMD_PRIVS, client, "%C %s", client, privbuf);
    /* Call client_set_privs() recursively so that privileges
       are set for a remote user rather than like any oper */
    client_set_privs(client);
  } else
    sendcmdto_serv_butone(&me, CMD_PRIVS, client, "%C %s", client, privbuf);
}

/** Report privileges of \a client to \a to.
 * @param[in] to Client requesting privilege list.
 * @param[in] client Client whos privileges should be listed.
 * @return Zero.
 */
int
client_report_privs(struct Client *to, struct Client *client)
{
  struct MsgBuf *mb;
  int found1 = 0;
  int i;

  mb = msgq_make(to, rpl_str(RPL_PRIVS), cli_name(&me), cli_name(to),
		 cli_name(client));

  for (i = 0; privtab[i].name; i++)
    if (HasPriv(client, privtab[i].priv))
      msgq_append(0, mb, "%s%s", found1++ ? " " : "", privtab[i].name);

  send_buffer(to, mb, 0); /* send response */
  msgq_clean(mb);

  return 0;
}

char *client_print_privs(struct Client *client)
{
  int i;

  privbufp[0] = '\0';
  for (i = 0; privtab[i].name; i++) {
    if (HasPriv(client, privtab[i].priv)) {
      strcat(privbufp, privtab[i].name);
      strcat(privbufp, " ");
    }
  }
  privbufp[strlen(privbufp)] = 0;

  return privbufp;
}

int client_modify_priv_by_name(struct Client *who, char *priv, int what) {
 int i = 0;
 assert(0 != priv);
 assert(0 != who);

 for (i = 0; privtab[i].name; i++)
  if (0 == ircd_strcmp(privtab[i].name, priv)) {
   if (what == PRIV_ADD)
    GrantPriv(who, privtab[i].priv);
   else if (what == PRIV_DEL) {
    RevokePriv(who, privtab[i].priv);
   }
  }
 return 0;
}
