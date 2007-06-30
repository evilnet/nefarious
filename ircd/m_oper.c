/*
 * IRC - Internet Relay Chat, ircd/m_oper.c
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

#include "channel.h"
#include "client.h"
#include "handlers.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "ircd_xopen.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "querycmds.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_serv.h"
#include "s_user.h"
#include "send.h"
#include "support.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

int oper_password_match(const char* to_match, const char* passwd)
{
  /*
   * use first two chars of the password they send in as salt
   *
   * passwd may be NULL. Head it off at the pass...
   */
  if (!to_match || !passwd)
    return 0;

  if (feature_bool(FEAT_CRYPT_OPER_PASSWORD))
    to_match = ircd_crypt(to_match, passwd);

  return (0 == strcmp(to_match, passwd));
}

int can_oper(struct Client *sptr, char *name, char *password, struct ConfItem **_aconf) {
  struct ConfItem *aconf;

  aconf = find_conf_exact(name, cli_username(sptr),
			  MyUser(sptr) ? cli_sockhost(sptr) :
			  cli_user(sptr)->realhost, CONF_OPS);
  if (!aconf)
    aconf = find_conf_exact(name, cli_username(sptr),
                            ircd_ntoa((const char*) &(cli_ip(sptr))), CONF_OPS);

  if (!aconf)
    aconf = find_conf_cidr(name, cli_username(sptr), 
                            cli_ip(sptr), CONF_OPS);

  if (!aconf || IsIllegal(aconf))
    return ERR_NOOPERHOST;
   assert(0 != (aconf->status & CONF_OPS));

  if (oper_password_match(password, aconf->passwd)) {
    int attach_result = attach_conf(sptr, aconf);
    if ((ACR_OK != attach_result) && (ACR_ALREADY_AUTHORIZED != attach_result)) {
      return ERR_NOOPERHOST;
    } 
  } else {
    *_aconf = aconf;
    return ERR_PASSWDMISMATCH;
  }
   *_aconf = aconf;
   return 0;
}

/*
 * m_oper - generic message handler
 */
int m_oper(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct ConfItem* aconf;
  char*            name;
  char*            password;
  char             chan[CHANNELLEN-1];
  char*            join[2];
  struct Flags old_mode = cli_flags(sptr);

  assert(0 != cptr);
  assert(cptr == sptr);

  if (parc > 3) { /* This is a remote OPER Request */
    struct Client *srv;
    if (!string_has_wildcards(parv[1]))
      srv = FindServer(parv[1]);
    else
      srv = find_match_server(parv[1]);

    if (!srv)
      return send_reply(sptr, ERR_NOOPERHOST);

    if (IsMe(srv)) {
      parv[1] = parv[2];
      parv[2] = parv[3];
    } else {
      sendcmdto_one(sptr, CMD_OPER, srv, "%C %s %s", srv, parv[2], parv[3]);
      return 0;
    }
  }

  name     = parc > 1 ? parv[1] : 0;
  password = parc > 2 ? parv[2] : 0;

  if (EmptyString(name) || EmptyString(password))
    return need_more_params(sptr, "OPER");

    switch (can_oper(sptr, name, password, &aconf)) {
    case ERR_NOOPERHOST:
     sendto_opmask_butone(0, SNO_OLDREALOP, "Failed OPER attempt by %s (%s@%s) (No O:line)",
			 parv[0], cli_user(sptr)->realusername, cli_sockhost(sptr));
     send_reply(sptr, ERR_NOOPERHOST);
     return 0;
     break;
    case ERR_PASSWDMISMATCH:
     sendto_opmask_butone(0, SNO_OLDREALOP, "Failed OPER attempt by %s (%s@%s) (Password Incorrect)",
			 parv[0], cli_user(sptr)->realusername, cli_sockhost(sptr));
     send_reply(sptr, ERR_PASSWDMISMATCH);
     return 0;
     break;
    }
 
    if (CONF_LOCOP == aconf->status) {
      ClearOper(sptr);
      SetLocOp(sptr);
    }
    else {
      /*
       * prevent someone from being both oper and local oper
       */
      ClearLocOp(sptr);
      if (!feature_bool(FEAT_OPERFLAGS) || !(aconf->port & OFLAG_ADMIN)) {
	/* Global Oper */
	SetOper(sptr);
	ClearAdmin(sptr);
      } else {
	/* Admin */
	SetOper(sptr);
	OSetGlobal(sptr);
	SetAdmin(sptr);
      }
      ++UserStats.opers;
    }
    cli_handler(cptr) = OPER_HANDLER;

    SetFlag(sptr, FLAG_WALLOP);
    SetFlag(sptr, FLAG_SERVNOTICE);
    SetFlag(sptr, FLAG_DEBUG);

    if (!IsAdmin(sptr))
      cli_oflags(sptr) = aconf->port;

    set_snomask(sptr, SNO_OPERDEFAULT, SNO_ADD); 
    client_set_privs(sptr);
    cli_max_sendq(sptr) = 0; /* Get the sendq from the oper's class */
    send_umode_out(cptr, sptr, &old_mode, HasPriv(sptr, PRIV_PROPAGATE));
    send_reply(sptr, RPL_YOUREOPER);

    if (IsAdmin(sptr)) {
      sendto_opmask_butone(&me, SNO_OLDSNO, "%s (%s@%s) is now an IRC Administrator",
                           parv[0], cli_user(sptr)->username, cli_sockhost(sptr));

      /* Autojoin admins to admin channel and oper channel (if enabled) */
      if (feature_bool(FEAT_AUTOJOIN_ADMIN)) {
        if (feature_bool(FEAT_AUTOJOIN_ADMIN_NOTICE))
              sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :%s", sptr, feature_str(FEAT_AUTOJOIN_ADMIN_NOTICE_VALUE));

        ircd_strncpy(chan, feature_str(FEAT_AUTOJOIN_ADMIN_CHANNEL), CHANNELLEN-1);
        join[0] = cli_name(sptr);
        join[1] = chan;
        m_join(sptr, sptr, 2, join);
      }
      if (feature_bool(FEAT_AUTOJOIN_OPER) && IsOper(sptr)) {
        if (feature_bool(FEAT_AUTOJOIN_OPER_NOTICE))
              sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :%s", sptr, feature_str(FEAT_AUTOJOIN_OPER_NOTICE_VALUE));

        ircd_strncpy(chan, feature_str(FEAT_AUTOJOIN_OPER_CHANNEL), CHANNELLEN-1);
        join[0] = cli_name(sptr);
        join[1] = chan;
        m_join(sptr, sptr, 2, join);
      }
    } else {
      sendto_opmask_butone(&me, SNO_OLDSNO, "%s (%s@%s) is now an IRC Operator (%c)",
                           parv[0], cli_user(sptr)->username, cli_sockhost(sptr),
                           IsOper(sptr) ? 'O' : 'o'); 

      if (feature_bool(FEAT_AUTOJOIN_OPER) && IsOper(sptr)) {
        if (feature_bool(FEAT_AUTOJOIN_OPER_NOTICE))
              sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :%s", sptr, feature_str(FEAT_AUTOJOIN_OPER_NOTICE_VALUE));

        ircd_strncpy(chan, feature_str(FEAT_AUTOJOIN_OPER_CHANNEL), CHANNELLEN-1);
        join[0] = cli_name(sptr);
        join[1] = chan;
        m_join(sptr, sptr, 2, join);
      }
    }

    if (feature_bool(FEAT_OPERMOTD))
      m_opermotd(sptr, sptr, 1, parv);

    log_write(LS_OPER, L_INFO, 0, "OPER (%s) by (%#C)", name, sptr);
  return 0;
}

/*
 * ms_oper - server message handler
 */
int ms_oper(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char             chan[CHANNELLEN-1];
  char*            join[2];

  struct ConfItem *aconf;
  assert(0 != cptr);
  assert(IsServer(cptr));
  /*
   * if message arrived from server, trust it, and set to oper
   */
#if 0
  if (!IsServer(sptr) && !IsOper(sptr)) {
    ++UserStats.opers;
    SetFlag(sptr, FLAG_OPER);
    sendcmdto_serv_butone(sptr, CMD_MODE, cptr, "%s :+o", parv[0]);
  } else 
#endif
  if (IsServer(cptr)) {
    struct Client *acptr;
    if (parc < 4) {
      return send_reply(sptr, ERR_NOOPERHOST);
    }
    if (!(acptr = FindNServer(parv[1]))) {
      return send_reply(sptr, ERR_NOOPERHOST);
    } else if (!IsMe(acptr)) {
      sendcmdto_one(sptr, CMD_OPER, acptr, "%C %s %s", acptr, parv[2],
		    parv[3]);
      return 0;
    }
    if (!feature_bool(FEAT_REMOTE_OPER))
      return send_reply(sptr, ERR_NOOPERHOST);

    /* Check login */
    switch (can_oper(sptr, parv[2], parv[3], &aconf)) {
	case ERR_NOOPERHOST:
	 sendwallto_group_butone(&me, WALL_DESYNCH, NULL, 
		"Failed OPER attempt by %s (%s@%s) (No O:line)", 
		parv[0], cli_user(sptr)->realusername,
		cli_user(sptr)->realhost);
	 send_reply(sptr, ERR_NOOPERHOST);
	 return 0;
	 break;
	case ERR_PASSWDMISMATCH:
	 sendwallto_group_butone(&me, WALL_DESYNCH, NULL,
		"Failed OPER attempt by %s (%s@%s) (Password Incorrect)",
		parv[0], cli_user(sptr)->realusername,
		cli_user(sptr)->realhost);
	 send_reply(sptr, ERR_PASSWDMISMATCH);
	 return 0;
	 break;
	case 0: /* Authentication successful */
	 if (aconf->status == CONF_LOCOP) {
	   send_reply(sptr, ERR_NOOPERHOST);
	   sendwallto_group_butone(&me, WALL_DESYNCH, NULL,
		  "Failed OPER attempt by %s (%s@%s) (Local Oper)",
		  parv[0], cli_user(sptr)->realusername,
		  cli_user(sptr)->realhost);
	   return 0;
	 }

	 /* This must be called before client_set_privs() */
	 SetRemoteOper(sptr);

	 /* Tell client_set_privs to send privileges to the user */
	 client_set_privs(sptr);

	 if (!feature_bool(FEAT_OPERFLAGS) || !(aconf->port & OFLAG_ADMIN))
	   ClearAdmin(sptr);
	 else {
	   OSetGlobal(sptr);
	   SetAdmin(sptr);
	 }
	 sendcmdto_one(&me, CMD_MODE, sptr, "%s %s", cli_name(sptr),
		       (IsAdmin(sptr)) ? "+aoiwsg" : "+oiwsg");
	 send_reply(sptr, RPL_YOUREOPER);

         if (IsAdmin(sptr)) {
           sendwallto_group_butone(&me, WALL_DESYNCH, NULL,
                                   "%s (%s@%s) is now an IRC Administrator",
                                   parv[0], cli_user(sptr)->username, cli_sockhost(sptr));

           /* Autojoin admins to admin channel and oper channel (if enabled) */
           if (feature_bool(FEAT_AUTOJOIN_OPER) && IsOper(sptr)) {
             if (feature_bool(FEAT_AUTOJOIN_OPER_NOTICE))
               sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :%s", sptr, feature_str(FEAT_AUTOJOIN_OPER_NOTICE_VALUE));

             ircd_strncpy(chan, feature_str(FEAT_AUTOJOIN_OPER_CHANNEL), CHANNELLEN-1);
             join[0] = cli_name(sptr);
             join[1] = chan;
             m_join(sptr, sptr, 2, join);
           }
           if (feature_bool(FEAT_AUTOJOIN_OPER) && IsOper(sptr)) {
             if (feature_bool(FEAT_AUTOJOIN_OPER_NOTICE))
               sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :%s", sptr, feature_str(FEAT_AUTOJOIN_OPER_NOTICE_VALUE));

             ircd_strncpy(chan, feature_str(FEAT_AUTOJOIN_OPER_CHANNEL), CHANNELLEN-1);
             join[0] = cli_name(sptr);
             join[1] = chan;
             m_join(sptr, sptr, 2, join);
           }
         } else {
            sendwallto_group_butone(&me, WALL_DESYNCH, NULL,
                                    "%s (%s@%s) is now an IRC Operator (O)",
                                    parv[0], cli_user(sptr)->username, cli_sockhost(sptr));

           if (feature_bool(FEAT_AUTOJOIN_OPER) && IsOper(sptr)) {
             if (feature_bool(FEAT_AUTOJOIN_OPER_NOTICE))
               sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :%s", sptr, feature_str(FEAT_AUTOJOIN_OPER_NOTICE_VALUE));

             ircd_strncpy(chan, feature_str(FEAT_AUTOJOIN_OPER_CHANNEL), CHANNELLEN-1);
             join[0] = cli_name(sptr);
             join[1] = chan;
             m_join(sptr, sptr, 2, join);
           }
         }

	 if (feature_bool(FEAT_OPERMOTD))
	   m_opermotd(sptr, sptr, 1, parv);
	 return 0;
	 break;
	default:
	 return 0; /* This should never happen */
	 break;
    }
  }
  return 0;
}

/*
 * mo_oper - oper message handler
 */
int mo_oper(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  assert(0 != cptr);
  assert(cptr == sptr);
  send_reply(sptr, RPL_YOUREOPER);
  return 0;
}
