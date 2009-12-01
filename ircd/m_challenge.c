/*
 * IRC - Internet Relay Chat, ircd/m_challenge.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 * Copyright (C) 2002 by the past and present hybird-ircd coders,
 *                    and others.
 * Copyright (C) 2008 Neil Spierling <sirvulcan@sirvulcan.co.nz>
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

 /* Port of Hybrid-IRCd's Oper Challenge System */

#include "config.h"

#include "channel.h"
#include "client.h"
#include "handlers.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
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
#include "ssl.h"
#include "support.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdlib.h>
#include <string.h>

void
failed_challenge_notice(struct Client *sptr, char *name, char *reason)
{
    sendto_allops(&me, SNO_OLDREALOP, "Failed CHALLENGE attempt as %s "
                  "by %s (%s@%s) - %s", name, cli_name(sptr),
                  cli_user(sptr)->realusername, cli_user(sptr)->host, reason);
}

int m_challenge(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
#ifdef USE_SSL
  struct ConfItem *aconf;
  RSA *rsa_public_key;
  BIO *file = NULL;
  char *challenge = NULL;
  char *name;
  char *tmpname;
  char             chan[CHANNELLEN-1];
  char*            join[2];
  int nl;
  struct Flags old_mode = cli_flags(sptr);

  if (!MyUser(sptr))
    return 0;

  if (parc < 2)
    return need_more_params(sptr, "CHALLENGE");

  if (parc > 2) { /* This is a remote OPER Request */
    struct Client *srv;
    if (!string_has_wildcards(parv[1]))
      srv = FindServer(parv[1]);
    else
      srv = find_match_server(parv[1]);

    if (!feature_bool(FEAT_REMOTE_OPER))
      return send_reply(sptr, ERR_NOOPERHOST);

    if (!srv)
      return send_reply(sptr, ERR_NOOPERHOST);

    if (IsMe(srv)) {
      parv[1] = parv[2];
    } else {
      sendcmdto_one(sptr, CMD_CHALLENGE, srv, "%C %s", srv, parv[2]);
      return 0;
    }
  }

  /* if theyre an oper, reprint oper motd and ignore */
  if (IsOper(sptr))
  {
    send_reply(sptr, RPL_YOUREOPER);
    if (feature_bool(FEAT_OPERMOTD))
      m_opermotd(sptr, sptr, 1, parv);
  }

  if (*parv[1] == '+')
  {
    /* Ignore it if we aren't expecting this... -A1kmm */
    if (cli_user(sptr)->response == NULL)
      return 0;

    if (ircd_strcmp(cli_user(sptr)->response, ++parv[1]))
    {
      send_reply(sptr, ERR_PASSWDMISMATCH);
      sendto_allops(&me, SNO_OLDREALOP, "Failed OPER attempt by %s (%s@%s) (Password Incorrect)",
                         parv[0], cli_user(sptr)->realusername, cli_sockhost(sptr));
      tmpname = strdup(cli_user(sptr)->auth_oper);
      failed_challenge_notice(sptr, tmpname, "challenge failed");
      return 0;
    }

    name = strdup(cli_user(sptr)->auth_oper);
     
    aconf = find_conf_exact(cli_user(sptr)->auth_oper, cli_user(sptr)->realusername,
                            MyUser(sptr) ? cli_sockhost(sptr) :
                            cli_user(sptr)->realhost, CONF_OPS);

    if (!aconf)
      aconf = find_conf_exact(cli_user(sptr)->auth_oper, cli_user(sptr)->realusername,
                              ircd_ntoa((const char*) &(cli_ip(sptr))), CONF_OPS);

    if (!aconf)
      aconf = find_conf_cidr(cli_user(sptr)->auth_oper, cli_user(sptr)->realusername,
                              cli_ip(sptr), CONF_OPS);

    if (!aconf)
    {
      send_reply(sptr, ERR_NOOPERHOST);
      sendto_allops(&me, SNO_OLDREALOP, "Failed OPER attempt by %s (%s@%s) (No O:line)",
                         parv[0], cli_user(sptr)->realusername, cli_sockhost(sptr));
      return 0;
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

    if (!feature_bool(FEAT_OPERFLAGS) || (aconf->port & OFLAG_WHOIS)) {
      OSetWhois(sptr);
    }
    if (!feature_bool(FEAT_OPERFLAGS) || (aconf->port & OFLAG_IDLE)) {
      OSetIdle(sptr);
    }
    if (!feature_bool(FEAT_OPERFLAGS) || (aconf->port & OFLAG_XTRAOP)) {
      OSetXtraop(sptr);
    }
    if (!feature_bool(FEAT_OPERFLAGS) || (aconf->port & OFLAG_HIDECHANS)) {
      OSetHideChans(sptr);
    }

    SetFlag(sptr, FLAG_WALLOP);
    SetFlag(sptr, FLAG_SERVNOTICE);
    SetFlag(sptr, FLAG_DEBUG);

    if (!IsAdmin(sptr))
      cli_oflags(sptr) = aconf->port;

    set_snomask(sptr, SNO_OPERDEFAULT, SNO_ADD);
    client_set_privs(sptr, aconf);
    cli_max_sendq(sptr) = 0; /* Get the sendq from the oper's class */
    send_umode_out(cptr, sptr, &old_mode, HasPriv(sptr, PRIV_PROPAGATE));
    send_reply(sptr, RPL_YOUREOPER);

    if (IsAdmin(sptr)) {
      sendto_allops(&me, SNO_OLDSNO, "%s (%s@%s) is now an IRC Administrator",
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
      sendto_allops(&me, SNO_OLDSNO, "%s (%s@%s) is now an IRC Operator (%c)",
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

    ircd_snprintf(0, cli_user(sptr)->response, BUFSIZE+1, "%s", "");
    return 0;
  }

  ircd_snprintf(0, cli_user(sptr)->response, BUFSIZE+1, "%s", "");
  ircd_snprintf(0, cli_user(sptr)->auth_oper, NICKLEN+1, "%s", "");

  aconf = find_conf_exact(parv[1], cli_user(sptr)->realusername,
                          cli_user(sptr)->realhost, CONF_OPS);

  if (!aconf)
    aconf = find_conf_exact(parv[1], cli_user(sptr)->realusername,
                            ircd_ntoa((const char*) &(cli_ip(sptr))), CONF_OPS);

  if (!aconf)
    aconf = find_conf_cidr(parv[1], cli_user(sptr)->realusername,
                            cli_ip(sptr), CONF_OPS);

  if (aconf == NULL)
  {
    send_reply(sptr, ERR_NOOPERHOST);
    failed_challenge_notice(sptr, parv[1], "No o:line");
    sendto_allops(&me, SNO_OLDREALOP, "Failed OPER attempt by %s (%s@%s) (No O:line)",
                       parv[0], cli_user(sptr)->realusername, cli_sockhost(sptr));
    return 0;
  }

  if (!(aconf->port & OFLAG_RSA))
  {
    send_reply(sptr, RPL_NO_CHALL);
    return 0;
  }

  if (!verify_sslclifp(sptr, aconf))
  {
    sendto_allops(&me, SNO_OLDREALOP,
           "Failed OPER attempt by %s (%s@%s) (SSL Fingerprint Missmatch)",
           parv[0], cli_user(sptr)->realusername,
           cli_user(sptr)->realhost);
    send_reply(sptr, ERR_SSLCLIFP);
    return 0;
  }

  if ((file = BIO_new_file(aconf->passwd, "r")) == NULL)
  {
    send_reply(sptr, RPL_NO_KEY);
    return 0;
  }

  rsa_public_key = (RSA *)PEM_read_bio_RSA_PUBKEY(file, NULL, 0, NULL);
  if (rsa_public_key == NULL)
     return send_reply(sptr, RPL_INVALID_KEY);


  if (!generate_challenge(&challenge, rsa_public_key, sptr)) {
      Debug((DEBUG_DEBUG, "generating challenge sum (%s)", challenge));
      send_reply(sptr, RPL_RSACHALLENGE, challenge);
      ircd_snprintf(0, cli_user(sptr)->auth_oper, NICKLEN + 1, "%s", aconf->name);
  }
  nl = BIO_set_close(file, BIO_CLOSE);
  BIO_free(file);

  return 1;
#else
  return 1;
#endif
}


int ms_challenge(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
#ifdef USE_SSL
  struct ConfItem *aconf;
  RSA *rsa_public_key;
  BIO *file = NULL;
  char *challenge = NULL;
  char *name;
  char *tmpname;
  char             chan[CHANNELLEN-1];
  char*            join[2];
  int nl;
  struct Client *acptr = NULL;
  char *privbuf;

  if (!IsServer(cptr))
    return 0;

  /* if theyre an oper, reprint oper motd and ignore */
  if (IsOper(sptr))
  {
    send_reply(sptr, RPL_YOUREOPER);
    if (feature_bool(FEAT_OPERMOTD))
      m_opermotd(sptr, sptr, 1, parv);
  }

  if (parc < 3) {
    return send_reply(sptr, ERR_NOOPERHOST);
  }

  if (!(acptr = FindNServer(parv[1]))) {
    return send_reply(sptr, ERR_NOOPERHOST);
  } else if (!IsMe(acptr)) {
    sendcmdto_one(sptr, CMD_CHALLENGE, acptr, "%C %s %s", acptr, parv[2],
                  parv[3]);
    return 0;
  }

  if (*parv[2] == '+')
  {
    /* Ignore it if we aren't expecting this... -A1kmm */
    if (cli_user(sptr)->response == NULL)
      return 0;

    if (ircd_strcmp(cli_user(sptr)->response, ++parv[2]))
    {
      send_reply(sptr, ERR_PASSWDMISMATCH);
      sendto_allops(&me, SNO_OLDREALOP, "Failed OPER attempt by %s (%s@%s) (Password Incorrect)",
                         parv[0], cli_user(sptr)->realusername, cli_sockhost(sptr));
      tmpname = strdup(cli_user(sptr)->auth_oper);
      failed_challenge_notice(sptr, tmpname, "challenge failed");
      return 0;
    }

    name = strdup(cli_user(sptr)->auth_oper);
     
    aconf = find_conf_exact(cli_user(sptr)->auth_oper, cli_user(sptr)->realusername,
                            MyUser(sptr) ? cli_sockhost(sptr) :
                            cli_user(sptr)->realhost, CONF_OPS);

    if (!aconf)
      aconf = find_conf_exact(cli_user(sptr)->auth_oper, cli_user(sptr)->realusername,
                              ircd_ntoa((const char*) &(cli_ip(sptr))), CONF_OPS);

    if (!aconf)
      aconf = find_conf_cidr(cli_user(sptr)->auth_oper, cli_user(sptr)->realusername,
                              cli_ip(sptr), CONF_OPS);

    if (!aconf)
    {
      send_reply(sptr, ERR_NOOPERHOST);
      sendto_allops(&me, SNO_OLDREALOP, "Failed OPER attempt by %s (%s@%s) (No O:line)",
                         parv[0], cli_user(sptr)->realusername, cli_sockhost(sptr));
      return 0;
    }

    if (CONF_LOCOP == aconf->status) {
      ClearOper(sptr);
      SetLocOp(sptr);
    }
    else {
      /* This must be called before client_set_privs() */
      SetRemoteOper(sptr);

      if (!feature_bool(FEAT_OPERFLAGS) || (aconf->port & OFLAG_WHOIS)) {
        OSetWhois(sptr);
      }
      if (!feature_bool(FEAT_OPERFLAGS) || (aconf->port & OFLAG_IDLE)) {
        OSetIdle(sptr);
      }
      if (!feature_bool(FEAT_OPERFLAGS) || (aconf->port & OFLAG_XTRAOP)) {
        OSetXtraop(sptr);
      }
      if (!feature_bool(FEAT_OPERFLAGS) || (aconf->port & OFLAG_HIDECHANS)) {
        OSetHideChans(sptr);
      }

      /* prevent someone from being both oper and local oper */
      ClearLocOp(sptr);

      if (!feature_bool(FEAT_OPERFLAGS) || !(aconf->port & OFLAG_ADMIN)) {
        /* Global Oper */
        ClearAdmin(sptr);
        OSetGlobal(sptr);
        SetOper(sptr);
      } else {
        /* Admin */
        OSetGlobal(sptr);
        OSetAdmin(sptr);
        SetOper(sptr);
        SetAdmin(sptr);
      }

      /* Tell client_set_privs to send privileges to the user */
      client_set_privs(sptr, aconf);

      ClearOper(sptr);
      ClearAdmin(sptr);

      ClearRemoteOper(sptr);
      privbuf = client_print_privs(sptr);
      sendcmdto_one(&me, CMD_PRIVS, sptr, "%C %s", sptr, privbuf);
    }

    sendcmdto_one(&me, CMD_MODE, sptr, "%s %s", cli_name(sptr),
                  (OIsAdmin(sptr)) ? "+aoiwsg" : "+oiwsg");

    send_reply(sptr, RPL_YOUREOPER);

    if (OIsAdmin(sptr)) {
      sendto_allops(&me, SNO_OLDSNO, "%s (%s@%s) is now an IRC Administrator",
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
      if (feature_bool(FEAT_AUTOJOIN_OPER) && OIsGlobal(sptr)) {
        if (feature_bool(FEAT_AUTOJOIN_OPER_NOTICE))
              sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :%s", sptr, feature_str(FEAT_AUTOJOIN_OPER_NOTICE_VALUE));

        ircd_strncpy(chan, feature_str(FEAT_AUTOJOIN_OPER_CHANNEL), CHANNELLEN-1);
        join[0] = cli_name(sptr);
        join[1] = chan;
        m_join(sptr, sptr, 2, join);
      }
    } else {
      sendto_allops(&me, SNO_OLDSNO, "%s (%s@%s) is now an IRC Operator (%c)",
                         parv[0], cli_user(sptr)->username, cli_sockhost(sptr),
                         OIsGlobal(sptr) ? 'O' : 'o');

      if (feature_bool(FEAT_AUTOJOIN_OPER) && OIsGlobal(sptr)) {
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

    ircd_snprintf(0, cli_user(sptr)->response, BUFSIZE+1, "%s", "");
    return 0;
  }

  ircd_snprintf(0, cli_user(sptr)->response, BUFSIZE+1, "%s", "");
  ircd_snprintf(0, cli_user(sptr)->auth_oper, NICKLEN+1, "%s", "");

  aconf = find_conf_exact(parv[2], cli_user(sptr)->realusername,
                          cli_user(sptr)->realhost, CONF_OPS);

  if (!aconf)
    aconf = find_conf_exact(parv[2], cli_user(sptr)->realusername,
                            ircd_ntoa((const char*) &(cli_ip(sptr))), CONF_OPS);

  if (!aconf)
    aconf = find_conf_cidr(parv[2], cli_user(sptr)->realusername,
                            cli_ip(sptr), CONF_OPS);

  if (aconf == NULL)
  {
    send_reply(sptr, ERR_NOOPERHOST);
    failed_challenge_notice(sptr, parv[2], "No o:line");
    sendto_allops(&me, SNO_OLDREALOP, "Failed OPER attempt by %s (%s@%s) (No O:line)",
                       parv[0], cli_user(sptr)->realusername, cli_sockhost(sptr));
    return 0;
  }

  if (!(aconf->port & OFLAG_REMOTE)) {
    send_reply(sptr, ERR_NOOPERHOST);
    sendto_allops(&me, SNO_OLDREALOP,
      "Failed OPER attempt by %s (%s@%s) (Remote Oper)", parv[0],
      cli_user(sptr)->realusername, cli_user(sptr)->realhost);
    return 0;
  }

  if (!(aconf->port & OFLAG_RSA))
  {
    send_reply(sptr, RPL_NO_CHALL);
    return 0;
  }

  if (!verify_sslclifp(sptr, aconf))
  {
    sendto_allops(&me, SNO_OLDREALOP,
           "Failed OPER attempt by %s (%s@%s) (SSL Fingerprint Missmatch)",
           parv[0], cli_user(sptr)->realusername,
           cli_user(sptr)->realhost);
    send_reply(sptr, ERR_SSLCLIFP);
    return 0;
  }

  if ((file = BIO_new_file(aconf->passwd, "r")) == NULL)
  {
    send_reply(sptr, RPL_NO_KEY);
    return 0;
  }

  rsa_public_key = (RSA *)PEM_read_bio_RSA_PUBKEY(file, NULL, 0, NULL);
  if (rsa_public_key == NULL)
     return send_reply(sptr, RPL_INVALID_KEY);


  if (!generate_challenge(&challenge, rsa_public_key, sptr)) {
      Debug((DEBUG_DEBUG, "generating challenge sum (%s)", challenge));
      send_reply(sptr, RPL_RSACHALLENGE, challenge);
      ircd_snprintf(0, cli_user(sptr)->auth_oper, NICKLEN + 1, "%s", aconf->name);
  }
  nl = BIO_set_close(file, BIO_CLOSE);
  BIO_free(file);

  return 1;
#else
  return 1;
#endif
}

int mo_challenge(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  send_reply(sptr, RPL_YOUREOPER);
  return 1;
}

