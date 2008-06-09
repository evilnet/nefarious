/*
 * IRC - Internet Relay Chat, ircd/s_user.c (formerly ircd/s_msg.c)
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

#include "s_user.h"
#include "IPcheck.h"
#include "channel.h"
#include "class.h"
#include "client.h"
#include "cloak.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_relay.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "ircd_struct.h"
#include "list.h"
#include "mark.h"
#include "match.h"
#include "motd.h"
#include "msg.h"
#include "msgq.h"
#include "numeric.h"
#include "numnicks.h"
#include "parse.h"
#include "querycmds.h"
#include "random.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_serv.h" /* max_client_count */
#include "send.h"
#include "shun.h"
#include "ircd_struct.h"
#include "support.h"
#include "supported.h"
#include "sys.h"
#include "userload.h"
#include "version.h"
#include "watch.h"
#include "whowas.h"

#include "handlers.h" /* m_motd and m_lusers */

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static char *IsVhost(char *hostmask, int oper);
static char *IsVhostPass(char *hostmask);

static int userCount = 0;

/*
 * 'make_user' add's an User information block to a client
 * if it was not previously allocated.
 */
struct User *make_user(struct Client *cptr)
{
  assert(0 != cptr);

  if (!cli_user(cptr)) {
    cli_user(cptr) = (struct User*) MyMalloc(sizeof(struct User));
    assert(0 != cli_user(cptr));

    /* All variables are 0 by default */
    memset(cli_user(cptr), 0, sizeof(struct User));
#ifdef  DEBUGMODE
    ++userCount;
#endif
    cli_user(cptr)->refcnt = 1;
  }
  return cli_user(cptr);
}

/*
 * free_user
 *
 * Decrease user reference count by one and release block, if count reaches 0.
 */
void free_user(struct User* user)
{
  assert(0 != user);
  assert(0 < user->refcnt);

  if (--user->refcnt == 0) {
    if (user->away)
      MyFree(user->away);
    if (user->swhois)
      MyFree(user->swhois);
    /*
     * sanity check
     */
    assert(0 == user->joined);
    assert(0 == user->invited);
    assert(0 == user->channel);

    MyFree(user);
#ifdef  DEBUGMODE
    --userCount;
#endif
  }
}

void user_count_memory(size_t* count_out, size_t* bytes_out)
{
  assert(0 != count_out);
  assert(0 != bytes_out);
  *count_out = userCount;
  *bytes_out = userCount * sizeof(struct User);
}


/*
 * next_client
 *
 * Local function to find the next matching client. The search
 * can be continued from the specified client entry. Normal
 * usage loop is:
 *
 * for (x = client; x = next_client(x,mask); x = x->next)
 *     HandleMatchingClient;
 *
 */
struct Client *next_client(struct Client *next, const char* ch)
{
  struct Client *tmp = next;

  if (!tmp)
    return NULL;

  next = FindClient(ch);
  next = next ? next : tmp;
  if (cli_prev(tmp) == next)
    return NULL;
  if (next != tmp)
    return next;
  for (; next; next = cli_next(next))
    if (!match(ch, cli_name(next)))
      break;
  return next;
}

/*
 * hunt_server
 *
 *    Do the basic thing in delivering the message (command)
 *    across the relays to the specific server (server) for
 *    actions.
 *
 *    Note:   The command is a format string and *MUST* be
 *            of prefixed style (e.g. ":%s COMMAND %s ...").
 *            Command can have only max 8 parameters.
 *
 *    server  parv[server] is the parameter identifying the
 *            target server. It can be a nickname, servername,
 *            or server mask (from a local user) or a server
 *            numeric (from a remote server).
 *
 *    *WARNING*
 *            parv[server] is replaced with the pointer to the
 *            real servername from the matched client (I'm lazy
 *            now --msa).
 *
 *    returns: (see #defines)
 */
int hunt_server_cmd(struct Client *from, const char *cmd, const char *tok,
                    struct Client *one, int MustBeOper, const char *pattern,
                    int server, int parc, char *parv[])
{
  struct Client *acptr;
  char *to;

  /* Assume it's me, if no server or an unregistered client */
  if (parc <= server || EmptyString((to = parv[server])) || IsUnknown(from))
    return (HUNTED_ISME);

  if (MustBeOper && !IsPrivileged(from))
  {
    send_reply(from, ERR_NOPRIVILEGES);
    return HUNTED_NOSUCH;
  }

  /* Make sure it's a server */
  if (MyUser(from)) {
    /* Make sure it's a server */
    if (!strchr(to, '*')) {
      if (0 == (acptr = FindClient(to))) {
        send_reply(from, ERR_NOSUCHSERVER, to);
        return HUNTED_NOSUCH;
      }

      if (cli_user(acptr))
        acptr = cli_user(acptr)->server;
    } else if (!(acptr = find_match_server(to))) {
      send_reply(from, ERR_NOSUCHSERVER, to);
      return (HUNTED_NOSUCH);
    }
  } else if (!(acptr = FindNServer(to)))
    return (HUNTED_NOSUCH);        /* Server broke off in the meantime */

  if (IsMe(acptr))
    return (HUNTED_ISME);

  if (MustBeOper && !IsPrivileged(from)) {
    send_reply(from, ERR_NOPRIVILEGES);
    return HUNTED_NOSUCH;
  }

  /* assert(!IsServer(from)); XXX testing without this */

  parv[server] = (char *) acptr; /* HACK! HACK! HACK! ARGH! */

  sendcmdto_one(from, cmd, tok, acptr, pattern, parv[1], parv[2], parv[3],
                parv[4], parv[5], parv[6], parv[7], parv[8]);

  return (HUNTED_PASS);
}

int hunt_server_prio_cmd(struct Client *from, const char *cmd, const char *tok,
			 struct Client *one, int MustBeOper,
			 const char *pattern, int server, int parc,
			 char *parv[])
{
  struct Client *acptr;
  char *to;

  /* Assume it's me, if no server or an unregistered client */
  if (parc <= server || EmptyString((to = parv[server])) || IsUnknown(from))
    return (HUNTED_ISME);

  /* Make sure it's a server */
  if (MyUser(from)) {
    /* Make sure it's a server */
    if (!strchr(to, '*')) {
      if (0 == (acptr = FindClient(to))) {
        send_reply(from, ERR_NOSUCHSERVER, to);
        return HUNTED_NOSUCH;
      }

      if (cli_user(acptr))
        acptr = cli_user(acptr)->server;
    } else if (!(acptr = find_match_server(to))) {
      send_reply(from, ERR_NOSUCHSERVER, to);
      return (HUNTED_NOSUCH);
    }
  } else if (!(acptr = FindNServer(to)))
    return (HUNTED_NOSUCH);        /* Server broke off in the meantime */

  if (IsMe(acptr))
    return (HUNTED_ISME);

  if (MustBeOper && !IsPrivileged(from)) {
    send_reply(from, ERR_NOPRIVILEGES);
    return HUNTED_NOSUCH;
  }

  /* assert(!IsServer(from)); SETTIME to particular destinations permitted */

  parv[server] = (char *) acptr; /* HACK! HACK! HACK! ARGH! */

  sendcmdto_prio_one(from, cmd, tok, acptr, pattern, parv[1], parv[2], parv[3],
		     parv[4], parv[5], parv[6], parv[7], parv[8]);

  return (HUNTED_PASS);
}


/*
 * clean_user_id
 *
 * Copy `source' to `dest', replacing all occurances of '~' and characters that
 * are not `isIrcUi' by an underscore.
 * Copies at most USERLEN - 1 characters or up till the first control character.
 * If `tilde' is true, then a tilde is prepended to `dest'.
 * Note that `dest' and `source' can point to the same area or to different
 * non-overlapping areas.
 */
static char *clean_user_id(char *dest, char *source, int tilde)
{
  char ch;
  char *d = dest;
  char *s = source;
  int rlen = USERLEN;

  ch = *s++;                        /* Store first character to copy: */
  if (tilde)
  {
    *d++ = '~';                        /* If `dest' == `source', then this overwrites `ch' */
    --rlen;
  }
  while (ch && !IsCntrl(ch) && rlen--)
  {
    char nch = *s++;        /* Store next character to copy */
    *d++ = IsUserChar(ch) ? ch : '_';        /* This possibly overwrites it */
    if (nch == '~')
      ch = '_';
    else
      ch = nch;
  }
  *d = 0;
  return dest;
}

/*
 * register_user
 *
 * This function is called when both NICK and USER messages
 * have been accepted for the client, in whatever order. Only
 * after this the USER message is propagated.
 *
 * NICK's must be propagated at once when received, although
 * it would be better to delay them too until full info is
 * available. Doing it is not so simple though, would have
 * to implement the following:
 *
 * 1) user telnets in and gives only "NICK foobar" and waits
 * 2) another user far away logs in normally with the nick
 *    "foobar" (quite legal, as this server didn't propagate it).
 * 3) now this server gets nick "foobar" from outside, but
 *    has already the same defined locally. Current server
 *    would just issue "KILL foobar" to clean out dups. But,
 *    this is not fair. It should actually request another
 *    nick from local user or kill him/her...
 */
int register_user(struct Client *cptr, struct Client *sptr,
                  const char *nick, char *username)
{
  struct ConfItem* aconf;
  struct Shun*     ashun = NULL;
  char*            parv[4];
  char*            join[2];
  char*            tmpstr;
  char*            tmpstr2;
  char             c = 0;    /* not alphanum */
  char             d = 'a';  /* not a digit */
  short            upper = 0;
  short            lower = 0;
  short            pos = 0;
  short            leadcaps = 0;
  short            other = 0;
  short            digits = 0;
  short            badid = 0;
  short            digitgroups = 0;
  struct User*     user = cli_user(sptr);
  char             chan[CHANNELLEN-1];
  int              killreason;
  char             ip_base64[8];

  user->last = CurrentTime;
  parv[0] = cli_name(sptr);
  parv[1] = parv[2] = NULL;

  if (MyConnect(sptr) && DoAccess(sptr))
  {
    static time_t last_too_many1;
    static time_t last_too_many2;

    ++UserStats.conncount;

    assert(cptr == sptr);
    switch (conf_check_client(sptr))
    {
      case ACR_OK:
        break;
      case ACR_NO_AUTHORIZATION:
        sendto_opmask_butone(0, SNO_UNAUTH, "Unauthorized connection from %s.",
                             get_client_name(sptr, HIDE_IP));
        ++ServerStats->is_ref;
        return exit_client(cptr, sptr, &me,
                           "No Authorization - use another server");
      case ACR_TOO_MANY_IN_CLASS:
        if (CurrentTime - last_too_many1 >= (time_t) 60)
        {
          last_too_many1 = CurrentTime;
          sendto_opmask_butone(0, SNO_TOOMANY, "Too many connections in "
                               "class %i for %s.", get_client_class(sptr),
                               get_client_name(sptr, SHOW_IP));
        }
        ++ServerStats->is_ref;
        IPcheck_connect_fail(cli_ip(sptr));
        return exit_client(cptr, sptr, &me,
                           "Sorry, your connection class is full - try "
                           "again later or try another server");
      case ACR_TOO_MANY_FROM_IP:
        if (CurrentTime - last_too_many2 >= (time_t) 60)
        {
          last_too_many2 = CurrentTime;
          sendto_opmask_butone(0, SNO_TOOMANY, "Too many connections from "
                               "same IP for %s.",
                               get_client_name(sptr, SHOW_IP));
        }
        ++ServerStats->is_ref;
        return exit_client(cptr, sptr, &me,
                           "Too many connections from your host");
      case ACR_ALREADY_AUTHORIZED:
        /* Can this ever happen? */
      case ACR_BAD_SOCKET:
        ++ServerStats->is_ref;
        IPcheck_connect_fail(cli_ip(sptr));
        return exit_client(cptr, sptr, &me, "Unknown error -- Try again");
    }

    /* Check for any Redirect (use another server) lines */
    if (find_csline(sptr, cli_sockhost(sptr)))
      return exit_client(cptr, sptr, &me,
			 "No Authorization - use another server");

    /* The host might already be set by login-on-connect */
    if (!HasHiddenHost(sptr) && (feature_int(FEAT_HOST_HIDING_STYLE) == 1))
      ircd_strncpy(user->host, cli_sockhost(sptr), HOSTLEN);
    ircd_strncpy(user->realhost, cli_sockhost(sptr), HOSTLEN);

    if (feature_bool(FEAT_FAKEHOST) && feature_str(FEAT_DEFAULT_FAKEHOST)) {
      /* If the server-wide default fakehost has been set, give
	 all users connecting to this server only a fakehost.
	 This does prevent them from using their account-based
	 hidden host permanently. */
      ircd_strncpy(user->fakehost, feature_str(FEAT_DEFAULT_FAKEHOST),
		   HOSTLEN);
      SetFakeHost(sptr);
    }

    aconf = cli_confs(sptr)->value.aconf;

    if ( feature_bool(FEAT_WEBIRC_USERIDENT) && IsWebIRC(sptr) ) {
      clean_user_id(user->username, username,
          HasFlag(sptr, FLAG_DOID) && !HasFlag(sptr, FLAG_GOTID)
          && !(HasSetHost(sptr))); /* No tilde for S-lined users. */
    }
    else {
      clean_user_id(user->username,
          HasFlag(sptr, FLAG_GOTID) ? cli_username(sptr) : username,
          HasFlag(sptr, FLAG_DOID) && !HasFlag(sptr, FLAG_GOTID)
          && !(HasSetHost(sptr))); /* No tilde for S-lined users. */
    }

    /* Have to set up "realusername" before doing the gline check below */
    ircd_strncpy(user->realusername, user->username, USERLEN);

    if ((user->username[0] == '\0')
        || ((user->username[0] == '~') && (user->username[1] == '\000')))
      return exit_client(cptr, sptr, &me, "USER: Bogus userid.");

    if (!EmptyString(aconf->passwd)
        && !(IsDigit(*aconf->passwd) && !aconf->passwd[1])
        && !(IsDigit(*aconf->passwd) && IsDigit(aconf->passwd[1]) && !aconf->passwd[2])
        && strcmp(cli_passwd(sptr), aconf->passwd))
    {
      ServerStats->is_ref++;
      send_reply(sptr, ERR_PASSWDMISMATCH);
      return exit_client(cptr, sptr, &me, "Bad Password");
    }
    memset(cli_passwd(sptr), 0, sizeof(cli_passwd(sptr)));
    /*
     * following block for the benefit of time-dependent K:-lines
     */
    if ((killreason=find_kill(sptr))) {
      ServerStats->is_ref++;
      return exit_client(cptr, sptr, &me,
        killreason == -1 ? "K-lined" : "G-lined");
    }
    /*
     * Check for mixed case usernames, meaning probably hacked.  Jon2 3-94
     * Summary of rules now implemented in this patch:         Ensor 11-94
     * In a mixed-case name, if first char is upper, one more upper may
     * appear anywhere.  (A mixed-case name *must* have an upper first
     * char, and may have one other upper.)
     * A third upper may appear if all 3 appear at the beginning of the
     * name, separated only by "others" (-/_/.).
     * A single group of digits is allowed anywhere.
     * Two groups of digits are allowed if at least one of the groups is
     * at the beginning or the end.
     * Only one '-', '_', or '.' is allowed (or two, if not consecutive).
     * But not as the first or last char.
     * No other special characters are allowed.
     * Name must contain at least one letter.
     */
    if(feature_bool(FEAT_STRICTUSERNAME)) {
        tmpstr2 = tmpstr = (username[0] == '~' ? &username[1] : username);
        while (*tmpstr && !badid)
        {
          pos++;
          c = *tmpstr;
          tmpstr++;
          if (IsLower(c))
          {
            lower++;
          }
          else if (IsUpper(c))
          {
            upper++;
            if ((leadcaps || pos == 1) && !lower && !digits)
              leadcaps++;
          }
          else if (IsDigit(c))
          {
            digits++;
            if (pos == 1 || !IsDigit(d))
            {
              digitgroups++;
              if (digitgroups > 2)
                badid = 1;
            }
          }
          else if (c == '-' || c == '_' || c == '.')
          {
            other++;
            if (pos == 1)
              badid = 1;
            else if (d == '-' || d == '_' || d == '.' || other > 2)
              badid = 1;
          }
          else
            badid = 1;
          d = c;
        }
        if (!badid)
        {
          if (lower && upper && (!leadcaps || leadcaps > 3 ||
              (upper > 2 && upper > leadcaps)))
            badid = 1;
          else if (digitgroups == 2 && !(IsDigit(tmpstr2[0]) || IsDigit(c)))
            badid = 1;
          else if ((!lower && !upper) || !IsAlnum(c))
            badid = 1;
        }
        if (badid && (!HasFlag(sptr, FLAG_GOTID) ||
            strcmp(cli_username(sptr), username) != 0))
        {
          ServerStats->is_ref++;

          send_reply(cptr, SND_EXPLICIT | ERR_INVALIDUSERNAME,
                     ":Your username is invalid.");
          send_reply(cptr, SND_EXPLICIT | ERR_INVALIDUSERNAME,
                     ":Connect with your real username, in lowercase.");
          send_reply(cptr, SND_EXPLICIT | ERR_INVALIDUSERNAME,
                     ":If your mail address were foo@bar.com, your username "
                     "would be foo.");
          send_reply(cptr, SND_EXPLICIT | ERR_INVALIDUSERNAME,
                     ":See %s for further information.",
                     feature_str(FEAT_BADUSER_URL));
          return exit_client(cptr, sptr, &me, "USER: Bad username");
        }
      }
  }

  if (!MyConnect(sptr)) {
    ircd_strncpy(user->username, username, USERLEN);
  } else if (cli_loc(sptr)) {
    /* Do the login-on-connect thing.
     * This happens after the checks above, but before incrementing any
     * counters as it may be called more than once
     */
    struct Client *acptr;

    if (cli_loc(sptr)->cookie)
      /* if already doing auth, ignore; 
       * broken and/or evil clients might trigger this
       */
      return 0;
    if (!(acptr = FindUser(cli_loc(sptr)->service)) || !IsChannelService(acptr)) {
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Service '%s' is not available", sptr, cli_loc(sptr)->service);
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Type \002/QUOTE PASS\002 to connect anyway", sptr);
      MyFree(cli_loc(sptr));
    } else {
      /* the cookie is used to verify replies from the service, in case the
       * client disconnects and the fd is reused
       */
      do {
        cli_loc(sptr)->cookie = ircrandom() & 0x7fffffff;
      } while (!cli_loc(sptr)->cookie);
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Attempting service login to %s",
	            sptr, cli_loc(sptr)->service);
      if ( feature_bool(FEAT_LOC_SENDHOST) ) {
        sendcmdto_one(&me, CMD_ACCOUNT, acptr, "%C H .%u.%u %s@%s:%s %s :%s", acptr,
                      cli_fd(sptr), cli_loc(sptr)->cookie, cli_user(sptr)->username,
                      (cli_user(sptr)->host ? cli_user(sptr)->host : cli_sock_ip(sptr)),
                      cli_sock_ip(sptr), cli_loc(sptr)->account, cli_loc(sptr)->password);
      } else {
        sendcmdto_one(&me, CMD_ACCOUNT, acptr, "%C C .%u.%u %s :%s", acptr,
	              cli_fd(sptr), cli_loc(sptr)->cookie,
	              cli_loc(sptr)->account, cli_loc(sptr)->password);
      }
      ServerStats->is_login++;
    }
    return 0;

  }

  if (MyConnect(sptr) && feature_bool(FEAT_DNSBL_CHECKS)) {
    struct SLink*  dp;
    char *dhost = NULL;
    char chkhosti[NICKLEN+USERLEN+SOCKIPLEN+3];
    char chkhosth[NICKLEN+USERLEN+HOSTLEN+3];

    release_dnsbl_reply(sptr);

    ircd_snprintf(0, chkhosti, NICKLEN+USERLEN+SOCKIPLEN+3, "%s!%s@%s", cli_name(sptr), user->username, (char*)ircd_ntoa((const char*) &(cli_ip(sptr))));
    ircd_snprintf(0, chkhosth, NICKLEN+USERLEN+HOSTLEN+3, "%s!%s@%s", cli_name(sptr), user->username, cli_sockhost(sptr));

    if (IsDNSBL(sptr)) {
      log_write(LS_DNSBL, L_INFO, 0, "Client %s - %p", cli_name(sptr), sptr);

      for (dp = cli_sdnsbls(sptr); dp; dp = dp->next) {
        if (EmptyString(cli_dnsbls(sptr)))
          strcat(cli_dnsbls(sptr), dp->value.cp);
        else {
          if(strlen(cli_dnsbls(sptr)) + strlen(dp->value.cp) + 2 < BUFSIZE) {
              strcat(cli_dnsbls(sptr), ", ");
              strcat(cli_dnsbls(sptr), dp->value.cp);
          }
        }
      }
    }

    process_exempts(sptr, chkhosti, 0);
    process_exempts(sptr, chkhosth, 0);

    if (IsDNSBL(sptr) && ((dhost = find_dnsblexempt(chkhosti)) || (dhost = find_dnsblexempt(chkhosth)))) {
      log_write(LS_DNSBL, L_INFO, 0, "Client %s is exempted, marking and allowing.", cli_name(sptr));
      SetDNSBLAllowed(sptr);
      SetDNSBLMarked(sptr);
    }


    if (IsDNSBL(sptr) && !IsDNSBLAllowed(sptr)) {
      if (feature_bool(FEAT_DNSBL_WALLOPS_ONLY))
         sendwallto_group_butone(&me, WALL_DESYNCH, NULL,
                "DNSBL Detected %s!%s@%s (%s)", cli_name(sptr), user->username,
                cli_user(sptr)->realhost, (char*)ircd_ntoa((const char*) &(cli_ip(sptr))));
      else {
        int class_exempt = 0, loc_exempt = 0;

        if ((get_client_class(sptr) == feature_int(FEAT_DNSBL_EXEMPT_CLASS)) &&
  	   (feature_int(FEAT_DNSBL_EXEMPT_CLASS) > 0)) {
    	  class_exempt = 1;
          log_write(LS_DNSBL, L_INFO, 0, "Client %s is class exempted.", cli_name(sptr));
        }

        if (IsAccount(sptr) && feature_bool(FEAT_DNSBL_LOC_EXEMPT)) {
  	  loc_exempt = 1;
          log_write(LS_DNSBL, L_INFO, 0, "Client %s is loc exempted.", cli_name(sptr));
        }

        if ((class_exempt == 1) || (loc_exempt == 1)) {
          SetDNSBLAllowed(sptr);
	  loc_exempt = 0;
	  class_exempt = 0;
        } else
          if (feature_bool(FEAT_DNSBL_LOC_EXEMPT) && !IsAccount(sptr)) {
            log_write(LS_DNSBL, L_INFO, 0, "Offering loc exemption to %s", cli_name(sptr));
            sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :%s", sptr,
                                   format_dnsbl_msg((char*)ircd_ntoa((const char*) &(cli_ip(sptr))),
                                                    cli_user(sptr)->realhost, user->username,
                                                    cli_name(sptr), cli_dnsblformat(sptr))
                                                    );
            sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :%s", sptr, feature_str(FEAT_DNSBL_LOC_EXEMPT_N_ONE));
            sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :%s", sptr, feature_str(FEAT_DNSBL_LOC_EXEMPT_N_TWO));
            MyFree(cli_loc(sptr));
            return 0;
          } else
            if ((feature_bool(FEAT_DNSBL_LOC_EXEMPT) && !IsAccount(sptr)) || !feature_bool(FEAT_DNSBL_LOC_EXEMPT)) {
              log_write(LS_DNSBL, L_INFO, 0, "Rejecting DNSBL infected client %s", chkhosth);
              return exit_client_msg(sptr, cptr, &me, "%s",
       		                     format_dnsbl_msg((char*)ircd_ntoa((const char*) &(cli_ip(sptr))),
 			  	     	  	      cli_user(sptr)->realhost, user->username,
						      cli_name(sptr), cli_dnsblformat(sptr))
		                                      );
            }
      }
    }
  }

  if (MyConnect(sptr) && feature_bool(FEAT_SETHOST_AUTO)) {
    if (conf_check_slines(sptr)) {
      send_reply(sptr, RPL_USINGSLINE);
      SetSetHost(sptr);
    }
  }

#ifdef USE_SSL
  if (MyConnect(sptr) && cli_socket(sptr).ssl)
    SetSSL(sptr);
#endif /* USE_SSL */

  if (MyConnect(sptr) && feature_bool(FEAT_AUTOINVISIBLE))
    SetInvisible(sptr);

  SetUser(sptr);

  /* increment global count if needed */
  if (UserStats.globalclients < UserStats.clients && IsUser(sptr)) {
    if (UserStats.globalclients >= 0) {
      ++UserStats.globalclients;
      save_tunefile();
    }
  }

  /* increment local count if needed */
  if (UserStats.localclients < UserStats.local_clients && IsUser(sptr)) {
    if (UserStats.localclients >= 0) {
      ++UserStats.localclients;
      save_tunefile();
    }
  }

  if (IsInvisible(sptr))
    ++UserStats.inv_clients;
  if (IsOper(sptr))
    ++UserStats.opers;
  if (IsAccount(sptr))
    ++UserStats.authed;

  if (MyConnect(sptr))
    Count_unknownbecomesclient(sptr, UserStats);
  else
    Count_newremoteclient(UserStats, user->server);

  if (MyConnect(sptr)) {
    cli_handler(sptr) = CLIENT_HANDLER;
    release_dns_reply(sptr);

    if ((ashun = shun_lookup(sptr, 0))) {
       sendto_allops(&me, SNO_GLINE, "Shun active for %s%s",
                          IsUnknown(sptr) ? "Unregistered Client ":"",
                          get_client_name(sptr, SHOW_IP));
      if (!feature_bool(FEAT_HIS_SHUN_REASON))
        sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :You are shunned: %s", sptr,
             ashun->sh_reason);
    }

  /*
   * even though a client isnt auto +x'ing we still do a virtual 
   * ip of the client so we dont have to do it each time the client +x's 
   */
    if (feature_int(FEAT_HOST_HIDING_STYLE) == 2) {

      if (!strcmp((char*)ircd_ntoa((const char*) &(cli_ip(sptr))), cli_user(sptr)->host)) {
        ircd_snprintf(0, cli_user(sptr)->virthost, HOSTLEN, hidehost_ipv4((char*)ircd_ntoa((const char*) &(cli_ip(sptr)))));
        ircd_snprintf(0, cli_user(sptr)->virtip, HOSTLEN, "%s", hidehost_ipv4((char*)ircd_ntoa((const char*) &(cli_ip(sptr)))));
      } else {
        ircd_snprintf(0, cli_user(sptr)->virtip, HOSTLEN, hidehost_ipv4((char*)ircd_ntoa((const char*) &(cli_ip(sptr)))));
        ircd_snprintf(0, cli_user(sptr)->virthost, HOSTLEN, "%s", hidehost_normalhost(cli_user(sptr)->host));
      }

      SetFlag(sptr, FLAG_CLOAKHOST);
      SetFlag(sptr, FLAG_CLOAKIP);

      SetCloakIP(sptr);
      SetCloakHost(sptr);

    }

    SetLocalNumNick(sptr);

    /* added by Vadtec 02/25/2008 */
    /* We do this here because CTCP VERSION isn't part of the RFC, so there is no reason to delay the user from 
       being able to join the network. */
    if (feature_bool(FEAT_CTCP_VERSIONING)) {
      if (feature_str(FEAT_CTCP_VERSIONING_NOTICE))
        sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :%s", sptr, feature_str(FEAT_CTCP_VERSIONING_NOTICE));
      sendcmdto_one(&me, CMD_PRIVATE, sptr, "%C :\001VERSION\001", sptr);
    }

    send_reply(
	sptr,
	RPL_WELCOME,
	feature_str(FEAT_NETWORK),
 	feature_str(FEAT_PROVIDER) ? " via " : "",
	feature_str(FEAT_PROVIDER) ? feature_str(FEAT_PROVIDER) : "",
	nick);

    /*
     * This is a duplicate of the NOTICE but see below...
     */
    send_reply(sptr, RPL_YOURHOST, cli_name(&me), version);

    send_reply(sptr, RPL_CREATED, creation,
        feature_str(FEAT_GEO_LOCATION) ? " and is located in " : "",
        feature_str(FEAT_GEO_LOCATION) ? feature_str(FEAT_GEO_LOCATION) : "");

    send_reply(sptr, RPL_MYINFO, cli_name(&me), version, infousermodes,
	       infochanmodes, infochanmodeswithparams);
    send_supported(sptr);
    if (feature_bool(FEAT_QUOTES))
      m_randquote(sptr, sptr, 1, parv);

#ifdef USE_SSL
    if (IsSSL(sptr))
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :You are connected to %s with %s", sptr,
		    cli_name(&me), ssl_get_cipher(cli_socket(sptr).ssl));
#endif

    m_lusers(sptr, sptr, 1, parv);
    update_load();
    motd_signon(sptr);
/*      nextping = CurrentTime; */
    if (cli_snomask(sptr) & SNO_NOISY)
      set_snomask(sptr, cli_snomask(sptr) & SNO_NOISY, SNO_ADD);
    if (feature_bool(FEAT_CONNEXIT_NOTICES))
       sendto_allops(&me, SNO_CONNEXIT,
			  "Client connecting: %s (%s@%s) [%s] {%d} [%s] <%s%s>",
			  cli_name(sptr), user->username, user->host,
			  cli_sock_ip(sptr), get_client_class(sptr),
			  cli_info(sptr),
			  NumNick(cptr) /* Two %'s */
			  );
    IPcheck_connect_succeeded(sptr);
  }
  else
    /* if (IsServer(cptr)) */
  {
    struct Client *acptr;

    acptr = user->server;
    if (cli_from(acptr) != cli_from(sptr))
    {
      sendcmdto_one(&me, CMD_KILL, cptr, "%C :%s (%s != %s[%s])",
                    sptr, cli_name(&me), cli_name(user->server), cli_name(cli_from(acptr)),
                    cli_sockhost(cli_from(acptr)));
      SetFlag(sptr, FLAG_KILLED);
      return exit_client(cptr, sptr, &me, "NICK server wrong direction");
    }
    else
      if (HasFlag(acptr, FLAG_TS8))
          SetFlag(sptr, FLAG_TS8);

    /*
     * Check to see if this user is being propogated
     * as part of a net.burst, or is using protocol 9.
     * FIXME: This can be speeded up - its stupid to check it for
     * every NICK message in a burst again  --Run.
     */
    for (acptr = user->server; acptr != &me; acptr = cli_serv(acptr)->up) {
      if (IsBurst(acptr) || Protocol(acptr) < 10)
        break;
    }
    if (!IPcheck_remote_connect(sptr, (acptr != &me))) {
      /*
       * We ran out of bits to count this
       */
      sendcmdto_one(&me, CMD_KILL, sptr, "%C :%s (Too many connections from "
		    "your host -- Ghost)", sptr, cli_name(&me));
      return exit_client(cptr, sptr, &me, "Too many connections from your"
			 " host -- throttled");
    }
  }

  /*
   * Set user's initial modes
   */
  if (MyUser(sptr)) {
    parv[0] = (char*)nick;
    parv[1] = (char*)nick;
    parv[2] = (char*)feature_str(FEAT_DEFAULT_UMODE);
    parv[3] = NULL;
    set_user_mode(sptr, sptr, 3, parv);
  }
  tmpstr = umode_str(sptr);
  sendcmdto_serv_butone(user->server, CMD_NICK, cptr,
			"%s %d %Tu %s %s %s%s%s%s %s%s :%s",
			nick, cli_hopcount(sptr) + 1, cli_lastnick(sptr),
			user->realusername, user->realhost,
			*tmpstr ? "+" : "", tmpstr, *tmpstr ? " " : "",
			inttobase64(ip_base64, ntohl(cli_ip(sptr).s_addr), 6),
			NumNick(sptr), cli_info(sptr));
  
  SetPropagated(sptr);

  /* Send umode to client */
  if (MyUser(sptr))
  {
    struct Flags flags;
    struct SLink*  lp;

    if (IsDNSBL(sptr) && IsDNSBLAllowed(sptr)) {
      char flagbuf[BUFSIZE];
      char* dnsblhost;
      memset(flagbuf, 0, BUFSIZE);

      if (IsDNSBLMarked(sptr) && !IsAccount(sptr)) {
        ircd_snprintf(0, cli_user(sptr)->dnsblhost, sizeof(cli_user(sptr)->dnsblhost), "%s.%s", cli_dnsbl(sptr), cli_sockhost(sptr));
        strcat(flagbuf, "m");

        if (feature_bool(FEAT_FAKEHOST) && feature_bool(FEAT_DNSBL_MARK_FAKEHOST)) {
          log_write(LS_DNSBL, L_INFO, 0, "Marking client %s", cli_name(sptr));
          SetFakeHost(sptr);
          SetHiddenHost(sptr);
          ircd_snprintf(0, cli_user(sptr)->fakehost, sizeof(cli_user(sptr)->fakehost), "%s.%s", cli_dnsbl(sptr), cli_sockhost(sptr));
          hide_hostmask(sptr);

          sendcmdto_serv_butone(cli_user(sptr)->server, CMD_FAKEHOST, cptr, "%C %s", sptr,
                                cli_user(sptr)->fakehost);
          sendcmdto_one(sptr, CMD_MODE, cptr, "%s %s", cli_name(sptr), "+x");
          sendcmdto_serv_butone(sptr, CMD_MODE, cptr, "%s %s", cli_name(sptr), "+x");
        }
      }

      if (IsDNSBLMarked(sptr) && IsAccount(sptr)) {
        log_write(LS_DNSBL, L_INFO, 0, "Clearing mark on client %s", cli_name(sptr));
        ClearDNSBLMarked(sptr);
      }

      strcat(flagbuf, "a");

      dnsblhost = cli_user(sptr)->dnsblhost;
      if(!dnsblhost[0])
          dnsblhost = "notmarked";
      sendcmdto_serv_butone(cli_user(sptr)->server, CMD_MARK, cptr, "%s %s %s %s", cli_name(sptr), MARK_DNSBL,
                            flagbuf, dnsblhost);

      for (lp = cli_sdnsbls(sptr); lp; lp = lp->next)
         sendcmdto_serv_butone(cli_user(sptr)->server, CMD_MARK, cptr, "%s %s %s", cli_name(sptr),
                               MARK_DNSBL_DATA, lp->value.cp);

      Debug((DEBUG_DEBUG, "MARKED DNSBL: %s (r %s - n %s) (d %s m %s a %s)", cli_dnsbl(sptr),
            cli_sockhost(sptr), IsDNSBLMarked(sptr) ? cli_user(sptr)->dnsblhost : "notmarked",
            IsDNSBL(sptr) ? "1" : "0", IsDNSBLMarked(sptr) ? "1" : "0", IsDNSBLAllowed(sptr) ? "1" : "0"));
      log_write(LS_DNSBL, L_INFO, 0, "MARK Sent %s (r %s - n %s) (d %s m %s a %s)", cli_dnsbl(sptr),
                cli_sockhost(sptr), IsDNSBLMarked(sptr) ? cli_user(sptr)->dnsblhost : "notmarked",
                IsDNSBL(sptr) ? "1" : "0", IsDNSBLMarked(sptr) ? "1" : "0", IsDNSBLAllowed(sptr) ? "1" : "0");
    }

#ifdef USE_SSL
    /* Let client know he/she has user mode +z */
    if (IsSSL(sptr))
      sendcmdto_one(sptr, CMD_MODE, sptr, "%s %s", cli_name(sptr), "+z");
#endif

    /* hack the 'old flags' so we don't send +r */
    if (HasFlag(sptr, FLAG_ACCOUNT))
      FlagSet(&flags, FLAG_ACCOUNT);
    else
      FlagClr(&flags, FLAG_ACCOUNT);

    if (cli_snomask(sptr) != SNO_DEFAULT && HasFlag(sptr, FLAG_SERVNOTICE))
      send_reply(sptr, RPL_SNOMASK, cli_snomask(sptr), cli_snomask(sptr));

    if (feature_bool(FEAT_POLICY_NOTICE)) {
      if (feature_bool(FEAT_RULES))
        sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :*** Notice -- Please be advised that use of this service constitutes consent to all network policies and server conditions of use, which are at \2%s\2, stated within the servers \2/MOTD\2 and \2/RULES\2", sptr, feature_str(FEAT_NETWORK));
      else
        sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :*** Notice -- Please be advised that use of this service constitutes consent to all network policies and server conditions of use, which are at \2%s\2, stated within the servers \2/MOTD\2", sptr, feature_str(FEAT_NETWORK));
    }

    if (feature_bool(FEAT_AUTOJOIN_USER)) {
      if (feature_bool(FEAT_AUTOJOIN_USER_NOTICE))
        sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :%s", sptr, feature_str(FEAT_AUTOJOIN_USER_NOTICE_VALUE));

      ircd_strncpy(chan, feature_str(FEAT_AUTOJOIN_USER_CHANNEL), CHANNELLEN-1);
      join[0] = cli_name(sptr);
      join[1] = chan;
      m_join(sptr, sptr, 2, join);
    }
  }

  /* Notify new local/remote user */
  check_status_watch(sptr, RPL_LOGON);

  return 0;
}


static const struct UserMode {
  unsigned int flag;
  char         c;
} userModeList[] = {
  { FLAG_OPER,        'o' },
  { FLAG_LOCOP,       'O' },
  { FLAG_INVISIBLE,   'i' },
  { FLAG_WALLOP,      'w' },
  { FLAG_SERVNOTICE,  's' },
  { FLAG_DEAF,        'd' },
  { FLAG_CHSERV,      'k' },
  { FLAG_DEBUG,       'g' },
  { FLAG_ACCOUNT,     'r' },
  { FLAG_HIDDENHOST,  'x' },
  { FLAG_SETHOST,     'h' },
  { FLAG_FAKEHOST,    'f' },
  { FLAG_CLOAKHOST,   'C' },
  { FLAG_CLOAKIP,     'c' },
  { FLAG_ACCOUNTONLY, 'R' },
  { FLAG_BOT,         'B' },
  { FLAG_XTRAOP,      'X' },
  { FLAG_NOCHAN,      'n' },
  { FLAG_NOIDLE,      'I' },
  { FLAG_ADMIN,       'a' },
  { FLAG_WHOIS,       'W' },
  { FLAG_SSL,         'z' }
};

#define USERMODELIST_SIZE sizeof(userModeList) / sizeof(struct UserMode)

/*
 * XXX - find a way to get rid of this
 */
static char umodeBuf[BUFSIZE];

int set_nick_name(struct Client* cptr, struct Client* sptr,
                  const char* nick, int parc, char* parv[], int svsnick)
{
  if (IsServer(sptr)) {
    int   i;
    const char* account = 0;
    const char* sethost = 0;
    const char* fakehost = 0;
    const char* cloakhost = 0;
    const char* cloakip = 0;
    char* host = 0;
    const char* p;

    /*
     * A server introducing a new client, change source
     */
    struct Client* new_client = make_client(cptr, STAT_UNKNOWN);
    assert(0 != new_client);

    cli_hopcount(new_client) = atoi(parv[2]);
    cli_lastnick(new_client) = atoi(parv[3]);
    if (Protocol(cptr) > 9 && parc > 7 && *parv[6] == '+') {
      int argi = 7;
      for (p = parv[6] + 1; *p; p++) {
        for (i = 0; i < USERMODELIST_SIZE; ++i) {
          if (userModeList[i].c == *p) {
            SetFlag(new_client, userModeList[i].flag);
	    if (userModeList[i].flag == FLAG_ACCOUNT)
	      account = parv[argi++];
	    if (userModeList[i].flag == FLAG_SETHOST)
	      sethost = parv[argi++];
            if (userModeList[i].flag == FLAG_FAKEHOST)
              fakehost = parv[argi++];
            if (userModeList[i].flag == FLAG_CLOAKHOST)
              cloakhost = parv[argi++];
            if (userModeList[i].flag == FLAG_CLOAKIP)
              cloakip = parv[argi++];
            break;
          }
        }
      }
    }
    client_set_privs(new_client); /* set privs on user */
    /*
     * Set new nick name.
     */
    strcpy(cli_name(new_client), nick);
    cli_user(new_client) = make_user(new_client);
    cli_user(new_client)->server = sptr;
    SetRemoteNumNick(new_client, parv[parc - 2]);
    /*
     * IP# of remote client
     */
    cli_ip(new_client).s_addr = htonl(base64toint(parv[parc - 3]));

    add_client_to_list(new_client);
    hAddClient(new_client);

    cli_serv(sptr)->ghost = 0;        /* :server NICK means end of net.burst */
    ircd_strncpy(cli_username(new_client), parv[4], USERLEN);
    ircd_strncpy(cli_user(new_client)->realusername, parv[4], USERLEN);
    ircd_strncpy(cli_user(new_client)->host, parv[5], HOSTLEN);
    ircd_strncpy(cli_user(new_client)->realhost, parv[5], HOSTLEN);
    ircd_strncpy(cli_info(new_client), parv[parc - 1], REALLEN);
    if (account) {
      int len = ACCOUNTLEN;
      if ((p = strchr(account, ':'))) {
	len = (p++) - account;
	cli_user(new_client)->acc_create = atoi(p);
	Debug((DEBUG_DEBUG, "Received timestamped account in user mode; "
	       "account \"%s\", timestamp %Tu", account,
	       cli_user(new_client)->acc_create));
      }
      ircd_strncpy(cli_user(new_client)->account, account, len);
    }
    if (fakehost) {
      SetFakeHost(new_client);
      ircd_strncpy(cli_user(new_client)->fakehost, fakehost, HOSTLEN);
    }
    if (HasHiddenHost(new_client) && (feature_int(FEAT_HOST_HIDING_STYLE) == 1))
      make_hidden_hostmask(cli_user(new_client)->host, new_client);
    else if ( feature_int(FEAT_HOST_HIDING_STYLE) == 2 )  {
      if ( HasCloakHost(new_client) && HasCloakIP(new_client) ) {
        ircd_strncpy(cli_user(new_client)->virthost, cloakhost, HOSTLEN);
        ircd_strncpy(cli_user(new_client)->virtip, cloakip, HOSTLEN);
      }
      else {

        if (!strcmp((char*)ircd_ntoa((const char*) &(cli_ip(new_client))), cli_user(new_client)->host)) {
          ircd_snprintf(0, cli_user(new_client)->virthost, HOSTLEN, hidehost_ipv4((char*)ircd_ntoa((const char*) &(cli_ip(new_client)))));
          ircd_snprintf(0, cli_user(new_client)->virtip, HOSTLEN, "%s", hidehost_ipv4((char*)ircd_ntoa((const char*) &(cli_ip(new_client)))));
        } else {
          ircd_snprintf(0, cli_user(new_client)->virtip, HOSTLEN, hidehost_ipv4((char*)ircd_ntoa((const char*) &(cli_ip(new_client)))));
          ircd_snprintf(0, cli_user(new_client)->virthost, HOSTLEN, "%s", hidehost_normalhost(cli_user(new_client)->host));
        }
      }
      SetFlag(new_client, FLAG_CLOAKHOST);
      SetFlag(new_client, FLAG_CLOAKIP);
      if ( IsHiddenHost(new_client) ) {
        ircd_strncpy(cli_user(new_client)->host, cli_user(new_client)->virthost, HOSTLEN);
        SetFlag(new_client, FLAG_HIDDENHOST);
      }
    }

    if (HasSetHost(new_client)) {
      if ((host = strrchr(sethost, '@')) != NULL) {
        *host++ = '\0';
	ircd_strncpy(cli_username(new_client), sethost, USERLEN);
	ircd_strncpy(cli_user(new_client)->host, host, HOSTLEN);
      }
    }

    return register_user(cptr, new_client, cli_name(new_client), cli_username(new_client));
  }
  else if ((cli_name(sptr))[0]) {
    /*
     * Client changing its nick
     *
     * If the client belongs to me, then check to see
     * if client is on any channels where it is currently
     * banned.  If so, do not allow the nick change to occur.
     */
    if (MyUser(sptr)) {
      const char* channel_name;
      struct Membership *member;
      if ((channel_name = find_no_nickchange_channel(sptr)) &&
	  !IsXtraOp(sptr) && !svsnick) {
        return send_reply(cptr, ERR_BANNICKCHANGE, channel_name);
      }
      /*
       * Refuse nick change if the last nick change was less
       * then 30 seconds ago. This is intended to get rid of
       * clone bots doing NICK FLOOD. -SeKs
       * If someone didn't change their nick for more then 60 seconds
       * however, allow to do two nick changes immedately after another
       * before limiting the nick flood. -Run
       */
      if (!svsnick) {
        if (CurrentTime < cli_nextnick(cptr)) {
          cli_nextnick(cptr) += 2;
          send_reply(cptr, ERR_NICKTOOFAST, parv[1],
                     cli_nextnick(cptr) - CurrentTime);
          /* Send error message */
          sendcmdto_one(cptr, CMD_NICK, cptr, "%s", cli_name(cptr));
          /* bounce NICK to user */
          return 0;                /* ignore nick change! */
        }
        else {
          /* Limit total to 1 change per NICK_DELAY seconds: */
          cli_nextnick(cptr) += feature_int(FEAT_NICK_DELAY);
          /* However allow _maximal_ 1 extra consecutive nick change: */
          if (cli_nextnick(cptr) < CurrentTime)
            cli_nextnick(cptr) = CurrentTime;
        }
      }
      /* Invalidate all bans against the user so we check them again */
      for (member = (cli_user(cptr))->channel; member;
	   member = member->next_channel)
	ClearBanValid(member);

      /* Invalidate all excepts against the user so we check them again */
      for (member = (cli_user(cptr))->channel; member;
           member = member->next_channel)
        ClearExceptValid(member);
    }
    /*
     * Also set 'lastnick' to current time, if changed.
     */
    if (0 != ircd_strcmp(parv[0], nick))
      cli_lastnick(sptr) = (sptr == cptr) ? TStime() : atoi(parv[2]);

    /*
     * Client just changing his/her nick. If he/she is
     * on a channel, send note of change to all clients
     * on that channel. Propagate notice to other servers.
     */
    if (IsUser(sptr)) {
      /* Notify exit user */
      check_status_watch(sptr, RPL_LOGOFF);

      sendcmdto_common_channels_butone(sptr, CMD_NICK, NULL, ":%s", nick);
      add_history(sptr, 1);
      sendcmdto_serv_butone(sptr, CMD_NICK, cptr, "%s %Tu", nick,
                            cli_lastnick(sptr));
    }
    else
      sendcmdto_one(sptr, CMD_NICK, sptr, ":%s", nick);

    /*
     * Send out a connexit notice for the nick change before
     * cli_name(sptr) is overwritten with the new nick. -reed
     */
    if (MyUser(sptr) && feature_bool(FEAT_CONNEXIT_NOTICES))
      sendto_allops(&me, SNO_NICKCHG,
			 "Nick change: From %s to %s [%s@%s] <%s%s>",
			 cli_name(sptr), nick,
			 cli_user(sptr)->realusername,
			 cli_user(sptr)->realhost,
			 NumNick(sptr) /* Two %'s */
			 );

    if ((cli_name(sptr))[0])
      hRemClient(sptr);
    strcpy(cli_name(sptr), nick);
    hAddClient(sptr);

    /* Notify change nick local/remote user */
    check_status_watch(sptr, RPL_LOGON);
  }
  else {
    /* Local client setting NICK the first time */

    strcpy(cli_name(sptr), nick);
    if (!cli_user(sptr)) {
      cli_user(sptr) = make_user(sptr);
      cli_user(sptr)->server = &me;
    }
    hAddClient(sptr);

    /*
     * If the client hasn't gotten a cookie-ping yet,
     * choose a cookie and send it. -record!jegelhof@cloud9.net
     */
    if (!cli_cookie(sptr)) {
      do {
        cli_cookie(sptr) = (ircrandom() & 0x7fffffff);
      } while (!cli_cookie(sptr));
      sendrawto_one(cptr, MSG_PING " :%u", cli_cookie(sptr));
    }
    else if (*(cli_user(sptr))->host && cli_cookie(sptr) == COOKIE_VERIFIED) {
      /*
       * USER and PONG already received, now we have NICK.
       * register_user may reject the client and call exit_client
       * for it - must test this and exit m_nick too !
       */
      cli_lastnick(sptr) = TStime();        /* Always local client */
      if (register_user(cptr, sptr, nick, cli_user(sptr)->username) == CPTR_KILLED)
        return CPTR_KILLED;
    }
  }

  return 0;
}

static unsigned char hash_target(unsigned int target)
{
  return (unsigned char) (target >> 16) ^ (target >> 8);
}

/*
 * add_target
 *
 * sptr must be a local client!
 *
 * Cannonifies target for client `sptr'.
 */
void add_target(struct Client *sptr, void *target)
{
  /* Ok, this shouldn't work esp on alpha
  */
  unsigned char  hash = hash_target((unsigned long) target);
  unsigned char* targets;
  int            i;
  assert(0 != sptr);
  assert(cli_local(sptr));

  targets = cli_targets(sptr);
  /* 
   * Already in table?
   */
  for (i = 0; i < MAXTARGETS; ++i) {
    if (targets[i] == hash)
      return;
  }
  /*
   * New target
   */
  memmove(&targets[RESERVEDTARGETS + 1],
          &targets[RESERVEDTARGETS], MAXTARGETS - RESERVEDTARGETS - 1);
  targets[RESERVEDTARGETS] = hash;
}

/*
 * check_target_limit
 *
 * sptr must be a local client !
 *
 * Returns 'true' (1) when too many targets are addressed.
 * Returns 'false' (0) when it's ok to send to this target.
 */
int check_target_limit(struct Client *sptr, void *target, const char *name,
    int created)
{
  unsigned char hash = hash_target((unsigned long) target);
  int            i;
  unsigned char* targets;

  assert(0 != sptr);
  assert(cli_local(sptr));
  targets = cli_targets(sptr);

  /* Is target limiting even enabled? */
  if (!feature_bool(FEAT_TARGET_LIMITING))
    return 0;

  /* If user is invited to channel, give him/her a free target */
  if (IsChannelName(name) && IsInvited(sptr, target))
    return 0;

  /* If user is an oper or bot, he/she/it always has a free target */
  if (IsOper(sptr) || IsBot(sptr))
    return 0;

  /*
   * Same target as last time?
   */
  if (targets[0] == hash)
    return 0;
  for (i = 1; i < MAXTARGETS; ++i) {
    if (targets[i] == hash) {
      memmove(&targets[1], &targets[0], i);
      targets[0] = hash;
      return 0;
    }
  }
  /*
   * New target
   */
  if (!created) {
    if (CurrentTime < cli_nexttarget(sptr)) {
      if (cli_nexttarget(sptr) - CurrentTime < TARGET_DELAY + 8) {
        /*
         * No server flooding
         */
        cli_nexttarget(sptr) += 2;
        send_reply(sptr, ERR_TARGETTOOFAST, name,
                   cli_nexttarget(sptr) - CurrentTime);
      }
      return 1;
    }
    else {
      cli_nexttarget(sptr) += TARGET_DELAY;
      if (cli_nexttarget(sptr) < CurrentTime - (TARGET_DELAY * (MAXTARGETS - 1)))
        cli_nexttarget(sptr) = CurrentTime - (TARGET_DELAY * (MAXTARGETS - 1));
    }
  }
  memmove(&targets[1], &targets[0], MAXTARGETS - 1);
  targets[0] = hash;
  return 0;
}

/*
 * whisper - called from m_cnotice and m_cprivmsg.
 *
 * parv[0] = sender prefix
 * parv[1] = nick
 * parv[2] = #channel
 * parv[3] = Private message text
 *
 * Added 971023 by Run.
 * Reason: Allows channel operators to sent an arbitrary number of private
 *   messages to users on their channel, avoiding the max.targets limit.
 *   Building this into m_private would use too much cpu because we'd have
 *   to a cross channel lookup for every private message!
 * Note that we can't allow non-chan ops to use this command, it would be
 *   abused by mass advertisers.
 *
 */
int whisper(struct Client* source, const char* nick, const char* channel,
            const char* text, int is_notice)
{
  struct Client*     dest;
  struct Channel*    chptr;
  struct Membership* membership;

  assert(0 != source);
  assert(0 != nick);
  assert(0 != channel);
  assert(MyUser(source));

  if (!(dest = FindUser(nick))) {
    return send_reply(source, ERR_NOSUCHNICK, nick);
  }
  if (!(chptr = FindChannel(channel))) {
    return send_reply(source, ERR_NOSUCHCHANNEL, channel);
  }
  /*
   * compare both users channel lists, instead of the channels user list
   * since the link is the same, this should be a little faster for channels
   * with a lot of users
   */
  for (membership = cli_user(source)->channel; membership; membership = membership->next_channel) {
    if (chptr == membership->channel)
      break;
  }
  if (0 == membership)
    return send_reply(source, ERR_NOTONCHANNEL, chptr->chname);
  if (!IsVoicedOrOpped(membership))
    return send_reply(source, ERR_VOICENEEDED, chptr->chname);
  /*
   * lookup channel in destination
   */
  assert(0 != cli_user(dest));
  for (membership = cli_user(dest)->channel; membership;
       membership = membership->next_channel) {
    if (chptr == membership->channel)
      break;
  }
  if (0 == membership || IsZombie(membership))
    return send_reply(source, ERR_USERNOTINCHANNEL, cli_name(dest),
		      chptr->chname);

  if (is_silenced(source, dest))
    return 0;

  if (cli_user(dest)->away)
    send_reply(source, RPL_AWAY, cli_name(dest), cli_user(dest)->away);

  if (IsAccountOnly(dest) && !IsAccount(source) && !IsOper(source) &&
      (dest != source))
    send_reply(source, ERR_ACCOUNTONLY, cli_name(dest),
	       (is_notice) ? "CNOTICE" : "CPRIVMSG", cli_name(dest));
  else if (is_notice)
    sendcmdto_one(source, CMD_NOTICE, dest, "%C :%s", dest, text);
  else
    sendcmdto_one(source, CMD_PRIVATE, dest, "%C :%s", dest, text);

  return 0;
}


/*
 * added Sat Jul 25 07:30:42 EST 1992
 */
void send_umode_out(struct Client *cptr, struct Client *sptr, struct Flags *old,
		    int prop)
{
  int i;
  struct Client *acptr;

  send_umode(NULL, sptr, old, prop ? SEND_UMODES : SEND_UMODES_BUT_OPER);

  for (i = HighestFd; i >= 0; i--) {
    if ((acptr = LocalClientArray[i]) && IsServer(acptr) &&
        (acptr != cptr) && (acptr != sptr) && *umodeBuf && IsPropagated(sptr))
      sendcmdto_one(sptr, CMD_MODE, acptr, "%s %s", cli_name(sptr), umodeBuf);
  }
  if (cptr && MyUser(cptr))
    send_umode(cptr, sptr, old, ALL_UMODES);
}


/*
 * send_user_info - send user info userip/userhost
 * NOTE: formatter must put info into buffer and return a pointer to the end of
 * the data it put in the buffer.
 */
void send_user_info(struct Client* sptr, char* names, int rpl, InfoFormatter fmt)
{
  char*          name;
  char*          p = 0;
  int            arg_count = 0;
  int            users_found = 0;
  struct Client* acptr;
  struct MsgBuf* mb;

  assert(0 != sptr);
  assert(0 != names);
  assert(0 != fmt);

  mb = msgq_make(sptr, rpl_str(rpl), cli_name(&me), cli_name(sptr));

  for (name = ircd_strtok(&p, names, " "); name; name = ircd_strtok(&p, 0, " ")) {
    if ((acptr = FindUser(name))) {
      if (users_found++)
	msgq_append(0, mb, " ");
      (*fmt)(acptr, sptr, mb);
    }
    if (5 == ++arg_count)
      break;
  }
  send_buffer(sptr, mb, 0);
  msgq_clean(mb);
}

/*
 * make_hidden_hostmask()
 *
 * Generates a user's hidden hostmask based on their account unless
 * they have a custom [vanity] host set. This function expects a
 * buffer of sufficient size to hold the resulting hostmask.
 */
void make_hidden_hostmask(char *buffer, struct Client *cptr)
{
  assert(HasFakeHost(cptr) || IsAccount(cptr));

  if (HasFakeHost(cptr)) {
    /* The user has a fake host; make that their hidden hostmask. */
    ircd_strncpy(buffer, cli_user(cptr)->fakehost, HOSTLEN);
    return;
  }

  if (IsAccount(cptr)) {
    /* Generate a hidden host based on the user's account name. */
    ircd_snprintf(0, buffer, HOSTLEN, "%s.%s", cli_user(cptr)->account,
		  (IsAnOper(cptr) && feature_bool(FEAT_OPERHOST_HIDING)) 
		   ? feature_str(FEAT_HIDDEN_OPERHOST)
		   : feature_str(FEAT_HIDDEN_HOST));
    return;
  }
}

/*
 * hide_hostmask()
 *
 * If the user has HiddenHost and either of Account or FakeHost set,
 * its hostmask is changed.
 */
int hide_hostmask(struct Client *cptr)
{
  struct Membership *chan;

  if (MyConnect(cptr) && !feature_bool(FEAT_HOST_HIDING))
    return 0;

  if (!HasHiddenHost(cptr))
    return 0;

  /* Invalidate all bans against the user so we check them again */
  for (chan = (cli_user(cptr))->channel; chan;
       chan = chan->next_channel)
    ClearBanValid(chan);

  /* Invalidate all excepts against the user so we check them again */
  for (chan = (cli_user(cptr))->channel; chan; chan = chan->next_channel)
    ClearExceptValid(chan);

  /* If user is +h, don't hide the host. Set flag to keep sync though. */
  if (HasSetHost(cptr)) {
    SetHiddenHost(cptr);
    return 0;
  }

  sendcmdto_common_channels_butone(cptr, CMD_QUIT, cptr, ":Registered");
  make_hidden_hostmask(cli_user(cptr)->host, cptr);

  /* ok, the client is now fully hidden, so let them know -- hikari */
  if (MyConnect(cptr) && IsRegistered(cptr) &&
      (0 != ircd_strcmp(cli_user(cptr)->host, cli_user(cptr)->dnsblhost)))
   send_reply(cptr, RPL_HOSTHIDDEN, cli_user(cptr)->host);

  /*
   * Go through all channels the client was on, rejoin him
   * and set the modes, if any
   */
  for (chan = cli_user(cptr)->channel; chan; chan = chan->next_channel) {
    if (IsZombie(chan))
      continue;
    sendcmdto_channel_butserv_butone(cptr, CMD_JOIN, chan->channel, cptr, 0,
      "%H", chan->channel);
    if (IsChanOp(chan) && HasVoice(chan) && IsHalfOp(chan)) {
      sendcmdto_channel_butserv_butone(feature_bool(FEAT_HIS_HIDEWHO) ? &his : &me, CMD_MODE, chan->channel, cptr, 0,
        "%H +ohv %C %C %C", chan->channel, cptr, cptr, cptr);
    } else if (IsChanOp(chan) || HasVoice(chan) || IsHalfOp(chan)) {
      if(IsChanOp(chan) && IsHalfOp(chan)) {
      	sendcmdto_channel_butserv_butone(feature_bool(FEAT_HIS_HIDEWHO) ? &his : &me, CMD_MODE, chan->channel, cptr, 0,
	                  	         "%H +oh %C %C", chan->channel, cptr, cptr);
      }
      else if(IsChanOp(chan) && HasVoice(chan)) {
        sendcmdto_channel_butserv_butone(feature_bool(FEAT_HIS_HIDEWHO) ? &his : &me, CMD_MODE, chan->channel, cptr, 0,
                                        "%H +ov %C %C", chan->channel, cptr, cptr);
      }
      else if(IsHalfOp(chan) && HasVoice(chan)) {
        sendcmdto_channel_butserv_butone(feature_bool(FEAT_HIS_HIDEWHO) ? &his : &me, CMD_MODE, chan->channel, cptr, 0,
                                         "%H +hv %C %C", chan->channel, cptr, cptr);
      }
      else if(IsChanOp(chan)) {
        sendcmdto_channel_butserv_butone(feature_bool(FEAT_HIS_HIDEWHO) ? &his : &me, CMD_MODE, chan->channel, cptr, 0,
                                         "%H +o %C", chan->channel, cptr);
      }
      else if(IsHalfOp(chan)) {
        sendcmdto_channel_butserv_butone(feature_bool(FEAT_HIS_HIDEWHO) ? &his : &me, CMD_MODE, chan->channel, cptr, 0,
                                         "%H +h %C", chan->channel, cptr);
      }
      else if(HasVoice(chan)) {
        sendcmdto_channel_butserv_butone(feature_bool(FEAT_HIS_HIDEWHO) ? &his : &me, CMD_MODE, chan->channel, cptr, 0,
                                         "%H +v %C", chan->channel, cptr);
      }
    }
  }
  return 0;
}

/*
 * unhide_hostmask()
 *
 */
int unhide_hostmask(struct Client *cptr)
{
  struct Membership *chan;

  /* Invalidate all bans against the user so we check them again */
  for (chan = (cli_user(cptr))->channel; chan;
       chan = chan->next_channel)
    ClearBanValid(chan);

  /* Invalidate all excepts against the user so we check them again */
  for (chan = (cli_user(cptr))->channel; chan; chan = chan->next_channel)
    ClearExceptValid(chan);

  /* If user is +h, don't unhide the host. Set flag to keep sync though. */
  if (HasSetHost(cptr)) {
    ClearHiddenHost(cptr);
    return 0;
  }

  sendcmdto_common_channels_butone(cptr, CMD_QUIT, cptr, ":UnRegistered");
  ircd_strncpy(cli_user(cptr)->host, cli_user(cptr)->realhost, HOSTLEN);

  /*
   * Go through all channels the client was on, rejoin him
   * and set the modes, if any
   */
  for (chan = cli_user(cptr)->channel; chan; chan = chan->next_channel) {
    if (IsZombie(chan))
      continue;
    sendcmdto_channel_butserv_butone(cptr, CMD_JOIN, chan->channel, cptr, 0,
      "%H", chan->channel);
    if (IsChanOp(chan) && HasVoice(chan) && IsHalfOp(chan)) {
      sendcmdto_channel_butserv_butone(&me, CMD_MODE, chan->channel, cptr, 0,
        "%H +ohv %C %C %C", chan->channel, cptr, cptr, cptr);
    } else if (IsChanOp(chan) || HasVoice(chan) || IsHalfOp(chan)) {
      if(IsChanOp(chan) && IsHalfOp(chan)) {
        sendcmdto_channel_butserv_butone(feature_bool(FEAT_HIS_HIDEWHO) ? &his : &me, CMD_MODE, chan->channel, cptr, 0,
                                         "%H +oh %C %C", chan->channel, cptr, cptr);
      }
      else if(IsChanOp(chan) && HasVoice(chan)) {
        sendcmdto_channel_butserv_butone(feature_bool(FEAT_HIS_HIDEWHO) ? &his : &me, CMD_MODE, chan->channel, cptr, 0,
                                        "%H +ov %C %C", chan->channel, cptr, cptr);
      }
      else if(IsHalfOp(chan) && HasVoice(chan)) {
        sendcmdto_channel_butserv_butone(feature_bool(FEAT_HIS_HIDEWHO) ? &his : &me, CMD_MODE, chan->channel, cptr, 0,
                                         "%H +hv %C %C", chan->channel, cptr, cptr);
      }
      else if(IsChanOp(chan)) {
        sendcmdto_channel_butserv_butone(feature_bool(FEAT_HIS_HIDEWHO) ? &his : &me, CMD_MODE, chan->channel, cptr, 0,
                                         "%H +o %C", chan->channel, cptr);
      }
      else if(IsHalfOp(chan)) {
        sendcmdto_channel_butserv_butone(feature_bool(FEAT_HIS_HIDEWHO) ? &his : &me, CMD_MODE, chan->channel, cptr, 0,
                                         "%H +h %C", chan->channel, cptr);
      }
      else if(HasVoice(chan)) {
        sendcmdto_channel_butserv_butone(feature_bool(FEAT_HIS_HIDEWHO) ? &his : &me, CMD_MODE, chan->channel, cptr, 0,
                                         "%H +v %C", chan->channel, cptr);
      }
    }
  }
  return 0;
}

/*
 * set_hostmask() - derived from hide_hostmask()
 *
 */
int set_hostmask(struct Client *sptr, struct Client *cptr, char *hostmask, char *password)
{
  int restore = 0;
  int freeform = 0;
  char *host, *new_vhost, *vhost_pass;
  char hiddenhost[USERLEN + HOSTLEN + 2];
  struct Membership *chan;

  Debug((DEBUG_INFO, "set_hostmask() %C %C, %s, %s", sptr, cptr, hostmask, password));

  /* sethost enabled? */
  if (MyConnect(cptr) && !feature_bool(FEAT_SETHOST)) {
    send_reply(cptr, ERR_DISABLED, "SETHOST");
    return 0;
  }

  /* sethost enabled for users? */
  if (MyConnect(cptr) && !IsAnOper(cptr) && !feature_bool(FEAT_SETHOST_USER)) {
    send_reply(cptr, ERR_NOPRIVILEGES);
    return 0;
  }

  /* MODE_DEL: restore original hostmask */
  if (EmptyString(hostmask)) {
    /* is already sethost'ed? */
    if (IsSetHost(cptr)) {
      restore = 1;
      sendcmdto_common_channels_butone(cptr, CMD_QUIT, cptr, ":Host change");
      /* If they are +rx, we need to return to their +x host, not their "real" host */
      if (HasHiddenHost(cptr))
	make_hidden_hostmask(cli_user(cptr)->host, cptr);
      else
        strncpy(cli_user(cptr)->host, cli_user(cptr)->realhost, HOSTLEN);
      strncpy(cli_user(cptr)->username, cli_user(cptr)->realusername, USERLEN);
      /* log it */
      if (MyConnect(cptr))
        log_write(LS_SETHOST, L_INFO, LOG_NOSNOTICE,
            "SETHOST (%s@%s) by (%#R): restoring real hostmask",
            cli_user(cptr)->username, cli_user(cptr)->host, cptr);
    } else
      return 0;
  /* MODE_ADD: set a new hostmask */
  } else {
    /* chop up ident and host.cc */
    if ((host = (strrchr(hostmask, '@')))) /* oper can specify ident@host.cc */
      *host++ = '\0';
    else /* user can only specify host.cc [password] */
      host = hostmask;
    /* Ignore the assignment if it changes nothing */
    if (HasSetHost(cptr) &&
	(ircd_strcmp(cli_user(cptr)->host, host) == 0))
      return 0;
    /*
     * Oper sethost
     */
    if (MyConnect(cptr) && !IsServer(sptr)) {
      if (IsAnOper(cptr)) {
        if ((new_vhost = IsVhost(host, 1)) == NULL) {
          if (!feature_bool(FEAT_SETHOST_FREEFORM)) {
            send_reply(cptr, ERR_HOSTUNAVAIL, hostmask);
            log_write(LS_SETHOST, L_INFO, LOG_NOSNOTICE,
                "SETHOST (%s@%s) by (%#R): no such s-line",
                (host != hostmask) ? hostmask : cli_user(cptr)->username, host, cptr);
            return 0;
          } else /* freeform active, log and go */
            freeform = 1;
        }
        sendcmdto_common_channels_butone(cptr, CMD_QUIT, cptr, ":Host change");
        /* set the new ident and host */
        if (host != hostmask) /* oper only specified host.cc */
          strncpy(cli_user(cptr)->username, hostmask, USERLEN);
        strncpy(cli_user(cptr)->host, host, HOSTLEN);
        /* log it */
        log_write(LS_SETHOST, (freeform) ? L_NOTICE : L_INFO,
            (freeform) ? 0 : LOG_NOSNOTICE, "SETHOST (%s@%s) by (%#R)%s",
            cli_user(cptr)->username, cli_user(cptr)->host, cptr,
            (freeform) ? ": using freeform" : "");
      /*
       * plain user sethost, handled here
       */
      } else {
        /* empty password? */
        if (EmptyString(password)) {
          send_reply(cptr, ERR_NEEDMOREPARAMS, "MODE");
          return 0;
        }
        /* no such s-line */
        if ((new_vhost = IsVhost(host, 0)) == NULL) {
          send_reply(cptr, ERR_HOSTUNAVAIL, hostmask);
          log_write(LS_SETHOST, L_INFO, LOG_NOSNOTICE, "SETHOST (%s@%s %s) by (%#R): no such s-line",
              cli_user(cptr)->username, host, password, cptr);
          return 0;
        }
        /* no password */
        if ((vhost_pass = IsVhostPass(new_vhost)) == NULL) {
          send_reply(cptr, ERR_PASSWDMISMATCH);
          log_write(LS_SETHOST, L_INFO, 0, "SETHOST (%s@%s %s) by (%#R): trying to use an oper s-line",
              cli_user(cptr)->username, host, password, cptr);
          return 0;
        }
        /* incorrect password */
        if (strCasediff(vhost_pass, password)) {
          send_reply(cptr, ERR_PASSWDMISMATCH);
          log_write(LS_SETHOST, L_NOTICE, 0, "SETHOST (%s@%s %s) by (%#R): incorrect password",
              cli_user(cptr)->username, host, password, cptr);
          return 0;
        }
        sendcmdto_common_channels_butone(cptr, CMD_QUIT, cptr, ":Host change");
        /* set the new host */
        strncpy(cli_user(cptr)->host, new_vhost, HOSTLEN);
        /* log it */
        log_write(LS_SETHOST, L_INFO, LOG_NOSNOTICE, "SETHOST (%s@%s) by (%#R)",
            cli_user(cptr)->username, cli_user(cptr)->host, cptr);
      }
    } else { /* remote user */
        sendcmdto_common_channels_butone(cptr, CMD_QUIT, cptr, ":Host change");
        if (host != hostmask) /* oper only specified host.cc */
          strncpy(cli_user(cptr)->username, hostmask, USERLEN);
        strncpy(cli_user(cptr)->host, host, HOSTLEN);
    }
  }

  if (restore)
    ClearSetHost(cptr);
  else
    SetSetHost(cptr);

  /* Invalidate all bans against the user so we check them again */
  for (chan = (cli_user(cptr))->channel; chan;
       chan = chan->next_channel)
     ClearBanValid(chan);

  /* Invalidate all excepts against the user so we check them again */
  for (chan = (cli_user(cptr))->channel; chan; chan = chan->next_channel)
    ClearExceptValid(chan);

  if (MyConnect(cptr)) {
    ircd_snprintf(0, hiddenhost, HOSTLEN + USERLEN + 2, "%s@%s",
      cli_user(cptr)->username, cli_user(cptr)->host);
    send_reply(cptr, RPL_HOSTHIDDEN, hiddenhost);
  }

  /* Code copied from hide_hostmask().  This is the old (pre-delayedjoin) 
   * version.  Switch this in if you're not using the delayed join patch. */
  /*
   * Go through all channels the client was on, rejoin him
   * and set the modes, if any
   */
  for (chan = cli_user(cptr)->channel; chan; chan = chan->next_channel) {
    if (IsZombie(chan)) 
      continue;
    sendcmdto_channel_butserv_butone(cptr, CMD_JOIN, chan->channel, cptr, 0,
      "%H", chan->channel);

    if (IsChanOp(chan) && HasVoice(chan) && IsHalfOp(chan)) {
      sendcmdto_channel_butserv_butone(&me, CMD_MODE, chan->channel, cptr, 0,
        "%H +ohv %C %C %C", chan->channel, cptr, cptr, cptr);
    } else if (IsChanOp(chan) || HasVoice(chan) || IsHalfOp(chan)) {
      if(IsChanOp(chan) && IsHalfOp(chan)) {
        sendcmdto_channel_butserv_butone(feature_bool(FEAT_HIS_HIDEWHO) ? &his : &me, CMD_MODE, chan->channel, cptr, 0,
                                         "%H +oh %C %C", chan->channel, cptr, cptr);
      }
      else if(IsChanOp(chan) && HasVoice(chan)) {
        sendcmdto_channel_butserv_butone(feature_bool(FEAT_HIS_HIDEWHO) ? &his : &me, CMD_MODE, chan->channel, cptr, 0,
                                        "%H +ov %C %C", chan->channel, cptr, cptr);
      }
      else if(IsHalfOp(chan) && HasVoice(chan)) {
        sendcmdto_channel_butserv_butone(feature_bool(FEAT_HIS_HIDEWHO) ? &his : &me, CMD_MODE, chan->channel, cptr, 0,
                                         "%H +hv %C %C", chan->channel, cptr, cptr);
      }
      else if(IsChanOp(chan)) {
        sendcmdto_channel_butserv_butone(feature_bool(FEAT_HIS_HIDEWHO) ? &his : &me, CMD_MODE, chan->channel, cptr, 0,
                                         "%H +o %C", chan->channel, cptr);
      }
      else if(IsHalfOp(chan)) {
        sendcmdto_channel_butserv_butone(feature_bool(FEAT_HIS_HIDEWHO) ? &his : &me, CMD_MODE, chan->channel, cptr, 0,
                                         "%H +h %C", chan->channel, cptr);
      }
      else if(HasVoice(chan)) {
        sendcmdto_channel_butserv_butone(feature_bool(FEAT_HIS_HIDEWHO) ? &his : &me, CMD_MODE, chan->channel, cptr, 0,
                                         "%H +v %C", chan->channel, cptr);
      }
    }
  }
  return 1;
}

/*
 * set_user_mode() added 15/10/91 By Darren Reed.
 *
 * parv[0] - sender
 * parv[1] - username to change mode for
 * parv[2] - modes to change
 */
int set_user_mode(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  char** p;
  char*  m;
  struct Client *acptr = NULL; /* Stupid Compiler Warning (tm) */
  int what;
  int i;
  struct Flags setflags;
  unsigned int tmpmask = 0;
  int snomask_given = 0;
  char buf[BUFSIZE];
  char *hostmask = NULL;
  char *password = NULL;
  int prop = 0;
  int do_host_hiding = 0;
  int do_set_host = 0;
  int is_svsmode = 0;
  int force = 0;

  if (MyUser(sptr) && (((int)cptr) == MAGIC_SVSMODE_OVERRIDE))
  {
    is_svsmode = 1;
    cptr = sptr;
  }

  what = MODE_ADD;

  if (parc < 2)
    return need_more_params(sptr, "MODE");

  if (IsServer(cptr))
    acptr = findNUser(parv[1]);
  
  if (!acptr && !(acptr = FindUser(parv[1])))
  {
    if (MyConnect(sptr))
      send_reply(sptr, ERR_NOSUCHCHANNEL, parv[1]);
    return 0;
  }

  if (IsServer(sptr) || sptr != acptr)
  {
    if (IsServer(sptr)) {
      if (!MyConnect(acptr)) {
        /* Just propagate and ignore */
        char buf[BUFSIZE] = "";
        for (i=1;i<parc;i++) {
          strcat(buf, " ");
          strcat(buf, parv[i]);
        }
        sendcmdto_serv_butone(sptr, CMD_MODE, cptr, "%s", buf);
        return 0;
      }
      force = 1;
    }
    else {
      send_reply(sptr, ERR_USERSDONTMATCH);
      return 0;
    }
  }

  if (parc < 3)
  {
    m = buf;
    *m++ = '+';
    for (i = 0; i < USERMODELIST_SIZE; ++i) {
      if (HasFlag(acptr, userModeList[i].flag) &&
	  ((userModeList[i].flag != FLAG_ACCOUNT) &&
	   (userModeList[i].flag != FLAG_SETHOST) &&
           (userModeList[i].flag != FLAG_CLOAKHOST) &&
           (userModeList[i].flag != FLAG_CLOAKIP) &&
	   (userModeList[i].flag != FLAG_FAKEHOST)))

        *m++ = userModeList[i].c;
    }
    *m = '\0';
    send_reply(acptr, RPL_UMODEIS, buf);
    if (HasFlag(acptr, FLAG_SERVNOTICE) && MyConnect(acptr)
        && cli_snomask(acptr) !=
        (unsigned int)(IsOper(acptr) ? SNO_OPERDEFAULT : SNO_DEFAULT))
      send_reply(acptr, RPL_SNOMASK, cli_snomask(acptr), cli_snomask(acptr));
    return 0;
  }

  /*
   * find flags already set for user
   * why not just copy them?
   */
  setflags = cli_flags(acptr);

  if (MyConnect(acptr))
    tmpmask = cli_snomask(acptr);

  /*
   * parse mode change string(s)
   */
  for (p = &parv[2]; *p; p++) {       /* p is changed in loop too */
    for (m = *p; *m; m++) {
      switch (*m) {
      case '+':
        what = MODE_ADD;
        break;
      case '-':
        what = MODE_DEL;
        break;
      case 's':
        if (*(p + 1) && is_snomask(*(p + 1))) {
          snomask_given = 1;
          tmpmask = umode_make_snomask(tmpmask, *++p, what);
          tmpmask &= (IsAnOper(acptr) ? SNO_ALL : SNO_USER);
        }
        else
          tmpmask = (what == MODE_ADD) ?
              (IsAnOper(acptr) ? SNO_OPERDEFAULT : SNO_DEFAULT) : 0;
        if (tmpmask)
	  SetServNotice(acptr);
        else
	  ClearServNotice(acptr);
        break;
      case 'w':
        if (what == MODE_ADD)
          SetWallops(acptr);
        else
          ClearWallops(acptr);
        break;
      case 'a':
        if (what == MODE_ADD)
          SetAdmin(acptr);
        else
          ClearAdmin(acptr);
        break;
      case 'o':
        if (what == MODE_ADD) {
          if (force)
            cli_handler(acptr) = OPER_HANDLER;
          SetOper(acptr);
        }
        else {
          ClearAdmin(acptr);
          ClearOper(acptr);
          ClearLocOp(acptr);
          if (MyConnect(acptr)) {
            tmpmask = cli_snomask(acptr) & ~SNO_OPER;
            cli_handler(acptr) = CLIENT_HANDLER;
            cli_oflags(acptr) = 0;
          }
        }
        break;
      case 'O':
        if (what == MODE_ADD) {
          SetLocOp(acptr);
          if (force && MyConnect(acptr))
            cli_handler(acptr) = OPER_HANDLER;
        }
        else {
          ClrFlag(acptr, FLAG_OPER);
          ClrFlag(acptr, FLAG_LOCOP);
          if (MyConnect(acptr)) {
            tmpmask = cli_snomask(acptr) & ~SNO_OPER;
            cli_handler(acptr) = CLIENT_HANDLER;
          }
        }
        break;
      case 'i':
        if (what == MODE_ADD)
          SetInvisible(acptr);
        else
          if (!feature_bool(FEAT_AUTOINVISIBLE) || IsOper(sptr)) /* Don't allow non-opers to -i if FEAT_AUTOINVISIBLE is set */
            ClearInvisible(sptr);
        break;
      case 'd':
        if (what == MODE_ADD)
          SetDeaf(acptr);
        else
          ClearDeaf(acptr);
        break;
      case 'k':
        if (what == MODE_ADD)
          SetChannelService(acptr);
        else
          ClearChannelService(acptr);
        break;
      case 'X':
        if (what == MODE_ADD)
          SetXtraOp(acptr);
        else
          ClearXtraOp(acptr);
        break;
      case 'n':
        if (what == MODE_ADD)
          SetNoChan(acptr);
        else
          ClearNoChan(acptr);
        break;
      case 'I':
        if (what == MODE_ADD)
          SetNoIdle(acptr);
        else
          ClearNoIdle(acptr);
        break;
      case 'g':
        if (what == MODE_ADD)
          SetDebug(acptr);
        else
          ClearDebug(acptr);
        break;
      case 'x':
        if (what == MODE_ADD) {
	  SetHiddenHost(acptr);
	  if (!FlagHas(&setflags, FLAG_HIDDENHOST))
	    do_host_hiding = 1;
	} else {
	  if (feature_int(FEAT_HOST_HIDING_STYLE) == 2) {
  	    ircd_strncpy(cli_user(acptr)->host, cli_user(acptr)->realhost, HOSTLEN);
	    ClearHiddenHost(acptr);
	  }
	}
	break;
      case 'C':
        if (what == MODE_ADD) {
          if (*(p + 1)) {
            SetCloakHost(acptr);
            ircd_strncpy(cli_user(acptr)->virthost, *++p, HOSTLEN);
          }
        }
      case 'c':
        if (what == MODE_ADD) {
          if (*(p + 1)) {
            SetCloakIP(acptr);
            ircd_strncpy(cli_user(acptr)->virtip, *++p, HOSTLEN);
          }
        }
      case 'h':
        if (what == MODE_ADD) {
          if (*(p + 1) && is_hostmask(*(p + 1))) {
            do_set_host = 1;
            hostmask = *++p;
            /* DON'T step p onto the trailing NULL in the parameter array! - splidge */
            if (*(p+1)) 
              password = *++p;
            else
              password = NULL;
          } else {
            if (!*(p+1))     
              send_reply(acptr, ERR_NEEDMOREPARAMS, "SETHOST");
            else {
              send_reply(acptr, ERR_BADHOSTMASK, *(p+1));
              p++; /* Swallow the arg anyway */
            }
          }
        } else { /* MODE_DEL */
          do_set_host = 1;
          hostmask = NULL;
          password = NULL;
        }
        break;
      case 'R':
	if (what == MODE_ADD)
	  SetAccountOnly(acptr);
	else
	  ClearAccountOnly(acptr);
	break;
      case 'B':
	if (what == MODE_ADD)
	  SetBot(acptr);
	else
	  ClearBot(acptr);
	break;
      case 'W':
	if (what == MODE_ADD)
	  SetWhois(acptr);
	else
	  ClearWhois(acptr);
	break;
      case 'z':
        if ( IsServer(cptr) ) {
          if (what == MODE_ADD) {
            SetSSL(acptr);
          }
          else {
            ClearSSL(acptr);
          }
        }
        break;
      default:
	send_reply(acptr, ERR_UMODEUNKNOWNFLAG, *m);
        break;
      }
    }
  }
  /*
   * Evaluate rules for new user mode
   * Stop users making themselves operators too easily:
   */
  if (!IsServer(cptr) && !is_svsmode) {
    if ((!FlagHas(&setflags, FLAG_ADMIN) && IsAdmin(acptr)) || !feature_bool(FEAT_OPERFLAGS))
      ClearAdmin(acptr);
    if (!FlagHas(&setflags, FLAG_OPER) && IsOper(acptr))
      ClearOper(acptr);
    if (!FlagHas(&setflags, FLAG_LOCOP) && IsLocOp(acptr))
      ClearLocOp(acptr);
    /*
     * new umode; servers can set it, local users cannot;
     * prevents users from /kick'ing or /mode -o'ing
     *
     * ASUKA: Allow opers to set +k.  Also, restrict +XnI to
     * opers only also.
     */
    if (!FlagHas(&setflags, FLAG_CHSERV) &&
	!(feature_bool(FEAT_OPER_XTRAOP) && IsOper(acptr) &&
	((feature_int(FEAT_XTRAOP_CLASS) > 0) &&
	 (get_client_class(acptr) == feature_int(FEAT_XTRAOP_CLASS)))))
      ClearChannelService(acptr);
    if (!FlagHas(&setflags, FLAG_XTRAOP) &&
	!(feature_bool(FEAT_OPER_XTRAOP) && IsOper(acptr) &&
	((feature_int(FEAT_XTRAOP_CLASS) > 0) &&
	 (get_client_class(acptr) == feature_int(FEAT_XTRAOP_CLASS)))))
      ClearXtraOp(acptr);
    if (!FlagHas(&setflags, FLAG_NOCHAN) && !(feature_bool(FEAT_OPER_HIDECHANS) && IsOper(acptr)))
      ClearNoChan(acptr);
    if (!FlagHas(&setflags, FLAG_NOIDLE) && !(feature_bool(FEAT_OPER_HIDEIDLE) && IsOper(acptr)))
      ClearNoIdle(acptr);

    /*
     * We have to deal with +B first before getting to +s or else we'll
     * run into problems (interference with +s if user is +B). -reed
     */
    if (!(FlagHas(&setflags, FLAG_BOT)) &&
	(get_client_class(acptr) != feature_int(FEAT_BOT_CLASS)))
      ClearBot(acptr);

    /*
     * only send wallops to opers
     */
    if (feature_bool(FEAT_WALLOPS_OPER_ONLY) && !IsAnOper(acptr) &&
	!FlagHas(&setflags, FLAG_WALLOP))
      ClearWallops(acptr);

    if (feature_bool(FEAT_HIS_SNOTICES_OPER_ONLY) && MyConnect(acptr) && 
	!IsAnOper(acptr) && !IsBot(acptr) &&
	!FlagHas(&setflags, FLAG_SERVNOTICE)) {
      ClearServNotice(acptr);
      set_snomask(acptr, 0, SNO_SET);
    }

    if (feature_bool(FEAT_HIS_DEBUG_OPER_ONLY) && !IsAnOper(acptr) && 
	!FlagHas(&setflags, FLAG_DEBUG))
      ClearDebug(acptr);

    if (!FlagHas(&setflags, FLAG_WHOIS) &&
	!(feature_bool(FEAT_OPER_WHOIS_PARANOIA) && IsOper(acptr)))
      ClearWhois(acptr);
  }

  if (MyConnect(acptr)) {
    if ((FlagHas(&setflags, FLAG_OPER) || FlagHas(&setflags, FLAG_LOCOP)) &&
        !IsAnOper(acptr))
      det_confs_butmask(acptr, CONF_CLIENT & ~CONF_OPS);

    if (SendServNotice(acptr)) {
      if (tmpmask != cli_snomask(acptr))
	set_snomask(acptr, tmpmask, SNO_SET);
      if (cli_snomask(acptr) && snomask_given)
	send_reply(acptr, RPL_SNOMASK, cli_snomask(acptr), cli_snomask(acptr));
    } else
      set_snomask(acptr, 0, SNO_SET);
  }
  /*
   * Compare new flags with old flags and send string which
   * will cause servers to update correctly.
   */
  if (!FlagHas(&setflags, FLAG_OPER) && IsOper(acptr)) { /* user now oper */
    ++UserStats.opers;
    client_set_privs(acptr); /* may set propagate privilege */
  }
  if (HasPriv(acptr, PRIV_PROPAGATE)) /* remember propagate privilege setting */
    prop = 1;
  if (FlagHas(&setflags, FLAG_OPER) && !IsOper(acptr)) { /* user no longer oper */
    --UserStats.opers;
    client_set_privs(acptr); /* will clear propagate privilege */
  }
  if (FlagHas(&setflags, FLAG_INVISIBLE) && !IsInvisible(acptr))
    --UserStats.inv_clients;
  if (!FlagHas(&setflags, FLAG_INVISIBLE) && IsInvisible(acptr))
    ++UserStats.inv_clients;
  if (!FlagHas(&setflags, FLAG_HIDDENHOST) && do_host_hiding) {
    if (feature_int(FEAT_HOST_HIDING_STYLE) == 1) {
      if (do_host_hiding)
	hide_hostmask(acptr);
    }
    else if (feature_int(FEAT_HOST_HIDING_STYLE) == 2) {
      ircd_snprintf(0, cli_user(acptr)->host, HOSTLEN, "%s", cli_user(acptr)->virthost);
      SetFlag(acptr, FLAG_HIDDENHOST);
    }
  }
  if (do_set_host) {
    /* We clear the flag in the old mask, so that the +h will be sent */
    /* Only do this if we're SETTING +h and it succeeded */
    if (set_hostmask(sptr, acptr, hostmask, password) && hostmask)
      FlagClr(&setflags, FLAG_SETHOST);
  }
  send_umode_out(cptr, acptr, &setflags, prop);
  if (force) /* Let the user know */
    send_umode_out(acptr, acptr, &setflags, 1);

  return 0;
}

/*
 * Build umode string for BURST command
 * --Run
 */
char *umode_str(struct Client *cptr)
{
  char* m = umodeBuf;                /* Maximum string size: "owidgrx\0" */
  int   i;
  struct Flags c_flags;

  c_flags = cli_flags(cptr);
  if (HasPriv(cptr, PRIV_PROPAGATE))
    FlagSet(&c_flags, FLAG_OPER);
  else
    FlagClr(&c_flags, FLAG_OPER);

  for (i = 0; i < USERMODELIST_SIZE; ++i) {
    if (FlagHas(&c_flags, userModeList[i].flag) &&
        (userModeList[i].flag >= FLAG_GLOBAL_UMODES))
      *m++ = userModeList[i].c;
  }

  if (IsAccount(cptr)) {
    char* t = cli_user(cptr)->account;

    *m++ = ' ';
    while ((*m++ = *t++))
      ; /* Empty loop */

    if (cli_user(cptr)->acc_create) {
      char nbuf[20];
      Debug((DEBUG_DEBUG, "Sending timestamped account in user mode for "
	     "account \"%s\"; timestamp %Tu", cli_user(cptr)->account,
	     cli_user(cptr)->acc_create));
      ircd_snprintf(0, t = nbuf, sizeof(nbuf), ":%Tu",
		    cli_user(cptr)->acc_create);
      m--; /* back up over previous nul-termination */
      while ((*m++ = *t++))
	; /* Empty loop */
    }
    m--; /* back up over previous nul-termination */
  }

  if (IsSetHost(cptr)) {
    char* t;
    char nbuf[USERLEN + HOSTLEN + 2];
    ircd_snprintf(0, t = nbuf, sizeof(nbuf), "%s@%s",
		  cli_user(cptr)->username, cli_user(cptr)->host);

    *m++ = ' ';
    while ((*m++ = *t++))
      ; /* Empty loop */
    m--; /* back up over previous nul-termination */
  }

  if (HasFakeHost(cptr)) {
    char* t = cli_user(cptr)->fakehost;

    *m++ = ' ';
    while ((*m++ = *t++))
      ; /* Empty loop */

     m--; /* back up over previous nul-termination */
   }

  if (HasCloakHost(cptr)) {
    char* t = cli_user(cptr)->virthost;

    *m++ = ' ';
    while ((*m++ = *t++))
      ; /* Empty loop */

     m--; /* back up over previous nul-termination */
   }

  if (HasCloakIP(cptr)) {
    char* t = cli_user(cptr)->virtip;

    *m++ = ' ';
    while ((*m++ = *t++))
      ; /* Empty loop */
   }

  *m = '\0';

  return umodeBuf;                /* Note: static buffer, gets
                                   overwritten by send_umode() */
}

/*
 * Send the MODE string for user (sptr) to connection cptr
 * -avalon
 */
void send_umode(struct Client *cptr, struct Client *sptr, struct Flags *old, int sendset)
{
  int i;
  int flag;
  int needhost = 0;
  char *m;
  int what = MODE_NULL;

  /*
   * Build a string in umodeBuf to represent the change in the user's
   * mode between the new (cli_flags(sptr)) and 'old', but skipping
   * the modes indicated by sendset.
   */
  m = umodeBuf;
  *m = '\0';
  for (i = 0; i < USERMODELIST_SIZE; ++i) {
    flag = userModeList[i].flag;
    if (FlagHas(old, flag) == HasFlag(sptr, flag))
      continue;
    switch (sendset)
    {
      case ALL_UMODES:
        break;
      case SEND_UMODES_BUT_OPER:
        if (flag == FLAG_OPER)
          continue;
        /* and fall through */
      case SEND_UMODES:
        if (flag < FLAG_GLOBAL_UMODES)
          continue;
        break;
    }

    if (flag == FLAG_CLOAKHOST) {
      /* Don't send to users */
      if (cptr && MyUser(cptr))
        continue;

      /* If we're setting +C, add the parameter later */
      if (!FlagHas(old, flag))
        needhost++;
    }

    if (flag == FLAG_CLOAKIP) {
      /* Don't send to users */
      if (cptr && MyUser(cptr))
        continue;

      /* If we're setting +c, add the parameter later */
      if (!FlagHas(old, flag))
        needhost++;
    }

    /* Special case for SETHOST.. */
    if (flag == FLAG_SETHOST) {
      /* Don't send to users */
      if (cptr && MyUser(cptr))
      	continue;
      
      /* If we're setting +h, add the parameter later */
      if (!FlagHas(old, flag))	
      	needhost++;
    } else if (flag == FLAG_ACCOUNT || flag == FLAG_FAKEHOST)
      continue;
    if (FlagHas(old, flag))
    {
      if (what == MODE_DEL)
        *m++ = userModeList[i].c;
      else
      {
        what = MODE_DEL;
        *m++ = '-';
        *m++ = userModeList[i].c;
      }
    }
    else /* !FlagHas(old, flag) */
    {
      if (what == MODE_ADD)
        *m++ = userModeList[i].c;
      else
      {
        what = MODE_ADD;
        *m++ = '+';
        *m++ = userModeList[i].c;
      }
    }
  }
  if (needhost) {
    *m++ = ' ';
    ircd_snprintf(0, m, USERLEN + HOSTLEN + 1, "%s@%s", cli_user(sptr)->username,
         cli_user(sptr)->host);
  } else
    *m = '\0';
  if (*umodeBuf && cptr)
    sendcmdto_one(sptr, CMD_MODE, cptr, "%s %s", cli_name(sptr), umodeBuf);
}

/*
 * Check to see if this resembles a sno_mask.  It is if 1) there is
 * at least one digit and 2) The first digit occurs before the first
 * alphabetic character.
 */
int is_snomask(char *word)
{
  if (word)
  {
    for (; *word; word++)
      if (IsDigit(*word))
        return 1;
      else if (IsAlpha(*word))
        return 0;
  }
  return 0;
}

/*
 * Check to see if it resembles a valid hostmask.
 */
int is_hostmask(char *word)
{
  int i = 0;
  char *host;

  Debug((DEBUG_INFO, "is_hostmask() %s", word));

  if (strlen(word) > (HOSTLEN + USERLEN + 1) || strlen(word) <= 0)
    return 0;

  /* if a host is specified, make sure it's valid */
  host = strrchr(word, '@');
  if (host) {
     if (strlen(++host) < 1)
       return 0;
     if (strlen(host) > HOSTLEN)
       return 0;
  }

  if (word) {
    if ('@' == *word)	/* no leading @'s */
        return 0;

    if ('#' == *word) {	/* numeric index given? */
      for (word++; *word; word++) {
        if (!IsDigit(*word))
          return 0;
      }
      return 1;
    }

    /* normal hostmask, account for at most one '@' */
    for (; *word; word++) {
      if ('@' == *word) {
        i++;
        continue;
      }
      if (!IsHostChar(*word))
        return 0;
    }
    return (1 < i) ? 0 : 1; /* no more than on '@' */
  }
  return 0;
}

/*
 * IsVhost() - Check if given host is a valid spoofhost
 * (ie: configured thru a S:line)
 */
static char *IsVhost(char *hostmask, int oper)
{
  unsigned int i = 0, y = 0;
  struct sline *sconf;

  Debug((DEBUG_INFO, "IsVhost() %s", hostmask));

  if (EmptyString(hostmask))
    return NULL;

  /* spoofhost specified as index, ie: #27 */
  if ('#' == hostmask[0]) {
    y = atoi(hostmask + 1);
    for (i = 0, sconf = GlobalSList; sconf; sconf = sconf->next) {
      if (!oper && EmptyString(sconf->passwd))
        continue;
      if (y == ++i)
        return sconf->spoofhost;
    }
    return NULL;
  }

  /* spoofhost specified as host, ie: host.cc */
  for (sconf = GlobalSList; sconf; sconf = sconf->next)
    if (strCasediff(hostmask, sconf->spoofhost) == 0)
      return sconf->spoofhost;

  return NULL;
}

/*
 * IsVhostPass() - Check if given spoofhost has a password
 * associated with it, and if, return the password (cleartext)
 */
static char *IsVhostPass(char *hostmask)
{
  struct sline *sconf;

  Debug((DEBUG_INFO, "IsVhostPass() %s", hostmask));

  if (EmptyString(hostmask))
    return NULL;

  for (sconf = GlobalSList; sconf; sconf = sconf->next)
    if (strCasediff(hostmask, sconf->spoofhost) == 0) {
      Debug((DEBUG_INFO, "sconf->passwd %s", sconf->passwd));
      return EmptyString(sconf->passwd) ? NULL : sconf->passwd;
    }

  return NULL;
}

/*
 * If it begins with a +, count this as an additive mask instead of just
 * a replacement.  If what == MODE_DEL, "+" has no special effect.
 */
unsigned int umode_make_snomask(unsigned int oldmask, char *arg, int what)
{
  unsigned int sno_what;
  unsigned int newmask;
  if (*arg == '+')
  {
    arg++;
    if (what == MODE_ADD)
      sno_what = SNO_ADD;
    else
      sno_what = SNO_DEL;
  }
  else if (*arg == '-')
  {
    arg++;
    if (what == MODE_ADD)
      sno_what = SNO_DEL;
    else
      sno_what = SNO_ADD;
  }
  else
    sno_what = (what == MODE_ADD) ? SNO_SET : SNO_DEL;
  /* pity we don't have strtoul everywhere */
  newmask = (unsigned int)atoi(arg);
  if (sno_what == SNO_DEL)
    newmask = oldmask & ~newmask;
  else if (sno_what == SNO_ADD)
    newmask |= oldmask;
  return newmask;
}

static void delfrom_list(struct Client *cptr, struct SLink **list)
{
  struct SLink* tmp;
  struct SLink* prv = NULL;

  for (tmp = *list; tmp; tmp = tmp->next) {
    if (tmp->value.cptr == cptr) {
      if (prv)
        prv->next = tmp->next;
      else
        *list = tmp->next;
      free_link(tmp);
      break;
    }
    prv = tmp;
  }
}

/*
 * This function sets a Client's server notices mask, according to
 * the parameter 'what'.  This could be even faster, but the code
 * gets mighty hard to read :)
 */
void set_snomask(struct Client *cptr, unsigned int newmask, int what)
{
  unsigned int oldmask, diffmask;        /* unsigned please */
  int i;
  struct SLink *tmp;

  oldmask = cli_snomask(cptr);

  if (what == SNO_ADD)
    newmask |= oldmask;
  else if (what == SNO_DEL)
    newmask = oldmask & ~newmask;
  else if (what != SNO_SET)        /* absolute set, no math needed */
    sendto_opmask_butone(0, SNO_OLDSNO, "setsnomask called with %d ?!", what);

  newmask &= (IsAnOper(cptr) ? SNO_ALL : SNO_USER);

  diffmask = oldmask ^ newmask;

  for (i = 0; diffmask >> i; i++) {
    if (((diffmask >> i) & 1))
    {
      if (((newmask >> i) & 1))
      {
        tmp = make_link();
        tmp->next = opsarray[i];
        tmp->value.cptr = cptr;
        opsarray[i] = tmp;
      }
      else
        /* not real portable :( */
        delfrom_list(cptr, &opsarray[i]);
    }
  }
  cli_snomask(cptr) = newmask;
}

/*
 * is_silenced : Does the actual check wether sptr is allowed
 *               to send a message to acptr.
 *               Both must be registered persons.
 * If sptr is silenced by acptr, his message should not be propagated,
 * but more over, if this is detected on a server not local to sptr
 * the SILENCE mask is sent upstream.
 */
int is_silenced(struct Client *sptr, struct Client *acptr)
{
  struct SLink *lp;
  struct User *user;
  static char sender[HOSTLEN + NICKLEN + USERLEN + 5];
  static char senderip[16 + NICKLEN + USERLEN + 5];
  static char senderh[HOSTLEN + ACCOUNTLEN + USERLEN + 6];

  if (!cli_user(acptr) || !(lp = cli_user(acptr)->silence) || !(user = cli_user(sptr)))
    return 0;
  ircd_snprintf(0, sender, sizeof(sender), "%s!%s@%s", cli_name(sptr),
		user->username, user->host);
  ircd_snprintf(0, senderip, sizeof(senderip), "%s!%s@%s", cli_name(sptr),
		user->username, ircd_ntoa((const char*) &(cli_ip(sptr))));
  if (((feature_int(FEAT_HOST_HIDING_STYLE) == 1) ? HasHiddenHost(sptr) :
       IsHiddenHost(sptr)) || HasSetHost(sptr))
    ircd_snprintf(0, senderh, sizeof(senderh), "%s!%s@%s", cli_name(sptr),
		  user->username, user->realhost);
  for (; lp; lp = lp->next)
  {
    if ((!(lp->flags & CHFL_SILENCE_IPMASK) && (!match(lp->value.cp, sender) ||
        (HasHiddenHost(sptr) && !match(lp->value.cp, senderh)) ||
        (HasSetHost(sptr) && !match(lp->value.cp, senderh)))) ||
        ((lp->flags & CHFL_SILENCE_IPMASK) && !match(lp->value.cp, senderip)))
    {
/*      if (!MyConnect(sptr))
 *      {
 *       sendcmdto_one(acptr, CMD_SILENCE, cli_from(sptr), "%C %s", sptr,
 *                     lp->value.cp);
 *     }
 */
      return 1;
    }
  }
  return 0;
}

/*
 * del_silence
 *
 * Removes all silence masks from the list of sptr that fall within `mask'
 * Returns -1 if none where found, 0 otherwise.
 */
int del_silence(struct Client *sptr, char *mask)
{
  struct SLink **lp;
  struct SLink *tmp;
  int ret = -1;

  for (lp = &(cli_user(sptr))->silence; *lp;) {
    if (!mmatch(mask, (*lp)->value.cp))
    {
      tmp = *lp;
      *lp = tmp->next;
      MyFree(tmp->value.cp);
      free_link(tmp);
      ret = 0;
    }
    else
      lp = &(*lp)->next;
  }
  return ret;
}

int add_silence(struct Client* sptr, const char* mask)
{
  struct SLink *lp, **lpp;
  int cnt = 0, len = strlen(mask);
  char *ip_start;

  for (lpp = &(cli_user(sptr))->silence, lp = *lpp; lp;)
  {
    if (0 == ircd_strcmp(mask, lp->value.cp))
      return -1;
    if (!mmatch(mask, lp->value.cp))
    {
      struct SLink *tmp = lp;
      *lpp = lp = lp->next;
      MyFree(tmp->value.cp);
      free_link(tmp);
      continue;
    }
    if (MyUser(sptr))
    {
      len += strlen(lp->value.cp);
      if ((len > (feature_int(FEAT_AVBANLEN) * feature_int(FEAT_MAXSILES))) ||
	  (++cnt >= feature_int(FEAT_MAXSILES)))
      {
        send_reply(sptr, ERR_SILELISTFULL, mask);
        return -1;
      }
      else if (!mmatch(lp->value.cp, mask))
        return -1;
    }
    lpp = &lp->next;
    lp = *lpp;
  }
  lp = make_link();
  memset(lp, 0, sizeof(struct SLink));
  lp->next = cli_user(sptr)->silence;
  lp->value.cp = (char*) MyMalloc(strlen(mask) + 1);
  assert(0 != lp->value.cp);
  strcpy(lp->value.cp, mask);
  if ((ip_start = strrchr(mask, '@')) && check_if_ipmask(ip_start + 1))
    lp->flags = CHFL_SILENCE_IPMASK;
  cli_user(sptr)->silence = lp;
  return 0;
}

/* handler for B:line commands -akl (adam@PGPN.com) */
int
lsc(struct Client *cptr, char *target, const char *prepend,
    const char *servicename, int parc, char* parv[])
{
  char *tmp;
  char msg[255] = "";
  char *kludge;
  int x; 

  if (!IsRegistered(cptr))
    return 0;

  if (feature_bool(FEAT_IDLE_FROM_MSG))
    cli_user(cptr)->last = CurrentTime;
  
  kludge = parv[1];

  if (strcmp(prepend, "*")) {
    strncpy(msg, prepend, sizeof(msg) - 1);
    strncat(msg, " ", sizeof(msg) - 1 - strlen(msg));
  }

  for (x = 1; x != parc; x++) {
     strncat(msg, parv[x], sizeof(msg) - 1 - strlen(msg));
     if (x != (parc - 1))
       strncat(msg, " ", sizeof(msg) - 1 - strlen(msg));
  }

  if (EmptyString(msg))
   return send_reply(cptr, ERR_NOTEXTTOSEND);
  
   /*
    * B:X2:#supersecretchannel:*
    * -- technically should be valid, so we allow it.
    * (note: doesn't work, though included in code here for sanity)
    * B:X2:X2@X2.AfterNET.Services:*
    * -- this is how all the lines *SHOULD* be formed, but I'm
    * sure many nets won't do it this way
    * B:X2:X2:*
    * -- equivelent of /msg X2
    */

   if (IsChannelPrefix(*target))
     relay_channel_message(cptr, target, msg, 1);
   else if ((tmp = strchr(target, '@')))
     relay_directed_message(cptr, target, tmp, msg);
   else
     relay_private_message(cptr, target, msg);

   return 0;
}

/** Describes one element of the ISUPPORT list. */
struct ISupport {
    const char *is_name; /**< Name of supported feature. */
    enum {
        OPT_NONE,
        OPT_INT,
        OPT_STRING
    } is_type; /**< Type of the feature's value. */
    union {
        int iv;
        char *sv;
    } is_value; /**< Feature's value. */
    struct ISupport *is_next; /**< Pointer to next feature. */
};

static struct ISupport *isupport; /**< List of supported ISUPPORT features. */
static struct SLink *isupport_lines; /**< List of formatted ISUPPORT lines. */

/** Mark #isupport_lines as dirty and needing a rebuild. */
static void
touch_isupport()
{
  while (isupport_lines) {
    struct SLink *link = isupport_lines;
    isupport_lines = link->next;
    MyFree(link->value.cp);
    free_link(link);
  }
}

/** Get (or create) an ISupport element from #isupport with the
 * specified name and OPT_NONE type.
 * @param[in] name Name of ISUPPORT feature to describe.
 * @return Pre-existing or newly allocated ISupport structure.
 */
static struct ISupport *
get_clean_isupport(const char *name)
{
  struct ISupport *isv, *prev;

  for (isv = isupport, prev = 0; isv; prev = isv, isv = isv->is_next) {
    if (strcmp(isv->is_name, name))
      continue;
    if (isv->is_type == OPT_STRING)
      MyFree(isv->is_value.sv);
    break;
  }

  if (!isv) {
    isv = MyMalloc(sizeof(*isv));
    if (prev)
        prev->is_next = isv;
    else
        isupport = isv;
    isv->is_next = NULL;
  }

  isv->is_name = name;
  isv->is_type = OPT_NONE;
  touch_isupport();
  return isv;
}

/** Declare support for a feature with no parameter.
 * @param[in] name Name of ISUPPORT feature to announce.
 */
static
void add_isupport(const char *name)
{
  get_clean_isupport(name);
}

/** Declare support for a feature with an integer parameter.
 * @param[in] name Name of ISUPPORT feature to announce.
 * @param[in] value Value associated with the feature.
 */
void add_isupport_i(const char *name, int value)
{
  struct ISupport *isv = get_clean_isupport(name);
  isv->is_type = OPT_INT;
  isv->is_value.iv = value;
}

/** Declare support for a feature with a string parameter.
 * @param[in] name Name of ISUPPORT feature to announce.
 * @param[in] value Value associated with the feature.
 */
void add_isupport_s(const char *name, const char *value)
{
  struct ISupport *isv = get_clean_isupport(name);
  isv->is_type = OPT_STRING;
  DupString(isv->is_value.sv, value);
}

/** Stop announcing support for a feature.
 * @param[in] name Name of ISUPPORT feature to revoke.
 */
void del_isupport(const char *name)
{
  struct ISupport *isv, *prev;

  for (isv = isupport, prev = 0; isv; prev = isv, isv = isv->is_next) {
    if (strcmp(isv->is_name, name))
      continue;
    if (isv->is_type == OPT_STRING)
      MyFree(isv->is_value.sv);
    if (prev)
      prev->is_next = isv->is_next;
    else
      isupport = isv->is_next;
    break;
  }
  touch_isupport();
}

/** Populate #isupport_lines from #isupport. */
static void
build_isupport_lines()
{
  struct ISupport *is;
  struct SLink **plink;
  char buf[BUFSIZE];
  int used, len, usable;

  /* Extra buffer space for :me.name 005 ClientNick <etc> */
  assert(isupport_lines == 0);
  usable = BUFSIZE - 10
      - strlen(cli_name(&me))
      - strlen(get_error_numeric(RPL_ISUPPORT)->format)
      - feature_int(FEAT_NICKLEN);
  plink = &isupport_lines;
  used = 0;

  /* For each ISUPPORT feature, */
  for (is = isupport; is; ) {
    /* Try to append it to the buffer. */
    switch (is->is_type) {
    case OPT_NONE:
      len = ircd_snprintf(NULL, buf + used, usable - used,
                          " %s", is->is_name);
      break;
    case OPT_INT:
      len = ircd_snprintf(NULL, buf + used, usable - used,
                          " %s=%d", is->is_name, is->is_value.iv);
      break;
    case OPT_STRING:
      len = ircd_snprintf(NULL, buf + used, usable - used,
                          " %s=%s", is->is_name, is->is_value.sv);
      break;
    default:
      assert(0 && "Unhandled ISUPPORT option type");
      len = 0;
      break;
    }

    /* If it fits, move on; else flush buffer and try again. */
    if (len + used < usable) {
      used += len;
      is = is->is_next;
    } else {
      assert(used > 0);
      *plink = make_link();
      DupString((*plink)->value.cp, buf + 1);
      (*plink)->next = 0;
      plink = &(*plink)->next;
      used = 0;
    }
  }

  /* Terminate buffer and flush last bit of it out. */
  buf[used] = '\0';
  *plink = make_link();
  DupString((*plink)->value.cp, buf + 1);
  (*plink)->next = 0;
}

/** Announce fixed-parameter and parameter-free ISUPPORT features
 * provided by ircu's core code.
 */
void init_isupport(void)
{
  add_isupport("NAMESX");
  add_isupport("UHNAMES");
  add_isupport("WHOX");
  add_isupport("WALLCHOPS");
  add_isupport("WALLVOICES");
  add_isupport("USERIP");
  add_isupport("CPRIVMSG");
  add_isupport("CNOTICE");
  add_isupport_i("MODES", MAXMODEPARAMS);
  add_isupport_i("MAXNICKLEN", NICKLEN);
  add_isupport_i("TOPICLEN", TOPICLEN);
  add_isupport_i("AWAYLEN", AWAYLEN);
  add_isupport_i("KICKLEN", TOPICLEN);
  add_isupport_i("MAXCHANNELLEN", CHANNELLEN);
  add_isupport_s("CASEMAPPING", "rfc1459");
  add_isupport_s("ELIST", "MNUCT");
}

/** Send RPL_ISUPPORT lines to \a cptr.
 * @param[in] cptr Client to send ISUPPORT to.
 * @return Zero.
 */
int
send_supported(struct Client *cptr)
{
  struct SLink *line;

  if (isupport && !isupport_lines)
    build_isupport_lines();

  for (line = isupport_lines; line; line = line->next)
    send_reply(cptr, RPL_ISUPPORT, line->value.cp);

  return 0; /* convenience return, if it's ever needed */
}

