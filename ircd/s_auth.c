/************************************************************************
 *   IRC - Internet Relay Chat, src/s_auth.c
 *   Copyright (C) 1992 Darren Reed
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 3, or (at your option)
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Changes:
 *   July 6, 1999 - Rewrote most of the code here. When a client connects
 *     to the server and passes initial socket validation checks, it
 *     is owned by this module (auth) which returns it to the rest of the
 *     server when dns and auth queries are finished. Until the client is
 *     released, the server does not know it exists and does not process
 *     any messages from it.
 *     --Bleep  Thomas Helvey <tomh@inxpress.net>
 */
/** @file
 * @brief Implementation of DNS and ident lookups.
 * @version $Id$
 */
#include "config.h"

#include "s_auth.h"
#include "client.h"
#include "IPcheck.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_chattr.h"
#include "ircd_events.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_osdep.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "ircd_struct.h"
#include "list.h"
#include "numeric.h"
#include "querycmds.h"
#include "res.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "send.h"
#ifdef USE_SSL
#include "ssl.h"
#endif /* USE_SSL */
#include "sys.h"               /* TRUE bleah */

#include <arpa/inet.h>         /* inet_netof */
/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>             /* struct hostent */
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

/** Array of message text (with length) pairs for AUTH status
 * messages.  Indexed using #ReportType.
 */
static struct {
  const char*  message;
  unsigned int length;
} HeaderMessages [] = {
#define MSG(STR) { STR, sizeof(STR) - 1 }
  MSG("NOTICE AUTH :*** Looking up your hostname\r\n"),
  MSG("NOTICE AUTH :*** Found your hostname\r\n"),
  MSG("NOTICE AUTH :*** Found your hostname, cached\r\n"),
  MSG("NOTICE AUTH :*** Couldn't look up your hostname\r\n"),
  MSG("NOTICE AUTH :*** Checking Ident\r\n"),
  MSG("NOTICE AUTH :*** Got ident response\r\n"),
  MSG("NOTICE AUTH :*** No ident response\r\n"),
  MSG("NOTICE AUTH :*** Your forward and reverse DNS do not match, "
    "ignoring hostname.\r\n"),
  MSG("NOTICE AUTH :*** Invalid hostname\r\n"),
  MSG("NOTICE AUTH :*** Checking your IP against DNS ban lists\r\n"),
  MSG("NOTICE AUTH :*** DNS ban list check failed\r\n"),
  MSG("NOTICE AUTH :*** DNS ban list check passed\r\n")
#undef MSG
};

/** Enum used to index messages in the HeaderMessages[] array. */
typedef enum {
  REPORT_DO_DNS,
  REPORT_FIN_DNS,
  REPORT_FIN_DNSC,
  REPORT_FAIL_DNS,
  REPORT_DO_ID,
  REPORT_FIN_ID,
  REPORT_FAIL_ID,
  REPORT_IP_MISMATCH,
  REPORT_INVAL_DNS,
  REPORT_DO_DNSBL,
  REPORT_F_DNSBL,
  REPORT_P_DNSBL
} ReportType;

/** Sends response \a r (from #HeaderMessages) to client \a c. */
#ifdef USE_SSL
#define sendheader(c, r) \
   ssl_send(c, HeaderMessages[(r)].message, HeaderMessages[(r)].length)
#else
#define sendheader(c, r) \
   send(cli_fd(c), HeaderMessages[(r)].message, HeaderMessages[(r)].length, 0)
#endif /* USE_SSL */

struct AuthRequest* AuthPollList = 0; /* GLOBAL - auth queries pending io */
static struct AuthRequest* AuthIncompleteList = 0;

static void release_auth_client(struct Client* client);
static void unlink_auth_request(struct AuthRequest* request,
                                struct AuthRequest** list);
void free_auth_request(struct AuthRequest* auth);


/** Process a DNSBL DNS reply against DNSBLBlocks.
 * @param[in] vptr Callback data containing the AuthRequest.
 * @param[in] reply Struct containing the DNS reply.
 */
void auth_dnsbl_callback(void* vptr, struct DNSReply* reply)
{
  struct AuthRequest* auth = (struct AuthRequest*) vptr;

  assert(0 != auth);
  /*
   * need to do this here so auth_kill_client doesn't
   * try have the resolver delete the query it's about
   * to delete anyways. --Bleep
   */

  --cli_dnsblcount(auth->client);

  if (reply) {
    const struct hostent* hp = reply->hp;
    int i;

    assert(0 != hp);

    for (i = 0; hp->h_addr_list[i]; ++i) {
      if (find_blline(auth->client, ircd_ntoa((char*) hp->h_addr_list[i]), hp->h_name))
        Debug((DEBUG_DEBUG, "DNSBL Matched"));
    }
  }

  /*
   * If we're using DNSBL and we've processed the last reply,
   * mark stuff as done and clean-up.
   */
  if (feature_bool(FEAT_DNSBL_CHECKS) && (cli_dnsblcount(auth->client) == 0)) {
    if (!IsDoingAuth(auth) && !IsDNSPending(auth)) {
      ClearDNSBLPending(auth);
      if (IsUserPort(auth->client)) {
        if (IsDNSBL(auth->client))
          sendheader(auth->client, REPORT_F_DNSBL);
        else
          sendheader(auth->client, REPORT_P_DNSBL);
      }

      Debug((DEBUG_DEBUG, "Freeing auth after dnsbl %s@%s [%s]",
	     cli_username(auth->client), cli_sockhost(auth->client),
	     cli_sock_ip(auth->client)));
      log_write(LS_DNSBL, L_INFO, 0, "DNSBL Checks Complete %p", auth->client);

      release_auth_client(auth->client);
      unlink_auth_request(auth, &AuthIncompleteList);
      free_auth_request(auth);
    } else {
      if (IsUserPort(auth->client)) {
        if (IsDNSBL(auth->client))
          sendheader(auth->client, REPORT_F_DNSBL);
        else
          sendheader(auth->client, REPORT_P_DNSBL);
      }
      ClearDNSBLPending(auth);
      log_write(LS_DNSBL, L_INFO, 0, "DNSBL Checks Complete %p", auth->client);
    }
  }
  return;
}

/** Begin the DNSBL checks if there are any DNSBLBlocks setup.
 * @param[in] auth struct containing the AuthRequest.
 * @param[in] client struct containing the client who is connecting.
 */
static int start_dnsblcheck(struct AuthRequest* auth, struct Client* client)
{
  u_long ip;
  u_char *ipo = (u_char *) &ip;
  char hname[HOSTLEN + 1] = "";
  struct blline *blline;
  struct DNSQuery query;
  int i;

  if (!feature_bool(FEAT_DNSBL_CHECKS))
    return 0;

  query.vptr     = auth;
  query.callback = auth_dnsbl_callback;

  ip = cli_ip(auth->client).s_addr;

  if (IsUserPort(auth->client))
    sendheader(client, REPORT_DO_DNSBL);

  log_write(LS_DNSBL, L_INFO, 0, "Beginning DNSBL Checks %p [%s] (t %u)", auth->client,
            cli_sockhost(auth->client), GlobalBLCount);
  Debug((DEBUG_DEBUG, "DNSBL t: %u", GlobalBLCount));

  cli_dnsblcount(auth->client) = GlobalBLCount;
  SetDNSBLPending(auth);

  for (blline = GlobalBLList; blline; blline = blline->next) {
    ircd_snprintf(0, hname, HOSTLEN + 1, "%d.%d.%d.%d.%s", ipo[3],
                  ipo[2], ipo[1], ipo[0], blline->server);

    cli_dnsbl_reply(client) = gethost_byname(hname, &query);

    if (cli_dnsbl_reply(client)) {
      log_write(LS_DNSBL, L_INFO, 0, "DNSBL entry for %p was cached (%s %s)", auth->client,
                cli_dnsbl_reply(client)->hp->h_name, hname);
      Debug((DEBUG_DEBUG, "DNSBL entry for %p was cached (%s %s)", auth->client,  
            cli_dnsbl_reply(client)->hp->h_name, hname));
      ++(cli_dnsbl_reply(client))->ref_count;
      --cli_dnsblcount(auth->client);
      for (i = 0; cli_dnsbl_reply(client)->hp->h_addr_list[i]; ++i) {
        if (find_blline(auth->client, ircd_ntoa((char*)cli_dnsbl_reply(client)->hp->h_addr_list[i]), hname))
          Debug((DEBUG_DEBUG, "DNSBL Matched"));
      }
    }
  }

  if (cli_dnsblcount(auth->client) == 0) {
    if (IsUserPort(auth->client)) {
      if (IsDNSBL(auth->client))
        sendheader(auth->client, REPORT_F_DNSBL);
      else
        sendheader(auth->client, REPORT_P_DNSBL);
    }
    ClearDNSBLPending(auth);
    log_write(LS_DNSBL, L_INFO, 0, "DNSBL Checks Complete (none left to check) %s", auth->client);
  }

  return 0;
}

/** Timeout a given auth request.
 * @param[in] ev A timer event whose associated data is the expired
 *   struct AuthRequest.
 */
static void auth_timeout_callback(struct Event* ev)
{
  struct AuthRequest* auth;

  assert(0 != ev_timer(ev));
  assert(0 != t_data(ev_timer(ev)));

  auth = t_data(ev_timer(ev));

  if (ev_type(ev) == ET_DESTROY) { /* being destroyed */
    auth->flags &= ~AM_TIMEOUT;

    if (!(auth->flags & AM_FREE_MASK)) {
      Debug((DEBUG_LIST, "Freeing auth from timeout callback; %p [%p]", auth,
	     ev_timer(ev)));
      MyFree(auth); /* done with it, finally */
    }
  } else {
    assert(ev_type(ev) == ET_EXPIRE);

    destroy_auth_request(auth, 1);
  }
}

/** Handle socket I/O activity.
 * @param[in] ev A socket event whos associated data is the active
 *   struct AuthRequest.
 */
static void auth_sock_callback(struct Event* ev)
{
  struct AuthRequest* auth;

  assert(0 != ev_socket(ev));
  assert(0 != s_data(ev_socket(ev)));

  auth = s_data(ev_socket(ev));

  switch (ev_type(ev)) {
  case ET_DESTROY: /* being destroyed */
    auth->flags &= ~AM_SOCKET;

    if (!(auth->flags & AM_FREE_MASK)) {
      Debug((DEBUG_LIST, "Freeing auth from sock callback; %p [%p]", auth,
	     ev_socket(ev)));
      MyFree(auth); /* done with it finally */
    }
    break;

  case ET_CONNECT: /* socket connection completed */
    Debug((DEBUG_LIST, "Connection completed for auth %p [%p]; sending query",
	   auth, ev_socket(ev)));
    socket_state(&auth->socket, SS_CONNECTED);
    send_auth_query(auth);
    break;

  case ET_READ: /* socket is readable */
  case ET_EOF: /* end of file on socket */
  case ET_ERROR: /* error on socket */
    Debug((DEBUG_LIST, "Auth socket %p [%p] readable", auth, ev_socket(ev)));
    read_auth_reply(auth);
    break;

  default:
#ifndef NDEBUG
    abort(); /* unrecognized event */
#endif
    break;
  }
}

/** Stop an auth request completely.
 * @param[in] auth The struct AuthRequest to cancel.
 * @param[in] send_reports If set to 1 then send the headers from HeaderMessages.
 */
void destroy_auth_request(struct AuthRequest* auth, int send_reports)
{
  struct AuthRequest** authList;

  if (IsDoingAuth(auth)) {
    authList = &AuthPollList;
    if (-1 < auth->fd) {
      close(auth->fd);
      auth->fd = -1;
      socket_del(&auth->socket);
    }

    if (send_reports && IsUserPort(auth->client))
      sendheader(auth->client, REPORT_FAIL_ID);
  } else
    authList = &AuthIncompleteList;

  if (IsDNSPending(auth)) {
    delete_resolver_queries(auth);
    if (send_reports && IsUserPort(auth->client))
      sendheader(auth->client, REPORT_FAIL_DNS);
  }

  if (IsDNSBLPending(auth) && feature_bool(FEAT_DNSBL_CHECKS))
    delete_resolver_queries(auth);

  if (send_reports) {
    log_write(LS_RESOLVER, L_INFO, 0, "DNS/AUTH timeout %s",
	      get_client_name(auth->client, HIDE_IP));
    release_auth_client(auth->client);
  }

  unlink_auth_request(auth, authList);
  free_auth_request(auth);
}

/** Allocate a new auth request
 * @param[in] client The client who we are allocating the request to.
 */
static struct AuthRequest* make_auth_request(struct Client* client)
{
  struct AuthRequest* auth = 
               (struct AuthRequest*) MyMalloc(sizeof(struct AuthRequest));
  assert(0 != auth);
  memset(auth, 0, sizeof(struct AuthRequest));
  auth->flags   = AM_TIMEOUT;
  auth->fd      = -1;
  auth->client  = client;
  cli_auth(client) = auth;
  timer_add(timer_init(&auth->timeout), auth_timeout_callback, (void*) auth,
	    TT_RELATIVE, feature_int(FEAT_AUTH_TIMEOUT));
  return auth;
}

/** Cleanup auth request allocations
 * @param[in] auth An authrequest who is being free'ed.
 */
void free_auth_request(struct AuthRequest* auth)
{
  if (-1 < auth->fd) {
    close(auth->fd);
    Debug((DEBUG_LIST, "Deleting auth socket for %p", auth->client));
    socket_del(&auth->socket);
  }
  Debug((DEBUG_LIST, "Deleting auth timeout timer for %p", auth->client));
  timer_del(&auth->timeout);
}

/*
 * unlink_auth_request - remove auth request from a list
 */
static void unlink_auth_request(struct AuthRequest* request,
                                struct AuthRequest** list)
{
  if (request->next)
    request->next->prev = request->prev;
  if (request->prev)
    request->prev->next = request->next;
  else
    *list = request->next;
}

/*
 * link_auth_request - add auth request to a list
 */
static void link_auth_request(struct AuthRequest* request,
                              struct AuthRequest** list)
{
  request->prev = 0;
  request->next = *list;
  if (*list)
    (*list)->prev = request;
  *list = request;
}

/** Release auth client from auth system
 * this adds the client into the local client lists so it can be read by
 * the main io processing loop
 * @param[in] client Client who we are releasing the auth request for.
 */
static void release_auth_client(struct Client* client)
{
  assert(0 != client);
  cli_auth(client) = 0;
  cli_lasttime(client) = cli_since(client) = CurrentTime;
  if (cli_fd(client) > HighestFd)
    HighestFd = cli_fd(client);
  LocalClientArray[cli_fd(client)] = client;

  add_client_to_list(client);
  socket_events(&(cli_socket(client)), SOCK_ACTION_SET | SOCK_EVENT_READABLE);
  Debug((DEBUG_INFO, "Auth: release_auth_client %s@%s[%s]",
         cli_username(client), cli_sockhost(client), cli_sock_ip(client)));
}

/** If part of an auth request has failed then this is used to kill their request
 * @param[in] auth Authrequest containing client that is being killed.
 */
static void auth_kill_client(struct AuthRequest* auth)
{
  assert(0 != auth);

  unlink_auth_request(auth, (IsDoingAuth(auth)) ? &AuthPollList : &AuthIncompleteList);

  if (IsDNSPending(auth) || (IsDNSBLPending(auth) && feature_bool(FEAT_DNSBL_CHECKS)))
    delete_resolver_queries(auth);
  if (feature_bool(FEAT_IPCHECK) && !find_eline(auth->client, EFLAG_IPCHECK))
    IPcheck_disconnect(auth->client);
  Count_unknowndisconnects(UserStats);
  cli_auth(auth->client) = 0;
  free_client(auth->client);
  free_auth_request(auth);
}

/** Verify that a hostname is valid, i.e., only contains characters
 * valid for a hostname and that a hostname is not too long.
 * @param host Hostname to check.
 * @param maxlen Maximum length of hostname, not including NUL terminator.
 * @return Non-zero if the hostname is valid.
 */
static int auth_verify_hostname(char *host, int maxlen)
{
  int i;

  /* Walk through the host name */
  for (i = 0; host[i]; i++)
    /* If it's not a hostname character or if it's too long, return false */
    if (!IsHostChar(host[i]) || i >= maxlen)
      return 0;

  return 1; /* it's a valid hostname */
}

/** Handle a complete DNS lookup.  Send the client on it's way to a
 * connection completion, regardless of success or failure -- unless
 * there was a mismatch and KILL_IPMISMATCH is set.
 * @param[in] vptr The pending struct AuthRequest.
 * @param[in] reply Resolved name, or NULL if lookup failed.
 */
static void auth_dns_callback(void* vptr, struct DNSReply* reply)
{
  struct AuthRequest* auth = (struct AuthRequest*) vptr;

  assert(0 != auth);
  /*
   * need to do this here so auth_kill_client doesn't
   * try have the resolver delete the query it's about
   * to delete anyways. --Bleep
   */
  ClearDNSPending(auth);

  if (reply) {
    const struct hostent* hp = reply->hp;
    int i;
    assert(0 != hp);
    /*
     * Verify that the host to ip mapping is correct both ways and that
     * the ip#(s) for the socket is listed for the host.
     */
    for (i = 0; hp->h_addr_list[i]; ++i) {
      if (0 == memcmp(hp->h_addr_list[i], &(cli_ip(auth->client)),
                      sizeof(struct in_addr)))
         break;
    }
    if (!hp->h_addr_list[i]) {
      if (IsUserPort(auth->client))
        sendheader(auth->client, REPORT_IP_MISMATCH);
      sendto_opmask_butone(0, SNO_IPMISMATCH, "IP# Mismatch: %s != %s[%s]",
			   cli_sock_ip(auth->client), hp->h_name, 
			   ircd_ntoa(hp->h_addr_list[0]));
      if (feature_bool(FEAT_KILL_IPMISMATCH)) {
	auth_kill_client(auth);
	return;
      }
    } else if (!auth_verify_hostname(hp->h_name, HOSTLEN)) {
      if (IsUserPort(auth->client))
	sendheader(auth->client, REPORT_INVAL_DNS);
    } else {
      ++reply->ref_count;
      cli_dns_reply(auth->client) = reply;
      ircd_strncpy(cli_sockhost(auth->client), hp->h_name, HOSTLEN);
      if (IsUserPort(auth->client))
        sendheader(auth->client, REPORT_FIN_DNS);
    }
  }
  else {
    /*
     * this should have already been done by s_bsd.c in add_connection
     *
     * strcpy(auth->client->sockhost, auth->client->sock_ip);
     */
    if (IsUserPort(auth->client))
      sendheader(auth->client, REPORT_FAIL_DNS);
  }
  if ((feature_bool(FEAT_DNSBL_CHECKS) && !IsDNSBLPending(auth)) && !IsDoingAuth(auth)) {
    Debug((DEBUG_DEBUG, "Freeing auth after dns %s@%s [%s]", cli_username(auth->client),
	 cli_sockhost(auth->client), cli_sock_ip(auth->client)));
    release_auth_client(auth->client);
    unlink_auth_request(auth, &AuthIncompleteList);
    free_auth_request(auth);
  }
}

/** Handle auth send errors.
 * @param[in] auth The request for which to handle the error for.
 * @param[in] kill If 1 then kill the auth request.
 */
static void auth_error(struct AuthRequest* auth, int kill)
{
  ++ServerStats->is_abad;

  assert(0 != auth);
  close(auth->fd);
  auth->fd = -1;
  socket_del(&auth->socket);

  if (IsUserPort(auth->client))
    sendheader(auth->client, REPORT_FAIL_ID);

  if (kill) {
    /*
     * we can't read the client info from the client socket,
     * close the client connection and free the client
     * Need to do this before we ClearAuth(auth) so we know
     * which list to remove the query from. --Bleep
     */
    auth_kill_client(auth);
    return;
  }

  ClearAuth(auth);
  unlink_auth_request(auth, &AuthPollList);

  if (IsDNSPending(auth) || (IsDNSBLPending(auth) && feature_bool(FEAT_DNSBL_CHECKS)))
    link_auth_request(auth, &AuthIncompleteList);
  else {
    release_auth_client(auth->client);
    free_auth_request(auth);
  }
}

/** Flag the client to show an attempt to contact the ident server on
 * the client's host.  Should the connect or any later phase of the
 * identifying process fail, it is aborted and the user is given a
 * username of "unknown".
 * @param[in] auth The request for which to start the ident lookup.
 */
static int start_auth_query(struct AuthRequest* auth)
{
  struct sockaddr_in remote_addr;
  struct sockaddr_in local_addr;
  int                fd;
  IOResult           result;

  assert(0 != auth);
  assert(0 != auth->client);

  if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    ++ServerStats->is_abad;
    return 0;
  }
  if ((MAXCONNECTIONS - 10) < fd) {
    close(fd);
    return 0;
  }
  if (!os_set_nonblocking(fd)) {
    close(fd);
    return 0;
  }
  if (IsUserPort(auth->client))
    sendheader(auth->client, REPORT_DO_ID);
  /* 
   * get the local address of the client and bind to that to
   * make the auth request.  This used to be done only for
   * ifdef VIRTTUAL_HOST, but needs to be done for all clients
   * since the ident request must originate from that same address--
   * and machines with multiple IP addresses are common now
   */
  memset(&local_addr, 0, sizeof(struct sockaddr_in));
  os_get_sockname(cli_fd(auth->client), &local_addr);
  local_addr.sin_port = htons(0);

  if (bind(fd, (struct sockaddr*) &local_addr, sizeof(struct sockaddr_in))) {
    close(fd);
    return 0;
  }

  remote_addr.sin_addr.s_addr = (cli_ip(auth->client)).s_addr;
  remote_addr.sin_port = htons(113);
  remote_addr.sin_family = AF_INET;

  if ((result = os_connect_nonb(fd, &remote_addr)) == IO_FAILURE ||
      !socket_add(&auth->socket, auth_sock_callback, (void*) auth,
		  result == IO_SUCCESS ? SS_CONNECTED : SS_CONNECTING,
		  SOCK_EVENT_READABLE, fd)) {
    ServerStats->is_abad++;
    /*
     * No error report from this...
     */
    close(fd);
    if (IsUserPort(auth->client))
      sendheader(auth->client, REPORT_FAIL_ID);
    return 0;
  }

  auth->flags |= AM_SOCKET;
  auth->fd = fd;

  SetAuthConnect(auth);
  if (result == IO_SUCCESS)
    send_auth_query(auth); /* this does a SetAuthPending(auth) for us */

  return 1;
}

/** Enum used to index ident reply fields in a human-readable way. */
enum IdentReplyFields {
  IDENT_PORT_NUMBERS,
  IDENT_REPLY_TYPE,
  IDENT_OS_TYPE,
  IDENT_INFO,
  USERID_TOKEN_COUNT
};

/** Parse an ident reply line and extract the userid from it.
 * @param[in] reply The ident reply line.
 * @return The userid, or NULL on parse failure.
 */
static char* check_ident_reply(char* reply)
{
  char* token;
  char* end;
  char* vector[USERID_TOKEN_COUNT];
  int count = token_vector(reply, ':', vector, USERID_TOKEN_COUNT);

  if (USERID_TOKEN_COUNT != count)
    return 0;
  /*
   * second token is the reply type
   */
  token = vector[IDENT_REPLY_TYPE];
  if (EmptyString(token))
    return 0;

  while (IsSpace(*token))
    ++token;

  if (0 != strncmp(token, "USERID", 6))
    return 0;

  /*
   * third token is the os type
   */
  token = vector[IDENT_OS_TYPE];
  if (EmptyString(token))
    return 0;
  while (IsSpace(*token))
   ++token;

  /*
   * Unless "OTHER" is specified as the operating system
   * type, the server is expected to return the "normal"
   * user identification of the owner of this connection.
   * "Normal" in this context may be taken to mean a string
   * of characters which uniquely identifies the connection
   * owner such as a user identifier assigned by the system
   * administrator and used by such user as a mail
   * identifier, or as the "user" part of a user/password
   * pair used to gain access to system resources.  When an
   * operating system is specified (e.g., anything but
   * "OTHER"), the user identifier is expected to be in a
   * more or less immediately useful form - e.g., something
   * that could be used as an argument to "finger" or as a
   * mail address.
   */
  if (0 == strncmp(token, "OTHER", 5))
    return 0;
  /*
   * fourth token is the username
   */
  token = vector[IDENT_INFO];
  if (EmptyString(token))
    return 0;
  while (IsSpace(*token))
    ++token;
  /*
   * look for the end of the username, terminators are '\0, @, <SPACE>, :'
   */
  for (end = token; *end; ++end) {
    if (IsSpace(*end) || '@' == *end || ':' == *end)
      break;
  }
  *end = '\0'; 
  return token;
}

enum { LOOPBACK = 127 };

/** Starts auth (identd) and dns queries for a client.
 * @param[in] client The client for which to start queries.
 */
void start_auth(struct Client* client)
{
  struct AuthRequest* auth = 0;

  assert(0 != client);

  auth = make_auth_request(client);
  assert(0 != auth);

  Debug((DEBUG_INFO, "Beginning auth request on client %p", client));

  if (!feature_bool(FEAT_NODNS)) {
    if (LOOPBACK == inet_netof(cli_ip(client)))
      strcpy(cli_sockhost(client), cli_name(&me));
    else {
      struct DNSQuery query;

      query.vptr     = auth;
      query.callback = auth_dns_callback;

      if (IsUserPort(auth->client))
	sendheader(client, REPORT_DO_DNS);

      cli_dns_reply(client) = gethost_byaddr((const char*) &(cli_ip(client)),
					     &query);

      if (cli_dns_reply(client)) {
	++(cli_dns_reply(client))->ref_count;
	ircd_strncpy(cli_sockhost(client), cli_dns_reply(client)->hp->h_name,
		     HOSTLEN);
	if (IsUserPort(auth->client))
	  sendheader(client, REPORT_FIN_DNSC);
	Debug((DEBUG_LIST, "DNS entry for %p was cached", auth->client));
      } else
	SetDNSPending(auth);
    }
  }

  start_dnsblcheck(auth, client);

  if (!feature_bool(FEAT_NOIDENT)) {
    if (start_auth_query(auth)) {
      Debug((DEBUG_LIST, "identd query for %p initiated successfully",
  	     auth->client));
      link_auth_request(auth, &AuthPollList);
    } else if (IsDNSPending(auth) || (IsDNSBLPending(auth) && feature_bool(FEAT_DNSBL_CHECKS))) {
      Debug((DEBUG_LIST, "identd query for %p not initiated successfully; "
 	     "waiting on DNS", auth->client));
      link_auth_request(auth, &AuthIncompleteList);
    } else {
      Debug((DEBUG_LIST, "identd query for %p not initiated successfully; "
	     "no DNS pending; releasing immediately", auth->client));
      free_auth_request(auth);
      release_auth_client(client);
    }
  }
}

/** Send the ident server a query giving "theirport , ourport". The
 * write is only attempted *once* so it is deemed to be a fail if the
 * entire write doesn't write all the data given.  This shouldn't be a
 * problem since the socket should have a write buffer far greater
 * than this message to store it in should problems arise. -avalon
 * @param[in] auth The request to send.
 */
void send_auth_query(struct AuthRequest* auth)
{
  struct sockaddr_in us;
  struct sockaddr_in them;
  char               authbuf[32];
  unsigned int       count;

  assert(0 != auth);
  assert(0 != auth->client);

  if (!os_get_sockname(cli_fd(auth->client), &us) ||
      !os_get_peername(cli_fd(auth->client), &them)) {
    auth_error(auth, 1);
    return;
  }
  ircd_snprintf(0, authbuf, sizeof(authbuf), "%u , %u\r\n",
		(unsigned int) ntohs(them.sin_port),
		(unsigned int) ntohs(us.sin_port));

  if (IO_SUCCESS == os_send_nonb(auth->fd, authbuf, strlen(authbuf), &count)) {
    ClearAuthConnect(auth);
    SetAuthPending(auth);
  }
  else
    auth_error(auth, 0);
}

/** Read the reply (if any) from the ident server we connected to.  We
 * only give it one shot, if the reply isn't good the first time fail
 * the authentication entirely. --Bleep
 * @param[in] auth The request to read.
 */
void read_auth_reply(struct AuthRequest* auth)
{
  char*        username = 0;
  unsigned int len;
  /*
   * rfc1453 sez we MUST accept 512 bytes
   */
  char   buf[BUFSIZE + 1];

  assert(0 != auth);
  assert(0 != auth->client);
  assert(auth == cli_auth(auth->client));

  if (IO_SUCCESS == os_recv_nonb(auth->fd, buf, BUFSIZE, &len)) {
    buf[len] = '\0';
    Debug((DEBUG_LIST, "Auth %p [%p] reply: %s", auth, &auth->socket, buf));
    username = check_ident_reply(buf);
    Debug((DEBUG_LIST, "Username: %s", username));
  }

  close(auth->fd);
  auth->fd = -1;
  Debug((DEBUG_LIST, "Deleting auth [%p] socket %p", auth, &auth->socket));
  socket_del(&auth->socket);
  ClearAuth(auth);
  
  if (!EmptyString(username)) {
    ircd_strncpy(cli_username(auth->client), username, USERLEN);
    /*
     * Not needed, struct is zeroed by memset
     * auth->client->username[USERLEN] = '\0';
     */
    SetGotId(auth->client);
    ++ServerStats->is_asuc;
    if (IsUserPort(auth->client))
      sendheader(auth->client, REPORT_FIN_ID);
  }
  else {
    ++ServerStats->is_abad;
  }
  unlink_auth_request(auth, &AuthPollList);

  if (IsDNSPending(auth) || (IsDNSBLPending(auth) && feature_bool(FEAT_DNSBL_CHECKS)))
    link_auth_request(auth, &AuthIncompleteList);
  else {
    release_auth_client(auth->client);
    free_auth_request(auth);
  }
}
