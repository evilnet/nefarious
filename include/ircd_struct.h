/*
 * IRC - Internet Relay Chat, include/ircd_struct.h
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 * Copyright (C) 1996-1997 Carlo Wood
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
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
#ifndef INCLUDED_ircd_struct_h
#define INCLUDED_ircd_struct_h
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>      /* time_t */
#define INCLUDED_sys_types_h
#endif
#ifndef INCLUDED_ircd_defs_h
#include "ircd_defs.h"       /* sizes */
#endif
#ifndef INCLUDED_ircd_reply_h
#include "ircd_reply.h"
#endif

struct DLink;
struct Client;
struct User;
struct Membership;
struct SLink;

struct Server {
  struct Server*  nexts;
  struct Client*  up;           /* Server one closer to me */
  struct DLink*   down;         /* List with downlink servers */
  struct DLink*   updown;       /* own Dlink in up->serv->down struct */
  struct Client** client_list;  /* List with client pointers on this server */
  struct User*    user;         /* who activated this connection */
  time_t          timestamp;    /* Remotely determined connect try time */
  time_t          ghost;        /* Local time at which a new server
                                   caused a Ghost */
  int             lag;          /* Approximation of the amount of lag to this server */                          
  unsigned int    clients;      /* Number of clients on the network */
  unsigned short  prot;         /* Major protocol */
  unsigned short  nn_last;      /* Last numeric nick for p9 servers only */
  unsigned int    nn_mask;      /* [Remote] FD_SETSIZE - 1 */
  char          nn_capacity[4]; /* numeric representation of server capacity */
  
  int		  asll_rtt;	/* AsLL round-trip time */
  int		  asll_to;	/* AsLL upstream lag */
  int		  asll_from;	/* AsLL downstream lag */

  char *last_error_msg;         /* Allocated memory with last message receive with an ERROR */
  char by[NICKLEN + 1];
};

struct User {
  struct User*       nextu;
  struct Client*     server;         /* client structure of server */
  struct Membership* channel;        /* chain of channel pointer blocks */
  struct SLink*      invited;        /* chain of invite pointer blocks */
  struct SLink*      silence;        /* chain of silence pointer blocks */
  struct SLink*      watch;          /**< chain of watch pointer blocks */
  char*              away;           /* pointer to away message */
  time_t             last;
  unsigned int       refcnt;          /* Number of times this block is referenced */
  unsigned int       joined;          /* number of channels joined */
  unsigned int       watches;        /**< Number of entrances in the watch list */
  unsigned int       invites;         /* Number of channels we've been invited to */
  char               username[USERLEN + 1];
  char               host[HOSTLEN + 1];
  char               realusername[USERLEN + 1];
  char               realhost[HOSTLEN + 1];
  char               fakehost[HOSTLEN + 41];
  char               account[ACCOUNTLEN + 1];
  time_t	     acc_create;
  char               virtip[HOSTLEN + 1];
  char               virthost[HOSTLEN + 1];
  char               dnsblhost[HOSTLEN + 40];
  char               shunreason[BUFSIZE + 1];
  char*              swhois;         /* pointer to swhois message */
  char               response[BUFSIZE + 1];
  char               auth_oper[NICKLEN + 1 ];
};

struct LOCInfo {
  unsigned int       cookie;
  char               service[NICKLEN + 1];
  char               account[ACCOUNTLEN + 1];
  char               password[ACCPASSWDLEN + 1];
};

struct dnsblexempts {
  struct dnsblexempts *next;
  struct dnsblexempts **prev;

  char                *host;
  time_t              lastseen;
};

extern struct dnsblexempts*    DNSBLExemptList;

extern char* find_dnsblexempt(const char* host);
extern char* process_exempts(struct Client* sptr, char* host, time_t lseen);
extern int add_exempt(struct Client* sptr, char* host, char* netburst, time_t lseen);

#endif /* INCLUDED_ircd_struct_h */
