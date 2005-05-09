/*
 * IRC - Internet Relay Chat, include/ircd_reply.h
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
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
#ifndef INCLUDED_ircd_reply_h
#define INCLUDED_ircd_reply_h

struct Client;
struct dnsbl_format_assoc
{
   char key;
   void *data;
   int type;
};

struct message_format_assoc
{
   char key;
   void *data;
   int type;
};

extern char *format_message(char *nick, char *ident, char *host, char *ip,
                            char *channel, char *format);

extern char *format_dnsbl_msg(char *dnsblip, char *dnsblhost, char *dnsbluser,
                              char *dnsblnick, char *format);

extern int protocol_violation(struct Client* cptr, const char* pattern, ...);
extern int need_more_params(struct Client* cptr, const char* cmd);
extern int send_error_to_client(struct Client* cptr, int error, ...);
extern int send_reply(struct Client* to, int reply, ...);

#define SND_EXPLICIT	0x40000000	/* first arg is a pattern to use */
#define FORMATTYPE_STRING 1

#endif /* INCLUDED_ircd_reply_h */
