#ifndef INCLUDED_ssl_h
#define INCLUDED_ssl_h
/*
 * IRC - Internet Relay Chat (SSL), include/ssl.h
 * Copyright (C) 2002 Alex Badea <vampire@go.ro>
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
   
#include "ircd_osdep.h"

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

struct Socket;
struct Listener;
 
extern IOResult ssl_recv(struct Socket *socket, char* buf, unsigned int length, unsigned int* count_out);
extern IOResult ssl_sendv(struct Socket *socket, struct MsgQ* buf, unsigned int* count_in, unsigned int* count_out);
extern int ssl_send(struct Client *cptr, const char *buf, unsigned int len);
extern int ssl_murder(void *ssl, int fd, const char *buf);
extern void ssl_add_connection(struct Listener *listener, int fd);
extern void ssl_free(struct Socket *socket);
extern void ssl_init(void);
extern int ssl_count(void);

#endif /* INCLUDED_ssl_h */
