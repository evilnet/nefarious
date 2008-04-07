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
#include "config.h"

#ifdef USE_SSL

#if 1 /* HAVE_OPENSSL */
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#elif defined(HAVE_GNUTLS)
#include <gnutls/openssl.h>
#endif /* HAVE_{OPENSSL,GNUTLS} */

#ifndef IOV_MAX
#define IOV_MAX 1024
#endif /* IOV_MAX */

struct Socket;
struct Listener;

char *my_itoa(int i);

extern int bio_spare_fd;

extern IOResult ssl_recv(struct Socket *socket, char* buf, unsigned int length, unsigned int* count_out);
extern IOResult ssl_sendv(struct Socket *socket, struct MsgQ* buf, unsigned int* count_in, unsigned int* count_out);

extern char  *ssl_get_cipher(SSL *ssl);

extern int ssl_send(struct Client *cptr, const char *buf, unsigned int len);
extern int ssl_murder(void *ssl, int fd, const char *buf);
extern int ssl_count(void);

extern void ssl_add_connection(struct Listener *listener, int fd);
extern void ssl_free(struct Socket *socket);
extern void ssl_init(void);

extern void report_crypto_errors(void);
extern int verify_private_key(void);
extern int generate_challenge(char **, RSA *, struct Client *sptr);
extern int get_randomness(unsigned char *, int);

extern int save_spare_fd(const char *);

#endif /* USE_SSL */
#endif /* INCLUDED_ssl_h */
