/*
 * IRC - Internet Relay Chat (SSL), ircd/ssl.c
 * Copyright (C) 2002 Alex Badea <vampire@go.ro>
 *
 * See file AUTHORS in IRC package for additional names of
 * the programmers.
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
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
 
#define _XOPEN_SOURCE
#include <limits.h>
#include <sys/uio.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>  

#include "config.h" 
#include "ircd.h"  
#include "ircd_defs.h"
#include "ircd_events.h"
#include "ircd_snprintf.h"
#include "ircd_alloc.h"
#include "s_debug.h"
#include "s_bsd.h"
#include "client.h"
#include "listener.h"
#include "send.h"
#include "ssl.h"


SSL_CTX *ctx;
static int ssl_inuse = 0;

struct ssl_data {
  struct Socket socket;
  struct Listener *listener;
  int fd;
};

static void abort_ssl(struct ssl_data *data)
{
  Debug((DEBUG_DEBUG, "SSL: aborted"));
  SSL_free(data->socket.ssl);
  --ssl_inuse;
  close(data->fd);
  socket_del(&data->socket);
}
 
static void accept_ssl(struct ssl_data *data)
{
  if (SSL_accept(data->socket.ssl) <= 0) {
    unsigned long err = ERR_get_error();
    char string[120];

    if (err) {
      ERR_error_string(err, string);
      Debug((DEBUG_ERROR, "SSL_accept: %s", string));
      abort_ssl(data);
    }
    return;   
  }
  if (SSL_is_init_finished(data->socket.ssl)) {
    add_connection(data->listener, data->fd, data->socket.ssl);
    socket_del(&data->socket);
  }
}

static void ssl_sock_callback(struct Event* ev)
{
  struct ssl_data *data;
   
  assert(0 != ev_socket(ev));
  assert(0 != s_data(ev_socket(ev)));
 
  data = s_data(ev_socket(ev));
  assert(0 != data);
  
  switch (ev_type(ev)) {
  case ET_DESTROY:
    --data->listener->ref_count;
    MyFree(data);   
    return;
  case ET_ERROR:
  case ET_EOF:
    abort_ssl(data);
    break;
  case ET_READ:
  case ET_WRITE:
    accept_ssl(data);
    break;
  default:
    break;
  }
}
  
void ssl_add_connection(struct Listener *listener, int fd)
{
  struct ssl_data *data;

  assert(0 != listener);

  if (!os_set_nonblocking(fd)) {
    close(fd);
    return;
  }
  os_disable_options(fd);
  
  data = (struct ssl_data *) MyMalloc(sizeof(struct ssl_data));
  data->listener = listener;
  data->fd = fd;
  if (!socket_add(&data->socket, ssl_sock_callback, (void *) data, SS_CONNECTED, SOCK_EVENT_READABLE, fd)) {
    close(fd);
    return;
  }
  if (!(data->socket.ssl = SSL_new(ctx))) {
    Debug((DEBUG_DEBUG, "SSL_new failed"));
    close(fd);
    return;
  }
  SSL_set_fd(data->socket.ssl, fd);
  ++ssl_inuse;
  ++listener->ref_count;
}

/*
 * ssl_recv - non blocking read of a connection
 * returns:
 *  1  if data was read or socket is blocked (recoverable error)
 *    count_out > 0 if data was read
 *
 *  0  if socket closed from other end
 *  -1 if an unrecoverable error occurred
 */
IOResult ssl_recv(struct Socket *socket, char* buf,
                 unsigned int length, unsigned int* count_out)
{
  int res;
   
  assert(0 != socket);
  assert(0 != buf);
  assert(0 != count_out);
  
  *count_out = 0;
  errno = 0;
  
  res = SSL_read(socket->ssl, buf, length);
  switch (SSL_get_error(socket->ssl, res)) {
  case SSL_ERROR_NONE:
    *count_out = (unsigned) res;
    return IO_SUCCESS;
  case SSL_ERROR_WANT_WRITE:
  case SSL_ERROR_WANT_READ:
  case SSL_ERROR_WANT_X509_LOOKUP:
    Debug((DEBUG_DEBUG, "SSL_read returned WANT_ - retrying"));
    return IO_BLOCKED;
  case SSL_ERROR_SYSCALL:   
    if (res < 0 && errno == EINTR)
      return IO_BLOCKED; /* ??? */
    break;
  case SSL_ERROR_ZERO_RETURN: /* close_notify received */
    SSL_shutdown(socket->ssl); /* Send close_notify back */
    break;
  }
  return IO_FAILURE;
}
    
/*
 * ssl_sendv - non blocking writev to a connection
 * returns:
 *  1  if data was written
 *    count_out contains amount written
 *
 *  0  if write call blocked, recoverable error   
 *  -1 if an unrecoverable error occurred
 */
IOResult ssl_sendv(struct Socket *socket, struct MsgQ* buf,
                  unsigned int* count_in, unsigned int* count_out)
{
  int res;
  int count;
  int k;
  struct iovec iov[IOV_MAX];
  IOResult retval = IO_BLOCKED;

  assert(0 != socket);
  assert(0 != buf);
  assert(0 != count_in);
  assert(0 != count_out);

  *count_in = 0;
  *count_out = 0;
  errno = 0;

  count = msgq_mapiov(buf, iov, IOV_MAX, count_in);
  for (k = 0; k < count; k++) {
    res = SSL_write(socket->ssl, iov[k].iov_base, iov[k].iov_len);
    switch (SSL_get_error(socket->ssl, res)) {
    case SSL_ERROR_NONE:
      *count_out += (unsigned) res;
      retval = IO_SUCCESS;
      break;
    case SSL_ERROR_WANT_WRITE:
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_X509_LOOKUP:
      Debug((DEBUG_DEBUG, "SSL_write returned WANT_ - retrying"));
      return retval;
    case SSL_ERROR_SYSCALL:
      return (res < 0 && errno == EINTR) ? retval : IO_FAILURE;
    case SSL_ERROR_ZERO_RETURN:
      SSL_shutdown(socket->ssl);
      return IO_FAILURE;
    default:
      return IO_FAILURE;
    }
  }
  return retval;
}
      
int ssl_send(struct Client *cptr, const char *buf, unsigned int len)
{
  char fmt[16];
    
  if (!cli_socket(cptr).ssl)
    return write(cli_fd(cptr), buf, len);
    
  /*
   * XXX HACK
   *
   * Incomplete SSL writes must be retried with the same write buffer;
   * at this point SSL_write usually fails, so the data must be queued.
   * We're abusing the normal send queue for this.
   * Also strip \r\n from message, as sendrawto_one adds it later
   */
  ircd_snprintf(0, fmt, sizeof(fmt), "%%.%us", len - 2);
  sendrawto_one(cptr, fmt, buf);
  send_queued(cptr);
  return len;
}
  
int ssl_murder(void *ssl, int fd, const char *buf)
{
  if (!ssl) {
    write(fd, buf, strlen(buf));
    close(fd);
    return 0;
  } 
  SSL_write((SSL *) ssl, buf, strlen(buf));
  SSL_free((SSL *) ssl);
  close(fd);
  return 0;
}
  
void ssl_free(struct Socket *socket)
{
  if (!socket->ssl)
    return;
  SSL_free(socket->ssl);
  --ssl_inuse;
}
  
int ssl_count(void)
{
  return ssl_inuse;
}   

static RSA *tmp_rsa_cb(SSL *s, int export, int keylen)
{
	Debug((DEBUG_DEBUG, "Generating %d bit temporary RSA key", keylen));
	return RSA_generate_key(keylen, RSA_F4, NULL, NULL);
} 

static void info_callback(SSL *s, int where, int ret)
{
	if (where & SSL_CB_LOOP)
	  Debug((DEBUG_DEBUG, "SSL state (%s): %s",
		where & SSL_ST_CONNECT ? "connect" :
		where & SSL_ST_ACCEPT ? "accept" :
		"undefined", SSL_state_string_long(s)));
	else if (where & SSL_CB_ALERT)
	  Debug((DEBUG_DEBUG, "SSL alert (%s): %s: %s",
		where & SSL_CB_READ ? "read" : "write",
		SSL_alert_type_string_long(ret),
		SSL_alert_desc_string_long(ret)));
	else if (where == SSL_CB_HANDSHAKE_DONE)
	  Debug((DEBUG_DEBUG, "SSL: handshake done"));
}
       
static void sslfail(char *txt)
{
	unsigned long err = ERR_get_error();
	char string[120];

	if (!err) {
	  Debug((DEBUG_DEBUG, "%s: poof", txt));
	} else {
	  ERR_error_string(err, string);
	  Debug((DEBUG_FATAL, "%s: %s", txt, string));
	  exit(2);
	}
}

void ssl_init(void)
{
	char pemfile[1024];

	SSLeay_add_ssl_algorithms();
	SSL_load_error_strings();

	Debug((DEBUG_NOTICE, "SSL: read %d bytes of randomness", RAND_load_file("/dev/urandom", 4096)));

	ctx = SSL_CTX_new(SSLv23_server_method());
	SSL_CTX_set_tmp_rsa_callback(ctx, tmp_rsa_cb);
	SSL_CTX_need_tmp_RSA(ctx);
	SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_BOTH);
	SSL_CTX_set_timeout(ctx, 300); /* XXX */
	SSL_CTX_set_info_callback(ctx, info_callback);

	ircd_snprintf(0, pemfile, sizeof(pemfile), "%s/ircd.pem", DPATH);
	Debug((DEBUG_DEBUG, "SSL: using pem file: %s", pemfile));
	if (!SSL_CTX_use_certificate_file(ctx, pemfile, SSL_FILETYPE_PEM))
	  sslfail("SSL_CTX_use_certificate_file");
	if (!SSL_CTX_use_RSAPrivateKey_file(ctx, pemfile, SSL_FILETYPE_PEM))
	  sslfail("SSL_CTX_use_RSAPrivateKey_file");
       
	Debug((DEBUG_DEBUG, "SSL: init ok"));
}
