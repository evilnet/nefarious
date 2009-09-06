/*
 * IRC - Internet Relay Chat
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
 *
 */

#include <arpa/inet.h>
#include <openssl/md5.h>
#include <openssl/ssl.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <algorithm>
#include <iostream>
#include <iterator>
#include <list>
#include <vector>
using std::list; 
using namespace std;

#define DEBUG

#define MSG_WEBIRC "WEBIRC %s ipv6gw %s %s\r\n"

#define CONF_SEP "|"

#define FLAG_SENTWEBIRC 0x0001

/*
 *  "Bounce" Class.
 */

class Listener;
class Connection;
class Bounce
{
public:
  list<Listener*> listenerList;      // List of 'Listeners'.
  list<Connection*> connectionsList; // List of 'Connections'.

  void bindListeners(); // Binds Listening Ports.
  void checkSockets();  // Polls all sockets.
  void recieveNewConnection(Listener*); // Accepts connections.
};

/*
 *  "Socket" Class.
 */

class Socket 
{
public:
  int fd;                               // File descriptor.
  SSL *ssl;                             // SSL Socket.
  int lastReadSize;                     // Size of last read buffer.
  struct sockaddr_in address;           // Socket addr_in struct.
  struct sockaddr_in6 address6;
  int connectTo(char*, unsigned short, int); // Connects the socket.
  int write(char*, int);                // Writes 'int' bytes from message.
  int write(char*);                     // Writes strlen(message).
  char* read();                         // Reads as much as possible into a 4k buffer.
  Socket();                             // Constructor.
};

/*
 *  "Listener" Class.
 */

class Bounce;
class Listener
{
public:
  int fd;                 // File descriptor.
  int remotePort;         // Remote port from config.
  int localPort;          // Local port for binding.
  char myVhost[39];       // Vhost to bind locally.
  char remoteServer[15];  // Remote server to connect to.

  char wircpass[255];
  char wircsuff[255];
  int isssl;

  void beginListening();  // Bind listening ports.
  Socket* handleAccept(); // Accept a new connection.
};

/*
 *  "Connection" Class.
 *  Simply a container for a local/remote Socket pair.
 */

class Connection 
{ 
public:
  Socket* localSocket;
  Socket* remoteSocket;

  char *wircpass;
  char *wircsuff;

  int flags;
  Connection();
};

/*
 *  "Config" Class.
 *  Simple config storage
 */
class Config
{
public:
  int debug;
};

/*
 *  "SSL" Class.
 *  Simple SSL global storage
 */
class Ssl
{
public:
  SSL_CTX *ctx;
  int enabled;

  void init_ctx();
  void destroy_ctx();
  SSL* connect(int);
  SSL* accept(int);
  Ssl();
};
