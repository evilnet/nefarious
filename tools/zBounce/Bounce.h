/*
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
 *
 */

#ifndef __BOUNCE_H
#define __BOUNCE_H "$Id$"

#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <netdb.h>

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <cstring>
#include <cstdarg>

#include <list>
#include <string>

#include "zlib.h"
#include "config.h"

using std::list;
using std::string ;

class Socket;
class Listener;
class Connection;

/**
 *  "Bounce" Class.
 */
class Bounce
{
public:
  typedef list<Listener*> listenerListType;
  listenerListType listenerList;      // List of 'Listeners'.

  typedef list<Connection*> connectionsListType;
  connectionsListType connectionsList; // List of 'Connections'.

  char cBuffer[MTU+1024];     // Compression scratch buffer.

  typedef list<unsigned long> allowListType;
  allowListType allowList;     // List of IP's allowed to connect.
  size_t savedBytes;

  void bindListeners(); // Binds Listening Ports.
  void checkSockets();  // Polls all sockets.
  void receiveNewConnection(Listener*); // Accepts connections.
  void dumpConfig(); // Accepts connections.
};

#endif // __BOUNCE_H
