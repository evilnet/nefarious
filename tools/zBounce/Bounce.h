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
using std::string;

class Socket;
class Listener;
class Connection;

/**
 *  "Bounce" Class.
 */
class Bounce {
public:
  Bounce();				// constructor
  virtual ~Bounce();			// deconstructor

  /**********************
   ** Type Definitions **
   **********************/

  typedef list<Connection*> connectionsListType;
  typedef list<Listener*> listenerListType;
  typedef list<unsigned long> allowListType;

  size_t savedBytes;

  char cBuffer[MTU + 1024];		// compression scratch buffer.

  void bindListeners(); // Binds Listening Ports.
  void checkSockets();  // Polls all sockets.
  void receiveNewConnection(Listener*); // Accepts connections.
  void dumpConfig(); // Accepts connections.

  /*************************
   ** Config Path Members **
   *************************/

  void setConfigPath(const string &setMe)
    { myConfigPath = setMe; }

  const string getConfigPath() const
    { return myConfigPath; }

  /*******************
   ** Debug Members **
   *******************/

  void setDebug(const bool setMe)
    { myDebug = setMe; }

  const bool getDebug() const
    { return myDebug; }

  /***********************
   ** Log Entry Members **
   ***********************/

  const bool openLog(const string &);
  const bool closeLog();
  const int logEntry(const char *, ...);

  /**********************
   ** Log Path Members **
   **********************/

  void setLogPath(const string &setMe)
    { myLogPath = setMe; }

  const string getLogPath() const
    { return myLogPath; }

  /*****************
   ** PID Members **
   *****************/

  void setPIDPath(const string &setMe)
    { myPIDPath = setMe; }

  const string getPIDPath() const
    { return myPIDPath; }

  /********************
   ** Prompt Members **
   ********************/

  void setPrompt(const string &setMe)
    { myPrompt = setMe; }

  const string getPrompt() const
    { return myPrompt; }

  /*******************
   ** VHost Members **
   *******************/

  void setVHost(const string &setMe)
    { myVHost = setMe; }

  const string getVHost() const
    { return myVHost; }

private:
  /***************
   ** Variables **
   ***************/

  // TODO: all variables should technically go in here
  // and be encapsed by members.
  allowListType allowList;			// List of IP's allowed to connect.
  bool myDebug;					// debug mode default: false
  connectionsListType connectionsList;		// List of 'Connections'.
  FILE *myLogFile;				// pointer to log file
  FILE *myPIDFile;				// pointer to pid file
  listenerListType listenerList;		// List of 'Listeners'.
  string myConfigPath;				// path to config file
  string myLogPath;				// path to log file
  string myPIDPath;				// path to pid file
  string myPrompt;				// command originally used to start me
  string myVHost;				// virtual host to bind to if any
};

extern Bounce *aBounce;

#endif // __BOUNCE_H
