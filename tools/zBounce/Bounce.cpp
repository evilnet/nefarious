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
 * zBounce - A compressing TCP port bouncer.
 *
 * This tool is designed to set up a number of local listening ports, and
 * then forward any data recived on those ports to another host/port combo.
 * (Optionally compressing the data between them).
 * Each listening port can bounce to a different host/port defined in the
 * config file.
 *
 * -- Greg Sikorski. (gte@atomicrevs.demon.co.uk).
 *
 * See Changelog for detailed project history.
 *
 * $Id$
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <list>
#include <string>
#include <iostream>
#include <fstream>

#include <cassert>

#include "Bounce.h"
#include "main.h"
#include "Listener.h"
#include "Connection.h"
#include "Socket.h"
#include "StringTokenizer.h"

#include "defs.h"

#ifndef INADDR_NONE
#define INADDR_NONE -1
#endif

using std::string;
using std::cerr;
using std::endl;
using std::ifstream;

/******************************
 ** Constructor / Destructor **
 ******************************/

Bounce::Bounce() {
  myDebug = false;  
  myConfigPath = "bounce.conf";
  myLogFile = NULL;
  myLogPath = "bounce.log";
  myPIDFile = NULL;
  myPIDPath = "bounce.pid";
  myVHost = "";
} // Bounce::Bounce

Bounce::~Bounce() {
} // Bounce::~Bounce

void Bounce::dumpConfig() {
  logEntry("Bounce::dumpConfig> ---------------");
  logEntry("Bounce::dumpConfig> Got SIGUSR1. Dumping config:");

  typedef Bounce::allowListType::iterator allowIter;

  allowIter a = allowList.begin();
  while(a != allowList.end()) {
    in_addr foo;
    foo.s_addr = (*a);

    logEntry("Bounce::dumpConfig> Allow: %s", inet_ntoa(foo));

    ++a;
  } // while

  typedef Bounce::listenerListType::iterator listIter;
  listIter b;
  b = listenerList.begin();

  while(b != listenerList.end()) {
    logEntry("Bounce::dumpConfig> Listener: %s:%i -> %s:%i", (*b)->getVHost().c_str(), (*b)->getLocalPort(), (*b)->getRemoteServer().c_str(), (*b)->getRemotePort());
    ++b;
  } // while

  logEntry("Bounce::DumpConfig> ---------------");
} // Bounce::dumpConfig

/**
 *  bindListeners.
 *  Inputs: Nothing.
 *  Outputs: Nothing.
 *  Process: 1. Reads the config file, and..
 *           2. Creates a new listener for each 'P' line found.
 *
 */
void Bounce::bindListeners() {
  ifstream inFile(getConfigPath().c_str());

  /*
   * Clear out the allow list.
   * We'll be reading in a new one now.
   */

  allowList.clear();

  /*
   *  Open config File.
   */
  savedBytes = 0;

  if (!inFile) {
    cerr << "ERROR: Unable to open config file!" << endl;
    ::exit(0);
  } // if

  string line;
  size_t lineNumber = 0;

  while(getline(inFile, line)) {
    ++lineNumber ;
    if (line.empty() || ('#' == line[ 0 ]) || ('\r' == line[ 0 ]))
      continue ;

    StringTokenizer st(line, ':');
    in_addr_t allowIP = 0;

    switch(line[0]) {
      case 'A':

        if (st.size() != 2) {
          cerr << "ERROR: " << getConfigPath() << ":" << lineNumber
               << "> Expected 1 token in A line, but got "
               << st.size() << endl;

          ::exit( 0 ) ;
        } // if

        allowIP = inet_addr(st[1].c_str());
        if (allowIP == (in_addr_t) INADDR_NONE) {
          logEntry("Bounce::bindListeners> Invalid IP specified in A Line. (%s)", st[1].c_str());

          ::exit(0);
        } // if 

        allowList.push_front( allowIP );
        logEntry("Bounce::bindListeners> Read A: line for %s", st[ 1 ].c_str());
        break;
      case 'P':
      case 'p':
        // P line requires 5 fields
        if (st.size() != 5) {
          cerr << getConfigPath() << ":" << lineNumber
               << "> Expected 4 tokens in P line, but got "
               << st.size() << endl;

          ::exit(0);
        } // if

        /*
         * Right.. lets check if this listener is already in our global
         * list. If it is, don't create a new listener object and bind() again.
         */

        typedef Bounce::listenerListType::iterator listIter;

        listIter b;
        b = listenerList.begin();
        bool notAdding = false;

        while(b != listenerList.end()) {
          if (((*b)->getVHost() == st[1]) && ((*b)->getLocalPort() == ::atoi(st[2].c_str()))) {
            logEntry("Bounce::bindListeners> Not adding local listener for %s:%i, its already loaded.",
                     (*b)->getVHost().c_str(), (*b)->getLocalPort());

            notAdding = true;
          } // if

          ++b;
        } // while

        if (notAdding)
          break;

        Listener *newListener = new Listener();
        newListener->setVHost(st[1]);
        newListener->setLocalPort(::atoi(st[2].c_str()));
        newListener->setRemoteServer(st[3]);
        newListener->setRemotePort(::atoi(st[4].c_str()));

        /*
         * Using a P means: Accept plain input, and send a compressed stream. (0)
         * Using a p means: Accept compressed input, and send a plain stream. (1)
         */

        newListener->setCompress(('p' == line[0]) ? true : false);

	if (getDebug() == true) {
          logEntry("Bounce::bindListeners> Adding new Listener: Local: %s:%i, Remote: %s:%i",
                   newListener->getVHost().c_str(),
                   newListener->getLocalPort(),
                   newListener->getRemoteServer().c_str(),
                   newListener->getRemotePort());
        } // if

        newListener->beginListening();
        listenerList.push_front(newListener);
        break;
    } // switch
  } // while
} // Bounce::bindListeners

/**
 *  checkSockets.
 *  Inputs: Nothing.
 *  Outputs: Nothing.
 *  Process: 1. Builds up a FD_SET of all sockets we wish to check.
 *              (Including all listeners & all open connections).
 *           2. SELECT(2) the set, and forward/accept as needed.
 *
 */
void Bounce::checkSockets() {

  typedef std::list<Listener*> listenerContainer;
  typedef listenerContainer::iterator listIter;

  typedef std::list<Connection*> connectionContainer;
  typedef connectionContainer::iterator connIter;

  struct timeval tv;
  fd_set readfds;
  fd_set writefds;

  tv.tv_sec = 0;
  tv.tv_usec = 2000;
  int tempFd = 0;
  int tempFd2 = 0;
  int highestFd = 0;
  bool delCheck = false ;
  char* tempBuf = 0;

  FD_ZERO(&readfds);
  FD_ZERO(&writefds);

  /*
   *  Add all Listeners to the Read set.
   */

  listIter a = listenerList.begin();
  for(; a != listenerList.end(); ++a) {
    tempFd = (*a)->getFD();
    FD_SET(tempFd, &readfds);

    if (highestFd < tempFd)
      highestFd = tempFd;
  } // for

  /*
   *  Add Local & Remote connections from each
   *  connection object to the read/write set.
   */

  connIter b = connectionsList.begin();
  for(; b != connectionsList.end(); ++b ) {
    tempFd = (*b)->localSocket->getFD();
    tempFd2 = (*b)->remoteSocket->getFD();

    FD_SET(tempFd, &readfds);
    FD_SET(tempFd, &writefds);

    if (highestFd < tempFd) highestFd = tempFd;

    FD_SET(tempFd2, &readfds);
    FD_SET(tempFd2, &writefds);

    if (highestFd < tempFd2) highestFd = tempFd2;
  } // for

  /*
   * Problem with select: As we are always checking for writabilty,
   * select(2) will almost always return immediately if there are no
   * problems. This is bad, we'll hit 100% CPU in no time :/
   * At this stage we aren't buffering output at all, keep it simple.
   * This also means we have no way of predicting when we are sending data
   * out.  Anyway, for now we call select with a timeout for the readset,
   * this will block as neccessary.  We then select again on the write
   * set, which will almost certainly return immediately anyway,
   * so in the cases it won't, we'll wait anyway, which is good. :)
   */

  // TODO: select() in Linux modifies the final argument
  ::select(highestFd + 1, &readfds, 0, 0, &tv);
  ::select(highestFd + 1, &readfds, &writefds, 0, &tv);

  /*
   *  Check all connections for readability.
   *  First check Local FD's.
   *  If the connection is closed on either side,
   *  shutdown both sockets, and clean up.
   *  Otherwise, send the data from local->remote, or
   *  remote->local.
   */

  b = connectionsList.begin();
  while(b != connectionsList.end()) {
    tempFd = (*b)->localSocket->getFD();
    tempFd2 = (*b)->remoteSocket->getFD();

    if (FD_ISSET(tempFd, &writefds))
      (*b)->localSocket->setWriteable(true);
    else
      (*b)->localSocket->setWriteable(false);

    if (FD_ISSET(tempFd2, &writefds))
      (*b)->remoteSocket->setWriteable(true);
    else
      (*b)->remoteSocket->setWriteable(false);

    if (FD_ISSET(tempFd, &readfds) && (*b)->remoteSocket->getWriteable()) {
      tempBuf = (*b)->localSocket->read();

      /*
       * If readsize is 0 connection was closed.
       */
      if ((*b)->localSocket->getLastReadSize() == 0) {
        close((*b)->localSocket->getFD());
        close((*b)->remoteSocket->getFD());

        if (getDebug() == true)
          logEntry("Bounce::checkSockets> Closing FD: l->r local(%i) remote(%i)", (*b)->localSocket->getFD(), (*b)->remoteSocket->getFD());

        delete *b;
        delCheck = true;
        b = connectionsList.erase(b);
      } // if
      else {
        if ((*b)->getCompress() == false) {
          if ((*b)->compressBuffer((Bytef*)tempBuf, (*b)->localSocket->getLastReadSize(), (Bytef*)cBuffer, (*b)->remoteSocket) == -1) {
            close((*b)->localSocket->getFD());
            close((*b)->remoteSocket->getFD());

            if (getDebug() == true)
              logEntry("Bounce::checkSockets> CompERR Closing FD: local(%i) remote(%i)", (*b)->localSocket->getFD(), (*b)->remoteSocket->getFD());

              delete *b;
              delCheck = true;
              b = connectionsList.erase(b);
            } // if
          } // if
        else {
          if ((*b)->deCompressBuffer((Bytef*)tempBuf, (*b)->localSocket->getLastReadSize(), (Bytef*)cBuffer, (*b)->remoteSocket) == -1) {
            close((*b)->localSocket->getFD());
            close((*b)->remoteSocket->getFD());

            if (getDebug() == true)
              logEntry("Bounce::checkSockets> DecompERR Closing FD: local(%i) remote(%i)", (*b)->localSocket->getFD(), (*b)->remoteSocket->getFD());

            delete *b;
            delCheck = true;
            b = connectionsList.erase(b);
          } // if
        } // else
      } // else
    } // if

    if ((delCheck == false) && (((*b)->localSocket->getFD() == -1) || ((*b)->remoteSocket->getFD() == -1))) {
      /*
       * Broken! Close the other endpoint.
       * (If its not already broken too).
       */
      if ((*b)->remoteSocket->getFD() != -1) {
        if (getDebug() == true)
          logEntry("Bounce::checkSockets> Closing FD: %i", (*b)->remoteSocket->getFD());

        ::close((*b)->remoteSocket->getFD());
      } // if

      if ((*b)->localSocket->getFD() != -1) {
        if (getDebug() == true)
          logEntry("Bounce::checkSockets> Closing FD: %i", (*b)->localSocket->getFD());

        ::close((*b)->localSocket->getFD());
      } // if

      delete *b;
      delCheck = true;
      b = connectionsList.erase(b);
    } // if

    if (!delCheck) ++b;

    delCheck = false;
  } // while

  /*
   *  Now check Remote FD's..
   */

  b = connectionsList.begin();
  while(b != connectionsList.end()) {
    tempFd = (*b)->remoteSocket->getFD();
    tempFd2 = (*b)->localSocket->getFD();

    if (FD_ISSET(tempFd, &writefds))
      (*b)->remoteSocket->setWriteable(true);
    else
      (*b)->remoteSocket->setWriteable(false);

    if (FD_ISSET(tempFd2, &writefds))
      (*b)->localSocket->setWriteable(true);
    else
      (*b)->localSocket->setWriteable(false);

    if (FD_ISSET(tempFd, &readfds) && (*b)->localSocket->getWriteable()) {
      tempBuf = (*b)->remoteSocket->read();

      /*
       * If readsize is 0 connection has close.
       */
      if ((*b)->remoteSocket->getLastReadSize() == 0) {
        close((*b)->localSocket->getFD());
        close((*b)->remoteSocket->getFD());

        if (getDebug() == true)
          logEntry("Bounce::checkSockets> Closing FD: r->l local(%i) remote(%i)", (*b)->localSocket->getFD(), (*b)->remoteSocket->getFD());

        delete *b;
        delCheck = true;
        b = connectionsList.erase(b);
      } // if
      else {
        if ((*b)->getCompress() == false) {
          if ((*b)->deCompressBuffer((Bytef*)tempBuf, (*b)->remoteSocket->getLastReadSize(), (Bytef*)cBuffer, (*b)->localSocket) == -1) {
            close((*b)->localSocket->getFD());
            close((*b)->remoteSocket->getFD());

            if (getDebug() == true)
              logEntry("Bounce::checkSockets> DecompERR Closing FD: local(%i) remote(%i)", (*b)->localSocket->getFD(), (*b)->remoteSocket->getFD());

            delete *b;
            delCheck = true;
            b = connectionsList.erase(b);
          } // if 
        } //if
        else {
          if ((*b)->compressBuffer((Bytef*)tempBuf, (*b)->remoteSocket->getLastReadSize(), (Bytef*)cBuffer, (*b)->localSocket) == -1) {
            close((*b)->localSocket->getFD());
            close((*b)->remoteSocket->getFD());

            if (getDebug() == true)
              logEntry("Bounce::checkSockets> CompERR Closing FD: local(%i) remote(%i)", (*b)->localSocket->getFD(), (*b)->remoteSocket->getFD());

            delete *b;
            delCheck = true;
            b = connectionsList.erase(b);
          } // if
        } // else
      } // else
    } // if

    if ((delCheck == false) && (((*b)->localSocket->getFD() == -1) || ((*b)->remoteSocket->getFD() == -1))) {
      /*
       * Broken! Close the other endpoint.
       * (If its not already broken too)
       */
       if ((*b)->remoteSocket->getFD() != -1) {
         if (getDebug() == true)
           logEntry("Bounce::checkSockets> Closing FD: %i", (*b)->remoteSocket->getFD());

         ::close((*b)->remoteSocket->getFD());
       } // if

       if ((*b)->localSocket->getFD() != -1) {
         if (getDebug() == true)
           logEntry("Bounce::checkSockets> Closing FD: %i", (*b)->localSocket->getFD());

         ::close((*b)->localSocket->getFD());
       } // if

       delete *b;
       delCheck = true;
       b = connectionsList.erase(b);
    } // if

    if (!delCheck) ++b;
      delCheck = false;
  } // while

  /*
   *  Check all listeners for new connections.
   */

  a = listenerList.begin();
  while(a != listenerList.end()) {
    tempFd = (*a)->getFD();

    if (FD_ISSET(tempFd, &readfds))
      receiveNewConnection(*a);

    ++a;
  } // while
} // Bounce::checkSockets

/**
 *  receiveNewConnection.
 *  Inputs: A Listener Object.
 *  Outputs: Nothing.
 *  Process: 1. Receives a new connection on a local port,
 *              and creates a connection object for it.
 *           2. Accepts the incomming connection.
 *           3. Creates a new Socket object for the remote
 *              end of the connection.
 *           4. Connects up the remote Socket.
 *           5. Adds the new Connection object to the
 *              connections list.
 *
 */
void Bounce::receiveNewConnection(Listener* listener) {
  typedef Bounce::allowListType::iterator allowIter;
  int access = 0;

  Connection* newConnection = new Connection();
  newConnection->localSocket = listener->handleAccept();

  /*
   *  Check connection access.
   */

  allowIter a = allowList.begin();
  while(a != allowList.end()) {
    if ((*a) == newConnection->localSocket->getAddress()->sin_addr.s_addr) {
      access = 1;
      break;
    } // if

    ++a;
  } // while

  if (access)
   logEntry("Bounce::receiveNewConnection> Connection attempt from %s: Granted.", inet_ntoa(newConnection->localSocket->getAddress()->sin_addr));
  else {
    logEntry("Bounce::receiveNewConnection> Connection attempt from %s: Denied.", inet_ntoa(newConnection->localSocket->getAddress()->sin_addr));
    close(newConnection->localSocket->getFD());
    delete newConnection;

    return;
  } // else

  Socket *remoteSocket = new Socket();
  newConnection->remoteSocket = remoteSocket;
  newConnection->setCompress(listener->getCompress());
  logEntry("Bounce::receiveNewConnection> Attempting connection to %s:%i.", listener->getRemoteServer().c_str(), listener->getRemotePort());

  if (remoteSocket->connectTo(listener->getRemoteServer(), listener->getRemotePort())) {
    connectionsList.insert(connectionsList.begin(), newConnection);
    /*
     * 06/12/2003: Initialization of compression buffers used to be here
     *             moved them to Connection contructor and destructor
     *             as they apply to each connection made might as well
     *             make it automagic. -GCARTER
     */
  } // if
  else {
    /*
     * 06/12/2003: This was defined under #define DEBUG
     * in almost every case this should probably
     * happen regardless, removed define. -GCARTER
     */
    newConnection->localSocket->write("ERROR Unable to connect to remote host. (This error reported by zBounce).\n");

    logEntry("Bounce::receiveNewConnection> Unable to connect to remote host %s:%i.", listener->getRemoteServer().c_str(), listener->getRemotePort());
    close(newConnection->localSocket->getFD());

    delete newConnection;
    delete remoteSocket;
  }  //else
} // Bounce::receiveNewConnection

/**
 *  Global routine for debug logging.
 *
 *  06/13/2003: Moved to Bounce class since it's global. -GCARTER
 */
const int Bounce::logEntry(const char *format, ...) {
  int returnResult;				// result returned

  // initialize variables
  returnResult = 0;

  /*
   * Note that the log file is only opened (in main()) if DEBUG
   * is defined.  Therefore, it only makes sense to log attempt to
   * log to the logFile if DEBUG is defined.
   *
   * 06/12/2003:  Same case but now it's not #define DEBUG,
   *              instead aBounce->getDebug() must be true.
   *              Logging large links can be verbose and is off by
   *              default. -GCARTER
   */
  if (aBounce->getDebug() == true) {
    char buf[ 4096 ] = { 0 };
    va_list msg;

    /*
     * 06/13/2003: Log file should be open or the program shouldn't
     *             have started. -GCARTER
     */

   if (myLogFile == NULL)
     assert(false);

    time_t utime = ::time(NULL);
    struct tm *now = localtime(&utime);

    va_start(msg, format);
    /*
     * 06/12/2003: Changed to vnsprintf to prevent buffer overflows.  Also got rid
     *             of nasty strcat to prevent overflows, not needed
     *             with vnsprintf. -GCARTER
     */
    vsnprintf(buf, sizeof(buf), format, msg);
    va_end(msg);

    returnResult = fprintf(myLogFile, "[%02d/%02d/%02d %02d:%02d:%02d]: %s\n",
                          now->tm_mday, (now->tm_mon + 1),
                          (1900 + now->tm_year), now->tm_hour,
                          now->tm_min, now->tm_sec, buf);

    // Commented out fflush() here because it will thrash the
    // HD if there is a lot of logging()...the system will flush
    // on its own.
    // Yep - but I need it for now because I'm impatient ;) --Gte
    fflush(myLogFile);
  } // if

  return returnResult;
} // Bounce::logEntry

/**
 *  Open debug log file.
 *
 * Returns: true on success
 *          false on failure
 */
const bool Bounce::openLog(const string &openFile) {
  if (openFile.length() < 1)
    return false;

  if ((myLogFile = fopen(openFile.c_str(), "a")) == NULL)
    return false;

  return true;
} // Bounce::openLog

/**
 *  Close debug log file.
 *
 *  Returns: true on success
 *           false on failure
 */
const bool Bounce::closeLog() {
  if (myLogFile == NULL)
    return false;

  if (fclose(myLogFile) != 0)
    return false;

  return true;
} // Bounce::closeLog
