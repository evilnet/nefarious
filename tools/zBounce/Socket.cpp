/*
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
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>

#include <string>

#include <cstring>
#include <cerrno>
#include <cassert>
#include <cstdio>

#include "Bounce.h"
#include "Socket.h"
#include "main.h"

using std::string;

/**
 *  Socket Constructor.
 *  Inputs: Nothing.
 *  Outputs: Nothing.
 *  Process: Initialises member variables.
 *
 */
Socket::Socket() {
  // initialize variables
  myFD = -1;
  setLastReadSize(0);
  setWriteable(true);
  ::memset(myReadBuffer, 0, MTU);
  ::memset(&myAddress, 0, sizeof(struct sockaddr_in));
} // Socket::Socket

/**
 *  Write.
 *  Inputs: Message string, and lenght.
 *  Outputs: Amount written, or 0 on error.
 *  Process: 1. Writes out 'len' amount of 'message'.
 *              to this socket.
 *  Returns:
 *   -1 on error (the socket is then invalid)
 *   number of bytes written (0 is a valid value)
 *
 */
int Socket::write(const char *message, size_t len) {
  #ifndef NDEBUG
   assert(message != 0);
  #endif

  // Is our descriptor valid?
  if (-1 == myFD)
    // Nope, return error
    return -1;

  // amount will hold the number of bytes read
  int amount = 0;

  // loopCnt is the number of times send() is called and is used
  // to limit the number of loops executed here
  unsigned short int loopCnt = 0;

  // Continue looping while all three of the following are true:
  // 1) A bad read occured
  // 2) The reason for a bad read was due to an interrupted system
  //    call
  // 3) We have not reached the max loop count
  do {
    // Since we're using errno as a loop guard, make sure
    // to reset it each iteration
    errno = 0;

    // Request a send opertion via the OS
    amount = ::send(myFD, message, len, 0);
  } while((amount < 0) && (EINTR == errno) && (++loopCnt <= 10));

  // if (aBounce->getDebug() == true)
  //   aBounce->logEntry("[%i]: Requested to send: %i, Wrote %i.", myFD, len, amount);

  // Was the send successful?
  if (-1 == amount) {
    // Nope, log it
    aBounce->logEntry("Socket::write> [%s]: Write Error: %i (%s)", inet_ntoa(myAddress.sin_addr), errno, ::strerror(errno));
    ::close(myFD);

    if (aBounce->getDebug() == true)
      aBounce->logEntry("Socket::write> Closing FD: %i", myFD);

    // The socket is now invalidated
    myFD = -1 ;
  } // if

  // Return the amount read
  return amount;
} // Socket::write

/**
 *  Write(2).
 *  Inputs: Message string.
 *  Outputs: Amount written, or 0 on error.
 *  Process: Writes out the whole of 'message'.
 *
 */
int Socket::write(const char *message) {
  #ifndef NDEBUG
    assert(message != 0);
  #endif

  if (-1 == myFD)
    return -1;

  int amount = -1;
  unsigned short int loopCnt = 0;

  do {
    errno = 0;
    amount = ::write(myFD, message, strlen(message));
  } while((amount < 0) && (EINTR == errno) && (++loopCnt <= 10));

  // if (aBounce->getDebug() == true)
  //  aBounce->logEntry("[%i]: Wrote %i Bytes.", myFD, amount);

  return amount;
} // Socket::write

/**
 *  connectTo.
 *  Inputs: Hostname and port.
 *  Outputs: +ve on success, 0 on failure.
 *  Process: 1. Connects this socket to remote 'hostname' on
 *              port 'portnum'.
 *
 */
int Socket::connectTo(const string& hostname, unsigned short portnum) {
  struct hostent *hp = ::gethostbyname(hostname.c_str());

  if (NULL == hp)
    return 0;

  ::memset(&myAddress, 0, sizeof(myAddress));
  ::memcpy(&myAddress.sin_addr, hp->h_addr, hp->h_length);
  myAddress.sin_family= hp->h_addrtype;
  myAddress.sin_port= htons((u_short) portnum);

  myFD = ::socket(hp->h_addrtype, SOCK_STREAM, 0);

  if (myFD < 0)
    return -1;

  /*
   * This section really isn't needed in most cases. However if the user
   * wishes to bind to another interface they have the freedom to before the
   * socket is connected.
   */
  if (aBounce->getVHost().length() > 0) {
    struct sockaddr_in la;
    struct hostent *vh;  

    if ((vh = gethostbyname(aBounce->getVHost().c_str())) == NULL) {
      aBounce->logEntry("Socket::connectTo> VHost[gethostbyname]: errno(%d) errmsg(%s)\n", h_errno, hstrerror(h_errno));
      return 0;
    } // if

    memset(&la, 0, sizeof(la));
    memcpy((char *) &la.sin_addr, vh->h_addr, vh->h_length);

    la.sin_family = vh->h_addrtype;
    la.sin_port = 0;
    
    if (bind(myFD, (struct sockaddr *) & la, sizeof(la)) == -1) {  
      close(myFD);
      aBounce->logEntry("Socket::connectTo> VHost[bind]: errno(%d) errmsg(%s)\n", errno, strerror(errno));
      return 0;
    } // if
  } // if

  if (::connect(myFD, (struct sockaddr*) &myAddress, sizeof(myAddress)) < 0) {
    ::close(myFD);

    if (aBounce->getDebug() == true)
      aBounce->logEntry("Socket::connectTo> Closing FD: %i", myFD);

    myFD = -1;
    return 0;
  } // if

  return 1;
} // Socket::connectTo

/**
 *  read.
 *  Inputs: Nothing.
 *  Outputs: pointer to static buffer containing data.
 *  Process: 1. Reads as much as possible from this socket, up to
 *              "MTU" bytes.
 *
 */
char *Socket::read() {

  if (-1 == myFD)
    return 0;

  int amount = 0;
  unsigned short int loopCnt = 0;

  do {
    errno = 0;
    amount = ::read(myFD, myReadBuffer, MTU);
  } while((amount < 0) && (EINTR == errno) && (++loopCnt <= 10));

  if(-1 == amount) {
    aBounce->logEntry("[%s]: Read Error: %i (%s)", ::inet_ntoa(myAddress.sin_addr), errno, ::strerror(errno));
    amount = 0;
  } // if

  setLastReadSize(amount);

  return myReadBuffer;
} // Socket::read
