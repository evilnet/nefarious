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

#include	<string>
#include	<cstring>
#include	<cerrno>

#include	"Socket.h"
#include	"main.h"

using std::string ;

/**
 *  Socket Constructor.
 *  Inputs: Nothing.
 *  Outputs: Nothing.
 *  Process: Initialises member variables.
 *
 */
Socket::Socket() {

  fd = -1;
  lastReadSize = 0;
  canWrite = true;
  ::memset( buffer, 0, MTU ) ;
  ::memset( &address, 0, sizeof( struct sockaddr_in ) ) ;
  sendq = 0 ;
}

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
int Socket::write(const char *message, size_t len)
{

  #ifndef NDEBUG
   assert( message != 0 ) ;
  #endif

   // Is our descriptor valid?
   if( -1 == fd )
	{
	// Nope, return error
	return -1 ;
	}

   // amount will hold the number of bytes read
   int amount = 0 ;

   // loopCnt is the number of times send() is called and is used
   // to limit the number of loops executed here
   unsigned short int loopCnt = 0 ;

   do
	{
	// Since we're using errno as a loop guard, make sure
	// to reset it each iteration
	errno = 0 ;

	// Request a send opertion via the OS
	amount = ::send(fd, message, len, 0) ;
	}
	// Continue looping while all three of the following are true:
	// 1) A bad read occured
	// 2) The reason for a bad read was due to an interrupted system
	//    call
	// 3) We have not reached the max loop count
	while( (amount < 0) && (EINTR == errno) && (++loopCnt <= 10) ) ;

#ifdef DEBUG
//   logEntry("[%i]: Requested to send: %i, Wrote %i.", fd, len, amount);
#endif

   // Was the send successful?
   if (-1 == amount)
	{
	// Nope, log it
     logEntry("[%s]: Write Error: %i (%s)", inet_ntoa(address.sin_addr),
	errno, ::strerror( errno ) ) ;
	::close(fd);
#ifdef DEBUG
	logEntry("Closing FD: %i", fd);
#endif

	// The socket is now invalidated
	fd = -1 ;
	}

   // Return the amount read
   return amount;
}

/**
 *  Write(2).
 *  Inputs: Message string.
 *  Outputs: Amount written, or 0 on error.
 *  Process: Writes out the whole of 'message'.
 *
 */
int Socket::write(const char *message)
{

  #ifndef NDEBUG
   assert( message != 0 ) ;
  #endif

   if( -1 == fd )
	{
	return -1 ;
	}

   int amount = 0 ;
   unsigned short int loopCnt = 0 ;

   do
	{
	errno = 0 ;
	amount = ::write(fd, message, strlen( message )) ;
	}
	while( (amount < 0) && (EINTR == errno) && (++loopCnt <= 10) ) ;

#ifdef DEBUG
//   logEntry("[%i]: Wrote %i Bytes.", fd, amount);
#endif
   return amount;
}

/**
 *  connectTo.
 *  Inputs: Hostname and port.
 *  Outputs: +ve on success, 0 on failure.
 *  Process: 1. Connects this socket to remote 'hostname' on
 *              port 'portnum'.
 *
 */
int Socket::connectTo(const string& hostname, unsigned short portnum)
{

  struct hostent *hp = ::gethostbyname( hostname.c_str() ) ;
  if( NULL == hp )
	{
	return 0 ;
	}

  ::memset(&address,0,sizeof(address));
  ::memcpy(&address.sin_addr,hp->h_addr,hp->h_length);
  address.sin_family= hp->h_addrtype;
  address.sin_port= htons((u_short)portnum);

  fd = ::socket( hp->h_addrtype, SOCK_STREAM, 0 ) ;
  if( fd < 0 )
	{
	return -1 ;
	}

if (::connect(fd, (struct sockaddr*)&address, sizeof(address)) < 0)
	{
	::close(fd);
#ifdef DEBUG
	logEntry("Closing FD: %i", fd);
#endif
	fd = -1;
	return 0;
	}

  return(1);
}

/**
 *  read.
 *  Inputs: Nothing.
 *  Outputs: char* to static buffer containing data.
 *  Process: 1. Reads as much as possible from this socket, up to
 *              "MTU" bytes.
 *
 */
char* Socket::read()
{

  if( -1 == fd )
	{
	return 0 ;
	}

   int amount = 0 ;
   unsigned short int loopCnt = 0 ;

   do
	{
	errno = 0 ;
	amount = ::read( fd, buffer, MTU ) ;
	}
	while( (amount < 0) && (EINTR == errno) && (++loopCnt <= 10) ) ;

  if( -1 == amount )
	{
    logEntry("[%s]: Read Error: %i (%s)",
	::inet_ntoa(address.sin_addr), errno, ::strerror( errno ) ) ;
    amount = 0;
	}


#ifdef DEBUG
//  printf("[%i]: Read %i Bytes.\n", fd, amount);
#endif

  lastReadSize = amount;
  return buffer;
}
