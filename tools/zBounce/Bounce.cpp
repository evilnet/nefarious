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

#include	<list>
#include	<string>
#include	<iostream>
#include	<fstream>

#include	"Bounce.h"
#include	"main.h"
#include	"Listener.h"
#include	"Connection.h"
#include	"Socket.h"
#include	"StringTokenizer.h"

using std::string ;
using std::cerr ;
using std::endl ;
using std::ifstream ;

void Bounce::dumpConfig()
{
	logEntry("---------------");
	logEntry("Got SIGUSR1. Dumping config:");

	typedef Bounce::allowListType::iterator allowIter;

	allowIter a = allowList.begin();
	while(a != allowList.end())
		{
		in_addr foo;
		foo.s_addr = (*a);
		logEntry("Allow: %s", inet_ntoa(foo));
		++a;
		}

	typedef Bounce::listenerListType::iterator listIter;
	listIter b;
	b = listenerList.begin();

	while(b != listenerList.end())
		{
		logEntry("Listener: %s:%i -> %s:%i", (*b)->myVhost.c_str(), (*b)->localPort,(*b)->remoteServer.c_str(), (*b)->remotePort);
		++b;
		}
	logEntry("---------------");
}

/**
 *  bindListeners.
 *  Inputs: Nothing.
 *  Outputs: Nothing.
 *  Process: 1. Reads the config file, and..
 *           2. Creates a new listener for each 'P' line found.
 *
 */
void Bounce::bindListeners()
{
ifstream inFile( "zbounce.conf" ) ;

/*
 * Clear out the allow list.
 * We'll be reading in a new one now.
 */

allowList.clear();

/*
 *  Open config File.
 */
savedBytes = 0;

if( !inFile )
	{
	cerr	<< "Error, unable to open config file!" << endl ;
	::exit( 0 ) ;
	}

string line ;
size_t lineNumber = 0 ;

while( getline( inFile, line ) )
	{
	++lineNumber ;
	if( line.empty() || ('#' == line[ 0 ]) || ('\r' == line[ 0 ]) )
		{
		continue ;
		}

	switch( line[ 0 ] )
		{
		case ('A'):
			{ /* Add new Allow Line */
			StringTokenizer st( line, ':' ) ;
			unsigned long allowIP = 0;

			if( st.size() != 2 )
				{
				cerr	<< "zbounce.conf:" << lineNumber
						<< "> Expected 1 token in A line, but got "
						<< st.size() << endl ;
				::exit( 0 ) ;
				}

			allowIP = inet_addr( st[ 1 ].c_str() );
			if ( allowIP == INADDR_NONE ) {
				logEntry("Invalid IP specified in A Line. (%s)", st[ 1 ].c_str());
				::exit( 0 );
			}

			allowList.push_front( allowIP );
			logEntry("Read A: line for %s", st[ 1 ].c_str());
			break;
			}

		case ('P'):
		case ('p'):
			{ /* Add new port listener */
			StringTokenizer st( line, ':' ) ;

			// P line requires 5 fields
			if( st.size() != 5 )
				{
				cerr	<< "zbounce.conf:" << lineNumber
						<< "> Expected 4 tokens in P line, but got "
						<< st.size() << endl ;
				::exit( 0 ) ;
				}

			/*
			 * Right.. lets check if this listener is already in our global
			 * list. If it is, don't create a new listener object and bind() again.
			 */
			typedef Bounce::listenerListType::iterator listIter;
			listIter b;
			b = listenerList.begin();
			bool notAdding = false;

			while(b != listenerList.end())
				{
					if( ((*b)->myVhost == st[ 1 ]) && ((*b)->localPort == ::atoi( st[ 2 ].c_str() ))  )
					{
						logEntry("Not adding local listener for %s:%i, its already loaded.",
							(*b)->myVhost.c_str(), (*b)->localPort);
						notAdding = true;
					}

				++b;
				}

			if(notAdding) break;

			Listener* newListener = new Listener();
			newListener->myVhost = st[ 1 ] ;
			newListener->localPort = ::atoi( st[ 2 ].c_str() ) ;
			newListener->remoteServer = st[ 3 ] ;
			newListener->remotePort = ::atoi( st[ 4 ].c_str() ) ;

		/*
		 * Using a P means: Accept plain input, and send a compressed stream. (0)
		 * Using a p means: Accept compressed input, and send a plain stream. (1)
		 */

			newListener->compress = ('p' == line[ 0 ]) ? true : false ;

#ifdef DEBUG
			logEntry("Adding new Listener: Local: %s:%i, Remote: %s:%i",
			newListener->myVhost.c_str(),
			newListener->localPort,
			newListener->remoteServer.c_str(),
			newListener->remotePort ) ;
#endif

			newListener->beginListening();
			listenerList.push_front( newListener ) ;
			break;
    }
    }
  }
}

/**
 *  checkSockets.
 *  Inputs: Nothing.
 *  Outputs: Nothing.
 *  Process: 1. Builds up a FD_SET of all sockets we wish to check.
 *              (Including all listeners & all open connections).
 *           2. SELECT(2) the set, and forward/accept as needed.
 *
 */
void Bounce::checkSockets()
{

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
for( ; a != listenerList.end() ; ++a )
	{
	tempFd = (*a)->fd;
	FD_SET(tempFd, &readfds);
	if (highestFd < tempFd) highestFd = tempFd;
	}

/*
 *  Add Local & Remote connections from each
 *  connection object to the read/write set.
 */

connIter b = connectionsList.begin();
for( ; b != connectionsList.end() ; ++b )
	{
	tempFd = (*b)->localSocket->fd;
	tempFd2 = (*b)->remoteSocket->fd;
	FD_SET(tempFd, &readfds);
	FD_SET(tempFd, &writefds);
	if (highestFd < tempFd) highestFd = tempFd;
	FD_SET(tempFd2, &readfds);
	FD_SET(tempFd2, &writefds);
	if (highestFd < tempFd2) highestFd = tempFd2;
	}

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
while(b != connectionsList.end())
	{
	tempFd = (*b)->localSocket->fd;
	tempFd2 = (*b)->remoteSocket->fd;

	if (FD_ISSET(tempFd, &writefds))
		{
		(*b)->localSocket->canWrite = true;
		}
	else
		{
		(*b)->localSocket->canWrite = false;
		}

	if (FD_ISSET(tempFd2, &writefds))
		{
		(*b)->remoteSocket->canWrite = true;
		}
	else
		{
		(*b)->remoteSocket->canWrite = false;
		}

	if (FD_ISSET(tempFd, &readfds) && (*b)->remoteSocket->canWrite)
		{
		tempBuf = (*b)->localSocket->read();
		if ((*b)->localSocket->lastReadSize == 0) // Connection closed.
			{
			close((*b)->localSocket->fd);
			close((*b)->remoteSocket->fd);
#ifdef DEBUG
			logEntry("Closing FD: %i", (*b)->localSocket->fd);
			logEntry("Closing FD: %i", (*b)->remoteSocket->fd);
#endif
			delete(*b);
			delCheck = true;
			b = connectionsList.erase(b);
			}
		else
			{
			if (!(*b)->compress)
				{
				(*b)->compressBuffer((Bytef*)tempBuf, (*b)->localSocket->lastReadSize, (Bytef*)cBuffer, (*b)->remoteSocket);
				}
			else
				{
				(*b)->deCompressBuffer((Bytef*)tempBuf, (*b)->localSocket->lastReadSize, (Bytef*)cBuffer, (*b)->remoteSocket);
				}
			}
		}

	if( (delCheck == false) && (((*b)->localSocket->fd == -1) || ((*b)->remoteSocket->fd == -1)) )
	{
		/*
		 * Broken! Close the other endpoint.
		 * (If its not already broken too).
		 */
		if( (*b)->remoteSocket->fd != -1 )
			{
#ifdef DEBUG
			logEntry("Closing FD: %i", (*b)->remoteSocket->fd);
#endif
			::close((*b)->remoteSocket->fd);
			}

		if( (*b)->localSocket->fd != -1 )
			{
#ifdef DEBUG
			logEntry("Closing FD: %i", (*b)->localSocket->fd);
#endif
			::close((*b)->localSocket->fd);
			}

		delete(*b);
		delCheck = true;
		b = connectionsList.erase(b);
	}

	if (!delCheck) ++b;
	delCheck = false;
	}

/*
 *  Now check Remote FD's..
 */

b = connectionsList.begin();
while(b != connectionsList.end())
	{
	tempFd = (*b)->remoteSocket->fd;
	tempFd2 = (*b)->localSocket->fd;

	if (FD_ISSET(tempFd, &writefds))
		{
		(*b)->remoteSocket->canWrite = true;
		}
	else
		{
		(*b)->remoteSocket->canWrite = false;
		}

	if (FD_ISSET(tempFd2, &writefds))
		{
		(*b)->localSocket->canWrite = true;
		}
	else
		{
		(*b)->localSocket->canWrite = false;
		}

	if (FD_ISSET(tempFd, &readfds) && (*b)->localSocket->canWrite)
		{
		tempBuf = (*b)->remoteSocket->read();
		if ((*b)->remoteSocket->lastReadSize == 0) // Connection closed.
			{
			close((*b)->localSocket->fd);
			close((*b)->remoteSocket->fd);
#ifdef DEBUG
			logEntry("Closing FD: %i", (*b)->localSocket->fd);
			logEntry("Closing FD: %i", (*b)->remoteSocket->fd);
#endif
			delete(*b);
			delCheck = true;
			b = connectionsList.erase(b);
			}
		else
			{
			if(!(*b)->compress)
				{
				(*b)->deCompressBuffer((Bytef*)tempBuf, (*b)->remoteSocket->lastReadSize, (Bytef*)cBuffer, (*b)->localSocket);
				}
			else
				{
				(*b)->compressBuffer((Bytef*)tempBuf, (*b)->remoteSocket->lastReadSize, (Bytef*)cBuffer, (*b)->localSocket);
				}
			}
		}

	if( (delCheck == false) && (((*b)->localSocket->fd == -1) || ((*b)->remoteSocket->fd == -1)) )
	{
		/*
		 * Broken! Close the other endpoint.
		 * (If its not already broken too).
		 */
		if( (*b)->remoteSocket->fd != -1 )
			{
#ifdef DEBUG
			logEntry("Closing FD: %i", (*b)->remoteSocket->fd);
#endif
			::close((*b)->remoteSocket->fd);
			}

		if( (*b)->localSocket->fd != -1 )
			{
#ifdef DEBUG
			logEntry("Closing FD: %i", (*b)->localSocket->fd);
#endif
			::close((*b)->localSocket->fd);
			}

		delete(*b);
		delCheck = true;
		b = connectionsList.erase(b);
	}

	if (!delCheck) ++b;
	delCheck = false;
	}

/*
 *  Check all listeners for new connections.
 */

a = listenerList.begin();
while(a != listenerList.end())
	{
	tempFd = (*a)->fd;
	if (FD_ISSET(tempFd, &readfds))
		{
		receiveNewConnection(*a);
		}
	++a;
	}
}

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
void Bounce::receiveNewConnection(Listener* listener)
{
typedef Bounce::allowListType::iterator allowIter;
int access = 0;

Connection* newConnection = new Connection();
newConnection->localSocket = listener->handleAccept();

/*
 *  Check connection access.
 */

allowIter a = allowList.begin();
while(a != allowList.end())
	{
	if ((*a) == newConnection->localSocket->address.sin_addr.s_addr)
		{
		access = 1;
		break;
		}
	++a;
	}

if (access)
	{
	logEntry("Connection attempt from %s: Granted.", inet_ntoa(newConnection->localSocket->address.sin_addr));
	}
else
	{
	logEntry("Connection attempt from %s: Denied.", inet_ntoa(newConnection->localSocket->address.sin_addr));
	close(newConnection->localSocket->fd);
	delete(newConnection);
	return;
	}

Socket* remoteSocket = new Socket();
newConnection->remoteSocket = remoteSocket;
newConnection->compress = listener->compress;
logEntry("Attempting connection to %s:%i.", listener->remoteServer.c_str(), listener->remotePort);

if(remoteSocket->connectTo(listener->remoteServer, listener->remotePort))
	{
	connectionsList.insert(connectionsList.begin(), newConnection);
	newConnection->decompStream.zalloc = (alloc_func)0;
	newConnection->decompStream.zfree = (free_func)0;
	newConnection->decompStream.opaque = (voidpf)0;

	newConnection->compStream.zalloc = (alloc_func)0;
	newConnection->compStream.zfree = (free_func)0;
	newConnection->compStream.opaque = (voidpf)0;
	newConnection->pCount = 0;

	inflateInit(&newConnection->decompStream);
	deflateInit2(&newConnection->compStream, COMP_TYPE, Z_DEFLATED, 15, 9, Z_DEFAULT_STRATEGY);

	}
else
	{

#ifdef DEBUG
	newConnection->localSocket->write("ERROR Unable to connect to remote host. (This error reported by zBounce).\n");
#endif
	logEntry("Unable to connect to remote host %s:%i.", listener->remoteServer.c_str(), listener->remotePort);
	close(newConnection->localSocket->fd);
	delete(newConnection);
	delete(remoteSocket);
	}
}
