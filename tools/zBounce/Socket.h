/* Socket.h */

#ifndef __SOCKET_H
#define __SOCKET_H "$Id$"

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

#include "config.h"

/**
 * This class is used to encapsulate a socket connection.
 */
class Socket
{
public:

  /**
   * This constructor will initialize all variables needed for
   * for this class.
   */
  Socket();

  /**
   * The file descriptor for this connection.
   */
  int fd;

  /**
   * The size of the last read buffer.
   */
  int lastReadSize;

  /**
   * This variable is true if the data can be written to the socket,
   * false otherwise.
   */
  bool canWrite;

  /**
   * Input buffer.
   */
  char buffer[MTU];

  /**
   * Socket address structure for the connection.
   */
  struct sockaddr_in address;

  /**
   * Pointer to sendq buffer.
   */
  char* sendq;
  
  /**
   * Connects the socket to the remote host on the given port.
   */
  int connectTo(const string&, unsigned short);

  /**
   * Writes numBytes bytes from the array "buf" to the socket.
   */
  int write(const char* buf, size_t numBytes);

  /**
   * Writes strlen(buf) bytes to the socket.
   */
  int write(const char*);
  
  // Reads as much as possible into a 4k buffer.
  char* read();
};

#endif // __SOCKET_H
