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

#include <string>

#include "config.h"

using std::string;

/**
 * This class is used to encapsulate a socket connection.
 */
class Socket {
  public:
    /**
     * This constructor will initialize all variables needed for
     * for this class.
     */
    Socket();

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
    char *read();

    /*********************
     ** Address Members **
     *********************/

    struct sockaddr_in *getAddress()
      { return &myAddress; }

    /****************
     ** FD Members **
     ****************/

    void setFD(const int setMe)
      { myFD = setMe; }

    const int getFD() const
      { return myFD; }

    /****************************
     ** Last Read Size Members **
     ****************************/

    void setLastReadSize(const int setMe)
      { myLastReadSize = setMe; }

    const int getLastReadSize() const
      { return myLastReadSize; }

    /***********************
     ** Writeable Members **
     ***********************/

    void setWriteable(const bool setMe)
      { myWriteable = setMe; }

    const bool getWriteable() const
      { return myWriteable; }

  private:
    /***************
     ** Variables **
     ***************/

    bool myWriteable;			// can we write to the socket?
    char myReadBuffer[MTU];		// input buffer
    int myFD;				// file descriptor for this connection
    int myLastReadSize;			// The size of the last read buffer.
    struct sockaddr_in myAddress;	// socket address structure
};

#endif // __SOCKET_H
