/* Listener.h */

#ifndef __LISTENER_H
#define __LISTENER_H "$Id$"

#include <string>

class Bounce;
class Socket;

using std::string;

/**
 *  "Listener" Class.
 */
class Listener {
  public:

    void beginListening();  // Bind listening ports.
    Socket *handleAccept(); // Accept a new connection.

    /**********************
     ** Compress Members **
     **********************/

    void setCompress(const bool setMe)
      { myCompress = setMe; }

    const bool getCompress() const
      { return myCompress; }

    /****************
     ** FD Members **
     ****************/

    void setFD(const int setMe)
      { myFD = setMe; }

    const int getFD() const
      { return myFD; }

    /***************************
     ** Remote Server Members **
     ***************************/

    void setRemoteServer(const string &setMe)
      { myRemoteServer = setMe; }

    const string getRemoteServer() const
      { return myRemoteServer; }

    /*******************
     ** VHost Members **
     *******************/

    void setVHost(const string &setMe)
      { myVHost = setMe; }

    const string getVHost() const
      { return myVHost; }

    /************************
     ** Local Port Members **
     ************************/

    void setLocalPort(const unsigned short setMe)
      { myLocalPort = setMe; }

    const unsigned short getLocalPort() const
      { return myLocalPort; }

    /*************************
     ** Remove Port Members **
     *************************/

    void setRemotePort(const unsigned short setMe)
      { myRemotePort = setMe; }

    const unsigned short getRemotePort() const
      { return myRemotePort; }

  private:
    bool myCompress;				// compress link?
    int myFD;					// File descriptor.
    string myRemoteServer;			// remote server
    string myVHost;				// vhost to bind to
    unsigned short int myLocalPort;		// local port
    unsigned short int myRemotePort;		// remote port
};

#endif // __LISTENER_H
