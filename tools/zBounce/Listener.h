/* Listener.h */

#ifndef __LISTENER_H
#define __LISTENER_H "$Id$"

class Bounce ;
class Socket ;

/**
 *  "Listener" Class.
 */
class Listener
{
public:
  int fd;                 // File descriptor.

  // Remote port from config.
  unsigned short int remotePort;

  // Local port for binding.
  unsigned short int localPort;

  // Vhost to bind locally.
  string myVhost ;

  // Remote server to connect to.
  string remoteServer ;

  /* If true, accept plain text and send compressed.
   * If 1, accept compressed and send plain text.
   */
  bool compress;

  void beginListening();  // Bind listening ports.
  Socket* handleAccept(); // Accept a new connection.
};

#endif // __LISTENER_H
