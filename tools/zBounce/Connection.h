/* Connection.h */

#ifndef __CONNECTION_H
#define __CONNECTION_H "$Id$"

#include	"config.h"

class Socket ;

/* 
 *  "Connection" Class.
 *  Simply a container for a local/remote Socket pair.
 */

class Connection {
  public:
    Connection();				// contructor
    virtual ~Connection();			// destructor

    Socket *localSocket;
    Socket *remoteSocket;

    /*
     *  compressBuffer: Compress data in specified buffer and send to
     *  'Socket'.
     */
 
    int compressBuffer(Bytef*, int, Bytef*, Socket*);
   
    /*
     *  decompressBuffer: Decompress data in specified buffer and send to
     *  'Socket'.
     */
  
     int deCompressBuffer(Bytef*, int, Bytef*, Socket*);

    /**********************
     ** Compress Members **
     **********************/

    void setCompress(const bool setMe)
      { myCompress = setMe; }

    const bool getCompress() const
      { return myCompress; }

  private:
    /***************
     ** Variables **
     ***************/
    bool myCompress;		/* If 0, accept plain text and send compressed.
                                 * If 1, accept compressed and send plain text.
                                 */
    int pCount;				// Packet Count (For statistical reporting).
    z_stream decompStream;		// Decompression stream for zlib.
    z_stream compStream;		// Compression stream for zlib.
};

#endif // __CONNECTION_H
