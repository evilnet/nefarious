/* Connection.h */

#ifndef __CONNECTION_H
#define __CONNECTION_H "$Id$"

#include	"config.h"

class Socket ;

/* 
 *  "Connection" Class.
 *  Simply a container for a local/remote Socket pair.
 */

class Connection
{
public:
  Socket* localSocket;
  Socket* remoteSocket;
  z_stream decompStream;
  z_stream compStream;
  int pCount;            // Packet Count (For statistical reporting).
  short compress;         /* If 0, accept plain text and send compressed.
                           * If 1, accept compressed and send plain text.
                           */
  
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
};

#endif // __CONNECTION_H
