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

#include <list>
#include <string>
#include <fstream>
#include <iostream>

#include "zlib.h"
#include "Connection.h"
#include "main.h"
#include "Socket.h"

using std::string ;
using std::cerr ;
using std::endl ;
using std::ifstream ;

int Connection::compressBuffer( Bytef* from, int fromSize, Bytef* to,
	Socket* sendto )
{
/*
 * Compresses from buffer "from" to buffer "to".
 * Returns size of "to" buffer.
 */

  compStream.next_in = from;
  compStream.avail_in = fromSize;
  pCount++;

  do {
       compStream.next_out = to;
       compStream.avail_out = MTU;
       int zlibCode = deflate(&compStream, Z_SYNC_FLUSH);
       if (zlibCode == Z_STREAM_ERROR || zlibCode == Z_DATA_ERROR) {
         logEntry("[  COMP]: Zlib has reported a data stream error, aborting process.");
         ::exit( 0 );
       }
       if (compStream.avail_out < MTU) {
         sendto->write((const char *)to, (MTU - compStream.avail_out));
       }
     } while ((compStream.avail_in > 0) || (compStream.avail_out < MTU));

#ifdef DEBUG
  if (pCount > STAT_FREQ) {
    logEntry("[  COMP]: Total Input Bytes: %li, Total Output Bytes: %li", compStream.total_in, compStream.total_out);
    pCount = 0;
  }
#endif

  return(compStream.total_out);
}

int Connection::deCompressBuffer(Bytef* from, int fromSize, Bytef* to,
	Socket* sendto)
{
  decompStream.next_in = from;
  decompStream.avail_in = fromSize;
  pCount++;

  do {
       decompStream.next_out = to;
       decompStream.avail_out = MTU;
       int zlibCode = inflate(&decompStream, Z_SYNC_FLUSH);
       if (zlibCode == Z_STREAM_ERROR || zlibCode == Z_DATA_ERROR) {
         logEntry("[DECOMP]: Zlib has reported a data stream error, aborting process.");
         ::exit( 0 );
       }
       if(decompStream.avail_out < MTU) {
         sendto->write((const char *)to, (MTU - decompStream.avail_out));
       }
     } while((decompStream.avail_in) > 0 || (decompStream.avail_out < MTU));

#ifdef DEBUG
  if (pCount > STAT_FREQ) {
    logEntry("[DECOMP]: Total Input Bytes: %li, Total Output Bytes: %li", decompStream.total_in, decompStream.total_out);
    pCount = 0;
  }
#endif

  return(decompStream.total_out);
}

