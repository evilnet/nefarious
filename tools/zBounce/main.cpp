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

#include <iostream>

#include "Bounce.h"
#include "main.h"

using std::cout ;
using std::endl ;

FILE* logFile = 0;
Bounce* application;

/**
 *  Global routine for debug logging.
 */
void logEntry( const char* format, ... )
{

// Note that the log file is only opened (in main()) if DEBUG
// is defined.  Therefore, it only makes sense to log attempt to
// log to the logFile if DEBUG is defined
#ifdef DEBUG
	char buf[ 4096 ] = { 0 } ;
	va_list msg;

	time_t utime = ::time(NULL);
	struct tm* now = localtime(&utime);

	va_start(msg, format);
	vsprintf(buf, format, msg);

	strcat(buf, "\0");
	va_end(msg);

	fprintf( logFile, "[%02d/%02d/%02d %02d:%02d]: %s\n",
		now->tm_mday, now->tm_mon,
		1900+now->tm_year, now->tm_hour,
		now->tm_min, buf ) ;

	// Commented out fflush() here because it will thrash the
	// HD if there is a lot of logging()...the system will flush
	// on its own.
	// Yep - but I need it for now because I'm impatient ;) --Gte
	 fflush( logFile );
#endif // DEBUG
}

void hup_handler(int sig)
{
	logEntry("Got SIGHUP -- Reloading configuration.");
	application->bindListeners();
}
void usr_handler(int sig)
{
	application->dumpConfig();
}

int main()
{
application = new Bounce();

/*
 *  Ignore SIGPIPE.
 */
struct sigaction act;
struct sigaction act2;
struct sigaction act3;

act.sa_handler = SIG_IGN;
act.sa_flags = 0;
sigemptyset(&act.sa_mask);
sigaction(SIGPIPE, &act, 0);

act2.sa_handler = hup_handler;
act2.sa_flags = 0;
sigemptyset(&act2.sa_mask);
sigaction(SIGHUP, &act2, 0);

act3.sa_handler = usr_handler;
act3.sa_flags = 0;
sigemptyset(&act3.sa_mask);
sigaction(SIGUSR1, &act3, 0);

#ifdef DEBUG
	// TODO: The name of this file should be specified
	// on command line or in a conf file
	logFile = fopen("bounce.log", "a");
	if( NULL == logFile )
		{
		cout	<< "Unable to open log file: "
			<< ::strerror( errno ) << endl ;
		return 0 ;
		}
#endif // DEBUG

/*
 * Detach from console.
 */
pid_t forkResult = ::fork() ;
if(forkResult < 0)
	{
	cout	<< "Unable to fork new process." << endl ;
	return -1 ;
	}
else if( forkResult != 0 )
	{
	cout	<< "Successfully forked, new process ID: "
		<< forkResult << endl ;
	return 0;
	}

/*
 *  Create new application object, bind listeners and begin
 *  polling them.
 */
application->bindListeners();

while( true )
	{
	application->checkSockets();
	}

#ifdef DEBUG
	fclose( logFile ) ;
	logFile = 0 ;
#endif

return 0 ;

} // main()
