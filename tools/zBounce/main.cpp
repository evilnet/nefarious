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

#include <string>
#include <iostream>

#include "Bounce.h"
#include "main.h"

using std::cout;
using std::cerr;
using std::endl;
using std::string;

FILE *pidFile;
Bounce *aBounce;

/**
 * Display usage for command line parameters.
 */
void usage(const string &usagePrompt) {
  cerr << "Usage: " << usagePrompt << " -d [-e config_file_path] [-l log_file_path] [-p pid_file_path] [-b vhost]" << endl;
  cerr << "See docs/zbounce_cmdline.readme for additional help." << endl;
  exit(1);
} // usage

void hup_handler(int sig) {
  aBounce->logEntry("::hup_handler> Got SIGHUP -- Reloading configuration.");
  aBounce->bindListeners();
} // hup_handler

void usr_handler(int sig) {
  aBounce->dumpConfig();
} // usr_handler

int main(int argc, char **argv) {
  int ch;				// for getopt
  char *prompt;				// pointer to my prompt

  // initialize variables
  aBounce = new Bounce();

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

  // remember prompt
  if ((prompt = strrchr(argv[0], '/')))
    prompt++;
  else
    prompt = argv[0];

  aBounce->setPrompt(prompt);

  /* parse command line options */
  while ((ch = getopt(argc, argv, "de:l:b:p:")) != -1) {
    switch (ch) {
      case 'd':
        aBounce->setDebug(true);
        break;
      case 'p':
        aBounce->setPIDPath(optarg);
        break;
      case 'e':
        aBounce->setConfigPath(optarg);
        break;
      case 'l':
        aBounce->setLogPath(optarg);
        break;
      case 'b':
        aBounce->setVHost(optarg);
        break;
      default:
        usage(aBounce->getPrompt());
        break;
    } // switch
  } // while

  if (aBounce->getDebug() == true) {        
    /*
     * TODO: The name of this file should be specified
     * on command line or in a conf file
     *
     * 06/12/2003: Done. -GCARTER
     * 06/13/2003: Moved fopen functions to Bounce class. -GCARTER
     */
    if (aBounce->openLog(aBounce->getLogPath()) == false) {
      cout << "ERROR: Unable to open log file: " << ::strerror(errno) << endl;

      return 0;
    } // if
  } // if

  /*
   * Create new aBounce object, bind listeners and begin
   * polling them.
   *
   * 06/12/2003 Do this before the fork in case of errors. -GCARTER
   */
  aBounce->bindListeners();

  /*
   * Detach from console.
   *
   * 06/12/2003: If we read in the configuration correctly NOW we can fork. -GCARTER
   */
  pid_t forkResult = ::fork();
  if(forkResult < 0) {
    cerr << "ERROR: Unable to fork new process." << endl;
    return -1;
  } // if
  else if (forkResult != 0) {
    if (aBounce->getDebug() == true)
      aBounce->logEntry("::main> zBounce started, process %d", forkResult);

  /*
   * 06/12/2003: Write out pid to either the default file or the path
   *             specified from the command line. -GCARTER
   */
  pidFile = fopen(aBounce->getPIDPath().c_str(), "w");

    if (NULL == pidFile) {
      cout << "ERROR: Unable to open log file: "
           << ::strerror(errno) << endl ;

      return 0;
    } // if

    fprintf(pidFile, "%d\n", forkResult);
    fflush(pidFile);
    fclose(pidFile);

    close(0);
    close(1);

    return 1;
  } // else

  while(true) {
    aBounce->checkSockets();
  } // while

  if (aBounce->getDebug() == true)
    aBounce->closeLog();

  // cleanup
  delete aBounce;

  return 0;
} // main
