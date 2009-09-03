/*
 * IRC - Internet Relay Chat
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 *
 * See file AUTHORS in IRC package for additional names of
 * the programmers.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
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
 * IPv6 Gateway (based off of Port Bouncer).
 *
 * This tool is designed to listen on an IPv6 address and forward
 * connections to an IPv4 address, injecting a WEBIRC message into
 * the connection spoof virtual IP and host for compatibility.
 *
 * $Id$ 
 *
 */


#include "ipv6gw.h"

using namespace std;

Config* conf = new Config();

vector<string> explode( const string &delimiter, const string &explodeme);

vector<string> explode( const string &delimiter, const string &str)
{
    vector<string> arr;

    int strleng = str.length();
    int delleng = delimiter.length();
    if (delleng==0)
        return arr;//no change

    int i=0;
    int k=0;
    while( i<strleng )
    {
        int j=0;
        while (i+j<strleng && j<delleng && str[i+j]==delimiter[j])
            j++;
        if (j==delleng)//found delimiter
        {
            arr.push_back(  str.substr(k, i-k) );
            i+=delleng;
            k=i;
        }
        else
        {
            i++;
        }
    }
    arr.push_back(  str.substr(k, i-k) );
    return arr;
}

char *encodehost(char *ipbuf) {
  int lparts, rparts, w, i;
  char *formattedhost = NULL;
  char tmphost[255] = "";
  string left;
  string right;

  vector<string> v = explode("::", ipbuf);

  if (v.size() > 0) {
    left = v[0];
    right = v[1];
  }

  v = explode(":", left);
  lparts = v.size();
  v = explode(":", right);
  rparts = v.size();

  w = 8 - (lparts + rparts);

  v = explode(":", left);
  for(int i=0; (unsigned int)i<v.size(); i++) {
    if (strlen(v[i].c_str()) == 4) {
      sprintf(tmphost, "%s%s", formattedhost ? formattedhost : "", v[i].c_str());
      formattedhost = strdup(tmphost);
    } else if (strlen(v[i].c_str()) == 3) {
      sprintf(tmphost, "%s0%s", formattedhost ? formattedhost : "", v[i].c_str());
      formattedhost = strdup(tmphost);
    } else if (strlen(v[i].c_str()) == 2) {
      sprintf(tmphost, "%s00%s", formattedhost ? formattedhost : "", v[i].c_str());
      formattedhost = strdup(tmphost);
    } else if (strlen(v[i].c_str()) == 1) {
      sprintf(tmphost, "%s000%s", formattedhost ? formattedhost : "", v[i].c_str());
      formattedhost = strdup(tmphost);
    } else {

      sprintf(tmphost, "%s0000", formattedhost ? formattedhost : "");
      formattedhost = strdup(tmphost);
    }
  }

  i = 0;
  for (i = 1; i <= w; i++) {
    sprintf(tmphost, "%s0000", formattedhost);
    formattedhost = strdup(tmphost);
  }

  v = explode(":", right);
  for(int i=0; (unsigned int)i<v.size(); i++) {
    if (strlen(v[i].c_str()) == 4) {
      sprintf(tmphost, "%s%s", formattedhost ? formattedhost : "", v[i].c_str());
      formattedhost = strdup(tmphost);
    } else if (strlen(v[i].c_str()) == 3) {
      sprintf(tmphost, "%s0%s", formattedhost ? formattedhost : "", v[i].c_str());
      formattedhost = strdup(tmphost);
    } else if (strlen(v[i].c_str()) == 2) {
      sprintf(tmphost, "%s00%s", formattedhost ? formattedhost : "", v[i].c_str());
      formattedhost = strdup(tmphost);
    } else if (strlen(v[i].c_str()) == 1) {
      sprintf(tmphost, "%s000%s", formattedhost ? formattedhost : "", v[i].c_str());
      formattedhost = strdup(tmphost);
   } else {
      sprintf(tmphost, "%s0000", formattedhost ? formattedhost : "");
      formattedhost = strdup(tmphost);
    }
  }

  return formattedhost;
}

int main(int argc, char* argv[]) {
  Bounce* application = new Bounce();

  /*
   *  Ignore SIGPIPE.
   */

  conf->debug = 0;
#ifdef DEBUG
  conf->debug = 1;
#endif

  for (int i = 1; i < argc; i++) {
    if ((strcmp(argv[i], "-d") == 0) && (!conf->debug)) {
      conf->debug = 1;
      printf("Enabling debug mode\n");
    }
    if ((strcmp(argv[i], "-debug") == 0) && (!conf->debug)) {
      conf->debug = 1;
      printf("Enabling debug mode\n");
    }
  }

   struct sigaction act; 
   act.sa_handler = SIG_IGN;
   act.sa_flags = 0;
   sigemptyset(&act.sa_mask);
   sigaction(SIGPIPE, &act, 0);

   if (!conf->debug) {
     /*
      *  If we aren't debugging, we might as well
      *  detach from the console.
      */

    pid_t forkResult = fork() ;
    if(forkResult < 0)
    { 
      printf("Unable to fork new process.\n");
      return -1 ;
    } 
    else if(forkResult != 0)
    {
     printf("Successfully Forked, New process ID is %i.\n", forkResult);
      return 0;
    } 
  }

  /*
   *  Create new application object, bind listeners and begin
   *  polling them.
   */
  application->bindListeners();

  while (1) {
    application->checkSockets();
  } 
}

/*
 ****************************************
 *                                      *
 *     Bounce class implementation.     *
 *                                      *
 ****************************************
 */
 
void Bounce::bindListeners() { 
/*
 *  bindListeners.
 *  Inputs: Nothing.
 *  Outputs: Nothing.
 *  Process: 1. Reads the config file, and..
 *           2. Creates a new listener for each 'P' line found.
 *
 */

  FILE* configFd;
  char tempBuf[256];
  int localPort = 0;
  int remotePort = 0;
  char* remoteServer;
  char* vHost;
  char* wpass;
  char* wsuff;
 
  /*
   *  Open config File.
   */
  
  if(!(configFd = fopen("ipv6gw.conf", "r")))
  {
    printf("Error, unable to open config file!\n");
    exit(0);
  } 

  while (fgets(tempBuf, 256, configFd) != NULL) { 
    if((tempBuf[0] != '#') && (tempBuf[0] != '\r')) {
    switch(tempBuf[0])
    {
      case 'P': { /* Add new port listener */ 
        strtok(tempBuf, CONF_SEP);
        vHost = strtok(NULL, CONF_SEP);
        localPort = atoi(strtok(NULL, CONF_SEP));
        remoteServer = strtok(NULL, CONF_SEP);
        remotePort = atoi(strtok(NULL, CONF_SEP)); 
        wpass = strtok(NULL, CONF_SEP);
        wsuff = strtok(NULL, CONF_SEP);

        for (int i = strlen(wsuff)-1; i >= 0; i--) {
          if ((wsuff[i] == 10) || (wsuff[i] == 13)) {
             wsuff[i] = '\0';
          }
        }

        Listener* newListener = new Listener();
        strcpy(newListener->myVhost, vHost); 
        strcpy(newListener->remoteServer, remoteServer);
        newListener->remotePort = remotePort;
        newListener->localPort = localPort;
        strcpy(newListener->wircpass, wpass);
        strcpy(newListener->wircsuff, wsuff);
        if (conf->debug)
          printf("Adding new Listener: Local: [%s]:%i, Remote: [%s]:%i\n", vHost, localPort, remoteServer, remotePort);

        newListener->beginListening();
        listenerList.insert(listenerList.begin(), newListener); 
        break;
      }
    }
    } 
  } 
}

void Bounce::checkSockets() { 
/*
 *  checkSockets.
 *  Inputs: Nothing.
 *  Outputs: Nothing.
 *  Process: 1. Builds up a FD_SET of all sockets we wish to check.
 *              (Including all listeners & all open connections).
 *           2. SELECT(2) the set, and forward/accept as needed.
 *
 */ 
  typedef std::list<Listener*> listenerContainer;
  typedef listenerContainer::iterator listIter;

  typedef std::list<Connection*> connectionContainer;
  typedef connectionContainer::iterator connIter; 

  struct timeval tv;
  fd_set readfds; 
  tv.tv_sec = 0;
  tv.tv_usec = 1000;
  int tempFd = 0;
  int tempFd2 = 0;
  int highestFd = 0;
  int delCheck = 0;
  char* tempBuf;

  FD_ZERO(&readfds);
 
  /*
   *  Add all Listeners to the set.
   */

  listIter a = listenerList.begin();
  while(a != listenerList.end())
  { 
    tempFd = (*a)->fd; 
    FD_SET(tempFd, &readfds);
    if (highestFd < tempFd) highestFd = tempFd;
    a++;
  }

  /*
   *  Add Local & Remote connections from each
   *  connection object to the set.
   */

  connIter b = connectionsList.begin();
  while(b != connectionsList.end())
  { 
    tempFd = (*b)->localSocket->fd;
    tempFd2 = (*b)->remoteSocket->fd;
    FD_SET(tempFd, &readfds);
    if (highestFd < tempFd) highestFd = tempFd;
    FD_SET(tempFd2, &readfds);
    if (highestFd < tempFd2) highestFd = tempFd2;
    b++;
  }

  select(highestFd+1, &readfds, NULL, NULL, &tv); 

  /*
   *  Check all connections for readability.   *  First check Local FD's.
   *  If the connection is closed on either side,
   *  shutdown both sockets, and clean up.
   *  Otherwise, send the data from local->remote, or
   *  remote->local.
   */

  b = connectionsList.begin();
  while(b != connectionsList.end())
  { 
    tempFd = (*b)->localSocket->fd;
 
    if (FD_ISSET(tempFd, &readfds))
    { 
      tempBuf = (*b)->localSocket->read();
      if ((tempBuf[0] == 0)) // Connection closed.
      {
        close((*b)->localSocket->fd);
        close((*b)->remoteSocket->fd); 
        if (conf->debug) {
          printf("Closing L FD: %i\n", (*b)->localSocket->fd);
          printf("Closing R FD: %i\n", (*b)->remoteSocket->fd); 
        }
        delete(*b);
        delCheck = 1;
        b = connectionsList.erase(b); 
      } else {
         if (strstr(tempBuf, "NICK ") && !((*b)->flags & FLAG_SENTWEBIRC)) {
           char *ipbuf = new char;
           char *ipbuff = new char;
           char *ipbufr = new char;
           static char result[64];
           MD5state_st ctx1, ctx2, ctx3;
           unsigned char hash1[16], hash2[16], hash3[16];
           char *webirc = new char;
           char *formattedhost = NULL;

           (*b)->flags |= FLAG_SENTWEBIRC;

           ipbuf = (char *)inet_ntop(AF_INET6, &(*b)->localSocket->address6.sin6_addr, result, 64);

           formattedhost = encodehost(ipbuf);

           ipbuff = strdup(formattedhost);
           string revtmp = ipbuff;

           MD5_Init(&ctx1);
           MD5_Update(&ctx1,(unsigned const char *)revtmp.substr(0,16).c_str(), 16);
           MD5_Final(hash1,&ctx1);
           MD5_Init(&ctx2);
           MD5_Update(&ctx2,(unsigned const char *)revtmp.substr(16,8).c_str(), 8);
           MD5_Final(hash2,&ctx2);
           MD5_Init(&ctx3);
           MD5_Update(&ctx3,(unsigned const char *)revtmp.substr(24).c_str(), 8);
           MD5_Final(hash3,&ctx3);

           string reversehost(revtmp.begin(),revtmp.end());
           reverse (reversehost.begin(), reversehost.end());
           ipbufr = (char *)reversehost.c_str();

           sprintf(webirc, "WEBIRC %s ipv6gw %s.%s 0.%d.%d.%d\r\n", (*b)->wircpass, ipbufr, (*b)->wircsuff, hash1[3], hash2[7], hash3[11]);
           int l = strlen(webirc);
           if (conf->debug)
             printf("Debug write local fd %s\n", webirc);
           (*b)->remoteSocket->write(webirc, l);
         }
         if (conf->debug)
           printf("Debug write local fd %s\n", tempBuf);
        (*b)->remoteSocket->write(tempBuf, (*b)->localSocket->lastReadSize); 
      }
    } 
 
  if (!delCheck) b++;
  delCheck = 0;
  } 

  /*
   *  Now check Remote FD's..
   */
  b = connectionsList.begin();
  while(b != connectionsList.end())
  { 
    tempFd = (*b)->remoteSocket->fd;
    if (FD_ISSET(tempFd, &readfds))
    {
      tempBuf = (*b)->remoteSocket->read();
      if ((tempBuf[0] == 0)) // Connection closed.
      {
        close((*b)->localSocket->fd);
        close((*b)->remoteSocket->fd); 
        if (conf->debug) {
          printf("Closing L FD: %i\n", (*b)->localSocket->fd);
          printf("Closing R FD: %i\n", (*b)->remoteSocket->fd);
        }
        delete(*b);
        delCheck = 1;
        b = connectionsList.erase(b); 
      } else {
         if (conf->debug)
           printf("Debug write remote fd %s\n", tempBuf);
        (*b)->localSocket->write(tempBuf, (*b)->remoteSocket->lastReadSize);
      }
    }
  if (!delCheck) b++;
  delCheck = 0;
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
      recieveNewConnection(*a);
    }
    a++;
  } 

}

void Bounce::recieveNewConnection(Listener* listener) {
/*
 *  recieveNewConnection.
 *  Inputs: A Listener Object.
 *  Outputs: Nothing.
 *  Process: 1. Recieves a new connection on a local port,
 *              and creates a connection object for it.
 *           2. Accepts the incomming connection.
 *           3. Creates a new Socket object for the remote
 *              end of the connection.
 *           4. Connects up the remote Socket.
 *           5. Adds the new Connection object to the
 *              connections list.
 *
 */
  Connection* newConnection = new Connection();
  newConnection->localSocket = listener->handleAccept();

  Socket* remoteSocket = new Socket();
  newConnection->remoteSocket = remoteSocket; 
  if(remoteSocket->connectTo(listener->remoteServer, listener->remotePort)) {
    connectionsList.insert(connectionsList.begin(), newConnection);
    strcpy(newConnection->wircpass, listener->wircpass);
    strcpy(newConnection->wircsuff, listener->wircsuff);
  } else {
    if (conf->debug)
      newConnection->localSocket->write((char *)"ERROR: Unable to connect to remote host.\n");
    close(newConnection->localSocket->fd);
    delete(newConnection);
    delete(remoteSocket);
  } 
}
 

/*
 ****************************************
 *                                      *
 *    Listener class implementation.    *
 *                                      *
 ****************************************
 */

 
Socket* Listener::handleAccept() {
/*
 *  handleAccept.
 *  Inputs: Nothing.
 *  Outputs: A Socket Object.
 *  Process: 1. Accept's an incomming connection,
 *              and returns a new socket object. 
 */

  int new_fd = 0;
  int sin_size = sizeof(struct sockaddr_in6);

  Socket* newSocket = new Socket();
  new_fd = accept(fd, (struct sockaddr*)&newSocket->address6, (socklen_t*)&sin_size);

  newSocket->fd = new_fd; 
  return newSocket;
}
 
void Listener::beginListening() {
/*
 *  beginListening.
 *  Inputs: Nothing.
 *  Outputs: Nothing.
 *  Process: 1. Binds the local ports for all the
 *              Listener objects.
 *
 */

  int bindRes;
  int optval;
  optval = 1;

  struct sockaddr_in6 servaddr;
  in6_addr addy;
  int size;

  memset(&servaddr, 0, sizeof(servaddr));

  if (inet_pton(AF_INET6, myVhost, &addy) < 0) {
    printf("Invalid IP address %s\n", myVhost);
    exit(0);
  }

  fd = socket(AF_INET6, SOCK_STREAM, 0); /* Check for no FD's left?! */

  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

  servaddr.sin6_family = AF_INET6;
  memcpy(&(servaddr.sin6_addr), &addy, sizeof(in6_addr));
  servaddr.sin6_port = htons(localPort);
  size = sizeof(sockaddr_in6);

  bindRes = bind(fd, (struct sockaddr *)&servaddr, size);
  if(bindRes >= 0)
  {
    listen(fd, 10);
  } else { 
     /*
      *  If we can't bind a listening port, we might aswell drop out.
      */
     printf("Unable to bind to [%s]:%i: %s (%d)\n", myVhost, localPort, strerror(errno), errno);
     exit(0);
   } 
}

/*
 ****************************************
 *                                      *
 *     Socket class implementation.     *
 *                                      *
 ****************************************
 */


Socket::Socket() {
/*
 *  Socket Constructor.
 *  Inputs: Nothing.
 *  Outputs: Nothing.
 *  Process: Initialises member variables.
 *
 */

  fd = -1;
  lastReadSize = 0;
}

int Socket::write(char *message, int len) { 
/*
 *  write.
 *  Inputs: Message string, and lenght.
 *  Outputs: Amount written, or 0 on error.
 *  Process: 1. Writes out 'len' amount of 'message'.
 *              to this socket.
 *
 */

   if (fd == -1) return 0; 
 
   int amount = ::write(fd, message, len); 
   if (conf->debug)
     printf("Wrote %i Bytes.\n", amount);
   return amount; 
}

int Socket::write(char *message) { 
/*
 *  write(2).
 *  Inputs: Message string.
 *  Outputs: Amount writte, or 0 on error.
 *  Process: Writes out the whole of 'message'.
 *
 */

   if (fd == -1) return 0; 
 
   int amount = ::write(fd, message, strlen(message)); 
   if (conf->debug)
     printf("Wrote %i Bytes.\n", amount);
   return amount; 
}


int Socket::connectTo(char *hostname, unsigned short portnum) { 
/*
 *  connectTo.
 *  Inputs: Hostname and port.
 *  Outputs: +ve on success, 0 on failure.
 *  Process: 1. Connects this socket to remote 'hostname' on
 *              port 'port'.
 *
 */

  struct hostent     *hp;
 
  if ((hp = gethostbyname(hostname)) == NULL) { 
     return 0; 
  }          

  memset(&address,0,sizeof(address));
  memcpy((char *)&address.sin_addr,hp->h_addr,hp->h_length);
  address.sin_family= hp->h_addrtype;
  address.sin_port= htons((u_short)portnum);

  if ((fd = socket(hp->h_addrtype,SOCK_STREAM,0)) < 0)
    return 0; 
 
  if (connect(fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
    close(fd);
    fd = -1; 
    return 0;
  } 
  return(1);
}

char* Socket::read() { 
/*
 *  read.
 *  Inputs: Nothing.
 *  Outputs: char* to static buffer containing data.
 *  Process: 1. Reads as much as possible from this socket, up to
 *              4k.
 *
 */

  int amountRead = 0;
  static char buffer[4096];

  amountRead = ::read(fd, &buffer, 4096);

  if ((amountRead == -1)) buffer[0] = '\0';
  buffer[amountRead] = '\0';

  if (conf->debug)
    printf("Read %s (%i Bytes).\n", buffer, amountRead);

  /* 
   * Record this just incase we're dealing with binary data with 0's in it.
   */
  lastReadSize = amountRead;
  return (char *)&buffer;
}

