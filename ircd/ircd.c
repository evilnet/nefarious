/*
 * IRC - Internet Relay Chat, ircd/ircd.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
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
 * $Id$
 */
#include "config.h"

#include "ircd.h"
#include "IPcheck.h"
#include "channel.h"
#include "class.h"
#include "client.h"
#include "crule.h"
#include "hash.h"
#include "ircd_alloc.h"
#include "ircd_events.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_signal.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "ircd_crypt.h"
#include "jupe.h"
#include "list.h"
#include "match.h"
#include "motd.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "opercmds.h"
#include "parse.h"
#include "querycmds.h"
#include "res.h"
#include "s_auth.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_stats.h"
#include "send.h"
#ifdef USE_SSL
#include "ssl.h"
#endif /* USE_SSL */
#include "sys.h"
#include "uping.h"
#include "userload.h"
#include "version.h"
#include "whowas.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>



/*----------------------------------------------------------------------------
 * External stuff
 *--------------------------------------------------------------------------*/
extern void init_counters(void);
extern void init_isupport(void);

/*----------------------------------------------------------------------------
 * Constants / Enums
 *--------------------------------------------------------------------------*/
enum {
  BOOT_DEBUG = 1,
  BOOT_TTY   = 2,
  BOOT_CHKCONF = 4
};


/*----------------------------------------------------------------------------
 * Global data (YUCK!)
 *--------------------------------------------------------------------------*/
struct Client  me;                      /* That's me */
struct Connection me_con;		/* That's me too */
struct Client *GlobalClientList  = &me; /* Pointer to beginning of
					   Client list */
time_t         TSoffset          = 0;/* Offset of timestamps to system clock */
int            GlobalRehashFlag  = 0;   /* do a rehash if set */
int            GlobalRestartFlag = 0;   /* do a restart if set */
time_t         CurrentTime;          /* Updated every time we leave select() */

char          *configfile        = CPATH; /* Server configuration file */
char          *logfile           = LPATH;
int            debuglevel        = -1;    /* Server debug level  */
char          *debugmode         = "";    /* Server debug level */
int            refuse            = 0;     /**< Refuse new connecting clients */
static char   *dpath             = DPATH;
static char   *spath             = SPATH;

static struct Timer connect_timer; /* timer structure for try_connections() */
static struct Timer ping_timer; /* timer structure for check_pings() */
static struct Timer alist_timer;
static struct Timer countdown_timer; /**< timer structure for exit_countdown() */

static struct Daemon thisServer  = { 0, 0, 0, 0, 0, 0, 0, -1 };

int running = 1;


/**
 * Perform a restart or die, sending and logging all necessary messages.
 * @param[in] pe Pointer to structure describing pending exit.
 */
static void pending_exit(struct PendingExit *pe)
{
  static int looping = 0;
  enum LogLevel level = pe->restart ? L_WARNING : L_CRIT;
  const char *what = pe->restart ? "restarting" : "terminating";

  if (looping++) /* increment looping to prevent looping */
    return;

  if (pe->message) {
    sendto_lusers("Server %s: %s", what, pe->message);

    if (pe->who) { /* write notice to log */
      log_write(LS_SYSTEM, level, 0, "%s %s server: %s", pe->who, what,
		pe->message);
      sendcmdto_serv_butone(&me, CMD_SQUIT, 0, "%s 0 :%s %s server: %s",
		     cli_name(&me), pe->who, what, pe->message);
    } else {
      log_write(LS_SYSTEM, level, 0, "Server %s: %s", what, pe->message);
      sendcmdto_serv_butone(&me, CMD_SQUIT, 0, "%s 0 :Server %s: %s",
		     cli_name(&me), what, pe->message);
    }
  } else { /* just notify of the restart/termination */
    sendto_lusers("Server %s...", what);

    if (pe->who) { /* write notice to log */
      log_write(LS_SYSTEM, level, 0, "%s %s server...", pe->who, what);
      sendcmdto_serv_butone(&me, CMD_SQUIT, 0, "%s 0 :%s %s server...",
		     cli_name(&me), pe->who, what);
    } else {
      log_write(LS_SYSTEM, level, 0, "Server %s...", what);
      sendcmdto_serv_butone(&me, CMD_SQUIT, 0, "%s 0 :Server %s...",
		     cli_name(&me), what);
    }
  }

  /* now let's perform the restart or exit */
  flush_connections(0);
  log_close();
  close_connections(!pe->restart ||
		    !(thisServer.bootopt & (BOOT_TTY | BOOT_DEBUG | BOOT_CHKCONF)));

  if (!pe->restart) { /* just set running = 0 */
    running = 0;
    return;
  }

  /* OK, so we're restarting... */
  reap_children();

  execv(SPATH, thisServer.argv); /* restart the server */

  /* something failed; reopen the logs so we can complain */
  log_reopen();

  log_write(LS_SYSTEM, L_CRIT,  0, "execv(%s,%s) failed: %m", SPATH,
	    *thisServer.argv);

  Debug((DEBUG_FATAL, "Couldn't restart server \"%s\": %s", SPATH,
	 (strerror(errno)) ? strerror(errno) : ""));
  exit(8);
}

/**
 * Issue server notice warning about impending restart or die.
 * @param[in] pe Pointer to structure describing pending exit.
 * @param[in] until How long until the exit (approximately).
 */
static void countdown_notice(struct PendingExit *pe, time_t until)
{
  const char *what = pe->restart ? "restarting" : "terminating";
  const char *units;

  if (until >= 60) { /* measure in minutes */
    until /= 60; /* so convert it to minutes */
    units = (until == 1) ? "minute" : "minutes";
  } else
    units = (until == 1) ? "second" : "seconds";

  /* send the message */
  if (pe->message)
    sendto_lusers("Server %s in %d %s: %s (%s)", what, until, units, pe->message, pe->who);
  else
    sendto_lusers("Server %s in %d %s... (%s)", what, until, units, pe->who);
}

static void exit_countdown(struct Event *ev);

/**
 * Performs a delayed pending exit, issuing server notices as appropriate.
 * Reschedules exit_countdown() as needed.
 * @param[in] pe Pending exit.
 * @param[in] do_notice If 1 then send notices.
 */
static void _exit_countdown(struct PendingExit *pe, int do_notice)
{
  time_t total, next, approx;

  if (CurrentTime >= pe->time) { /* time to do the exit */
    pending_exit(pe);
    return;
  }

  /* OK, we need to figure out how long to the next message and approximate
   * how long until the actual exit.
   */
  total = pe->time - CurrentTime; /* how long until exit */

#define t_adjust(interval, interval2)				\
  do {								\
    approx = next = total - (total % (interval));		\
    if (next >= total - (interval2)) {				\
      next -= (interval); /* have to adjust next... */		\
      if (next < (interval)) /* slipped into next interval */	\
	next = (interval) - (interval2);			\
    } else /* have to adjust approx... */			\
      approx += (interval);					\
  } while (0)

  if (total > PEND_INT_LONG) /* in the long interval regime */
    t_adjust(PEND_INT_LONG, PEND_INT_MEDIUM);
  else if (total > PEND_INT_MEDIUM) /* in the medium interval regime */
    t_adjust(PEND_INT_MEDIUM, PEND_INT_SHORT);
  else if (total > PEND_INT_SHORT) /* in the short interval regime */
    t_adjust(PEND_INT_SHORT, PEND_INT_END);
  else if (total > PEND_INT_END) /* in the end interval regime */
    t_adjust(PEND_INT_END, PEND_INT_LAST);
  else if (total > PEND_INT_LAST) /* in the last message interval */
    t_adjust(PEND_INT_LAST, PEND_INT_LAST);
  else { /* next event is to actually exit */
    next = 0;
    approx = PEND_INT_LAST;
  }

  /* convert next to an absolute timestamp */
  next = pe->time - next;
  assert(next > CurrentTime);

  /* issue the warning notices... */
  if (do_notice)
    countdown_notice(pe, approx);

  /* reschedule the timer... */
  timer_add(&countdown_timer, exit_countdown, pe, TT_ABSOLUTE, next);
}

/**
 * Timer callback for _exit_countdown().
 * @param[in] ev Timer event.
 */
static void exit_countdown(struct Event *ev)
{
  if (ev_type(ev) == ET_DESTROY)
    return; /* do nothing with destroy events */

  assert(ET_EXPIRE == ev_type(ev));

  /* perform the event we were called to do */
  _exit_countdown(t_data(&countdown_timer), 1);
}

/**
 * Cancel a pending exit.
 * @param[in] who Client cancelling the impending exit.
 */
void exit_cancel(struct Client *who)
{
  const char *what;
  struct PendingExit *pe;

  if (!t_onqueue(&countdown_timer))
    return; /* it's not running... */

  pe = t_data(&countdown_timer); /* get the pending exit data */
  timer_del(&countdown_timer); /* delete the timer */

  if (who) { /* explicitly issued cancellation */
    /* issue a notice about the exit being canceled */
    sendto_lusers("Server %s CANCELED",
		  what = (pe->restart ? "restart" : "termination"));

    /* log the cancellation */
    if (IsUser(who))
      log_write(LS_SYSTEM, L_NOTICE, 0, "Server %s CANCELED by %s!%s@%s", what,
		cli_name(who), cli_user(who)->username, cli_sockhost(who));
    else
      log_write(LS_SYSTEM, L_NOTICE, 0, "Server %s CANCELED by %s", what,
		cli_name(who));
  }

  /* release the pending exit structure */
  if (pe->who)
    MyFree(pe->who);
  if (pe->message)
    MyFree(pe->message);
  MyFree(pe);

  /* Oh, and restore connections */
  refuse = 0;
}

/**
 * Schedule a pending exit.  Note that only real people issue delayed
 * exits, so \a who should not be NULL if \a when is non-zero.
 * @param[in] restart True if a restart is desired, false otherwise.
 * @param[in] when Interval until the exit; 0 for immediate exit.
 * @param[in] who Client issuing exit (or NULL).
 * @param[in] message Message explaining exit.
 */
void exit_schedule(int restart, time_t when, struct Client *who,
		   const char *message)
{
  struct PendingExit *pe;

  /* first, let's cancel any pending exit */
  exit_cancel(0);

  /* now create a new pending exit */
  pe = MyMalloc(sizeof(struct PendingExit));
  pe->restart = restart;
  pe->time = when + CurrentTime; /* make time absolute */
  if (who) { /* save who issued it... */
    if (IsUser(who)) {
      char nuhbuf[NICKLEN + USERLEN + HOSTLEN + 3];
      ircd_snprintf(0, nuhbuf, sizeof(nuhbuf), "%s!%s@%s", cli_name(who),
		    cli_user(who)->username, cli_user(who)->host);
      DupString(pe->who, nuhbuf);
    } else
      DupString(pe->who, cli_name(who));
  } else
    pe->who = 0;
  if (message) /* also save the message */
    DupString(pe->message, message);
  else
    pe->message = 0;

  /* let's refuse new connections... */
  refuse = 1;

  if (!when) { /* do it right now? */
    pending_exit(pe);
    return;
  }

  assert(who); /* only people issue delayed exits */

  /* issue a countdown notice... */
  countdown_notice(pe, when);

  /* log who issued the shutdown */
  if (pe->message)
    log_write(LS_SYSTEM, L_NOTICE, 0, "Delayed server %s issued by %s: %s",
	      restart ? "restart" : "termination", pe->who, pe->message);
  else
    log_write(LS_SYSTEM, L_NOTICE, 0, "Delayed server %s issued by %s...",
	      restart ? "restart" : "termination", pe->who);

  /* and schedule the timer */
  _exit_countdown(pe, 0);
}

/*----------------------------------------------------------------------------
 * API: server_panic
 *--------------------------------------------------------------------------*/
/** Immediately terminate the server with a message.
 * @param[in] message Message to log, but not send to operators.
 */
void server_panic(const char *message)
{
  /* inhibit sending server notice--we may be panicking due to low memory */
  log_write(LS_SYSTEM, L_CRIT, LOG_NOSNOTICE, "Server panic: %s", message);
  flush_connections(0);
  log_close();
  close_connections(1);
  exit(1);
}


/*----------------------------------------------------------------------------
 * outofmemory:  Handler for out of memory conditions...
 *--------------------------------------------------------------------------*/
static void outofmemory(void) {
  Debug((DEBUG_FATAL, "Out of memory: restarting server..."));
  exit_schedule(1, 0, 0, "Out of Memory");
} 


/*----------------------------------------------------------------------------
 * write_pidfile
 *--------------------------------------------------------------------------*/
static void write_pidfile(void) {
  char buff[20];
  if ((thisServer.pid_fd >= 0) && (!feature_bool(FEAT_NEFARIOUS))) {
    memset(buff, 0, sizeof(buff));
    sprintf(buff, "%5d\n", (int)getpid());
    if (write(thisServer.pid_fd, buff, strlen(buff)) == -1)
      Debug((DEBUG_NOTICE, "Error writing to pid file %s: %m",
	     feature_str(FEAT_PPATH)));
    return;
  }
  Debug((DEBUG_NOTICE, "Error opening pid file %s: %m",
	 feature_str(FEAT_PPATH)));
}

/* check_pid
 * 
 * inputs: 
 *   none
 * returns:
 *   true - if the pid file exists (and is readable), and the pid refered
 *          to in the file is still running.
 *   false - otherwise.
 */
static int check_pid(void)
{
  struct flock lock;

  lock.l_type = F_WRLCK;
  lock.l_start = 0;
  lock.l_whence = SEEK_SET;
  lock.l_len = 0;

  if (((thisServer.pid_fd = open(feature_str(FEAT_PPATH),
	O_CREAT | O_RDWR, 0600)) >= 0) && (!feature_bool(FEAT_NEFARIOUS)))
    return fcntl(thisServer.pid_fd, F_SETLK, &lock);
  return 0;
}


static void send_alist(struct Event* ev) {
  time_t next, cur;
  struct Channel *chptr;

  cur = CurrentTime - feature_int(FEAT_ALIST_SEND_DIFF);
  for (chptr = GlobalChannelList; chptr; chptr = chptr->next) {
    if ((chptr->last_message > cur) && (chptr->last_sent != chptr->last_message)) {
      chptr->last_sent = chptr->last_message;
      sendcmdto_serv_butone(&me, CMD_ALIST, 0, "%s %Tu", chptr->chname, chptr->last_message);
    }
  }

  next = CurrentTime + feature_int(FEAT_ALIST_SEND_FREQ);

  Debug((DEBUG_NOTICE, "Next ALIST send : %s", myctime(next)));

  timer_add(&alist_timer, send_alist, 0, TT_ABSOLUTE, next);
}


/*----------------------------------------------------------------------------
 * try_connections
 *
 * Scan through configuration and try new connections.
 *
 * Returns the calendar time when the next call to this
 * function should be made latest. (No harm done if this
 * is called earlier or later...)
 *--------------------------------------------------------------------------*/
static void try_connections(struct Event* ev) {
  struct ConfItem*  aconf;
  struct ConfItem** pconf;
  time_t            next;
  struct Jupe*      ajupe;
  int               hold;
  int               done;

  assert(ET_EXPIRE == ev_type(ev));
  assert(0 != ev_timer(ev));

  Debug((DEBUG_NOTICE, "Connection check at   : %s", myctime(CurrentTime)));
  next = CurrentTime + feature_int(FEAT_CONNECTFREQUENCY);
  done = 0;

  for (aconf = GlobalConfList; aconf; aconf = aconf->next) {
    /* Only consider server items with non-zero port and non-zero
     * connect times that are not actively juped.
     */
    if (!(aconf->status & CONF_SERVER)
        || aconf->port == 0
        || !(aconf->flags & CONF_AUTOCONNECT)
        || ((ajupe = jupe_find(aconf->name)) && JupeIsActive(ajupe)))
      continue;

    /* Do we need to postpone this connection further? */
    hold = aconf->hold > CurrentTime;

    /* Update next possible connection check time. */
    if (hold && next > aconf->hold)
        next = aconf->hold;

    /* Do not try to connect if its use is still on hold until future,
     * we have already initiated a connection this try_connections(),
     * too many links in its connection class, it is already linked,
     * or if connect rules forbid a link now.
     */
    if (hold || done
        || (ConfLinks(aconf) > ConfMaxLinks(aconf))
        || FindServer(aconf->name)
        || conf_eval_crule(aconf->name, CRULE_MASK))
      continue;

    /* Ensure it is at the end of the list for future checks. */
    if (aconf->next) {
      /* Find aconf's location in the list and splice it out. */
      for (pconf = &GlobalConfList; *pconf; pconf = &(*pconf)->next)
        if (*pconf == aconf)
          *pconf = aconf->next;
      /* Reinsert it at the end of the list (where pconf is now). */
      *pconf = aconf;
      aconf->next = 0;
    }

    /* Activate the connection itself. */
    if (connect_server(aconf, 0, 0))
      sendto_opmask_butone(0, SNO_OLDSNO, "Connection to %s activated.",
                           aconf->name);

    /* And stop looking for further candidates. */
    done = 1;
  }

  Debug((DEBUG_NOTICE, "Next connection check : %s", myctime(next)));
  timer_add(&connect_timer, try_connections, 0, TT_ABSOLUTE, next);
}


/*----------------------------------------------------------------------------
 * check_pings
 *
 * TODO: This should be moved out of ircd.c.  It's protocol-specific when you
 *       get right down to it.  Can't really be done until the server is more
 *       modular, however...
 *--------------------------------------------------------------------------*/
static void check_pings(struct Event* ev) {
  int expire     = 0;
  int next_check = CurrentTime;
  int max_ping   = 0;
  int i;

  assert(ET_EXPIRE == ev_type(ev));
  assert(0 != ev_timer(ev));

  next_check += feature_int(FEAT_PINGFREQUENCY);
  
  /* Scan through the client table */
  for (i=0; i <= HighestFd; i++) {
    struct Client *cptr = LocalClientArray[i];
   
    if (!cptr)
      continue;
     
    assert(&me != cptr);  /* I should never be in the local client array! */
   

    /* Remove dead clients. */
    if (IsDead(cptr)) {
      exit_client(cptr, cptr, &me, cli_info(cptr));
      continue;
    }

    max_ping = IsRegistered(cptr) ? client_get_ping(cptr) :
      feature_int(FEAT_CONNECTTIMEOUT);
   
    Debug((DEBUG_DEBUG, "check_pings(%s)=status:%s limit: %d current: %d",
	   cli_name(cptr),
	   HasFlag(cptr, FLAG_PINGSENT) ? "[Ping Sent]" : "[]", 
	   max_ping, (int)(CurrentTime - cli_lasttime(cptr))));

    /* Ok, the thing that will happen most frequently, is that someone will
     * have sent something recently.  Cover this first for speed.
     * -- 
     * If it's an unregisterd client and hasn't managed to register within
     * max_ping then it's obviously having problems (broken client) or it's
     * just up to no good, so we won't skip it, even if its been sending
     * data to us. 
     * -- hikari */
    if ((CurrentTime-cli_lasttime(cptr) < max_ping) &&
        (IsRegistered(cptr))) {
      expire = cli_lasttime(cptr) + max_ping;
      if (expire < next_check) 
	next_check = expire;
      continue;
    }

    /* Unregistered clients pingout after max_ping seconds, they don't
     * get given a second chance - if they were then people could not quite
     * finish registration and hold resources without being subject to k/g
     * lines
     */
    if (!IsRegistered(cptr)) {
      assert(!IsServer(cptr));
      if ((CurrentTime-cli_firsttime(cptr) >= max_ping)) {
       /* Display message if they have sent a NICK and a USER but no
        * nospoof PONG.
        */
       if (*(cli_name(cptr)) && cli_user(cptr) && *(cli_user(cptr))->username) {
         send_reply(cptr, SND_EXPLICIT | ERR_BADPING,
           ":Your client may not be compatible with this server.");
         send_reply(cptr, SND_EXPLICIT | ERR_BADPING,
           ":Compatible clients are available at %s",
         feature_str(FEAT_URL_CLIENTS));
       }
       exit_client_msg(cptr,cptr,&me, "Registration Timeout");
       continue;
      } else {
        /* OK, they still have enough time left, so we'll just skip to the
         * next client.  Set the next check to be when their time is up, if
         * that's before the currently scheduled next check -- hikari */
        expire = cli_firsttime(cptr) + max_ping;
        if (expire < next_check)
          next_check = expire;
        continue;
      }
    }

    /* Quit the client after max_ping*2 - they should have answered by now */
    if (CurrentTime-cli_lasttime(cptr) >= (max_ping*2) ) {
      /* If it was a server, then tell ops about it. */
      if (IsServer(cptr) || IsConnecting(cptr) || IsHandshake(cptr))
        sendto_opmask_butone(0, SNO_OLDSNO,
                             "No response from %s, closing link",
                             cli_name(cptr));

      if (feature_bool(FEAT_TIME_IN_TIMEOUT))
        exit_client_msg(cptr, cptr, &me, "Ping timeout: %d seconds",CurrentTime-cli_lasttime(cptr));
      else
        exit_client_msg(cptr, cptr, &me, "Ping timeout");

      continue;
    }
    
    if (!HasFlag(cptr, FLAG_PINGSENT)) {
      /* If we havent PINGed the connection and we havent heard from it in a
       * while, PING it to make sure it is still alive.
       */
      SetFlag(cptr, FLAG_PINGSENT);

      /* If we're late in noticing don't hold it against them :) */
      cli_lasttime(cptr) = CurrentTime - max_ping;
      
      if (IsUser(cptr))
	sendrawto_one(cptr, MSG_PING " :%s", cli_name(&me));
      else  {
        char *asll_ts = militime_float(NULL);
	sendcmdto_one(&me, CMD_PING, cptr, "!%s %s %s", asll_ts,
		      cli_name(cptr), asll_ts);
      }
    }
    
    expire = cli_lasttime(cptr) + max_ping * 2;
    if (expire < next_check)
      next_check=expire;
  }
  
  assert(next_check >= CurrentTime);
  
  Debug((DEBUG_DEBUG, "[%i] check_pings() again in %is",
	 CurrentTime, next_check-CurrentTime));
  
  timer_add(&ping_timer, check_pings, 0, TT_ABSOLUTE, next_check);
}


/*----------------------------------------------------------------------------
 * parse_command_line
 * Side Effects: changes GLOBALS me, thisServer, dpath, configfile, debuglevel
 * debugmode
 *--------------------------------------------------------------------------*/
static void parse_command_line(int argc, char** argv) {
  const char *options = "d:s:f:l:h:nktvx:";
  int opt;

  if (thisServer.euid != thisServer.uid)
    setuid(thisServer.uid);

  /* Do we really need to santiy check the non-NULLness of optarg?  That's
   * getopt()'s job...  Removing those... -zs
   */
  while ((opt = getopt(argc, argv, options)) != EOF)
    switch (opt) {
    case 'k':  thisServer.bootopt |= BOOT_CHKCONF | BOOT_TTY; break;
    case 'n':
    case 't':  thisServer.bootopt |= BOOT_TTY;         break;
    case 'd':  dpath      = optarg;                    break;
    case 's':  spath      = optarg;                    break;
    case 'f':  configfile = optarg;                    break;
    case 'l':  logfile    = optarg;                    break;
    case 'h':  ircd_strncpy(cli_name(&me), optarg, HOSTLEN); break;
    case 'v':
      printf("ircd %s\n", version);
      printf("Event engines: ");
#ifdef USE_KQUEUE
      printf("kqueue() ");
#endif
#ifdef USE_DEVPOLL
      printf("/dev/poll ");
#endif
#ifdef USE_POLL
      printf("poll()");
#else
      printf("select()");
#endif
      printf("\nCompiled for a maximum of %d connections.\n", MAXCONNECTIONS);


      exit(0);
      break;
      
    case 'x':
      debuglevel = atoi(optarg);
      if (debuglevel < 0)
	debuglevel = 0;
      debugmode = optarg;
      thisServer.bootopt |= BOOT_DEBUG;
 #ifndef DEBUGMODE
      printf("WARNING: DEBUGMODE disabled; -x has no effect.\n");
#endif
      break;
      
    default:
      printf("Usage: ircd [-f config] [-d configpath] [-s serverpath] [-h servername] [-l logpath] [-x loglevel] [-ntv]\n");
      printf("\n -x loglevel\t set debug logging verbosity");
      printf("\n -n -t\t\t Don't detach");
      printf("\n -k\t\t check configuration file");
      printf("\n -v\t\t display version\n\n");
      printf("Server not started.\n");
      exit(1);
    }
}


/*----------------------------------------------------------------------------
 * daemon_init
 *--------------------------------------------------------------------------*/
static void daemon_init(int no_fork) {
  if (!init_connection_limits())
    exit(9);

  close_connections(!(thisServer.bootopt & (BOOT_DEBUG | BOOT_TTY | BOOT_CHKCONF)));

  if (no_fork)
    return;

  if (fork())
    exit(0);

#ifdef TIOCNOTTY
  {
    int fd;
    if ((fd = open("/dev/tty", O_RDWR)) > -1) {
      ioctl(fd, TIOCNOTTY, 0);
      close(fd);
    }
  }
#endif

  setsid();
}

/*----------------------------------------------------------------------------
 * check_file_access:  random helper function to make sure that a file is
 *                     accessible in a certain way, and complain if not.
 *--------------------------------------------------------------------------*/
static char check_file_access(const char *path, char which, int mode) {
  if (!access(path, mode))
    return 1;

  fprintf(stderr, 
	  "Check on %cPATH (%s) failed: %s\n"
	  "Please create this file and/or rerun `configure' "
	  "using --with-%cpath and recompile to correct this.\n",
	  which, path, strerror(errno), which);

  return 0;
}


/*----------------------------------------------------------------------------
 * set_core_limit
 *--------------------------------------------------------------------------*/
#if defined(HAVE_SETRLIMIT) && defined(FORCE_CORE)
static void set_core_limit(void) {
  struct rlimit corelim;

  if (getrlimit(RLIMIT_CORE, &corelim)) {
    fprintf(stderr, "Read of rlimit core size failed: %s\n", strerror(errno));
    corelim.rlim_max = RLIM_INFINITY;   /* Try to recover */
  }

  corelim.rlim_cur = corelim.rlim_max = RLIM_INFINITY;
  if (setrlimit(RLIMIT_CORE, &corelim))
    fprintf(stderr, "Setting rlimit core size failed: %s\n", strerror(errno));
}
#endif



/*----------------------------------------------------------------------------
 * set_userid_if_needed()
 *--------------------------------------------------------------------------*/
static int set_userid_if_needed(void) {
  if (getuid() == 0 || geteuid() == 0 ||
      getgid() == 0 || getegid() == 0) {
    fprintf(stderr, "ERROR:  This server will not run as superuser.\n");
    return 0;
  }

  return 1;
}


/*----------------------------------------------------------------------------
 * main - entrypoint
 *
 * TODO:  This should set the basic environment up and start the main loop.
 *        we're doing waaaaaaaaay too much server initialization here.  I hate
 *        long and ugly control paths...  -smd
 *--------------------------------------------------------------------------*/
int main(int argc, char **argv) {
  CurrentTime = time(NULL);

  thisServer.argc = argc;
  thisServer.argv = argv;
  thisServer.uid  = getuid();
  thisServer.euid = geteuid();

#if defined(HAVE_SETRLIMIT) && defined(FORCE_CORE)
  set_core_limit();
#endif

  umask(077);                   /* better safe than sorry --SRB */
  memset(&me, 0, sizeof(me));
  memset(&me_con, 0, sizeof(me_con));
  cli_connect(&me) = &me_con;
  cli_fd(&me) = -1;

  parse_command_line(argc, argv);

  if (chdir(dpath)) {
    fprintf(stderr, "Fail: Cannot chdir(%s): %s, check DPATH\n", dpath, strerror(errno));
    return 2;
  }

  if (!set_userid_if_needed())
    return 3;

  /* Check paths for accessibility */
  if (!check_file_access(SPATH, 'S', X_OK) ||
      !check_file_access(configfile, 'C', R_OK))
    return 4;

  debug_init(thisServer.bootopt & BOOT_TTY);
  daemon_init(thisServer.bootopt & BOOT_TTY);
  event_init(MAXCONNECTIONS);

  setup_signals();
  init_isupport();
  feature_init(); /* initialize features... */
  log_init(*argv);
  set_nomem_handler(outofmemory);
  
  if (!init_string()) {
    log_write(LS_SYSTEM, L_CRIT, 0, "Failed to initialize string module");
    return 6;
  }

  initload();
  init_list();
  init_hash();
  init_class();
  initwhowas();
  initmsgtree();
  initstats();

  init_resolver();
  ircd_crypt_init();

  if (!init_conf()) {
    log_write(LS_SYSTEM, L_CRIT, 0, "Failed to read configuration file %s",
	      configfile);
    return 7;
  }

  if (thisServer.bootopt & BOOT_CHKCONF) {
    fprintf(stderr, "Configuration file %s checked okay.\n", configfile);
    return 0;
  }

  if (check_pid()) {
    Debug((DEBUG_FATAL, "Failed to acquire PID file lock after fork"));
    exit(2);
  }

  if (init_server_identity()) {
    fprintf(stderr, "General and/or Admin blocks are missing or are incorrect.");
    return 0;
  }

  uping_init();

#ifdef USE_SSL
  ssl_init();
#endif /* USE_SSL */

  stats_init();

  IPcheck_init();
  timer_add(timer_init(&connect_timer), try_connections, 0, TT_RELATIVE, 1);
  timer_add(timer_init(&ping_timer), check_pings, 0, TT_RELATIVE, 1);
  timer_add(timer_init(&alist_timer), send_alist, 0, TT_RELATIVE, 1);
  timer_init(&countdown_timer);

  CurrentTime = time(NULL);

  SetMe(&me);
  cli_magic(&me) = CLIENT_MAGIC;
  cli_from(&me) = &me;
  make_server(&me);

  cli_serv(&me)->timestamp = TStime();  /* Abuse own link timestamp as start TS */
  cli_serv(&me)->prot      = atoi(MAJOR_PROTOCOL);
  cli_serv(&me)->up        = &me;
  cli_serv(&me)->down      = NULL;
  cli_handler(&me)         = SERVER_HANDLER;

  SetYXXCapacity(&me, MAXCLIENTS);

  cli_lasttime(&me) = cli_since(&me) = cli_firsttime(&me) = CurrentTime;

  hAddClient(&me);

  write_pidfile();
  init_counters();
  load_tunefile();

  Debug((DEBUG_NOTICE, "Server ready..."));
  log_write(LS_SYSTEM, L_NOTICE, 0, "Server Ready");

  event_loop();

  return 0;
}
