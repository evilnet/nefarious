/*
 * ircd.h
 *
 * $Id$
 */
#ifndef INCLUDED_ircd_h
#define INCLUDED_ircd_h
#ifndef INCLUDED_ircd_struct_h
#include "ircd_struct.h"           /* struct Client */
#endif
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>        /* size_t, time_t */
#endif

struct Daemon
{
  int          argc;
  char**       argv;
  pid_t        pid;
  uid_t        uid;
  uid_t        euid;
  unsigned int bootopt;
  int          running;
  int          pid_fd;
  const char*  server_bin;
  const char*  server_root;
  const char*  server_log;
};

/** Describes pending exit. */
struct PendingExit
{
  int          restart;     /**< Pending exit is for a restart. */
  char*        who;         /**< Who initiated the exit. */
  char*        message;     /**< Message to emit. */
  time_t       time;        /**< Absolute time at which to exit. */
};

/*
 * Macros
 */
#define TStime() (CurrentTime + TSoffset)
#define OLDEST_TS 780000000	/* Any TS older than this is bogus */
#define BadPtr(x) (!(x) || (*(x) == '\0'))

/* Miscellaneous defines */

#define UDP_PORT        "7007"
#define MINOR_PROTOCOL  "09"
#define MAJOR_PROTOCOL  "10"
#define BASE_VERSION    "u2.10"

#define PEND_INT_LONG   300     /**< Length of long message interval. */
#define PEND_INT_MEDIUM  60     /**< Length of medium message interval. */
#define PEND_INT_SHORT   30     /**< Length of short message interval. */
#define PEND_INT_END     10     /**< Length of the end message interval. */
#define PEND_INT_LAST     1     /**< Length of last message interval. */

/*
 * Proto types
 */
extern void server_panic(const char* message);


extern void exit_cancel(struct Client *who);
extern void exit_schedule(int restart, time_t when, struct Client *who,
			  const char *message);

extern struct Client  me;
extern time_t         CurrentTime;
extern struct Client* GlobalClientList;
extern time_t         TSoffset;
extern time_t         nextdnscheck;
extern time_t         nextconnect;
extern int            GlobalRehashFlag;      /* 1 if SIGHUP is received */
extern int            GlobalRestartFlag;     /* 1 if SIGINT is received */
extern time_t         nextping;
extern char*          configfile;
extern int            debuglevel;
extern char*          debugmode;
extern int	      running;
extern int            refuse;

#endif /* INCLUDED_ircd_h */

