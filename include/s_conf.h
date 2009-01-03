/*
 * s_conf.h
 *
 * $Id$ 
 */
#ifndef INCLUDED_s_conf_h
#define INCLUDED_s_conf_h
#ifndef INCLUDED_config_h
#include "config.h"
#endif
#ifndef INCLUDED_time_h
#include <time.h>              /* struct tm */
#define INCLUDED_time_h
#endif
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif
#ifndef INCLUDED_netinet_in_h
#include <netinet/in.h>        /* struct in_addr */
#define INCLUDED_netinet_in_h
#endif

#include "client.h"

#ifdef PCRE_SYSTEM
#include <pcre.h>
#include <pcreposix.h>
#else
#include "pcre.h"
#include "pcreposix.h"
#endif

struct StatDesc;
struct Client;
struct SLink;
struct TRecord;


/*
 * General defines
 */

/*-----------------------------------------------------------------------------
 * Macros
 */

#define CONF_ILLEGAL            0x80000000
#define CONF_MATCH              0x40000000
#define CONF_CLIENT             0x0002
#define CONF_SERVER             0x0004
#define CONF_LOCOP              0x0010
#define CONF_OPERATOR           0x0020
#define CONF_AUTOCONNECT        0x0040

#define CONF_OPS                (CONF_OPERATOR | CONF_LOCOP)
#define CONF_CLIENT_MASK        (CONF_CLIENT | CONF_OPS | CONF_SERVER)

#define IsIllegal(x)    ((x)->status & CONF_ILLEGAL)

/*
 * Structures
 */

struct ConfItem {
  struct ConfItem*         next;
  unsigned int             status;      /* If CONF_ILLEGAL, delete when no clients */
  unsigned int             clients;     /* Number of *LOCAL* clients using this */
  unsigned int             maximum;
  struct ConnectionClass*  conn_class;  /* Class of connection */
  struct in_addr           origin;      /* ip number of connect origin */
  struct in_addr           ipnum;       /* ip number of host field */
  char*                    host;
  char*                    passwd;
  char*                    name;
  char*                    hub_limit;
  time_t                   hold;        /* Hold until this time (calendar time) */
  int                      dns_pending; /* a dns request is pending */
  unsigned short           port;
  char 		           bits;        /* Number of bits for ipkills */
  int                      flags;
  struct Privs privs; /* Priviledges for opers. */
  struct Privs privs_dirty;
};

struct ServerConf {
  struct ServerConf* next;
  char*              hostname;
  char*              passwd;
  char*              alias;
  struct in_addr     address;
  int                port;
  int                dns_pending;
  int                connected;
  time_t             hold;
  struct ConnectionClass*  conn_class;
};

struct DenyConf {
  struct DenyConf*    next;
  char*               hostmask;
  char*               message;
  char*               usermask;
  unsigned int        address;
  unsigned int        flags;
  char                bits;        /* Number of bits for ipkills */
};

#define DENY_FLAGS_FILE     0x0001 /* Comment is a filename */
#define DENY_FLAGS_IP       0x0002 /* K-line by IP address */
#define DENY_FLAGS_REALNAME 0x0004 /* K-line by real name */
#define DENY_FLAGS_VERSION  0x0008 /* K-line by CTCP version - added by Vadtec 02/26/2008 */

/*
 * A line: A:<line 1>:<line 2>:<line 3>
 */
struct LocalConf {
  char*          name;
  char*          description;
  struct in_addr vhost_address;
  unsigned int   numeric;
  char*          location1;
  char*          location2;
  char*          contact;
};

struct MotdItem {
  char line[82];
  struct MotdItem *next;
};

struct MotdConf {
  struct MotdConf* next;
  char* hostmask;
  char* path;
};

enum {
  CRULE_AUTO = 1,
  CRULE_ALL  = 2,
  CRULE_MASK = 3
};

struct CRuleNode;

struct CRuleConf {
  struct CRuleConf* next;
  char*             hostmask;
  char*             rule;
  int               type;
  struct CRuleNode* node;
};

struct TRecord {
  struct TRecord *next;
  char *hostmask;
  struct MotdItem *tmotd;
  struct tm tmotd_tm;
};

enum AuthorizationCheckResult {
  ACR_OK,
  ACR_NO_AUTHORIZATION,
  ACR_TOO_MANY_IN_CLASS,
  ACR_TOO_MANY_FROM_IP,
  ACR_ALREADY_AUTHORIZED,
  ACR_BAD_SOCKET
};

struct qline {
  struct qline *next;
  char *chname;
  char *reason;
};

struct sline {
  struct sline *next;
  char *spoofhost;
  char *passwd;
  char *realhost;
  char *username;
  struct in_addr address;
  unsigned int flags;
  char bits; /* Number of bits for CIDR match on realhost */
};

#define SLINE_FLAGS_HOSTNAME 0x0001 /* S-line by hostname */
#define SLINE_FLAGS_IP       0x0002 /* S-line by IP address/CIDR */

/*
 * str2prefix() - converts a string to in_addr and bits.
 */

#define IPV4_MAX_BITLEN 32

struct prefix
{
    struct in_addr address;
    unsigned char bits;
};

struct csline {
  struct csline *next;
  char *mask;
  char *server;
  char *port;
};

struct svcline {
  struct svcline *next;
  char *cmd;
  char *target;
  char *prepend;
};

struct blline {
  struct blline *next;
  char *server;
  char *name;
  char *flags;
  char *replies;
  char *reply;
  char *rank;
};

struct wline {
  struct wline *next;
  char *mask;
  char *passwd;
  char *ident;
  char *desc;
  char *flags;
};

struct eline {
  struct eline *next;
  char *mask;
  char *flags;
};

struct fline {
  struct fline *next;
  pcre *filter;
  char *rawfilter;
  char *rflags;
  char *wflags;
  char *reason;
  char *nchan;
  int length;
  int active;
};

/*
 * GLOBALS
 */
extern struct ConfItem* GlobalConfList;
extern int              GlobalConfCount;
extern struct tm        motd_tm;
extern struct MotdItem* motd;
extern struct MotdItem* rmotd;
extern struct TRecord*  tdata;
extern struct qline*	GlobalQuarantineList;
extern struct sline*	GlobalSList;
extern struct csline*	GlobalConnStopList;
extern struct svcline*	GlobalServicesList;
extern struct blline*	GlobalBLList;
extern struct wline*    GlobalWList;
extern struct eline*    GlobalEList;
extern struct fline*    GlobalFList;
extern unsigned int	GlobalBLCount;
extern char*		GlobalForwards[256];

/*
 * Proto types
 */

extern int init_conf(void);

extern const struct LocalConf* conf_get_local(void);
extern const struct MotdConf*  conf_get_motd_list(void);
extern const struct CRuleConf* conf_get_crule_list(void);
extern const struct DenyConf*  conf_get_deny_list(void);

extern const char* conf_eval_crule(const char* name, int mask);

extern struct ConfItem* attach_confs_byhost(struct Client* cptr, const char* host, int statmask);
extern struct ConfItem* find_conf_byhost(struct SLink* lp, const char* host, int statmask);
extern struct ConfItem* find_conf_byname(struct SLink* lp, const char *name, int statmask);
extern struct ConfItem* conf_find_server(const char* name);
extern struct ConfItem* find_conf_entry(struct ConfItem *aconf, unsigned int mask);

extern void update_uworld_flags(struct Client *cptr);
extern void conf_make_uworld(char *name);
extern void stats_uworld(struct Client* to, const struct StatDesc *sd, char* param);

extern void det_confs_butmask(struct Client *cptr, int mask);
extern enum AuthorizationCheckResult attach_conf(struct Client *cptr, struct ConfItem *aconf);
extern struct ConfItem* find_conf_exact(const char* name, const char* user,
                                        const char* host, int statmask);
extern struct ConfItem* find_conf_cidr(const char* name, const char* user,
                                       struct in_addr cli_addr, int statmask);
extern enum AuthorizationCheckResult conf_check_client(struct Client *cptr);
extern void lookup_confhost(struct ConfItem *aconf);
extern int  conf_check_server(struct Client *cptr);
extern struct ConfItem* find_conf_name(const char* name, int statmask);
extern int rehash(struct Client *cptr, int sig);
extern void read_tlines(void);
extern int find_fline(struct Client *cptr, struct Client *sptr, char *string, unsigned int flags, char *target);
extern int find_eline(struct Client *cptr, unsigned int flags);
extern int find_kill(struct Client *cptr);
extern int find_restrict(struct Client *cptr);
extern struct MotdItem* read_motd(const char* motdfile);

extern void set_initial_oper_privs(struct ConfItem *oper, int flags);

extern char* find_quarantine(const char* chname);
extern void conf_add_sline(const char* const* fields, int count);
extern int conf_check_slines(struct Client *cptr);
extern void clear_slines(void);
extern int str2prefix(char *s, struct prefix *p);
extern int find_csline(struct Client* sptr, const char* mask);
extern void conf_add_csline(const char* const* fields, int count);
extern void clear_cslines(void);
extern void conf_add_dnsbl_line(const char* const* fields, int count);
extern void clear_dnsbl_lines(void);
extern int find_blline(struct Client* sptr, const char* replyip, char *checkhost);
extern void conf_add_svcline(const char * const* fields, int count); 
extern void clear_svclines(void);
extern struct svcline *find_svc(const char *cmd);
extern char *oflagstr(long);
extern char dflagstr(const char* dflags);
extern int find_dnsbl(struct Client* sptr, const char* dnsbl);
extern int add_dnsbl(struct Client* sptr, const char* dnsbl);
extern int del_dnsbl(struct Client* sptr, char* dnsbl);
extern int watchfflagstr(const char* fflags);
extern int reactfflagstr(const char* fflags);

extern void yyerror(const char *msg);
extern void yyserror(const char *fmt, ...);
extern void yywarning(const char *fmt, ...);

#endif /* INCLUDED_s_conf_h */
