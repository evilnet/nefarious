/*
 * IRC - Internet Relay Chat, ircd/s_conf.c
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

#include "s_conf.h"
#include "IPcheck.h"
#include "channel.h"
#include "class.h"
#include "client.h"
#include "crule.h"
#include "ircd_features.h"
#include "fileio.h"
#include "gline.h"
#include "handlers.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_chattr.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "list.h"
#include "listener.h"
#include "mark.h"
#include "match.h"
#include "motd.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "opercmds.h"
#include "parse.h"
#include "res.h"
#include "s_bsd.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_stats.h"
#include "send.h"
#include "spamfilter.h"
#ifdef USE_SSL
#include "ssl.h"
#endif /* USE_SSL */
#include "ircd_struct.h"
#include "support.h"
#include "sys.h"

#ifdef PCRE_SYSTEM
#include <pcre.h>
#include <pcreposix.h>
#else
#include "pcre.h"
#include "pcreposix.h"
#endif

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef HPUX
#include <sys/syscall.h>
#define getrusage(a,b) syscall(SYS_GETRUSAGE, a, b)
#endif

#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif

struct ConfItem* GlobalConfList;
int              GlobalConfCount = 0;
char*            GlobalForwards[256];

unsigned int     GlobalBLCount;

struct eline*    GlobalEList;
struct svcline*  GlobalServicesList;
struct sline*    GlobalSList;
struct csline*   GlobalConnStopList;
struct wline*    GlobalWList;
struct fline*    GlobalFList;
struct blline*   GlobalBLList;
struct qline*    GlobalQuarantineList;
struct SpamFilter* GlobalSpamFilterList;

struct LocalConf   localConf;
struct DenyConf*   denyConfList;
struct CRuleConf*  cruleConfList;

/* static struct ServerConf* serverConfList; */

/** Current line number in scanner input. */
int lineno;

static int eline_flags[] = {
  EFLAG_KLINE,    'k',
  EFLAG_GLINE,    'g',
  EFLAG_ZLINE,    'z',
  EFLAG_SHUN,     's',
  EFLAG_SFILTER,  'S',
  EFLAG_LIST,     'L',
  EFLAG_IDENT,    'i',
  EFLAG_IPCHECK,  'I'
};

static int fline_rflags[] = {
  RFFLAG_AUTH,      'a',
  RFFLAG_CALERT,    'C',
  RFFLAG_SALERT,    'S',
  RFFLAG_KILL,      'k',
  RFFLAG_GLINE,     'g',
  RFFLAG_SHUN,      's',
  RFFLAG_BLOCK,     'b',
  RFFLAG_NOTIFY,    'n',
  RFFLAG_ZLINE,     'z',
  RFFLAG_MARK,      'm',
  RFFLAG_IP,        'i',
  RFFLAG_KICK,      'K',
  RFFLAG_OPS,       'o',
  RFFLAG_VOICE,     'v'
};

static int fline_wflags[] = {
  WFFLAG_NOTICE,    'n',
  WFFLAG_CHANNOTICE,'N',
  WFFLAG_PRIVMSG,   'p',
  WFFLAG_CHANMSG,   'C',
  WFFLAG_AWAY,      'a',
  WFFLAG_TOPIC,     't',
  WFFLAG_CONNECT,   'u',
  WFFLAG_PART,      'P',
  WFFLAG_QUIT,      'q',
  WFFLAG_DCC,       'd',
  WFFLAG_NICK,      'i'
};

static int dnsbl_flags[] = {
  DFLAG_BITMASK,  'b',
  DFLAG_REPLY,    'r',
  DFLAG_ALLOW,    'a',
  DFLAG_MARK,     'm',
  DFLAG_DENY,     'd'
};


static int oper_access[] = {
  OFLAG_GLOBAL,	  'O',
  OFLAG_ADMIN,	  'A',
  OFLAG_RSA,  	  'R',
  OFLAG_REMOTE,   'r',
  OFLAG_WHOIS,    'W',
  OFLAG_IDLE,     'I',
  OFLAG_XTRAOP,   'X',
  OFLAG_HIDECHANS, 'n',
  0, 0
};

char eflagstr(const char* eflags)
{
  unsigned int *flag_p;
  unsigned int x_flag = 0;
  const char *flagstr;

  flagstr = eflags;

  /* This should never happen... */
  assert(flagstr != 0);

  for (; *flagstr; flagstr++) {
    for (flag_p = (unsigned int*)eline_flags; flag_p[0]; flag_p += 2) {
      if (flag_p[1] == *flagstr)
        break;
    }

    if (!flag_p[0])
      continue;

    x_flag |= flag_p[0];
  }

  return x_flag;
}

int watchfflagstr(const char* fflags)
{
  unsigned int *flag_p;
  unsigned int x_flag = 0;
  const char *flagstr;

  flagstr = fflags;

  /* This should never happen... */
  assert(flagstr != 0);

  for (; *flagstr; flagstr++) {
    for (flag_p = (unsigned int*)fline_wflags; flag_p[0]; flag_p += 2) {
      if (flag_p[1] == *flagstr)
        break;
    }

    if (!flag_p[0])
      continue;

    x_flag |= flag_p[0];
  }

  return x_flag;
}

int reactfflagstr(const char* fflags)
{
  unsigned int *flag_p;
  unsigned int x_flag = 0;
  const char *flagstr;

  flagstr = fflags;

  /* This should never happen... */
  assert(flagstr != 0);

  for (; *flagstr; flagstr++) {
    for (flag_p = (unsigned int*)fline_rflags; flag_p[0]; flag_p += 2) {
      if (flag_p[1] == *flagstr)
        break;
    }

    if (!flag_p[0])
      continue;

    x_flag |= flag_p[0];
  }

  return x_flag;
}

int react_check(const char* fflags)
{
  unsigned int *flag_p;
  const char *flagstr;
  int bad = 1;

  flagstr = fflags;

  /* This should never happen... */
  assert(flagstr != 0);

  for (; *flagstr; flagstr++) {
    for (flag_p = (unsigned int*)fline_rflags; flag_p[0]; flag_p += 2) {
      if (flag_p[1] == *flagstr) {
        bad = 0;
        break;
      }
    }
  }

  return bad;
}

int watch_check(const char* fflags)
{
  unsigned int *flag_p;
  const char *flagstr;
  int bad = 1;

  flagstr = fflags;

  /* This should never happen... */
  assert(flagstr != 0);

  for (; *flagstr; flagstr++) {
    for (flag_p = (unsigned int*)fline_wflags; flag_p[0]; flag_p += 2) {

      if (flag_p[1] == *flagstr) {
        bad = 0;
        break;
      }
    }
  }

  return bad;
}

char oflagbuf[128];

char *oflagstr(long oflag)
{
 int *i;
 int flag;
 char m;
 char *p = oflagbuf;

 for (i = &oper_access[0], m = *(i + 1); (flag = *i);
      i += 2, m = *(i + 1))
   if (oflag & flag) {
     *p = m;
     p++;
   }
 *p = '\0';
 return oflagbuf;
}

char dflagstr(const char* dflags)
{
  unsigned int *flag_p;
  unsigned int x_flag = 0;
  const char *flagstr;

  flagstr = dflags;

  /* This should never happen... */
  assert(flagstr != 0);

  for (; *flagstr; flagstr++) {
    for (flag_p = (unsigned int*)dnsbl_flags; flag_p[0]; flag_p += 2) {
      if (flag_p[1] == *flagstr)
        break;
    }

    if (!flag_p[0])
      continue;

    x_flag |= flag_p[0];
  }

  return x_flag;
}

/*
 * output the reason for being k lined from a file  - Mmmm
 * sptr is client being dumped
 * filename is the file that is to be output to the K lined client
 */
static void killcomment(struct Client* sptr, const char* filename)
{
  FBFILE*     file = 0;
  char        line[80];
  struct stat sb;
  struct tm*  tm;

  if (NULL == (file = fbopen(filename, "r"))) {
    send_reply(sptr, ERR_NOMOTD);
    send_reply(sptr, SND_EXPLICIT | ERR_YOUREBANNEDCREEP,
               ":Connection from your host is refused on this server.");
    return;
  }
  fbstat(&sb, file);
  tm = localtime((time_t*) &sb.st_mtime);        /* NetBSD needs cast */
  while (fbgets(line, sizeof(line) - 1, file)) {
    char* end = line + strlen(line);
    while (end > line) {
      --end;
      if ('\n' == *end || '\r' == *end)
        *end = '\0';
      else
        break;
    }
    send_reply(sptr, RPL_MOTD, line);
  }
  send_reply(sptr, SND_EXPLICIT | ERR_YOUREBANNEDCREEP,
             ":Connection from your host is refused on this server.");
  fbclose(file);
}

/*
 * output the reason for being k lined from a file  - Mmmm
 * sptr is client being dumped
 * filename is the file that is to be output to the K lined client
 */
int promptcomment(struct Client* sptr, const char* filename)
{
  FBFILE*     file = 0;
  char        line[80];
  struct stat sb;
  struct tm*  tm;

  if (NULL == (file = fbopen(filename, "r"))) {
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :K-lined: Connection from your host is refused on this server.", sptr);
    return 0;
  }
  fbstat(&sb, file);
  tm = localtime((time_t*) &sb.st_mtime);        /* NetBSD needs cast */
  while (fbgets(line, sizeof(line) - 1, file)) {
    char* end = line + strlen(line);
    while (end > line) {
      --end;
      if ('\n' == *end || '\r' == *end)
        *end = '\0';
      else
        break;
    }
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :K-lined: %s", line);
  }

  fbclose(file);
  return 0;
}

struct ConfItem* make_conf(int type)
{
  struct ConfItem* aconf;

  aconf = (struct ConfItem*) MyMalloc(sizeof(struct ConfItem));
  assert(0 != aconf);

#ifdef        DEBUGMODE
  ++GlobalConfCount;
#endif

  memset(aconf, 0, sizeof(struct ConfItem));
  aconf->status       = type;
  aconf->ipnum.s_addr = INADDR_NONE;
  aconf->next    = GlobalConfList;
  GlobalConfList = aconf;
  return aconf;
}

void free_conf(struct ConfItem *aconf)
{
  Debug((DEBUG_DEBUG, "free_conf: %s %s %d",
         aconf->host ? aconf->host : "*",
         aconf->name ? aconf->name : "*",
         aconf->port));
  if (aconf->dns_pending)
    delete_resolver_queries(aconf);
  MyFree(aconf->username);
  MyFree(aconf->host);
  if (aconf->passwd)
    memset(aconf->passwd, 0, strlen(aconf->passwd));
  MyFree(aconf->passwd);
  MyFree(aconf->name);
  MyFree(aconf->hub_limit);
  MyFree(aconf);

#ifdef        DEBUGMODE
  --GlobalConfCount;
#endif
}

/*
 * detach_conf - Disassociate configuration from the client.
 */
static void detach_conf(struct Client* cptr, struct ConfItem* aconf)
{
  struct SLink** lp;
  struct SLink*  tmp;

  assert(0 != aconf);
  assert(0 != cptr);
  assert(0 < aconf->clients);

  lp = &(cli_confs(cptr));

  while (*lp) {
    if ((*lp)->value.aconf == aconf) {
      if (aconf->conn_class && (aconf->status & CONF_CLIENT_MASK) && ConfLinks(aconf) > 0)
        --ConfLinks(aconf);

      assert(0 < aconf->clients);
      if (0 == --aconf->clients && IsIllegal(aconf))
        free_conf(aconf);
      tmp = *lp;
      *lp = tmp->next;
      free_link(tmp);
      return;
    }
    lp = &((*lp)->next);
  }
}

/*
 * conf_dns_callback - called when resolver query finishes
 * if the query resulted in a successful search, hp will contain
 * a non-null pointer, otherwise hp will be null.
 * if successful save hp in the conf item it was called with
 */
static void conf_dns_callback(void* vptr, struct DNSReply* reply)
{
  struct ConfItem* aconf = (struct ConfItem*) vptr;
  aconf->dns_pending = 0;
  if (reply)
    memcpy(&aconf->ipnum, reply->hp->h_addr, sizeof(struct in_addr));
}

/*
 * conf_dns_lookup - do a nameserver lookup of the conf host
 * if the conf entry is currently doing a ns lookup do nothing, otherwise
 * if the lookup returns a null pointer, set the conf dns_pending flag
 */
static struct DNSReply* conf_dns_lookup(struct ConfItem* aconf)
{
  struct DNSReply* dns_reply = 0;
  if (!aconf->dns_pending) {
    char            buf[HOSTLEN + 1];
    struct DNSQuery query;
    query.vptr     = aconf;
    query.callback = conf_dns_callback;
    host_from_uh(buf, aconf->host, HOSTLEN);
    buf[HOSTLEN] = '\0';

    if (0 == (dns_reply = gethost_byname(buf, &query)))
      aconf->dns_pending = 1;
  }
  return dns_reply;
}


/*
 * lookup_confhost
 *
 * Do (start) DNS lookups of all hostnames in the conf line and convert
 * an IP addresses in a.b.c.d number for to IP#s.
 */
void lookup_confhost(struct ConfItem *aconf)
{
  char *tmp, *tmp2;
  struct DNSReply* reply;

  if (EmptyString(aconf->host) || EmptyString(aconf->name)) {
    Debug((DEBUG_ERROR, "Host/server name error: (%s) (%s)",
           aconf->host, aconf->name));
    return;
  }
  /*
   * Do name lookup now on hostnames given and store the
   * ip numbers in conf structure.
   */
  if ((tmp = strchr(aconf->host, '/'))) {
    *(tmp++) = '\0';
    aconf->origin.s_addr = inet_addr(aconf->host);
    tmp2 = aconf->host;
    DupString(aconf->host, tmp);
    free(tmp2);
  } else
    aconf->origin.s_addr = INADDR_NONE;

  if (IsDigit(*aconf->host)) {
    /*
     * rfc 1035 sez host names may not start with a digit
     * XXX - this has changed code needs to be updated
     */
    aconf->ipnum.s_addr = inet_addr(aconf->host);
    if (INADDR_NONE == aconf->ipnum.s_addr) {
      Debug((DEBUG_ERROR, "Host/server name error: (%s) (%s)",
            aconf->host, aconf->name));
    }
  }
  else if ((reply = conf_dns_lookup(aconf)))
    memcpy(&aconf->ipnum, reply->hp->h_addr, sizeof(struct in_addr));
}

/*
 * conf_find_server - find a server by name or hostname
 * returns a server conf item pointer if found, 0 otherwise
 *
 * NOTE: at some point when we don't have to scan the entire
 * list it may be cheaper to look for server names and host
 * names in separate loops (original code did it that way)
 */
struct ConfItem* conf_find_server(const char* name)
{
  struct ConfItem* conf;
  assert(0 != name);

  for (conf = GlobalConfList; conf; conf = conf->next) {
    if (CONF_SERVER == conf->status) {
      /*
       * Check first servernames, then try hostnames.
       * XXX - match returns 0 if there _is_ a match... guess they
       * haven't decided what true is yet
       */
      if (0 == match(name, conf->name))
        return conf;
    }
  }
  return 0;
}

/*
 * conf_eval_crule - evaluate connection rules
 * returns the name of the rule triggered if found, 0 otherwise
 *
 * Evaluate connection rules...  If no rules found, allow the
 * connect.   Otherwise stop with the first true rule (ie: rules
 * are ored together.  Oper connects are effected only by D
 * lines (CRULE_ALL) not d lines (CRULE_AUTO).
 */
const char* conf_eval_crule(const char* name, int mask)
{
  struct CRuleConf* p = cruleConfList;
  assert(0 != name);

  for ( ; p; p = p->next) {
    if (0 != (p->type & mask) && 0 == match(p->hostmask, name)) {
      if (crule_eval(p->node))
        return p->rule;
    }
  }
  return 0;
}

/*
 * Remove all conf entries from the client except those which match
 * the status field mask.
 */
void det_confs_butmask(struct Client* cptr, int mask)
{
  struct SLink* linkh;
  struct SLink* next;
  assert(0 != cptr);

  for (linkh = cli_confs(cptr); linkh; linkh = next) {
    next = linkh->next;
    if ((linkh->value.aconf->status & mask) == 0)
      detach_conf(cptr, linkh->value.aconf);
  }
}

/*
 * Find the first (best) I line to attach.
 */
enum AuthorizationCheckResult attach_iline(struct Client*  cptr)
{
  struct ConfItem* aconf;
  const char*      hname;
  int              i, m = 0;
  static char      fullname[HOSTLEN + 1];
  struct hostent*  hp = 0;

  assert(0 != cptr);

  if (cli_dns_reply(cptr))
    hp = cli_dns_reply(cptr)->hp;

  for (aconf = GlobalConfList; aconf; aconf = aconf->next) {
    if (aconf->status != CONF_CLIENT)
      continue;
    if (aconf->port && aconf->port != cli_listener(cptr)->port)
      continue;
    if (aconf->username && match(aconf->username, cli_username(cptr)))
      continue;

    if (hp && aconf->host) {
      for (i = 0, hname = hp->h_name; hname; hname = hp->h_aliases[i++]) {
        m = 0;
        ircd_strncpy(fullname, hname, HOSTLEN);
        fullname[HOSTLEN] = '\0';

        Debug((DEBUG_DNS, "a_il: %s->%s", cli_sockhost(cptr), fullname));

        if (match(aconf->host, fullname)) {
           m = 1;
           break;
        }
      }
      if (m == 1)
        continue;
    }
 
    if ((aconf->bits >= 0) && ((cli_ip(cptr).s_addr & NETMASK(aconf->bits)) != aconf->ipnum.s_addr))
        continue;

    if (feature_bool(FEAT_IPCHECK) && !find_eline(cptr, EFLAG_IPCHECK)) {
      if (IPcheck_nr(cptr) > aconf->maximum)
        return ACR_TOO_MANY_FROM_IP;
    }
    if (aconf->username)
      SetFlag(cptr, FLAG_DOID);
    return attach_conf(cptr, aconf);
  }
  return ACR_NO_AUTHORIZATION;
}

static int is_attached(struct ConfItem *aconf, struct Client *cptr)
{
  struct SLink *lp;

  for (lp = cli_confs(cptr); lp; lp = lp->next) {
    if (lp->value.aconf == aconf)
      return 1;
  }
  return 0;
}

/*
 * attach_conf
 *
 * Associate a specific configuration entry to a *local*
 * client (this is the one which used in accepting the
 * connection). Note, that this automaticly changes the
 * attachment if there was an old one...
 */
enum AuthorizationCheckResult attach_conf(struct Client *cptr, struct ConfItem *aconf)
{
  struct SLink *lp;

  if (is_attached(aconf, cptr))
    return ACR_ALREADY_AUTHORIZED;
  if (IsIllegal(aconf))
    return ACR_NO_AUTHORIZATION;
  if ((aconf->status & (CONF_LOCOP | CONF_OPERATOR | CONF_CLIENT)) &&
      ConfLinks(aconf) >= ConfMaxLinks(aconf) && ConfMaxLinks(aconf) > 0)
    return ACR_TOO_MANY_IN_CLASS;  /* Use this for printing error message */
  lp = make_link();
  lp->next = cli_confs(cptr);
  lp->value.aconf = aconf;
  cli_confs(cptr) = lp;
  ++aconf->clients;
  if (aconf->status & CONF_CLIENT_MASK)
    ConfLinks(aconf)++;
  return ACR_OK;
}

const struct LocalConf* conf_get_local(void)
{
  return &localConf;
}

/*
 * attach_confs_byname
 *
 * Attach a CONF line to a client if the name passed matches that for
 * the conf file (for non-C lines) or is an exact match (C lines
 * only).  The difference in behaviour is to stop C:*::*.
 */
struct ConfItem* attach_confs_byname(struct Client* cptr, const char* name,
                                     int statmask)
{
  struct ConfItem* tmp;
  struct ConfItem* first = NULL;

  assert(0 != name);

  if (HOSTLEN < strlen(name))
    return 0;

  for (tmp = GlobalConfList; tmp; tmp = tmp->next) {
    if (0 != (tmp->status & statmask) && !IsIllegal(tmp)) {
      assert(0 != tmp->name);
      if (0 == match(tmp->name, name) || 0 == ircd_strcmp(tmp->name, name)) { 
        if (ACR_OK == attach_conf(cptr, tmp) && !first)
          first = tmp;
      }
    }
  }
  return first;
}

/*
 * Added for new access check    meLazy
 */
struct ConfItem* attach_confs_byhost(struct Client* cptr, const char* host,
                                     int statmask)
{
  struct ConfItem* tmp;
  struct ConfItem* first = 0;

  assert(0 != host);
  if (HOSTLEN < strlen(host))
    return 0;

  for (tmp = GlobalConfList; tmp; tmp = tmp->next) {
    if (0 != (tmp->status & statmask) && !IsIllegal(tmp)) {
      assert(0 != tmp->host);
      if (0 == match(tmp->host, host) || 0 == ircd_strcmp(tmp->host, host)) { 
        if (ACR_OK == attach_conf(cptr, tmp) && !first)
          first = tmp;
      }
    }
  }
  return first;
}

/*
 * find a conf entry which matches the hostname and has the same name.
 */
struct ConfItem* find_conf_exact(const char* name, const char* user,
                                 const char* host, int statmask)
{
  struct ConfItem *tmp;
  char userhost[USERLEN + HOSTLEN + 3];

  if (user)
    ircd_snprintf(0, userhost, sizeof(userhost), "%s@%s", user, host);
  else
    ircd_strncpy(userhost, host, sizeof(userhost) - 1);

  for (tmp = GlobalConfList; tmp; tmp = tmp->next) {
    if (!(tmp->status & statmask) || !tmp->name || !tmp->host ||
        0 != ircd_strcmp(tmp->name, name))
      continue;
    /*
     * Accept if the *real* hostname (usually sockecthost)
     * socket host) matches *either* host or name field
     * of the configuration.
     */

    if (match(tmp->host, userhost))
      continue;

    if ((tmp->status & (CONF_OPERATOR | CONF_LOCOP))
      && (MaxLinks(tmp->conn_class) > 0)
      && (tmp->clients >= MaxLinks(tmp->conn_class)))
      continue;

    return tmp;
  }
  return 0;
}

/*
 * find a conf entry by CIDR host entry which has the same name.
 */
struct ConfItem* find_conf_cidr(const char* name, const char* user,
                                 struct in_addr cli_addr, int statmask)
{
  struct ConfItem *tmp;
  char *ip_start;
  char *cidr_start;
  struct in_addr conf_addr;
  int bits;

  for (tmp = GlobalConfList; tmp; tmp = tmp->next) {
    if (!(tmp->status & statmask) || !tmp->name || !tmp->host ||
        0 != ircd_strcmp(tmp->name, name))
      continue;
    
    ip_start = strrchr(tmp->host, '@');
    if (ip_start == NULL)
      ip_start = tmp->host;
    else {
      *ip_start = 0;
      if (match(tmp->host, user)) {
        *ip_start = '@';
        continue;
      }
      *ip_start = '@';
      ip_start++;
    }
    cidr_start = strchr(ip_start, '/');
    if (!cidr_start)
      continue;
    
    *cidr_start = 0;
    if (inet_aton(ip_start, &conf_addr) == 0) {
      *cidr_start = '/';
      continue;
    }
    bits = atoi(cidr_start + 1);
    *cidr_start = '/';
    if ((bits < 1) || (bits > 32))
      continue;
    
    if ((cli_addr.s_addr & NETMASK(bits)) != conf_addr.s_addr)
      continue;

    if ((tmp->status & (CONF_OPERATOR | CONF_LOCOP))
      && (MaxLinks(tmp->conn_class) > 0)
      && (tmp->clients >= MaxLinks(tmp->conn_class)))
      continue;

    return tmp;
  }
  return 0;
}

struct ConfItem* find_conf_byname(struct SLink* lp, const char* name,
                                  int statmask)
{
  struct ConfItem* tmp;
  assert(0 != name);

  if (HOSTLEN < strlen(name))
    return 0;

  for (; lp; lp = lp->next) {
    tmp = lp->value.aconf;
    if (0 != (tmp->status & statmask)) {
      assert(0 != tmp->name);
      if (0 == ircd_strcmp(tmp->name, name) || 0 == match(tmp->name, name))
        return tmp;
    }
  }
  return 0;
}

/*
 * Added for new access check    meLazy
 */
struct ConfItem* find_conf_byhost(struct SLink* lp, const char* host,
                                  int statmask)
{
  struct ConfItem* tmp = NULL;
  assert(0 != host);

  if (HOSTLEN < strlen(host))
    return 0;

  for (; lp; lp = lp->next) {
    tmp = lp->value.aconf;
    if (0 != (tmp->status & statmask)) {
      assert(0 != tmp->host);
      if (0 == match(tmp->host, host))
        return tmp;
    }
  }
  return 0;
}

/*
 * find_conf_ip
 *
 * Find a conf line using the IP# stored in it to search upon.
 * Added 1/8/92 by Avalon.
 */
struct ConfItem* find_conf_byip(struct SLink* lp, const char* ip, 
                                int statmask)
{
  struct ConfItem* tmp;

  for (; lp; lp = lp->next) {
    tmp = lp->value.aconf;
    if (0 != (tmp->status & statmask)) {
      if (0 == memcmp(&tmp->ipnum, ip, sizeof(struct in_addr)))
        return tmp;
    }
  }
  return 0;
}

void clear_lblines(void)
{
  unsigned int ii;
  for (ii = 0; ii < 256; ++ii)
    MyFree(GlobalForwards[ii]);
}

char* find_quarantine(const char* chname)
{
  struct qline *qline;
  
  for (qline = GlobalQuarantineList; qline; qline = qline->next)
    if (!ircd_strcmp(qline->chname, chname))
      return qline->reason;
  return NULL;
}

void clear_quarantines(void)
{
  struct qline *qline;
  while ((qline = GlobalQuarantineList)) {
    GlobalQuarantineList = qline->next;
    MyFree(qline->reason);
    MyFree(qline->chname);
    MyFree(qline);
  }
  GlobalQuarantineList = 0;
}

int find_csline(struct Client* sptr, const char* mask)
{
  struct csline *csline;

  for (csline = GlobalConnStopList; csline; csline = csline->next) {
    if (!match(csline->mask, mask)) {
      send_reply(sptr, RPL_BOUNCE, csline->server, csline->port);
      return 1;
    }
  }
  return 0;
}

void clear_cslines(void)
{
  struct csline *csline;
  while ((csline = GlobalConnStopList)) {
    GlobalConnStopList = csline->next;
    MyFree(csline->mask);
    MyFree(csline->server);
    MyFree(csline->port);
    MyFree(csline);
  }
  GlobalConnStopList = 0;
}

void clear_webirc_list(void)
{
  struct wline *wline;
  while ((wline = GlobalWList)) {
    GlobalWList = wline->next;
    MyFree(wline->mask);
    MyFree(wline->passwd);
    MyFree(wline->flags);
    MyFree(wline->ident);
    MyFree(wline->desc);
  }
  GlobalWList = 0;
}

void clear_fline_list(void)
{
  struct fline *fline;
  while ((fline = GlobalFList)) {
    GlobalFList = fline->next;
    pcre_free(fline->filter);
    fline->length = 0;
    fline->active = 0;
    MyFree(fline->nchan);
    MyFree(fline->rawfilter);
    MyFree(fline->wflags);
    MyFree(fline->rflags);
    MyFree(fline->reason);
  }
  GlobalFList = 0;
}

void clear_eline_list(void)
{
  struct eline *eline;
  while ((eline = GlobalEList)) {
    GlobalEList = eline->next;
    MyFree(eline->mask);
    MyFree(eline->flags);
  }
  GlobalEList = 0;
}

void clear_dnsbl_list(void)
{
  struct blline *blline;
  while ((blline = GlobalBLList)) {
    GlobalBLList = blline->next;
    MyFree(blline->server);
    MyFree(blline->name);
    MyFree(blline->flags);
    MyFree(blline->replies);
    MyFree(blline->reply);
    MyFree(blline->rank);
    MyFree(blline);
  }
  GlobalBLList = 0;
}

extern int find_dnsbl(struct Client* sptr, const char* dnsbl)
{
  struct SLink *lp;

  for (lp = cli_sdnsbls(sptr); lp; lp = lp->next) {
    if (!ircd_strcmp(lp->value.cp, dnsbl))
      return 1;
  }

  return 0;
}

extern int add_dnsbl(struct Client* sptr, const char* dnsbl)
{
  struct SLink *lp;

  if (!find_dnsbl(sptr, dnsbl)) {
    lp = make_link();
    memset(lp, 0, sizeof(struct SLink));
    lp->next = cli_sdnsbls(sptr);
    lp->value.cp = (char*) MyMalloc(strlen(dnsbl) + 1);
    assert(0 != lp->value.cp);
    strcpy(lp->value.cp, dnsbl);
    cli_sdnsbls(sptr) = lp;
  }
  return 0;
}

extern int del_dnsbl(struct Client *sptr, char *dnsbl)
{
  struct SLink **lp;
  struct SLink *tmp;
  int ret = -1;

  for (lp = &(cli_sdnsbls(sptr)); *lp;) {
    if (!ircd_strcmp(dnsbl, (*lp)->value.cp))
    {
      tmp = *lp;
      *lp = tmp->next;
      MyFree(tmp->value.cp);
      free_link(tmp);
      ret = 0;
    }
    else
      lp = &(*lp)->next;
  }
  return ret;
}

/* Check if ip (returned by the dnsbl) is a match for check (in X line)
 *
 * @check = 127.0.0.54 or 0.0.54 or 0.54 or 1
 * @ip = 127.0.0.54
 * example, check=2, ip=127.0.0.2; match
 *          check=2, ip=124.9.124.2; no match
 *          check=127.0.0.1, ip=127.0.0.1; match
 * returns 1 for match, 0 for not a match.
 */
int dnsbl_result_match(char* check, const char* ip)
{
    char full_check[4][4] = {"127","0","0","0"};
    char check_str[16];
    int i, s, j;
    int octet=3;
    for(i=strlen(check);i>=0;i--) {
        if(check[i] == '.' || i==0) {
            j = 0;
            if(i>0) s=i+1;
            else s=0;
            for(;check[s] != '\0' && check[s] != '.';s++) {
                if(j > 3) return 0; /* overrun protection */
                full_check[octet][j++] = check[s];
            }
            full_check[octet--][j] = '\0';
        }
    }
    sprintf(check_str, "%s.%s.%s.%s", full_check[0], full_check[1], full_check[2], full_check[3]);
    return strcmp(check_str, ip) == 0;
}


/* Find an X:line matching the rbl reply and mark the client appropreately
 *
 * @sptr
 * @replyip = the 127.0.0.x ip returned by the dnsrbl
 * @checkhost = the hostname we looked up, eg d.c.b.a.dnsbl.sorbs.net
 * Example: replyip="127.0.0.10", checkhost="28.148.169.68.dnsbl.sorbs.net"
 */
int find_blline(struct Client* sptr, const char* replyip, char *checkhost)
{
  struct blline *blline;
  char *dhname;
  char *csep;
  char oct[4]; /* last bit of replyip, and a null */
  char cstr_buf[HOSTLEN +1];
  char *cstr = cstr_buf;
  int da = 0;
  int ret = 0;
  int c = 0;
  int j = 0;
  unsigned int x_flag = 0;

  /* Weird sanity checks :) */
  if (!sptr || !replyip || !checkhost) {
    log_write(LS_DNSBL, L_INFO, 0, "find_blline missing parameter(s) aborting check.");
    Debug((DEBUG_DEBUG, "find_blline missing parameter(s) aborting check."));
    return 0;
  }

  /* Pull the last octet out of the reply ip into oct */
  for(j=strlen(replyip);j>0;j--) {
      if(replyip[j] == '.') {
          ircd_strncpy(oct, replyip+j+1, 3);
          oct[3] = 0;
	  break;
      }
  }
  if(!*oct) {
      log_write(LS_DNSBL, L_INFO, 0, "find_blline passed invalid replyip %s.", replyip);
      Debug((DEBUG_DEBUG, "find_blline passed invalid replyip %s.", replyip));
      return 0; /* malformed replyip */
  }
          
  /* Find the users IP address from the dnsbl reply msg */
  for(dhname = checkhost,c=0;*dhname;dhname++)
      if(*dhname == '.') {
            if(++c >= 4)
	      break;
      }
  dhname++;
  if(c!=4 || !*dhname) {
          log_write(LS_DNSBL, L_INFO, 0, "find_blline passed invalid checkhost %s.", checkhost);
	  Debug((DEBUG_DEBUG, "find_blline passed invalid checkhost %s.", checkhost));
	  return 0;
  }

  
  /* Walk the whole list of X lines */
  for (blline = GlobalBLList; blline; blline = blline->next) {
    if (!ircd_strcmp(dhname, blline->server)) {
        x_flag = dflagstr(blline->flags);

        memset(cstr, 0, HOSTLEN +1);
        ircd_strncpy(cstr, blline->replies, HOSTLEN); /* what bits we are looking for */

        if (x_flag & DFLAG_BITMASK) {
          int total = 0; /* bits are added together */

          /* For each int in the replies, add its bits to total */
	  for(csep = cstr; *(csep+1); csep++); /* set csep to the end */
          for (;csep >= cstr; csep--)
              if(*csep == ',' || csep==cstr) {
                  total += atoi(csep+1);
                  *csep = 0;
              }
                 
          if (total & atoi(oct)) { /* bitwise AND */
            log_write(LS_DNSBL, L_INFO, 0, "DNSBL Matched %p %s (B)", sptr, blline->name);
            SetDNSBL(sptr);

            if (x_flag & DFLAG_MARK)
              SetDNSBLMarked(sptr);

            if ((x_flag & DFLAG_ALLOW) && (!IsDNSBLDenied(sptr)))
              SetDNSBLAllowed(sptr);

            if (x_flag & DFLAG_DENY) {
              ClearDNSBLAllowed(sptr);
              SetDNSBLDenied(sptr);
            }

            if (atoi(blline->rank) > cli_dnsbllastrank(sptr)) {
              ircd_strncpy(cli_dnsbl(sptr), blline->name, BUFSIZE);
              ircd_strncpy(cli_dnsblformat(sptr), blline->reply, BUFSIZE);
            }

            cli_dnsbllastrank(sptr) = atoi(blline->rank);
            add_dnsbl(sptr, blline->name);
            ret = 1;
          }
        } else if (x_flag & DFLAG_REPLY) {
	    for(csep = cstr; *(csep+1); csep++); /* set csep to the end */
            for (;csep >= cstr; csep--) {
              if (*csep == ',' || csep==cstr) {
                char *checkval;

                if (*csep == ',')
                  checkval = csep+1;
                else
                  checkval = cstr;

                if (dnsbl_result_match(checkval, replyip)) {
                  log_write(LS_DNSBL, L_INFO, 0, "DNSBL Matched %p %s (R)", sptr, blline->name);
                  SetDNSBL(sptr);

                  if (x_flag & DFLAG_MARK)
                    SetDNSBLMarked(sptr);

                  if ((x_flag & DFLAG_ALLOW) && (!IsDNSBLDenied(sptr)))
                    SetDNSBLAllowed(sptr);

                  if (x_flag & DFLAG_DENY) {
                    ClearDNSBLAllowed(sptr);
                    SetDNSBLDenied(sptr);
                  }

                  if (atoi(blline->rank) > cli_dnsbllastrank(sptr)) {
                    ircd_strncpy(cli_dnsbl(sptr), blline->name, BUFSIZE);
                    ircd_strncpy(cli_dnsblformat(sptr), blline->reply, BUFSIZE);
                  }

                  cli_dnsbllastrank(sptr) = atoi(blline->rank);

                  add_dnsbl(sptr, blline->name);
                  da = 0;
                  ret = 1;
                }
              *csep = 0;
              }
            }
        }
    }
  }
  return ret;
}

/** When non-zero, indicates that a configuration error has been seen in this pass. */
static int conf_error;
/** When non-zero, indicates that the configuration file was loaded at least once. */
static int conf_already_read;
extern void yyparse(void);
extern int init_lexer(void);
extern void deinit_lexer(void);

/** Read configuration file.
 * @return Zero on failure, non-zero on success. */
int read_configuration_file(void)
{
  conf_error = 0;
  feature_unmark(); /* unmark all features for resetting later */
  if (!init_lexer())
    return 0;
  yyparse();
  deinit_lexer();
  feature_mark(); /* reset unmarked features */
  conf_already_read = 1;

  /* Set our local FLAG_HUB if necessary. */
  if (feature_bool(FEAT_HUB))
    SetFlag(&me, FLAG_HUB);
  else
    ClrFlag(&me, FLAG_HUB);

  return 1;
}

/** Report an error message about the configuration file.
 * @param msg The error to report.
 */
void
yyerror(const char *msg)
{
 sendto_opmask_butone(0, SNO_ALL, "Config file parse error line %d: %s",
                      lineno, msg);
 log_write(LS_CONFIG, L_ERROR, 0, "Config file parse error line %d: %s",
           lineno, msg);
 if (!conf_already_read)
   fprintf(stderr, "Config file parse error line %d: %s\n", lineno, msg);
 conf_error = 1;
}

/** List of server names with UWorld privileges. */
static struct SLink *uworlds;

/** Update the UWorld status flag for a server and every server behind it.
 * @param[in] cptr The server to check against UWorld.
 */
void
update_uworld_flags(struct Client *cptr)
{
  struct DLink *lp;
  struct SLink *sp;

  assert(cli_serv(cptr) != NULL);

  for (sp = uworlds; sp; sp = sp->next)
    if (0 == ircd_strcmp(cli_name(cptr), sp->value.cp))
      break;

  if (sp)
    cli_serv(cptr)->flags |= SFLAG_UWORLD;
  else
    cli_serv(cptr)->flags &= ~SFLAG_UWORLD;

  for (lp = cli_serv(cptr)->down; lp; lp = lp->next)
    update_uworld_flags(lp->value.cptr);
}

/** Empty the list of known UWorld servers. */
static void
conf_erase_uworld_list(void)
{
  struct SLink *sp;

  while (uworlds)
  {
    sp = uworlds;
    uworlds = sp->next;
    MyFree(sp->value.cp);
    free_link(sp);
  }

  update_uworld_flags(&me);
}

/** Record the name of a server having UWorld privileges.
 * @param[in] name Privileged server's name.
 */
void conf_make_uworld(char *name)
{
  struct SLink *sp;

  sp = make_link();
  sp->value.cp = name;
  sp->next = uworlds;
  uworlds = sp;
}

/** Send a list of UWorld servers.
 * @param[in] to Client requesting statistics.
 * @param[in] sd Stats descriptor for request (ignored).
 * @param[in] param Extra parameter from user (ignored).
 */
void
stats_uworld(struct Client* to, const struct StatDesc *sd, char* param)
{
  struct SLink *sp;
  char *tmp = NULL;

  send_reply(to, SND_EXPLICIT | RPL_STATSHEADER,
    "U Server");

  for (sp = uworlds; sp; sp = sp->next) {
    tmp = strdup(sp->value.cp);

    send_reply(to, RPL_STATSULINE, tmp);
  }
}

void conf_erase_crule_list(void)
{
  struct CRuleConf* next;
  struct CRuleConf* p = cruleConfList;

  for ( ; p; p = next) {
    next = p->next;
    crule_free(&p->node);
    MyFree(p->hostmask);
    MyFree(p->rule);
    MyFree(p);
  }
  cruleConfList = 0;
}

const struct CRuleConf* conf_get_crule_list(void)
{
  return cruleConfList;
}

void conf_add_deny(const char* const* fields, int count, int ip_kill)
{
  struct DenyConf* conf;

  if (count < 4 || EmptyString(fields[1]) || EmptyString(fields[3]))
    return;
  
  conf = (struct DenyConf*) MyMalloc(sizeof(struct DenyConf));
  assert(0 != conf);
  memset(conf, 0, sizeof(struct DenyConf));

  if (fields[1][0] == '$' && fields[1][1] == 'R')
    conf->flags |= DENY_FLAGS_REALNAME;

  DupString(conf->hostmask, fields[1]);
  collapse(conf->hostmask);

  if (!EmptyString(fields[2])) {
    const char* p = fields[2];
    if ('!' == *p) {
      conf->flags |= DENY_FLAGS_FILE;
      ++p;
    }
    DupString(conf->message, p);
  }
  DupString(conf->usermask, fields[3]);
  collapse(conf->usermask);

  if (ip_kill) {
    /* 
     * Here we use the same kludge as in listener.c to parse
     * a.b.c.d, or a.b.c.*, or a.b.c.d/e.
     */
    int  c_class;
    char ipname[16];
    int  ad[4] = { 0 };
    int  bits2 = 0;

    /* very simple check to make sure this could even be a valid IP kline,
     * this does preclude us ever have IP klines of the form *.xxx.yyy.zzz
     * though - I can't see it being a problem. -- hikari */
    if (!IsDigit(conf->hostmask[0]))
    {
     sendto_opmask_butone(0, SNO_OLDSNO, 
        "Mangled IP in IP K-Line: k:%s:%s:%s", conf->hostmask, conf->message,
         conf->usermask);
     return;
    }

    c_class = sscanf(conf->hostmask, "%d.%d.%d.%d/%d",
                     &ad[0], &ad[1], &ad[2], &ad[3], &bits2);
    if (c_class != 5) {
      conf->bits = c_class * 8;
    }
    else {
      conf->bits = bits2;
    }
    ircd_snprintf(0, ipname, sizeof(ipname), "%d.%d.%d.%d", ad[0], ad[1],
		  ad[2], ad[3]);
    
    /*
     * This ensures endian correctness
     */
    conf->address = inet_addr(ipname);
    Debug((DEBUG_DEBUG, "IPkill: %s = %08x/%i (%08x)", ipname,
           conf->address, conf->bits, NETMASK(conf->bits)));
    conf->flags |= DENY_FLAGS_IP;
  }
  conf->next = denyConfList;
  denyConfList = conf;
}

void conf_erase_deny_list(void)
{
  struct DenyConf* next;
  struct DenyConf* p = denyConfList;
  for ( ; p; p = next) {
    next = p->next;
    MyFree(p->hostmask);
    MyFree(p->usermask);
    MyFree(p->message);
    MyFree(p);
  }
  denyConfList = 0;
}
 
const struct DenyConf* conf_get_deny_list(void)
{
  return denyConfList;
}

/*
 * rehash
 *
 * Actual REHASH service routine. Called with sig == 0 if it has been called
 * as a result of an operator issuing this command, else assume it has been
 * called as a result of the server receiving a HUP signal.
 */
int rehash(struct Client *cptr, int sig)
{
  struct ConfItem** tmp = &GlobalConfList;
  struct ConfItem*  tmp2;
  struct Client*    acptr;
  int               i;
  int               ret = 0;
  int               found_g = 0;

  if (1 == sig)
    sendto_opmask_butone(0, SNO_OLDSNO,
                         "Got signal SIGHUP, reloading ircd.conf file");

  while ((tmp2 = *tmp)) {
    if (tmp2->clients) {
      /*
       * Configuration entry is still in use by some
       * local clients, cannot delete it--mark it so
       * that it will be deleted when the last client
       * exits...
       */
      if (CONF_CLIENT == (tmp2->status & CONF_CLIENT))
        tmp = &tmp2->next;
      else {
        *tmp = tmp2->next;
        tmp2->next = 0;
      }
      tmp2->status |= CONF_ILLEGAL;
    }
    else {
      *tmp = tmp2->next;
      free_conf(tmp2);
    }
  }
  conf_erase_uworld_list();
  conf_erase_crule_list();
  conf_erase_deny_list();
  motd_clear();

  /*
   * delete the juped nicks list
   */
  clearNickJupes();

  clear_quarantines();
  clear_slines();
  clear_cslines();
  clear_dnsbl_list();
  clear_webirc_list();
  clear_eline_list();
  clear_fline_list();
  clear_svclines();
  clear_lblines();

  if (sig != 2)
    flush_resolver_cache();

  restart_resolver();

  class_mark_delete();
  mark_listeners_closing();

  read_configuration_file();

  log_reopen(); /* reopen log files */

#ifdef USE_SSL
  ssl_init();
#endif /* USE_SSL */

  close_listeners();
  class_delete_marked();         /* unless it fails */

  /*
   * Flush out deleted I and P lines although still in use.
   */
  for (tmp = &GlobalConfList; (tmp2 = *tmp);) {
    if (CONF_ILLEGAL == (tmp2->status & CONF_ILLEGAL)) {
      *tmp = tmp2->next;
      tmp2->next = NULL;
      if (!tmp2->clients)
        free_conf(tmp2);
    }
    else
      tmp = &tmp2->next;
  }

  for (i = 0; i <= HighestFd; i++) {
    if ((acptr = LocalClientArray[i])) {
      assert(!IsMe(acptr));
      if (IsServer(acptr))
        det_confs_butmask(acptr, ~(CONF_ILLEGAL));

      /* Because admin's are getting so uppity about people managing to
       * get past K/G's etc, we'll "fix" the bug by actually explaining
       * whats going on.
       */
      if ((found_g = find_kill(acptr))) {
        sendto_opmask_butone(0, found_g == -2 ? SNO_GLINE : SNO_OPERKILL,
                             found_g == -2 ? "G-line active for %s%s" :
                             "K-line active for %s%s",
                             IsUnknown(acptr) ? "Unregistered Client ":"",
                             get_client_name(acptr, SHOW_IP));
        if (exit_client(cptr, acptr, &me, found_g == -2 ? "G-lined" :
            "K-lined") == CPTR_KILLED)
            ret = CPTR_KILLED;
      }
    }
  }

  update_uworld_flags(&me);

  return ret;
}

/*
 * init_conf
 *
 * Read configuration file.
 *
 * returns 0, if file cannot be opened
 *         1, if file read
 */

int init_conf(void)
{
  if (read_configuration_file())
    return 1;
  else
    return 0;
}

char* iitoa (int n){
  int i=0,j;
  char* s;
  char* u;

  s= (char*) malloc(17);
  u= (char*) malloc(17);

  do{
    s[i++]=(char)( n%10+48 );
    n-=n%10;
  }
  while((n/=10)>0);
  for (j=0;j<i;j++)
  u[i-1-j]=s[j];

  u[j]='\0';
  return u;
}

char* get_type(unsigned int flag)
{
  if (WFFLAG_NOTICE & flag)
    return "NOTICE";
  else if (WFFLAG_CHANNOTICE & flag)
    return "CHANNEL NOTICE";
  else if (WFFLAG_PRIVMSG & flag)
    return "PRIVATE MESSAGE";
  else if (WFFLAG_CHANMSG & flag)
    return "CHANNEL MESSAGE";
  else if (WFFLAG_AWAY & flag)
    return "AWAY";
  else if (WFFLAG_TOPIC & flag)
    return "TOPIC";
  else if (WFFLAG_CONNECT & flag)
   return "CONNECT";
  else if (WFFLAG_PART & flag)
    return "PART";
  else if (WFFLAG_QUIT & flag)
    return "QUIT";
  else if (WFFLAG_DCC & flag)
    return "DCC";
  else if (WFFLAG_NICK & flag)
    return "NICK";
  else
    return "(unknown)";
}

/*
 * find_fline
 * input:
 *  client pointer
 *  combination of FFLAG_*'s
*/
int find_fline(struct Client *cptr, struct Client *sptr, char *string, unsigned int flags, char *target)
{
  struct fline *fline;
  struct Channel *chptr;
  struct Membership *member,*nmember;
  struct rusage rnow, rprev;
  struct SpamFilter *spamfilter;
  struct SpamFilter *sspamfilter;
  long ms_past;
  int rf_flag = 0, wf_flag = 0, regmatch = 0;
  int ret = 0, brk = 0, ovector[186];
  char temp1[BUFSIZE], temp2[BUFSIZE], temphost[HOSTLEN +3], reason[BUFSIZE];
  char* gline[6];
  char* zline[6];
  char* shun[6];

  for (fline = GlobalFList; fline; fline = fline->next) {
    regmatch = 0;
    rf_flag = reactfflagstr(fline->rflags);
    wf_flag = watchfflagstr(fline->wflags);

    if (IsAnOper(sptr))
      break;

    if (fline->active == 0) {
      Debug((DEBUG_DEBUG, "filter has been disabled"));
      break;
    }

    if (rf_flag & RFFLAG_AUTH && IsAccount(sptr)) {
      Debug((DEBUG_DEBUG, "regexec IsAccount and FFLAG_AUTH yes, breaking"));
      break;
    }

    if (find_eline(sptr, EFLAG_SFILTER)) {
      Debug((DEBUG_DEBUG, "Exempt from spam filter, breaking"));
      break;
    }

    if (target && *target) {
      if (IsChannelPrefix(*target) && (rf_flag & RFFLAG_OPS)) {
        chptr = FindChannel(target);

        if (chptr) {
          for (member=chptr->members;member;member=nmember) {
            nmember=member->next_member;
            if ((member->user == sptr) && (IsChanOp(member) || IsHalfOp(member)))
              brk = 1;
          }
        }
        if (brk == 1)
          break;
      }
      brk = 0;

      if (IsChannelPrefix(*target) && (rf_flag & RFFLAG_VOICE)) {
        chptr = FindChannel(target);

        if (chptr) {
          for (member=chptr->members;member;member=nmember) {
            nmember=member->next_member;
            if ((member->user == sptr) && (IsVoicedOrOpped(member)))
              brk = 1;
          }
        }
        if (brk == 1)
          break;
      }
      brk = 0;
    }

    if (wf_flag & flags) {
      memset(&rnow, 0, sizeof(rnow));
      memset(&rprev, 0, sizeof(rnow));

      getrusage(RUSAGE_SELF, &rprev);
      regmatch = pcre_exec(fline->filter, NULL, string, strlen(string), 0, 0, ovector, 186);
      getrusage(RUSAGE_SELF, &rnow);


      ms_past = ((rnow.ru_utime.tv_sec - rprev.ru_utime.tv_sec) * 1000) +
                ((rnow.ru_utime.tv_usec - rprev.ru_utime.tv_usec) / 1000);

      if ((feature_int(FEAT_FILTER_FATAL_TIME) > 0) && (ms_past > feature_int(FEAT_FILTER_FATAL_TIME))) {
        sendto_allops(&me, SNO_OLDSNO, "Warning: Very slow spam filter detected (%s) - (took %ld msec to execute). Filter has been disabled",
                      fline->rawfilter, ms_past);
        fline->active = 0;
        break;
      } else if ((feature_int(FEAT_FILTER_WARN_TIME) > 0) && (ms_past > feature_int(FEAT_FILTER_WARN_TIME))) {
        sendto_allops(&me, SNO_OLDSNO, "Warning: Slow spam filter detected (%s) - (took %ld msec to execute).",
                      fline->rawfilter, ms_past);
      }

      if (regmatch > 0) {
        Debug((DEBUG_DEBUG, "regexec match"));
        if (rf_flag & RFFLAG_CALERT) {
          chptr = FindChannel(fline->nchan);
          if (chptr) {
            ircd_snprintf(0, temp1, sizeof(temp1), "%s has triggered a filter the following %s%s%s%s", cli_name(sptr), get_type(flags),
                          !EmptyString(target) ? " (Targets: " : "", !EmptyString(target) ? target : "", !EmptyString(target) ? ")" : "");
            ircd_snprintf(0, temp2, sizeof(temp2), "%s", string);
            if (feature_bool(FEAT_FILTER_ALERT_USEMSG)) {
              sendcmdto_channel_butone(&me, CMD_PRIVATE, chptr, cptr, SKIP_DEAF | SKIP_BURST, '\0', "%H :%s", chptr, temp1);
              sendcmdto_channel_butone(&me, CMD_PRIVATE, chptr, cptr, SKIP_DEAF | SKIP_BURST, '\0', "%H :%s", chptr, temp2);
            } else {
              sendcmdto_channel_butone(&me, CMD_NOTICE, chptr, cptr, SKIP_DEAF | SKIP_BURST, '\0', "%H :%s", chptr, temp1);
              sendcmdto_channel_butone(&me, CMD_NOTICE, chptr, cptr, SKIP_DEAF | SKIP_BURST, '\0', "%H :%s", chptr, temp2);
            }
          }
        }
        if (rf_flag & RFFLAG_MARK) {
          SetSpam(sptr);
          sendcmdto_serv_butone(cli_user(sptr)->server, CMD_MARK, cptr, "%s %s +", cli_name(sptr), MARK_SFILTER);
        }
        if (rf_flag & RFFLAG_SALERT) {
          sendto_allops(&me, SNO_OLDSNO, "%s has triggered a filter line for the following %s%s%s%s", cli_name(sptr),
          get_type(flags), !EmptyString(target) ? " (Targets: " : "", !EmptyString(target) ? target : "",
          !EmptyString(target) ? ")" : "");
          sendto_allops(&me, SNO_OLDSNO, "%s", string);
        }
        if (rf_flag & RFFLAG_NOTIFY) {
          sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Your last %s was blocked as it matched a spam filter.", sptr, get_type(flags));
        }
        if (rf_flag & RFFLAG_KICK) {
          if (((WFFLAG_CHANNOTICE & flags) || (WFFLAG_CHANMSG & flags)) && (target && *target)) {
            chptr = FindChannel(target);

            if (chptr) {
              for (member=chptr->members;member;member=nmember) {
                nmember=member->next_member;
                if (member->user == sptr) {
                  if (!MyUser(member->user) || IsZombie(member))
                    continue;

                  sendcmdto_serv_butone(feature_bool(FEAT_HIS_HIDEWHO) ? &his : &me, CMD_KICK, NULL, "%H %C :%s", chptr, member->user, fline->reason);
                  sendcmdto_channel_butserv_butone(&me, CMD_KICK, chptr, NULL, 0, "%H %C :%s", chptr, member->user, fline->reason);
                  make_zombie(member, member->user, &me, &me, chptr);
                }
              }
            }
          }
        }
        if (rf_flag & RFFLAG_GLINE) {
          gline[0] = strdup(NumServ(&me));
          gline[1] = strdup(NumServ(&me));
          if (rf_flag & RFFLAG_IP)
            ircd_snprintf(0, temphost, sizeof(temphost), "*@%s", ircd_ntoa((const char*) &(cli_ip(cptr))));
          else
            ircd_snprintf(0, temphost, sizeof(temphost), "*@%s", cli_user(cptr)->realhost);
          gline[2] = strdup(temphost);
          gline[3] = iitoa(fline->length);
          gline[4] = iitoa(CurrentTime);
          ircd_snprintf(0, reason, sizeof(reason), "Filter Match (%s)", fline->reason);
          gline[5] = strdup(reason);
          ms_gline(&me, &me, 6, gline);
          ret = 2;
        } else {
          if (rf_flag & RFFLAG_ZLINE) {
            zline[0] = strdup(NumServ(&me));
            zline[1] = strdup(NumServ(&me));
            ircd_snprintf(0, temphost, sizeof(temphost), "*@%s", ircd_ntoa((const char*) &(cli_ip(cptr))));
            zline[2] = strdup(temphost);
            zline[3] = iitoa(fline->length);
            zline[4] = iitoa(CurrentTime);
            ircd_snprintf(0, reason, sizeof(reason), "Filter Match (%s)", fline->reason);
            zline[5] = strdup(reason);
            ms_zline(&me, &me, 6, zline);
            ret = 2;
          } else {
            if (rf_flag & RFFLAG_KILL) {
               exit_client_msg(cptr, sptr, &me, "Filter Match (%s)", fline->reason);
               ret = 2;
            }
            if (rf_flag & RFFLAG_SHUN) {
              shun[0] = strdup(NumServ(&me));
              shun[1] = strdup(NumServ(&me));
              if (rf_flag & RFFLAG_IP)
                ircd_snprintf(0, temphost, sizeof(temphost), "*@%s", ircd_ntoa((const char*) &(cli_ip(cptr))));
              else
                ircd_snprintf(0, temphost, sizeof(temphost), "*@%s", cli_user(cptr)->realhost);
              shun[2] = strdup(temphost);
              shun[3] = iitoa(fline->length);
              shun[4] = iitoa(CurrentTime);
              ircd_snprintf(0, reason, sizeof(reason), "Filter Match (%s)", fline->reason);
              shun[5] = strdup(reason);
              ms_shun(&me, &me, 6, shun);
            }
          }
        }
        if ((rf_flag & RFFLAG_BLOCK) && (ret != 2)) {
           ret = 1;
        }
        if (ret)
          return ret;
      }
    }
  }

  for (spamfilter = GlobalSpamFilterList; spamfilter; spamfilter = sspamfilter) {
    sspamfilter = spamfilter->sf_next;

    if (spamfilter->sf_expire <= CurrentTime) {
      spamfilter_free(spamfilter);
      continue;
    }

    regmatch = 0;
    rf_flag = reactfflagstr(spamfilter->sf_rflags);
    wf_flag = watchfflagstr(spamfilter->sf_wflags);

    if (IsAnOper(sptr))
      break;

    if (!SpamFilterIsActive(spamfilter)) {
      Debug((DEBUG_DEBUG, "filter has been disabled"));
      break;
    }

    if (rf_flag & RFFLAG_AUTH && IsAccount(sptr)) {
      Debug((DEBUG_DEBUG, "regexec IsAccount and FFLAG_AUTH yes, breaking"));
      break;
    }

    if (find_eline(sptr, EFLAG_SFILTER)) {
      Debug((DEBUG_DEBUG, "Exempt from spam filter, breaking"));
      break;
    }

    if (target && *target) {
      if (IsChannelPrefix(*target) && (rf_flag & RFFLAG_OPS)) {
        chptr = FindChannel(target);

        if (chptr) {
          for (member=chptr->members;member;member=nmember) {
            nmember=member->next_member;
            if ((member->user == sptr) && (IsChanOp(member) || IsHalfOp(member)))
              brk = 1;
          }
        }
        if (brk == 1)
          break;
      }
      brk = 0;

      if (IsChannelPrefix(*target) && (rf_flag & RFFLAG_VOICE)) {
        chptr = FindChannel(target);

        if (chptr) {
          for (member=chptr->members;member;member=nmember) {
            nmember=member->next_member;
            if ((member->user == sptr) && (IsVoicedOrOpped(member)))
              brk = 1;
          }
        }
        if (brk == 1)
          break;
      }
      brk = 0;
    }

    if (wf_flag & flags) {
      memset(&rnow, 0, sizeof(rnow));
      memset(&rprev, 0, sizeof(rnow));

      getrusage(RUSAGE_SELF, &rprev);
      regmatch = pcre_exec(spamfilter->sf_filter, NULL, string, strlen(string), 0, 0, ovector, 186);
      getrusage(RUSAGE_SELF, &rnow);


      ms_past = ((rnow.ru_utime.tv_sec - rprev.ru_utime.tv_sec) * 1000) +
                ((rnow.ru_utime.tv_usec - rprev.ru_utime.tv_usec) / 1000);

      if ((feature_int(FEAT_FILTER_FATAL_TIME) > 0) && (ms_past > feature_int(FEAT_FILTER_FATAL_TIME))) {
        sendto_allops(&me, SNO_OLDSNO, "Warning: Very slow spam filter detected (%s) - (took %ld msec to execute). Filter has been disabled",
                      spamfilter->sf_rawfilter, ms_past);
        spamfilter->sf_flags &= ~SPAMFILTER_ACTIVE;
        sendcmdto_serv_butone(&me, CMD_SPAMFILTER, cptr, "* - %s %s %Tu %s :%s",
                              spamfilter->sf_wflags, spamfilter->sf_rflags,
                              spamfilter->sf_expire - CurrentTime,
                              spamfilter->sf_reason, spamfilter->sf_rawfilter);

        break;
      } else if ((feature_int(FEAT_FILTER_WARN_TIME) > 0) && (ms_past > feature_int(FEAT_FILTER_WARN_TIME))) {
        sendto_allops(&me, SNO_OLDSNO, "Warning: Slow spam filter detected (%s) - (took %ld msec to execute).",
                      spamfilter->sf_rawfilter, ms_past);
      }

      if (regmatch > 0) {
        Debug((DEBUG_DEBUG, "regexec match"));
        if (rf_flag & RFFLAG_CALERT) {
          chptr = FindChannel(spamfilter->sf_nchan);
          if (chptr) {
            ircd_snprintf(0, temp1, sizeof(temp1), "%s has triggered a filter the following %s%s%s%s", cli_name(sptr), get_type(flags),
                          !EmptyString(target) ? " (Targets: " : "", !EmptyString(target) ? target : "", !EmptyString(target) ? ")" : "");
            ircd_snprintf(0, temp2, sizeof(temp2), "%s", string);
            if (feature_bool(FEAT_FILTER_ALERT_USEMSG)) {
              sendcmdto_channel_butone(&me, CMD_PRIVATE, chptr, cptr, SKIP_DEAF | SKIP_BURST, '\0', "%H :%s", chptr, temp1);
              sendcmdto_channel_butone(&me, CMD_PRIVATE, chptr, cptr, SKIP_DEAF | SKIP_BURST, '\0', "%H :%s", chptr, temp2);
            } else {
              sendcmdto_channel_butone(&me, CMD_NOTICE, chptr, cptr, SKIP_DEAF | SKIP_BURST, '\0', "%H :%s", chptr, temp1);
              sendcmdto_channel_butone(&me, CMD_NOTICE, chptr, cptr, SKIP_DEAF | SKIP_BURST, '\0', "%H :%s", chptr, temp2);
            }
          }
        }
        if (rf_flag & RFFLAG_MARK) {
          SetSpam(sptr);
          sendcmdto_serv_butone(cli_user(sptr)->server, CMD_MARK, cptr, "%s %s +", cli_name(sptr), MARK_SFILTER);
        }
        if (rf_flag & RFFLAG_SALERT) {
          sendto_allops(&me, SNO_OLDSNO, "%s has triggered a filter line for the following %s%s%s%s", cli_name(sptr),
          get_type(flags), !EmptyString(target) ? " (Targets: " : "", !EmptyString(target) ? target : "",
          !EmptyString(target) ? ")" : "");
          sendto_allops(&me, SNO_OLDSNO, "%s", string);
        }
        if (rf_flag & RFFLAG_NOTIFY) {
          sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Your last %s was blocked as it matched a spam filter.", sptr, get_type(flags));
        }
        if (rf_flag & RFFLAG_KICK) {
          if (((WFFLAG_CHANNOTICE & flags) || (WFFLAG_CHANMSG & flags)) && (target && *target)) {
            chptr = FindChannel(target);

            if (chptr) {
              for (member=chptr->members;member;member=nmember) {
                nmember=member->next_member;
                if (member->user == sptr) {
                  if (!MyUser(member->user) || IsZombie(member))
                    continue;

                  sendcmdto_serv_butone(feature_bool(FEAT_HIS_HIDEWHO) ? &his : &me, CMD_KICK, NULL, "%H %C :%s", chptr, member->user, decodespace(spamfilter->sf_reason));
                  sendcmdto_channel_butserv_butone(&me, CMD_KICK, chptr, NULL, 0, "%H %C :%s", chptr, member->user, decodespace(spamfilter->sf_reason));
                  make_zombie(member, member->user, &me, &me, chptr);
                }
              }
            }
          }
        }
        if (rf_flag & RFFLAG_GLINE) {
          gline[0] = strdup(NumServ(&me));
          gline[1] = strdup(NumServ(&me));
          if (rf_flag & RFFLAG_IP)
            ircd_snprintf(0, temphost, sizeof(temphost), "*@%s", ircd_ntoa((const char*) &(cli_ip(cptr))));
          else
            ircd_snprintf(0, temphost, sizeof(temphost), "*@%s", cli_user(cptr)->realhost);
          gline[2] = strdup(temphost);
          gline[3] = iitoa(spamfilter->sf_length);
          gline[4] = iitoa(CurrentTime);
          ircd_snprintf(0, reason, sizeof(reason), "Filter Match (%s)", decodespace(spamfilter->sf_reason));
          gline[5] = strdup(reason);
          ms_gline(&me, &me, 6, gline);
          ret = 2;
        } else {
          if (rf_flag & RFFLAG_ZLINE) {
            zline[0] = strdup(NumServ(&me));
            zline[1] = strdup(NumServ(&me));
            ircd_snprintf(0, temphost, sizeof(temphost), "*@%s", ircd_ntoa((const char*) &(cli_ip(cptr))));
            zline[2] = strdup(temphost);
            zline[3] = iitoa(spamfilter->sf_length);
            zline[4] = iitoa(CurrentTime);
            ircd_snprintf(0, reason, sizeof(reason), "Filter Match (%s)", decodespace(spamfilter->sf_reason));
            zline[5] = strdup(reason);
            ms_zline(&me, &me, 6, zline);
            ret = 2;
          } else {
            if (rf_flag & RFFLAG_KILL) {
               exit_client_msg(cptr, sptr, &me, "Filter Match (%s)", decodespace(spamfilter->sf_reason));
               ret = 2;
            }
            if (rf_flag & RFFLAG_SHUN) {
              shun[0] = strdup(NumServ(&me));
              shun[1] = strdup(NumServ(&me));
              if (rf_flag & RFFLAG_IP)
                ircd_snprintf(0, temphost, sizeof(temphost), "*@%s", ircd_ntoa((const char*) &(cli_ip(cptr))));
              else
                ircd_snprintf(0, temphost, sizeof(temphost), "*@%s", cli_user(cptr)->realhost);
              shun[2] = strdup(temphost);
              shun[3] = iitoa(spamfilter->sf_length);
              shun[4] = iitoa(CurrentTime);
              ircd_snprintf(0, reason, sizeof(reason), "Filter Match (%s)", decodespace(spamfilter->sf_reason));
              shun[5] = strdup(reason);
              ms_shun(&me, &me, 6, shun);
            }
          }
        }
        if ((rf_flag & RFFLAG_BLOCK) && (ret != 2)) {
           ret = 1;
        }
        if (ret)
          return ret;
      }
    }
  }

  return ret;
}

/*
 * find_eline
 * input:
 *  client pointer
 *  combination of EFLAG_*'s
 * returns:
 *  0: Client does not have an E:Line.
 * -1: Client has an E:Line with 1 or more of the supplied flags.
*/
int find_eline(struct Client *cptr, unsigned int flags)
{
  char i_host[SOCKIPLEN + USERLEN + 2];
  char s_host[HOSTLEN + USERLEN + 2];
  int found = 0;
  unsigned int e_flag = 0;
  struct eline *eline;

  if (flags & EFLAG_IPCHECK) {
    if (IsIPCheckExempted(cptr))
      return -1;

    if (IsNotIPCheckExempted(cptr))
      return 0;

    ircd_snprintf(0, i_host, USERLEN+SOCKIPLEN+2, "nobody@%s", ircd_ntoa((const char*) &(cli_ip(cptr))));
  } else {
    ircd_snprintf(0, i_host, USERLEN+SOCKIPLEN+2, "%s@%s", cli_username(cptr), ircd_ntoa((const char*) &(cli_ip(cptr))));
    ircd_snprintf(0, s_host, USERLEN+HOSTLEN+2, "%s@%s", cli_username(cptr), cli_sockhost(cptr));
  }

  for (eline = GlobalEList; eline; eline = eline->next) {
    char* ip_start;
    char* cidr_start;
    in_addr_t cli_addr = 0;

    e_flag = eflagstr(eline->flags);

    if (s_host) {
      if ((match(eline->mask, s_host) == 0) || (match(eline->mask, i_host) == 0)) {
        if (e_flag & flags) {
          found = 1;
        }
      }
    }

    if ((ip_start = strrchr(i_host, '@')))
      cli_addr = inet_addr(ip_start + 1);

    if ((ip_start = strrchr(eline->mask, '@')) && (cidr_start = strchr(ip_start + 1, '/'))) {
      int bits = atoi(cidr_start + 1);
      char* p = strchr(i_host, '@');

      if (p) {
        *p = *ip_start = 0;
        if (match(eline->mask, i_host) == 0) {
          if ((bits > 0) && (bits < 33)) {
            in_addr_t ban_addr;
            *cidr_start = 0;
            ban_addr = inet_addr(ip_start + 1);
            *cidr_start = '/';
            if ((NETMASK(bits) & cli_addr) == ban_addr) {
              *p = *ip_start = '@';
              if (e_flag & flags) {
                found = 1;
              }
            }
          }
        }
        *p = *ip_start = '@';
      }
    }

  }

  if (found)
      return -1;

  if (flags & EFLAG_IPCHECK)
    SetNotIPCheckExempted(cptr);

  return 0;
}

/*
 * find_eline_from_ip
 * input:
 *  client ip address
 *  combination of EFLAG_*'s
 * returns:
 *  0: Client does not have an E:Line.
 * -1: Client has an E:Line with 1 or more of the supplied flags.
*/
int find_eline_from_ip(struct in_addr addr, unsigned int flags)
{
  char i_host[SOCKIPLEN + USERLEN + 2];
  int found = 0;
  unsigned int e_flag = 0;
  struct eline *eline;

  if (flags & EFLAG_IPCHECK)
    ircd_snprintf(0, i_host, USERLEN+SOCKIPLEN+2, "nobody@%s", ircd_ntoa((const char*) &addr.s_addr));
  else
    return 0;

  for (eline = GlobalEList; eline; eline = eline->next) {
    char* ip_start;
    char* cidr_start;
    in_addr_t cli_addr = 0;

    e_flag = eflagstr(eline->flags);

    if ((ip_start = strrchr(i_host, '@')))
      cli_addr = inet_addr(ip_start + 1);

    if ((ip_start = strrchr(eline->mask, '@')) && (cidr_start = strchr(ip_start + 1, '/'))) {
      int bits = atoi(cidr_start + 1);
      char* p = strchr(i_host, '@');

      if (p) {
        *p = *ip_start = 0;
        if (match(eline->mask, i_host) == 0) {
          if ((bits > 0) && (bits < 33)) {
            in_addr_t ban_addr;
            *cidr_start = 0;
            ban_addr = inet_addr(ip_start + 1);
            *cidr_start = '/';
            if ((NETMASK(bits) & cli_addr) == ban_addr) {
              *p = *ip_start = '@';
              if (e_flag & flags) {
                found = 1;
              }
            }
          }
        }
        *p = *ip_start = '@';
      }
    }

  }

  if (found) {
    return -1;
  }

  return 0;
}

/*
 * find_kill
 * input:
 *  client pointer
 * returns:
 *  0: Client may continue to try and connect
 * -1: Client was K/k:'d - sideeffect: reason was sent.
 * -2: Client was G/g:'d - sideeffect: reason was sent.
 * sideeffects:
 *  Client may have been sent a reason why they are denied, as above.
 */
int find_kill(struct Client *cptr)
{
  const char*      host;
  const char*      name;
  const char*      realname;
  const char*      version; /* added by Vadtec 02/26/2008 */
  struct DenyConf* deny;
  struct Gline*    agline = NULL;

  assert(0 != cptr);

  if (!cli_user(cptr))
    return 0;

  host = cli_sockhost(cptr);
  name = cli_user(cptr)->username;
  realname = cli_info(cptr);
  version = cli_version(cptr); /* added by Vadtec 02/26/2008 */

  assert(strlen(host) <= HOSTLEN);
  assert((name ? strlen(name) : 0) <= HOSTLEN);
  assert((realname ? strlen(realname) : 0) <= REALLEN);
  assert((version ? strlen(version) : 0) <= VERSIONLEN); /* added by Vadtec 02/26/2008 */

  /* 2000-07-14: Rewrote this loop for massive speed increases.
   *             -- Isomer
   */
  for (deny = denyConfList; deny; deny = deny->next) {
    if (deny->flags & DENY_FLAGS_PROMPT) /* handled by find_prompt */
      continue;

    if (0 != match(deny->usermask, name))
      continue;

    if (EmptyString(deny->hostmask))
      break;

    if (deny->flags & DENY_FLAGS_VERSION && feature_bool(FEAT_CTCP_VERSIONING) && feature_bool(FEAT_CTCP_VERSIONING_KILL)) { /* K: by version - added by Vadtec 02/25/2006 */
      if (0 == match(deny->hostmask, version))
	break;
    }
    else if (deny->flags & DENY_FLAGS_REALNAME) { /* K: by real name */
      if (0 == match(deny->hostmask, realname))
	break;
    } else if (deny->flags & DENY_FLAGS_IP) { /* k: by IP */
      Debug((DEBUG_DEBUG, "ip: %08x network: %08x/%i mask: %08x",
             cli_ip(cptr).s_addr, deny->address, deny->bits, NETMASK(deny->bits)));
      if ((cli_ip(cptr).s_addr & NETMASK(deny->bits)) == deny->address)
        break;
    }
    else if (0 == match(deny->hostmask, host))
      break;
  }
  if (deny && !find_eline(cptr, EFLAG_KLINE)) {
    if (EmptyString(deny->message))
      send_reply(cptr, SND_EXPLICIT | ERR_YOUREBANNEDCREEP,
                 ":Connection from your host is refused on this server.");
    else {
      if (deny->flags & DENY_FLAGS_FILE)
        killcomment(cptr, deny->message);
      else
        send_reply(cptr, SND_EXPLICIT | ERR_YOUREBANNEDCREEP, ":%s.", deny->message);
    }
  }
  else if ((agline = gline_lookup(cptr, 0))) {
    /*
     * find active glines
     * added a check against the user's IP address to find_gline() -Kev
     */
    send_reply(cptr, SND_EXPLICIT | ERR_YOUREBANNEDCREEP, ":%s.", GlineReason(agline));
  }

  if (deny && !find_eline(cptr, EFLAG_KLINE))
    return -1;
  if (agline)
    return -2;
    
  return 0;
}

/*
 * find_prompt
 * input:
 *  client pointer
 * returns:
 *  dconf
 */
struct DenyConf *find_prompt(struct Client *cptr)
{
  const char*      host;
  const char*      name;
  const char*      realname;
  const char*      version; /* added by Vadtec 02/26/2008 */
  struct DenyConf* deny;

  assert(0 != cptr);

  if (!cli_user(cptr))
    return 0;

  host = cli_sockhost(cptr);
  name = cli_user(cptr)->username;
  realname = cli_info(cptr);
  version = cli_version(cptr); /* added by Vadtec 02/26/2008 */

  assert(strlen(host) <= HOSTLEN);
  assert((name ? strlen(name) : 0) <= HOSTLEN);
  assert((realname ? strlen(realname) : 0) <= REALLEN);
  assert((version ? strlen(version) : 0) <= VERSIONLEN); /* added by Vadtec 02/26/2008 */

  /* 2000-07-14: Rewrote this loop for massive speed increases.
   *             -- Isomer
   */
  for (deny = denyConfList; deny; deny = deny->next) {
    if (deny->flags & DENY_FLAGS_PROMPT) {

      if (0 != match(deny->usermask, name))
        continue;

      if (EmptyString(deny->hostmask))
        break;

      if (deny->flags & DENY_FLAGS_VERSION && feature_bool(FEAT_CTCP_VERSIONING) && feature_bool(FEAT_CTCP_VERSIONING_KILL)) { /* K: by version - added by Vadtec 02/25/2006 */
        if (0 == match(deny->hostmask, version))
	break;
      }
      else if (deny->flags & DENY_FLAGS_REALNAME) { /* K: by real name */
        if (0 == match(deny->hostmask, realname))
	  break;
      } else if (deny->flags & DENY_FLAGS_IP) { /* k: by IP */
        Debug((DEBUG_DEBUG, "ip: %08x network: %08x/%i mask: %08x",
               cli_ip(cptr).s_addr, deny->address, deny->bits, NETMASK(deny->bits)));
        if ((cli_ip(cptr).s_addr & NETMASK(deny->bits)) == deny->address)
          break;
      }
      else if (0 == match(deny->hostmask, host))
        break;
    }
  }

  if (deny && !find_eline(cptr, EFLAG_KLINE))
    return deny;
  else
    return NULL;
}

/*
 * Ordinary client access check. Look for conf lines which have the same
 * status as the flags passed.
 */
enum AuthorizationCheckResult conf_check_client(struct Client *cptr)
{
  enum AuthorizationCheckResult acr = ACR_OK;

  ClearAccess(cptr);

  if ((acr = attach_iline(cptr))) {
    Debug((DEBUG_DNS, "ch_cl: access denied: %s[%s]", 
          cli_name(cptr), cli_sockhost(cptr)));
    return acr;
  }
  return ACR_OK;
}

/*
 * check_server()
 *
 * Check access for a server given its name (passed in cptr struct).
 * Must check for all C lines which have a name which matches the
 * name given and a host which matches. A host alias which is the
 * same as the server name is also acceptable in the host field of a
 * C line.
 *
 * Returns
 *  0 = Success
 * -1 = Access denied
 * -2 = Bad socket.
 */
int conf_check_server(struct Client *cptr)
{
  struct ConfItem* c_conf = NULL;
  struct SLink*    lp;

  Debug((DEBUG_DNS, "sv_cl: check access for %s[%s]", 
        cli_name(cptr), cli_sockhost(cptr)));

  if (IsUnknown(cptr) && !attach_confs_byname(cptr, cli_name(cptr), CONF_SERVER)) {
    Debug((DEBUG_DNS, "No C:line for %s", cli_sockhost(cptr)));
    return -1;
  }
  lp = cli_confs(cptr);
  /*
   * We initiated this connection so the client should have a C line
   * already attached after passing through the connect_server()
   * function earlier.
   */
  if (IsConnecting(cptr) || IsHandshake(cptr)) {
    c_conf = find_conf_byname(lp, cli_name(cptr), CONF_SERVER);
    if (!c_conf) {
      sendto_opmask_butone(0, SNO_OLDSNO, "Connect Error: lost C:line for %s",
                           cli_name(cptr));
      det_confs_butmask(cptr, 0);
      return -1;
    }
  }

  ClearAccess(cptr);

  if (!c_conf) {
    if (cli_dns_reply(cptr)) {
      int             i;
      struct hostent* hp = cli_dns_reply(cptr)->hp;
      const char*     name = hp->h_name;
      /*
       * If we are missing a C line from above, search for
       * it under all known hostnames we have for this ip#.
       */
      for (i = 0; name; name = hp->h_aliases[i++]) {
        if ((c_conf = find_conf_byhost(lp, name, CONF_SERVER))) {
          ircd_strncpy(cli_sockhost(cptr), name, HOSTLEN);
          break;
        }
      }
      if (!c_conf) {
        for (i = 0; hp->h_addr_list[i]; i++) {
          if ((c_conf = find_conf_byip(lp, hp->h_addr_list[i], CONF_SERVER)))
            break;
        }
      }
    }
    else {
      /*
       * Check for C lines with the hostname portion the ip number
       * of the host the server runs on. This also checks the case where
       * there is a server connecting from 'localhost'.
       */
      c_conf = find_conf_byhost(lp, cli_sockhost(cptr), CONF_SERVER);
    }
  }
  /*
   * Attach by IP# only if all other checks have failed.
   * It is quite possible to get here with the strange things that can
   * happen when using DNS in the way the irc server does. -avalon
   */
  if (!c_conf)
    c_conf = find_conf_byip(lp, (const char*) &(cli_ip(cptr)), CONF_SERVER);
  /*
   * detach all conf lines that got attached by attach_confs()
   */
  det_confs_butmask(cptr, 0);
  /*
   * if no C line, then deny access
   */
  if (!c_conf) {
    Debug((DEBUG_DNS, "sv_cl: access denied: %s[%s@%s]",
          cli_name(cptr), cli_username(cptr), cli_sockhost(cptr)));
    return -1;
  }
  /*
   * attach the C line to the client structure for later use.
   */
  attach_conf(cptr, c_conf);

  if (INADDR_NONE == c_conf->ipnum.s_addr)
    c_conf->ipnum.s_addr = cli_ip(cptr).s_addr;

  Debug((DEBUG_DNS, "sv_cl: access ok: %s[%s]", cli_name(cptr), cli_sockhost(cptr)));
  return 0;
}
 
void clear_svclines(void)
{
  struct svcline *svc;

  while ((svc = GlobalServicesList)) {
	 GlobalServicesList = svc->next;
	 MyFree(svc->cmd);
	 MyFree(svc->target);
	 if (!EmptyString(svc->prepend))
	   MyFree(svc->prepend);
	 MyFree(svc);
  }
  GlobalServicesList = 0;
}

struct svcline *find_svc(const char *cmd)
{
  struct svcline *confbot = NULL;
  
  for (confbot = GlobalServicesList; confbot; confbot = confbot->next) {
    if (confbot->cmd && !match(confbot->cmd, cmd)) 
      return confbot;
  }
  return NULL;
}

void clear_slines(void)
{
  struct sline *sline;
  while ((sline = GlobalSList)) {
    GlobalSList = sline->next;
    MyFree(sline->spoofhost);
    if (!EmptyString(sline->passwd))
      MyFree(sline->passwd);
    if (!EmptyString(sline->realhost))
      MyFree(sline->realhost);
    if (!EmptyString(sline->username))
      MyFree(sline->username);
    MyFree(sline);
  }
  GlobalSList = 0;
}

/*
 * conf_check_slines()
 *
 * Check S lines for the specified client, passed in cptr struct.
 * If the client's IP is S-lined, process the substitution here.
 *
 * Precondition
 *  cptr != NULL
 *
 * Returns
 *  0 = No S-line found
 *  1 = S-line found and substitution done.
 *
 * -mbuna 9/2001
 * -froo 1/2003
 *
 */

int
conf_check_slines(struct Client *cptr)
{
  struct sline *sconf;
  char *hostonly;

  for (sconf = GlobalSList; sconf; sconf = sconf->next) {
    if (sconf->flags == SLINE_FLAGS_IP) {
      if (((cli_ip(cptr)).s_addr & NETMASK(sconf->bits)) != sconf->address.s_addr)
        continue;
    } else if (sconf->flags == SLINE_FLAGS_HOSTNAME) {
        if ((match(sconf->realhost, cli_sockhost(cptr)) != 0) &&
           (match(sconf->realhost, cli_sock_ip(cptr)) != 0))	/* wildcarded IP address */
          continue;
    } else {
        continue;
    }

    if (match(sconf->username, cli_user(cptr)->username) == 0) {
     /* Ignore user part if u@h. */
     if ((hostonly = strchr(sconf->spoofhost, '@')))
        hostonly++;
      else
        hostonly = sconf->spoofhost;

      if(!*hostonly)
        continue;

      ircd_strncpy(cli_user(cptr)->host, hostonly, HOSTLEN);
      log_write(LS_USER, L_INFO, LOG_NOSNOTICE, "S-Line (%s@%s) by (%#R)",
          cli_user(cptr)->username, hostonly, cptr);
      return 1;
    }
  }
  return 0;
}

/*
 * str2prefix() - converts a string to in_addr and bits.
 * based on str2prefix_ipv4() from Kunihiro Ishiguro's Zebra
 *
 * -froo 1/2003
 */
int str2prefix(char *str, struct prefix *p)
{
  int ret;
  char *ptr, *cp;

  /* Find slash inside string. */
  if ((ptr = (char *)strchr(str, '/')) == NULL) { /* String doesn't contail slash. */
    /* Convert string to prefix. */
    if ((ret = inet_aton(str, &p->address)) == 0)
        return 0;

    /* If address doesn't contain slash we assume it host address. */
    p->bits = IPV4_MAX_BITLEN;

    return ret;
  } else {
    cp = (char *)MyMalloc((ptr - str) + 1);
    ircd_strncpy(cp, str, ptr - str);
    *(cp + (ptr - str)) = '\0';
    ret = inet_aton(cp, &p->address);
    MyFree(cp);

    /* Get prefix length. */
    ret = (unsigned char) atoi(++ptr);
    if (ret > 32)
        return 0;

    p->bits = ret;
  }

  return ret;
}

int verify_sslclifp(struct Client* cptr, struct ConfItem* aconf)
{
  if (!(aconf->sslfp))
    return 1;

  if (!cli_sslclifp(cptr))
    return 0;

  if (ircd_strcmp(aconf->sslfp, cli_sslclifp(cptr)) != 0)
    return 0;

  return 1;
}

