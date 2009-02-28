/*
 * ircd_parser.y: A yacc/bison parser for ircd config files.
 * This is part of ircu, an Internet Relay Chat server.
 * The contents of this file are Copyright 2001 Diane Bruce,
 * Andrew Miller, the ircd-hybrid team and the ircu team.
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307,
 *  USA.
 * $Id$
 */
%{

#include "config.h"
#include "s_conf.h"
#include "channel.h"
#include "class.h"
#include "client.h"
#include "crule.h"
#include "ircd_features.h"
#include "fileio.h"
#include "gline.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_chattr.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "ircd_struct.h"
#include "list.h"
#include "listener.h"
#include "match.h"
#include "motd.h"
#include "numeric.h"
#include "numnicks.h"
#include "opercmds.h"
#include "parse.h"
#include "res.h"
#include "s_auth.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "send.h"
#include "support.h"

#ifdef PCRE_SYSTEM
#include <pcre.h>
#include <pcreposix.h>
#else
#include "pcre.h"
#include "pcreposix.h"
#endif

/* #include <assert.h> */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#define MAX_STRINGS 80 /* Maximum number of feature params. */

  int yylex(void);

  /* Now all the globals we need :/... */
  char* GlobalForwards[256];
  static int tping, tconn, maxlinks, sendq, port, stringno, flags;
  static int is_ssl, is_server, is_hidden, is_exempt, i_class;
  static int is_leaf, is_hub, invert, length;
  static char *name, *pass, *host, *vhost, *username, *hub_limit;
  static char *server, *reply, *replies, *rank, *dflags, *mask, *ident, *desc;
  static char *rtype, *action, *reason, *sport, *oflags, *ip;
  static char *prefix, *command, *service, *regex, *channel;

  struct SLink *hosts;
  static char *stringlist[MAX_STRINGS];
  struct fline*    GlobalFList = 0;
  struct blline*   GlobalBLList = 0;
  struct wline*    GlobalWList = 0;
  struct csline*   GlobalConnStopList = 0;
  struct sline*    GlobalSList = 0;
  struct svcline*  GlobalServicesList = 0;
  struct eline*    GlobalEList = 0;
  struct ConfItem* GlobalConfList;
  unsigned int     GlobalBLCount = 0;

  static struct DenyConf *dconf;
  static struct ConnectionClass *c_class;

  extern struct DenyConf*   denyConfList;
  extern struct CRuleConf*  cruleConfList;
  extern struct LocalConf   localConf;

  struct sline *spoof;
  struct Privs privs;
  struct Privs privs_dirty;

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

static void parse_error(char *pattern,...) {
  static char error_buffer[1024];
  va_list vl;
  va_start(vl,pattern);
  ircd_vsnprintf(NULL, error_buffer, sizeof(error_buffer), pattern, vl);
  va_end(vl);
  yyerror(error_buffer);
}

static void free_slist(struct SLink **link) {
  struct SLink *next;
  while (*link != NULL) {
    next = (*link)->next;
    MyFree((*link)->value.cp);
    free_link(*link);
    *link = next;
  }
}

%}

%token <text> QSTRING
%token <num> NUMBER

%token ACTION
%token ADMIN
%token ALL
%token AUTOCONNECT
%token BYTES
%token CHANNEL
%token CHNAME
%token CLASS
%token CLIENT
%token CMD
%token COMMAND
%token CONNECT
%token CONNECTFREQ
%token CONTACT
%token CRULE
%token CRYPT
%token DAYS
%token DECADES
%token DESC
%token DESCRIPTION
%token DNS
%token DNSBL
%token EXCEPT
%token EXEMPT
%token FAST
%token FEATURES
%token FLAGS
%token FORWARD
%token GBYTES
%token GENERAL
%token HIDDEN
%token HOST
%token HOSTMASK
%token HOURS
%token HUB
%token IDENT
%token IP
%token JUPE
%token KBYTES
%token KILL
%token KLINEPROMPT
%token LEAF
%token LENGTH
%token LOCAL
%token LOCATION
%token MASK
%token MAXHOPS
%token MAXLINKS
%token MBYTES
%token MINUTES
%token MONTHS
%token MOTD
%token NAME
%token NICK
%token NICKJUPE
%token NO
%token NUMERIC
%token OPER
%token PASS
%token PINGFREQ
%token PORT
%token PREFIX
%token PREPEND
%token PROGRAM
%token PSEUDO
%token QUARANTINE
%token RANK
%token REAL
%token REASON
%token REDIRECT
%token REGEX
%token REPLIES
%token REPLY
%token RTYPE
%token RULE
%token SECONDS
%token SENDQ
%token SERVER
%token SERVICE
%token SFILTER
%token SPOOF
%token SPOOFHOST
%token TBYTES
%token TFILE
%token USERMODE
%token USERNAME
%token UWORLD
%token VERSION
%token VHOST
%token WEBIRC
%token WEEKS
%token YEARS
%token YES
/* and now a lot of priviledges... */
%token TPRIV_FREEFORM
%token TPRIV_CHAN_LIMIT
%token TPRIV_MODE_LCHAN
%token TPRIV_WALK_LCHAN
%token TPRIV_DEOP_LCHAN
%token TPRIV_SHOW_INVIS
%token TPRIV_SHOW_ALL_INVIS
%token TPRIV_UNLIMIT_QUERY
%token TPRIV_KILL
%token TPRIV_LOCAL_KILL
%token TPRIV_REHASH
%token TPRIV_RESTART
%token TPRIV_DIE
%token TPRIV_GLINE
%token TPRIV_LOCAL_GLINE
%token TPRIV_JUPE
%token TPRIV_LOCAL_JUPE
%token TPRIV_OPMODE
%token TPRIV_LOCAL_OPMODE
%token TPRIV_SET
%token TPRIV_WHOX
%token TPRIV_BADCHAN
%token TPRIV_LOCAL_BADCHAN
%token TPRIV_SEE_CHAN
%token TPRIV_PROPAGATE
%token TPRIV_DISPLAY
%token TPRIV_SEE_OPERS
%token TPRIV_WIDE_GLINE
%token TPRIV_FORCE_OPMODE
%token TPRIV_FORCE_LOCAL_OPMODE
%token TPRIV_REMOTEREHASH
%token TPRIV_CHECK
%token TPRIV_SEE_SECRET_CHAN
%token TPRIV_SHUN
%token TPRIV_LOCAL_SHUN
%token TPRIV_WIDE_SHUN
%token TPRIV_ZLINE
%token TPRIV_LOCAL_ZLINE
%token TPRIV_WIDE_ZLINE
%token TPRIV_LIST_CHAN
%token TPRIV_WHOIS_NOTICE
%token TPRIV_HIDE_IDLE
%token TPRIV_XTRAOP
%token TPRIV_HIDE_CHANNELS
%token TPRIV_DISPLAY_MODE
/* and some types... */
%type <num> sizespec
%type <num> timespec timefactor factoredtimes factoredtime
%type <num> expr yesorno privtype
%left LOGICAL_OR
%left LOGICAL_AND
%left '+' '-'
%left '*' '/'
%nonassoc '!'
%nonassoc '(' ')'

%union{
 char *text;
 int num;
}

%%
/* Blocks in the config file... */
blocks: blocks block | block;
block: adminblock   | commandblock | classblock      | clientblock   | cruleblock   |
       connectblock | dnsblblock   | exceptblock     | featuresblock | sfilterblock |
       generalblock | forwardblock | killblock       | jupeblock    |
       motdblock    | operblock    | quarantineblock | redirectblock | spoofhostblock |
       uworldblock  | webircblock  | portblock       | error ';';

/* The timespec, sizespec and expr was ripped straight from
 * ircd-hybrid-7. */
timespec: expr | factoredtimes;

factoredtimes: factoredtimes factoredtime
{
  $$ = $1 + $2;
} | factoredtime;

factoredtime: expr timefactor
{
  $$ = $1 * $2;
};

timefactor: SECONDS { $$ = 1; }
| MINUTES { $$ = 60; }
| HOURS { $$ = 60 * 60; }
| DAYS { $$ = 60 * 60 * 24; }
| WEEKS { $$ = 60 * 60 * 24 * 7; }
| MONTHS { $$ = 60 * 60 * 24 * 7 * 4; }
| YEARS { $$ = 60 * 60 * 24 * 365; }
| DECADES { $$ = 60 * 60 * 24 * 365 * 10; };


sizespec:	expr	{
			$$ = $1;
		}
		| expr BYTES  { 
			$$ = $1;
		}
		| expr KBYTES {
			$$ = $1 * 1024;
		}
		| expr MBYTES {
			$$ = $1 * 1024 * 1024;
		}
		| expr GBYTES {
			$$ = $1 * 1024 * 1024 * 1024;
		}
		| expr TBYTES {
			$$ = $1 * 1024 * 1024 * 1024;
		}
		;

/* this is an arithmetic expression */
expr: NUMBER
		{ 
			$$ = $1;
		}
		| expr '+' expr { 
			$$ = $1 + $3;
		}
		| expr '-' expr { 
			$$ = $1 - $3;
		}
		| expr '*' expr { 
			$$ = $1 * $3;
		}
		| expr '/' expr { 
			$$ = $1 / $3;
		}
/* leave this out until we find why it makes BSD yacc dump core -larne
		| '-' expr  %prec NEG {
			$$ = -$2;
		} */
		| '(' expr ')' {
			$$ = $2;
		}
		;

stringlist: stringlist extrastring | extrastring;
extrastring: QSTRING
{
  if (stringno < MAX_STRINGS)
    stringlist[stringno++] = $1;
  else
    MyFree($1);
};

connectblock: CONNECT
{
 maxlinks = 65535;
 flags = CONF_AUTOCONNECT;
} '{' connectitems '}' ';'
{
 struct ConfItem *aconf = NULL;

 if (name == NULL)
  parse_error("Missing name in connect block");
 else if (pass == NULL)
  parse_error("Missing password in connect block");
 else if (strlen(pass) > PASSWDLEN)
  parse_error("Password too long in connect block");
 else if (host == NULL)
  parse_error("Missing host in connect block");
 else if (strchr(host, '*') || strchr(host, '?'))
  parse_error("Invalid host '%s' in connect block", host);
 else if (!c_class)
  parse_error("Missing or non-existent class in connect block");
 else {
   aconf = make_conf();
   aconf->status = CONF_SERVER;	

   aconf->name = name;
   aconf->passwd = pass;

   aconf->conn_class = c_class;
   aconf->port = port;
   aconf->host = host;
   aconf->flags = flags;

   aconf->maximum = maxlinks;
   aconf->hub_limit = hub_limit;

   lookup_confhost(aconf);
 }
 if (!aconf) {
   MyFree(name);
   MyFree(pass);
   MyFree(host);
   MyFree(hub_limit);
 } else {
   aconf->next = GlobalConfList;
   GlobalConfList = aconf;
   aconf = NULL;
 }
 name = pass = host = hub_limit = NULL;
 is_hub = is_leaf = port = flags = 0;
}
connectitems: connectitem connectitems | connectitem;
connectitem: connectname | connectpass | connectclass | connecthost
              | connectport | connectleaf | connecthub
              | connecthublimit | connectmaxhops | connectauto;
connectname: NAME '=' QSTRING ';'
{
 MyFree(name);
 name = $3;
};
connectpass: PASS '=' QSTRING ';'
{
 MyFree(pass);
 pass = $3;
};
connectclass: CLASS '=' QSTRING ';'
{
 c_class = find_class($3);
 if (!c_class)
  parse_error("No such connection class '%s' for Connect block", $3);
};
connecthost: HOST '=' QSTRING ';'
{
 MyFree(host);
 host = $3;
};
connectport: PORT '=' NUMBER ';'
{
 port = $3;
};
connectleaf: LEAF ';'
{
 is_leaf = 1;
 maxlinks = 0;
};
connecthub: HUB ';'
{
 is_hub = 1;
 MyFree(hub_limit);
 DupString(hub_limit, "*");
};
connecthublimit: HUB '=' QSTRING ';'
{
 is_hub = 1;
 MyFree(hub_limit);
 hub_limit = $3;
};
connectmaxhops: MAXHOPS '=' expr ';'
{
  maxlinks = $3;
};
connectauto: AUTOCONNECT '=' YES ';' { flags |= CONF_AUTOCONNECT; }
 | AUTOCONNECT '=' NO ';' { flags &= ~CONF_AUTOCONNECT; };


uworldblock: UWORLD '{' uworlditems '}' ';';
uworlditems: uworlditem uworlditems | uworlditem;
uworlditem: uworldname;
uworldname: NAME '=' QSTRING ';'
{
  conf_make_uworld($3);
};

uworldblock: UWORLD QSTRING ';'
{
  conf_make_uworld($2);
}


jupeblock: NICKJUPE '{' jupeitems '}' ';';
jupeitems: jupeitem jupeitems | jupeitem;
jupeitem: jupenick;
jupenick: NICK '=' QSTRING ';'
{
  addNickJupes($3);
  MyFree($3);
};


clientblock: CLIENT
{
  maxlinks = 65535;
  port = 0;
}
'{' clientitems '}' ';'
{
  struct ConfItem *aconf = 0;
  int bits = 0;
  int g = 0;

  if (ip) {
    if (!strcmp(ip, "*"))
      g = 1;
  }

  if (!c_class)
    parse_error("Invalid or missing class in Client block");
  else if (pass && strlen(pass) > PASSWDLEN)
    parse_error("Password too long in connect block");
  else if (!g && ip && !check_if_ipmask(ip))
    parse_error("Invalid IP address %s in Client block", ip);
  else {
    aconf = make_conf();
    aconf->status = CONF_CLIENT;

    if (ip) {
      int  c_class;
      char ipname[16];
      int  ad[4] = { 0 };
      int  bits2 = 0;

      c_class = sscanf(ip, "%d.%d.%d.%d/%d", &ad[0], &ad[1], &ad[2], &ad[3], &bits2);
      if (c_class != 5) {
        bits = c_class * 8;
      }
      else {
        bits = bits2;
      }
      ircd_snprintf(0, ipname, sizeof(ipname), "%d.%d.%d.%d", ad[0], ad[1],
                    ad[2], ad[3]);

      aconf->bits = bits;
      aconf->ipnum.s_addr = inet_addr(ipname);
    }


    aconf->conn_class = c_class;
    aconf->username = username;
    aconf->host = host;
    aconf->port = port;
    aconf->name = ip;
    aconf->maximum = maxlinks;
    aconf->passwd = pass;
    Debug((DEBUG_DEBUG, "CLIENT: %s %s %d", host, ip ? ip : "", bits));
  }
  if (!aconf) {
    MyFree(username);
    MyFree(host);
    MyFree(ip);
    MyFree(pass);
  } else {
    aconf->next = GlobalConfList;
    GlobalConfList = aconf;
    aconf = NULL;
  }

  host = NULL;
  username = NULL;
  c_class = NULL;
  ip = NULL;
  pass = NULL;
  port = 0;
};
clientitems: clientitem clientitems | clientitem;
clientitem: clienthost | clientip | clientusername | clientclass | clientpass | clientmaxlinks | clientport;
clienthost: HOST '=' QSTRING ';'
{
  char *sep = strchr($3, '@');
  MyFree(host);
  if (sep) {
    *sep++ = '\0';
    MyFree(username);
    DupString(host, sep);
    username = $3;
  } else {
    host = $3;
  }
};
clientip: IP '=' QSTRING ';'
{
  char *sep;
  sep = strchr($3, '@');
  MyFree(ip);
  if (sep) {
    *sep++ = '\0';
    MyFree(username);
    DupString(ip, sep);
    username = $3;
  } else {
    ip = $3;
  }
};
clientusername: USERNAME '=' QSTRING ';'
{
  MyFree(username);
  username = $3;
};
clientclass: CLASS '=' QSTRING ';'
{
  c_class = find_class($3);
  if (!c_class)
    parse_error("No such connection class '%s' for Client block", $3);
};
clientpass: PASS '=' QSTRING ';'
{
  MyFree(pass);
  pass = $3;
};
clientmaxlinks: MAXLINKS '=' expr ';'
{
  maxlinks = $3;
};
clientport: PORT '=' expr ';'
{
  port = $3;
};


classblock: CLASS {
  tping = 90;
} '{' classitems '}' ';'
{
  if (name != NULL)
  {
    struct ConnectionClass *c_class;
    add_class(name, tping, tconn, maxlinks, sendq);
    c_class = find_class(name);
    c_class->default_umode = pass;
    memcpy(&c_class->privs, &privs, sizeof(c_class->privs));
    memcpy(&c_class->privs_dirty, &privs_dirty, sizeof(c_class->privs_dirty));
  }
  else {
   parse_error("Missing class number in class block");
  }
  name = NULL;
  pass = NULL;
  tconn = 0;
  maxlinks = 0;
  sendq = 0;
  i_class = 0;
  memset(&privs, 0, sizeof(privs));
  memset(&privs_dirty, 0, sizeof(privs_dirty));
};
classitems: classitem classitems | classitem;
classitem: classname | classpingfreq | classconnfreq | classmaxlinks | priv |
           classsendq | classusermode;
classname: NAME '=' QSTRING ';'
{
  MyFree(name);
  name = $3;
};
classpingfreq: PINGFREQ '=' timespec ';'
{
  tping = $3;
};
classconnfreq: CONNECTFREQ '=' timespec ';'
{
  tconn = $3;
};
classmaxlinks: MAXLINKS '=' expr ';'
{
  maxlinks = $3;
};
classsendq: SENDQ '=' sizespec ';'
{
  sendq = $3;
};
classusermode: USERMODE '=' QSTRING ';'
{
  pass = $3;
};


operblock: OPER '{' operitems '}' ';'
{
  struct SLink *link;
  int* i;
  int iflag;
  char *m;
  struct ConfItem *aconf = NULL;

  if (name == NULL)
    parse_error("Missing name in operator block");
  else if (pass == NULL)
    parse_error("Missing password in operator block");
  else if (hosts == NULL)
    parse_error("Missing host(s) in operator block");
  else if (c_class == NULL)
    parse_error("Invalid or missing class in operator block");
  else if (!FlagHas(&privs_dirty, PRIV_PROPAGATE)
           && !FlagHas(&c_class->privs_dirty, PRIV_PROPAGATE))
    parse_error("Operator block for %s and class %s have no LOCAL setting", name, c_class->cc_name);
  else for (link = hosts; link != NULL; link = link->next) {
    aconf = make_conf();

    if (FlagHas(&privs, PRIV_PROPAGATE)) {
      m = "O";
      aconf->status = CONF_OPERATOR;
    } else {
      m = "o";
      aconf->status = CONF_LOCOP;
    }
    DupString(aconf->name, name);
    DupString(aconf->passwd, pass);
    DupString(aconf->host, link->value.cp);

    if (!strchr(aconf->host, '@')) {
      char* newhost;
      int len = 3;                /* *@\0 = 3 */

      len += strlen(aconf->host);
      newhost = (char*) MyMalloc(len);
      assert(0 != newhost);
      ircd_snprintf(0, newhost, len, "*@%s", aconf->host);
      MyFree(aconf->host);
      aconf->host = newhost;
    }

    aconf->conn_class = c_class;

    if (!oflags)
      DupString(oflags, "O");

    if (*oflags)
      DupString(m, oflags);
    for (; *m; m++) {
      for (i = oper_access; (iflag = *i); i += 2) {
        if (*m == (char)(*(i + 1))) {
          aconf->port |= iflag;
          break;
        }
      }
    }
    memcpy(&aconf->privs, &privs, sizeof(aconf->privs));
    memcpy(&aconf->privs_dirty, &privs_dirty, sizeof(aconf->privs_dirty));

    aconf->next = GlobalConfList;
    GlobalConfList = aconf;
    aconf = NULL;
 }
  MyFree(oflags);
  MyFree(name);
  MyFree(pass);
  free_slist(&hosts);
  name = pass = NULL;
  c_class = NULL;
  memset(&privs, 0, sizeof(privs));
  memset(&privs_dirty, 0, sizeof(privs_dirty));
};
operitems: operitem | operitems operitem;
operitem: opername | operpass | operhost | operflags | operclass | priv;
opername: NAME '=' QSTRING ';'
{
  MyFree(name);
  name = $3;
};
operpass: PASS '=' QSTRING ';'
{
  MyFree(pass);
  pass = $3;
};
operhost: HOST '=' QSTRING ';'
{
 struct SLink *link;
 link = make_link();
 if (!strchr($3, '@'))
 {
   int uh_len;
   link->value.cp = (char*) MyMalloc((uh_len = strlen($3)+3));
   ircd_snprintf(0, link->value.cp, uh_len, "*@%s", $3);
 }
 else
   DupString(link->value.cp, $3);
 MyFree($3);
 link->next = hosts;
 hosts = link;
};
operflags: FLAGS '=' QSTRING ';'
{
  MyFree(oflags);
  oflags = $3;
};
operclass: CLASS '=' QSTRING ';'
{
 c_class = find_class($3);
 if (!c_class)
  parse_error("No such connection class '%s' for Operator block", $3);
};

priv: privtype '=' yesorno ';'
{
  FlagSet(&privs_dirty, $1);
  if (($3 == 1) ^ invert)
    FlagSet(&privs, $1);
  else
    FlagClr(&privs, $1);
  invert = 0;
};

privtype:  TPRIV_DISPLAY_MODE { $$ = PRIV_DISPLAY_MODE; } |
           TPRIV_CHAN_LIMIT { $$ = PRIV_CHAN_LIMIT; } |
           TPRIV_MODE_LCHAN { $$ = PRIV_MODE_LCHAN; } |
           TPRIV_WALK_LCHAN { $$ = PRIV_WALK_LCHAN; } |
           TPRIV_DEOP_LCHAN { $$ = PRIV_DEOP_LCHAN; } |
           TPRIV_SHOW_INVIS { $$ = PRIV_SHOW_INVIS; } |
           TPRIV_SHOW_ALL_INVIS { $$ = PRIV_SHOW_ALL_INVIS; } |
           TPRIV_UNLIMIT_QUERY { $$ = PRIV_UNLIMIT_QUERY; } |
           KILL { $$ = PRIV_KILL; } |
           TPRIV_LOCAL_KILL { $$ = PRIV_LOCAL_KILL; } |
           TPRIV_REHASH { $$ = PRIV_REHASH; } |
           TPRIV_RESTART { $$ = PRIV_RESTART; } |
           TPRIV_DIE { $$ = PRIV_DIE; } |
           TPRIV_GLINE { $$ = PRIV_GLINE; } |
           TPRIV_LOCAL_GLINE { $$ = PRIV_LOCAL_GLINE; } |
           JUPE { $$ = PRIV_JUPE; } |
           TPRIV_LOCAL_JUPE { $$ = PRIV_LOCAL_JUPE; } |
           TPRIV_OPMODE { $$ = PRIV_OPMODE; } |
           TPRIV_LOCAL_OPMODE { $$ = PRIV_LOCAL_OPMODE; } |
           TPRIV_SET { $$ = PRIV_SET; } |
           TPRIV_WHOX { $$ = PRIV_WHOX; } |
           TPRIV_BADCHAN { $$ = PRIV_BADCHAN; } |
           TPRIV_LOCAL_BADCHAN { $$ = PRIV_LOCAL_BADCHAN; } |
           TPRIV_SEE_CHAN { $$ = PRIV_SEE_CHAN; } |
           TPRIV_PROPAGATE { $$ = PRIV_PROPAGATE; } |
           TPRIV_DISPLAY { $$ = PRIV_DISPLAY; } |
           TPRIV_SEE_OPERS { $$ = PRIV_SEE_OPERS; } |
           TPRIV_WIDE_GLINE { $$ = PRIV_WIDE_GLINE; } |
           TPRIV_FORCE_OPMODE { $$ = PRIV_FORCE_OPMODE; } |
           TPRIV_FORCE_LOCAL_OPMODE { $$ = PRIV_FORCE_LOCAL_OPMODE; } |
           TPRIV_REMOTEREHASH { $$ = PRIV_REMOTEREHASH; } |
           TPRIV_CHECK { $$ = PRIV_CHECK; } |
           TPRIV_SEE_SECRET_CHAN { $$ = PRIV_SEE_SECRET_CHAN; } |
           TPRIV_SHUN { $$ = PRIV_SHUN; } |
           TPRIV_LOCAL_SHUN { $$ = PRIV_LOCAL_SHUN; } |
           TPRIV_WIDE_SHUN { $$ = PRIV_WIDE_GLINE; } |
           TPRIV_ZLINE { $$ = PRIV_ZLINE; } |
           TPRIV_LOCAL_ZLINE { $$ = PRIV_LOCAL_ZLINE; } |
           TPRIV_WIDE_ZLINE { $$ = PRIV_WIDE_ZLINE; } |
           TPRIV_LIST_CHAN { $$ = PRIV_LIST_CHAN; } |
           TPRIV_WHOIS_NOTICE { $$ = PRIV_WHOIS_NOTICE; } |
           TPRIV_HIDE_IDLE { $$ = PRIV_HIDE_IDLE; } |
           TPRIV_XTRAOP { $$ = PRIV_XTRAOP; } |
           TPRIV_HIDE_CHANNELS { $$ = PRIV_HIDE_CHANNELS; } |
           TPRIV_FREEFORM { $$ = PRIV_FREEFORM; } |
           LOCAL { $$ = PRIV_PROPAGATE; invert = 1; } ;

yesorno: YES { $$ = 1; } | NO { $$ = 0; };

motdblock: MOTD '{' motditems '}' ';'
{
  struct SLink *link;
  if (pass != NULL) {
    for (link = hosts; link != NULL; link = link->next)
      motd_add(link->value.cp, pass);
  }
  free_slist(&hosts);
  MyFree(pass);
  pass = NULL;
};

motditems: motditem motditems | motditem;
motditem: motdhost | motdfile;
motdhost: HOST '=' QSTRING ';'
{
  struct SLink *link;
  link = make_link();
  link->value.cp = $3;
  link->next = hosts;
  hosts = link;
};

motdfile: TFILE '=' QSTRING ';'
{
  MyFree(pass);
  pass = $3;
};


killblock: KILL
{
  dconf = (struct DenyConf*) MyMalloc(sizeof(struct DenyConf));
  memset(dconf, 0, sizeof(struct DenyConf));
} '{' killitems '}' ';'
{
  if (dconf->usermask || dconf->hostmask || (dconf->flags & DENY_FLAGS_REALNAME) ||
          (dconf->flags & DENY_FLAGS_VERSION) || (dconf->flags & DENY_FLAGS_PROMPT))
  {
    if ((dconf->flags & DENY_FLAGS_REALNAME) || (dconf->flags & DENY_FLAGS_VERSION))
      DupString(dconf->usermask, "*");

    dconf->next = denyConfList;
    denyConfList = dconf;
  }
  else
  {
    MyFree(dconf->usermask);
    MyFree(dconf->hostmask);
    MyFree(dconf->message);
    MyFree(dconf);
    parse_error("Kill block must match on at least one of username, host or realname");
  }
  dconf = NULL;
};
killitems: killitem killitems | killitem;
killitem: killuhost | killversion | killreal | killusername | killreasonfile | killreason | killname | killprompt;
killuhost: HOST '=' QSTRING ';'
{
  char *h;
  char *bhost;

  MyFree(dconf->hostmask);
  MyFree(dconf->usermask);

  bhost = strdup($3);

  if ((h = strchr($3, '@')) == NULL)
  {
    DupString(dconf->usermask, "*");
    dconf->hostmask = bhost;
  }
  else
  {
    *h++ = '\0';
    DupString(dconf->hostmask, h);
    dconf->usermask = $3;
  }

  if (check_if_ipmask(dconf->hostmask)) {
    int  c_class;
    char ipname[16];
    int  ad[4] = { 0 };
    int  bits2 = 0;

    if (!IsDigit(dconf->hostmask[0]))
    {
     sendto_opmask_butone(0, SNO_OLDSNO, 
        "Mangled IP in IP Kill block: k:%s:%s", dconf->hostmask, dconf->usermask);
    } else {
      c_class = sscanf(dconf->hostmask, "%d.%d.%d.%d/%d",
                       &ad[0], &ad[1], &ad[2], &ad[3], &bits2);
      if (c_class != 5) {
        dconf->bits = c_class * 8;
      }
      else {
        dconf->bits = bits2;
      }
      ircd_snprintf(0, ipname, sizeof(ipname), "%d.%d.%d.%d", ad[0], ad[1],
  		  ad[2], ad[3]);
    
      dconf->address = inet_addr(ipname);
      dconf->flags |= DENY_FLAGS_IP;
    }
  }
};

killusername: USERNAME '=' QSTRING ';'
{
  MyFree(dconf->usermask);
  dconf->usermask = $3;
};
killversion: VERSION '=' QSTRING ';'
{
  MyFree(dconf->hostmask);
  dconf->hostmask = $3;
  dconf->flags |= DENY_FLAGS_VERSION;
};
killreal: REAL '=' QSTRING ';'
{
  MyFree(dconf->hostmask);
  dconf->hostmask = $3;
  dconf->flags |= DENY_FLAGS_REALNAME;
};
killreason: REASON '=' QSTRING ';'
{
 dconf->flags &= ~DENY_FLAGS_FILE;
 MyFree(dconf->message);
 dconf->message = $3;
};
killreasonfile: TFILE '=' QSTRING ';'
{
 dconf->flags |= DENY_FLAGS_FILE;
 MyFree(dconf->message);
 dconf->message = $3;
};
killname: NAME '=' QSTRING ';'
{
 MyFree(dconf->mark);
 dconf->mark= $3;
};
killprompt: KLINEPROMPT ';'
{
  dconf->flags |= DENY_FLAGS_PROMPT;
};


cruleblock: CRULE
{
  tconn = CRULE_AUTO;
} '{' cruleitems '}' ';'
{
  struct CRuleNode *node = NULL;
  struct SLink *link;

  if (hosts == NULL)
    parse_error("Missing server(s) in crule block");
  else if (pass == NULL)
    parse_error("Missing rule in crule block");
  else if ((node = crule_parse(pass)) == NULL)
    parse_error("Invalid rule '%s' in crule block", pass);
  else for (link = hosts; link != NULL; link = link->next)
  {
    struct CRuleConf *p = (struct CRuleConf*) MyMalloc(sizeof(*p));
    if (node == NULL)
      node = crule_parse(pass);
    DupString(p->hostmask, link->value.cp);
    DupString(p->rule, pass);
    p->type = tconn;
    p->node = node;
    node = NULL;
    p->next = cruleConfList;
    cruleConfList = p;
  }
  free_slist(&hosts);
  MyFree(pass);
  pass = NULL;
  tconn = 0;
};

cruleitems: cruleitem cruleitems | cruleitem;
cruleitem: cruleserver | crulerule | cruleall;

cruleserver: SERVER '=' QSTRING ';'
{
  struct SLink *link;
  link = make_link();
  link->value.cp = $3;
  link->next = hosts;
  hosts = link;
};

crulerule: RULE '=' QSTRING ';'
{
 MyFree(pass);
 pass = $3;
};

cruleall: ALL '=' YES ';'
{
 tconn = CRULE_ALL;
} | ALL '=' NO ';'
{
 tconn = CRULE_AUTO;
};

featuresblock: FEATURES '{' featureitems '}' ';';
featureitems: featureitems featureitem | featureitem;

featureitem: QSTRING
{
  stringlist[0] = $1;
  stringno = 1;
} '=' stringlist ';' {
  int ii;
  feature_set(NULL, (const char * const *)stringlist, stringno);
  for (ii = 0; ii < stringno; ++ii)
    MyFree(stringlist[ii]);
};

/* The port block... */
portblock: PORT {
  is_server = 0;
  is_ssl = 0;
  is_hidden = 0;
  is_exempt = 0;
} '{' portitems '}' ';'
{
#ifdef USE_SSL
  add_listener(port, vhost, pass, is_server, is_hidden, is_ssl, is_exempt);
#else
  add_listener(port, vhost, pass, is_server, is_hidden, is_exempt);
#endif
  MyFree(pass);
  pass = NULL;
  port = 0;
};
portitems: portitem portitems | portitem;
portitem: portnumber | portvhost | portmask | portserver | porthidden | portexempt | portssl;
portnumber: PORT '=' NUMBER ';'
{
  if ($3 < 1 || $3 > 65535) {
    parse_error("Port %d is out of range", port);
  } else {
    port = $3;
  }
};

portvhost: VHOST '=' QSTRING ';'
{
  MyFree(vhost);
  vhost = $3;
};

portmask: MASK '=' QSTRING ';'
{
  MyFree(pass);
  pass = $3;
};

portserver: SERVER '=' YES ';'
{
  is_server = 1;
} | SERVER '=' NO ';'
{
  is_server = 0;
};

porthidden: HIDDEN '=' YES ';'
{
  is_hidden = 1;
} | HIDDEN '=' NO ';'
{
  is_hidden = 0;
};

portexempt: EXEMPT '=' YES ';'
{
  is_exempt = 1;
} | EXEMPT '=' NO ';'
{
  is_exempt = 0;
};

portssl: CRYPT '=' YES ';'
{
  is_ssl = 1;
} | CRYPT '=' NO ';'
{
  is_ssl = 0;
};

generalblock: GENERAL '{' generalitems '}' ';' {
  if (localConf.name == NULL)
    parse_error("Your General block must contain a name.");
  if (localConf.numeric == 0)
    parse_error("Your General block must contain a numeric (between 1 and 4095).");

  set_virtual_host(localConf.vhost_address);
};
generalitems: generalitem generalitems | generalitem;
generalitem: generalnumeric | generalname | generalvhost | generaldesc;

generalnumeric: NUMERIC '=' NUMBER ';'
{
  if (localConf.numeric == 0)
    localConf.numeric = $3;
  else if (localConf.numeric != (unsigned int)$3)
    parse_error("Redefinition of server numeric %i (%i)", $3,
    		localConf.numeric);
};

generalname: NAME '=' QSTRING ';'
{
  if (localConf.name == NULL)
    localConf.name = $3;
  else
  {
    if (strcmp(localConf.name, $3))
      parse_error("Redefinition of server name %s (%s)", $3,
                  localConf.name);
    MyFree($3);
  }
};

generaldesc: DESCRIPTION '=' QSTRING ';'
{
  MyFree(localConf.description);
  localConf.description = $3;
  ircd_strncpy(cli_info(&me), $3, REALLEN);
};

generalvhost: VHOST '=' QSTRING ';'
{
  char *vhost = $3;

  if (string_is_address(vhost)) {
    if (INADDR_NONE == (localConf.vhost_address.s_addr = inet_addr(vhost)))
      localConf.vhost_address.s_addr = INADDR_ANY;
  }

  MyFree(vhost);
};


adminblock: ADMIN
{
  MyFree(localConf.location1);
  MyFree(localConf.location2);
  MyFree(localConf.contact);
  localConf.location1 = localConf.location2 = localConf.contact = NULL;
}
'{' adminitems '}' ';'
{
  if (localConf.location1 == NULL)
    DupString(localConf.location1, "");
  if (localConf.location2 == NULL)
    DupString(localConf.location2, "");
  if (localConf.contact == NULL)
    DupString(localConf.contact, "");
};
adminitems: adminitems adminitem | adminitem;
adminitem: adminlocation | admincontact;
adminlocation: LOCATION '=' QSTRING ';'
{
  if (localConf.location1 == NULL)
    localConf.location1 = $3;
  else if (localConf.location2 == NULL)
    localConf.location2 = $3;
  else /* Otherwise just drop it. -A1kmm */
    MyFree($3);
};
admincontact: CONTACT '=' QSTRING ';'
{
  MyFree(localConf.contact);
  localConf.contact = $3;
};


dnsblblock: DNSBL '{' dnsblitems '}' ';'
{
  struct blline *blline;

  if (!server)
    parse_error("Your DNSBL block must contain a server.");
  else if (!name)
    parse_error("Your DNSBL block must contain a name.");
  else if (!dflags)
    parse_error("Your DNSBL block must contain flags.");
  else if (!replies)
    parse_error("Your DNSBL block must contain replies.");
  else if (!reply)
    parse_error("Your DNSBL block must contain a reply.");
  else if (!rank)
    parse_error("Your DNSBL block must contain a rank.");
  else {
    ++GlobalBLCount;

    blline = (struct blline *) MyMalloc(sizeof(struct blline));
    memset(blline, 0, sizeof(struct blline));
    DupString(blline->server, server);
    DupString(blline->name, name);
    DupString(blline->flags, dflags);
    DupString(blline->replies, replies);
    DupString(blline->reply, reply);
    DupString(blline->rank, rank);
    blline->next = GlobalBLList;
    GlobalBLList = blline;

    server = NULL;
    name = NULL;
    dflags = NULL;
    replies = NULL;
    reply = NULL;
    rank = NULL;
  }
};
dnsblitems: dnsblitem | dnsblitems dnsblitem;
dnsblitem: dnsblserver | dnsblname | dnsblflags | dnsblreplies | dnsblreply | dnsblrank;
dnsblserver: NAME '=' QSTRING ';'
{
  MyFree(name);
  name = $3;
};
dnsblname: SERVER '=' QSTRING ';'
{
  MyFree(server);
  server = $3;
};
dnsblflags: FLAGS '=' QSTRING ';'
{
  MyFree(dflags);
  dflags = $3;
};
dnsblreplies: REPLIES '=' QSTRING ';'
{
  MyFree(replies);
  replies = $3;
};
dnsblreply: REPLY '=' QSTRING ';'
{
  MyFree(reply);
  reply = $3;
};
dnsblrank: RANK '=' QSTRING ';'
{
  MyFree(rank);
  rank = $3;
};

commandblock: COMMAND '{' commanditems '}' ';'
{
  struct svcline *new_svc;

  if (!command)
    parse_error("Your Command block must contain a command.");
  else if (!service)
    parse_error("Your Command block must contain a service.");
  else {
    new_svc = (struct svcline *)MyMalloc(sizeof(struct svcline));

    DupString(new_svc->cmd, command);
    DupString(new_svc->target, service);
 
    if (prefix && (strlen(prefix) > 0)) {
        Debug((DEBUG_DEBUG, "Command Prefix: %s", prefix));
        DupString(new_svc->prepend, prefix);
    } else {
        DupString(new_svc->prepend, "*");
        MyFree(new_svc->prepend);
    }

    new_svc->next = GlobalServicesList;
    GlobalServicesList = new_svc;

    command = NULL;
    service = NULL;
    prefix = NULL;
  }
};
commanditems: commanditem | commanditems commanditem;
commanditem: commandcmd | commandservice | commandprefix;
commandcmd: CMD '=' QSTRING ';'
{
  MyFree(command);
  command = $3;
};
commandservice: SERVICE '=' QSTRING ';'
{
  MyFree(service);
  service = $3;
};
commandprefix: PREFIX '=' QSTRING ';'
{
  MyFree(prefix);
  prefix = $3;
};

forwardblock: FORWARD '{' forwarditems '}' ';';
forwarditems: forwarditems forwarditem | forwarditem;
forwarditem: QSTRING '=' QSTRING ';'
{
  char *fields;
  unsigned char ch = 0;

  DupString(fields, $1);
  ch = *fields;

  MyFree(GlobalForwards[ch]);
  DupString(GlobalForwards[ch], $3);
};

exceptblock: EXCEPT '{' exceptitems '}' ';'
{
  struct eline *eline;

  if (!mask)
    parse_error("Your Except block must contain a mask.");
  else if (!dflags)
    parse_error("Your Except block must contain flags.");
  else {
    eline = (struct eline *) MyMalloc(sizeof(struct eline));
    memset(eline, 0, sizeof(struct eline));
    DupString(eline->mask, mask);
    DupString(eline->flags, dflags);
    eline->next = GlobalEList;
    GlobalEList = eline;   
  }
};
exceptitems: exceptitem | exceptitems exceptitem;
exceptitem: exceptmask | exceptflags;
exceptmask: MASK '=' QSTRING ';'
{
  MyFree(mask);
  mask = $3;
};
exceptflags: FLAGS '=' QSTRING ';'
{
  MyFree(dflags);
  dflags = $3;
};

spoofhostblock: SPOOFHOST QSTRING '{'
{
  spoof = MyCalloc(1, sizeof(struct sline));
  spoof->spoofhost = $2;
  spoof->passwd = NULL;
  spoof->realhost = NULL;
  spoof->username = NULL;
}
spoofhostitems '}' ';'
{
  int valid = 0;
  struct prefix *p = NULL;

  if (spoof->username == NULL && spoof->realhost) {
    parse_error("Username missing in spoofhost.");
  } else if (spoof->realhost == NULL && spoof->username) {
    parse_error("Realhost missing in spoofhost.");
  } else 
    valid = 1;

  if (valid) {
    if (spoof->realhost) {
      if (check_if_ipmask(spoof->realhost)) {
        if (str2prefix(spoof->realhost, p) != 0) {
          spoof->address = p->address;
          spoof->bits = p->bits;
          spoof->flags = SLINE_FLAGS_IP;
        } else {
           spoof->flags = SLINE_FLAGS_HOSTNAME;
        }
      } else
        spoof->flags = SLINE_FLAGS_HOSTNAME;
    } else {
      spoof->realhost = NULL;
      spoof->flags = 0;
    }

    spoof->next = GlobalSList;
    GlobalSList = spoof;
  } else {
    MyFree(spoof->spoofhost);
    MyFree(spoof->passwd);
    MyFree(spoof->realhost);
    MyFree(spoof->username);
    MyFree(spoof);
  }
  spoof = NULL;
};

spoofhostitems: spoofhostitem spoofhostitems | spoofhostitem;
spoofhostitem: spoofhostpassword | spoofhostrealhost | spoofhostrealident;
spoofhostpassword: PASS '=' QSTRING ';'
{
  MyFree(spoof->passwd);
  spoof->passwd = $3;
};
spoofhostrealhost: HOST '=' QSTRING ';'
{
  MyFree(spoof->realhost);
  spoof->realhost = $3;
};
spoofhostrealident: USERNAME '=' QSTRING ';'
{
  MyFree(spoof->username);
  spoof->username = $3;
};


redirectblock: REDIRECT '{' redirectitems '}' ';'
{
  struct csline *csline;
  if (!mask)
    parse_error("Your Redirect block must contain a mask.");
  else if (!server)
    parse_error("Your Redirect block must contain a server.");
  else if (!sport)
    parse_error("Your Redirect block must contain a port.");
  else {
    csline = (struct csline *) MyMalloc(sizeof(struct csline));
    DupString(csline->mask, mask);
    DupString(csline->server, server);
    DupString(csline->port, sport);
    csline->next = GlobalConnStopList;
    GlobalConnStopList = csline;

    mask = NULL;
    server = NULL;
    sport = NULL;
  }
};
redirectitems: redirectitem | redirectitems redirectitem;
redirectitem: redirectmask | redirectserver | redirectport;
redirectmask: MASK '=' QSTRING ';'
{
  MyFree(mask);
  mask = $3;
};
redirectserver: SERVER '=' QSTRING ';'
{
  MyFree(server);
  server = $3;
};
redirectport: PORT '=' QSTRING ';'
{
  MyFree(sport);
  sport = $3;
};

quarantineblock: QUARANTINE '{' quarantineitems '}' ';';
quarantineitems: quarantineitems quarantineitem | quarantineitem;
quarantineitem: QSTRING '=' QSTRING ';'
{
  struct qline *qconf = MyCalloc(1, sizeof(*qconf));
  qconf->chname = $1;
  qconf->reason = $3;
  qconf->next = GlobalQuarantineList;
  GlobalQuarantineList = qconf;
};

webircblock: WEBIRC '{' webircitems '}' ';'
{
  struct wline *wline;

  if (!mask)
    parse_error("Your WebIRC block must contain a mask.");
  else if (!pass)
    parse_error("Your WebIRC block must contain a passwd.");
  else if (!dflags)
    parse_error("Your WebIRC block must contain flags.");
  else if (!ident)
     parse_error("Your WebIRC block must contain a ident.");
  else if (!desc)
    parse_error("Your WebIRC block must contain a description.");
  else {
    wline = (struct wline *) MyMalloc(sizeof(struct wline));
    memset(wline, 0, sizeof(struct wline));
    DupString(wline->mask, mask);
    DupString(wline->passwd, pass);
    DupString(wline->flags, dflags);
    DupString(wline->ident, ident);
    DupString(wline->desc, desc);
    wline->next = GlobalWList;
    GlobalWList = wline;

    mask = NULL;
    pass = NULL;
    dflags = NULL;
    ident = NULL;
    desc = NULL;
  }
};
webircitems: webircitem | webircitems webircitem;
webircitem: webircmask | webircpasswd | webircflags | webircident | webircdesc;
webircmask: MASK '=' QSTRING ';'
{
  MyFree(mask);
  mask = $3;
};
webircpasswd: PASS '=' QSTRING ';'
{
  MyFree(pass);
  pass = $3;
};
webircflags: FLAGS '=' QSTRING ';'
{
  MyFree(dflags);
  dflags = $3;
};
webircident: IDENT '=' QSTRING ';'
{
  MyFree(ident);
  ident = $3;
};
webircdesc: DESC '=' QSTRING ';'
{
  MyFree(desc);
  desc = $3;
};


sfilterblock: SFILTER {
  length = 0;
} '{' sfilteritems '}' ';'
{
  struct fline *fline;
  char *errbuf;
  const char *error;
  int erroffset;

  if (!regex)
    parse_error("Your Filter block must contain a filter.");
  else if (!rtype)
    parse_error("Your Filter block must contain a type");
  else if (!action)
    parse_error("Your Filter block must contain a action.");
  else if (!reason)
    parse_error("Your Filter block must contain a reason.");
  else {
    if ((errbuf = checkregex(regex,0))) {
      parse_error("SFilter block (%s) contains an invalid regex: %s", regex, errbuf);
    } else {
      fline = (struct fline *) MyMalloc(sizeof(struct fline));
      memset(fline, 0, sizeof(struct fline));

      if (length == 0)
        length = feature_int(FEAT_FILTER_DEFAULT_LENGTH);

      fline->filter = pcre_compile(regex, PCRE_CASELESS|PCRE_EXTENDED, &error, &erroffset, NULL);
      DupString(fline->rawfilter, regex);
      DupString(fline->wflags, rtype);
      DupString(fline->rflags, action);
      DupString(fline->reason, reason);

      if (channel && *channel) {
        if ((!IsChannelName(channel)) || (HasCntrl(channel)))
          parse_error("Your Filter block channel name is invalid");
        else
          DupString(fline->nchan, channel);
      } else {
        if ((!IsChannelName(feature_str(FEAT_FILTER_DEFAULT_CHANNAME))))
          parse_error("Your Filter default alert channel name is invalid");
        else
          DupString(fline->nchan, feature_str(FEAT_FILTER_DEFAULT_CHANNAME));
      }

      fline->length = length;
      fline->active = 1;

      fline->next = GlobalFList;
      GlobalFList = fline;

      regex = NULL;
      rtype = NULL;
      action = NULL;
      reason = NULL;
      channel = NULL;
      length = 0;
    }
  }
};
sfilteritems: sfilteritem | sfilteritems sfilteritem;
sfilteritem: sfilterregex | sfilterrtype | sfilteraction | sfilterreason | sfilterlength | 
             sfilterchannel;
sfilterregex: REGEX '=' QSTRING ';'
{
  MyFree(regex);
  regex = $3;
};
sfilterrtype: RTYPE '=' QSTRING ';'
{
  MyFree(rtype);
  rtype = $3;
};
sfilteraction: ACTION '=' QSTRING ';'
{
  MyFree(action);
  action = $3;
};
sfilterreason: REASON '=' QSTRING ';'
{
  MyFree(reason);
  reason = $3;
};
sfilterlength: LENGTH '=' NUMBER ';'
{
  length = $3;
};
sfilterchannel: CHANNEL '=' QSTRING ';'
{
  MyFree(channel);
  channel = $3;
};
