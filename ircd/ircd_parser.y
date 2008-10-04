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
 * $Id: ircd_parser.y,v 1.76 2008/03/16 01:52:59 klmitch Exp $
 */
%{

#include "config.h"
#include "s_conf.h"
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

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <tre/regex.h>

#define MAX_STRINGS 80 /* Maximum number of feature params. */

  int yylex(void);
  void lexer_include(const char *filename);

  /* Now all the globals we need :/... */
  char* GlobalForwards[256];
  static int tping, tconn, maxlinks, sendq, port, stringno, flags;
  static int is_ssl, is_server, is_hidden, is_exempt, i_class, is_local;
  static int is_leaf, is_hub;
  static char *name, *pass, *host, *vhost, *ip, *username, *origin, *hub_limit;
  static char *server, *reply, *replies, *rank, *dflags, *mask, *ident, *desc;
  static char *rtype, *action, *reason, *sport, *spoofhost, *hostmask, *oflags;
  static char *prefix, *command, *service;
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

#define parse_error yyserror

enum ConfigBlock
{
  BLOCK_ADMIN,
  BLOCK_CLASS,
  BLOCK_CLIENT,
  BLOCK_CRULE,
  BLOCK_COMMAND,
  BLOCK_CONNECT,
  BLOCK_DNSBL,
  BLOCK_EXCEPT,
  BLOCK_FEATURES,
  BLOCK_FILTER,
  BLOCK_FORWARD,
  BLOCK_GENERAL,
  BLOCK_KILL,
  BLOCK_INCLUDE,
  BLOCK_MOTD,
  BLOCK_JUPE,
  BLOCK_OPER,
  BLOCK_PORT,
  BLOCK_QUARANTINE,
  BLOCK_REDIRECT,
  BLOCK_SPOOFHOST,
  BLOCK_UWORLD,
  BLOCK_WEBIRC,
  BLOCK_LAST_BLOCK
};

struct ConfigBlocks
{
  struct ConfigBlocks *cb_parent;
  unsigned long cb_allowed;
  char cb_fname[1];
};

static struct ConfigBlocks *includes;

static int
permitted(enum ConfigBlock type, int warn)
{
  static const char *block_names[BLOCK_LAST_BLOCK] = {
    "Admin", "Command", "Class", "Client", "CRule", "Connect", "DNSBL",
    "Except", "Features", "Filter", "Forward", "Kill", "Include", "Jupe",
    "General", "Oper", "Port", "Quarantine", "Redirect", "Spoofhost",
    "UWorld", "WebIRC", "Motd"
  };

  if (!includes)
    return 1;
  if (includes->cb_allowed & (1 << type))
    return 1;
  if (warn)
  {
    /* Unfortunately, flex's yylineno is hosed for included files, so
     * do not try to use it.
     */
    yywarning("Forbidden '%s' block at %s.", block_names[type],
              includes->cb_fname);
  }
  return 0;
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

%token GENERAL
%token ADMIN
%token LOCATION
%token RTYPE
%token ACTION
%token CHNAME
%token REASON
%token FLAGS
%token REPLIES
%token REPLY
%token RANK
%token CONTACT
%token CONNECT
%token CLASS
%token PINGFREQ
%token CONNECTFREQ
%token WEBIRC
%token SPOOFHOST
%token SPOOF
%token COMMAND
%token FORWARD
%token PREFIX
%token CMD
%token SERVICE
%token EXCEPT
%token MASK
%token IDENT
%token VERSION
%token DESC
%token FILTER
%token DNSBL
%token REDIRECT
%token MAXLINKS
%token MAXHOPS
%token SENDQ
%token NAME
%token HOST
%token HOSTMASK
%token IP
%token USERNAME
%token PASS
%token LOCAL
%token SECONDS
%token MINUTES
%token HOURS
%token DAYS
%token WEEKS
%token MONTHS
%token YEARS
%token DECADES
%token BYTES
%token KBYTES
%token MBYTES
%token GBYTES
%token TBYTES
%token SERVER
%token PORT
%token HUB
%token LEAF
%token UWORLD
%token YES
%token NO
%token OPER
%token VHOST
%token HIDDEN
%token EXEMPT
%token MOTD
%token JUPE
%token NICK
%token NUMERIC
%token DESCRIPTION
%token CLIENT
%token KILL
%token CRULE
%token REAL
%token TFILE
%token RULE
%token SSL
%token ALL
%token FEATURES
%token QUARANTINE
%token PSEUDO
%token PREPEND
%token USERMODE
%token IAUTH
%token FAST
%token AUTOCONNECT
%token PROGRAM
%token DNS
%token INCLUDE
%token LINESYNC
%token FROM
%token TEOF
%token LOGICAL_AND LOGICAL_OR
%token CONNECTED DIRECTCON VIA DIRECTOP
/* and some types... */
%type <num> sizespec
%type <num> timespec timefactor factoredtimes factoredtime
%type <num> expr yesorno
%type <num> blocklimit blocktypes blocktype
%type <num> optall
%type <crule> crule_expr
%left LOGICAL_OR
%left LOGICAL_AND
%left '+' '-'
%left '*' '/'
%nonassoc '!'
%nonassoc '(' ')'

%union{
 struct CRuleNode *crule;
 char *text;
 int num;
}

%%
/* Blocks in the config file... */
blocks: blocks block | block;
block: adminblock   | commandblock | classblock      | clientblock   | cruleblock   |
       connectblock | dnsblblock   | exceptblock     | featuresblock | filterblock |
       generalblock | forwardblock | killblock       | includeblock  | jupeblock    |
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

yesorno: YES { $$ = 1; } | NO { $$ = 0; };

optall: { $$ = 0; };
  | ALL { $$ = 1; };

crule_expr:
    '(' crule_expr ')' { $$ = $2; }
  | crule_expr LOGICAL_AND crule_expr { $$ = crule_make_and($1, $3); }
  | crule_expr LOGICAL_OR crule_expr { $$ = crule_make_or($1, $3); }
  | '!' crule_expr { $$ = crule_make_not($2); }
  | CONNECTED '(' QSTRING ')' { $$ = crule_make_connected($3); }
  | DIRECTCON '(' QSTRING ')' { $$ = crule_make_directcon($3); }
  | VIA '(' QSTRING ',' QSTRING ')' { $$ = crule_make_via($3, $5); }
  | DIRECTOP '(' ')' { $$ = crule_make_directop(); }
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
 struct ConfItem *lconf = NULL;
 struct ConfItem *hconf = NULL;

 if (!permitted(BLOCK_CONNECT, 1))
   ;
 else if (name == NULL)
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

   lookup_confhost(aconf);

   if (is_hub) {
     hconf = make_conf();
     hconf->status = CONF_HUB;
     hconf->host = hub_limit;
     hconf->name = name;
     hconf->port = maxlinks;
   } else {
     if (is_leaf) {
       lconf = make_conf();
       lconf->status = CONF_LEAF;
       lconf->name = name;
       lconf->port = maxlinks;
     }
  }
 }
 if (!aconf) {
   MyFree(name);
   MyFree(pass);
   MyFree(origin);
   MyFree(host);
   MyFree(hub_limit);
 } else {
   aconf->next = GlobalConfList;
   GlobalConfList = aconf;
   aconf = NULL;
 }

 if (hconf) {
   hconf->next = GlobalConfList;
   GlobalConfList = hconf;
   hconf = NULL;
 }

 if (lconf) {
   lconf->next = GlobalConfList;
   GlobalConfList = lconf;
   lconf = NULL;
 }

 name = pass = host = origin = hub_limit = NULL;
 is_hub = is_leaf = port = flags = 0;
}
connectitems: connectitem connectitems | connectitem;
connectitem: connectname | connectpass | connectclass | connecthost
              | connectvhost | connectport | connectleaf | connecthub
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
connectvhost: VHOST '=' QSTRING ';'
{
 MyFree(origin);
 origin = $3;
};
connectclass: CLASS '=' NUMBER ';'
{
 c_class = find_class($3);
 if (!c_class)
  parse_error("No such connection class '%d' for Connect block", $3);
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
 MyFree(hub_limit);
 hub_limit = $3;
};
connectmaxhops: MAXHOPS '=' expr ';'
{
  maxlinks = $3;
};
connectauto: AUTOCONNECT '=' YES ';' { flags |= CONF_AUTOCONNECT; }
 | AUTOCONNECT '=' NO ';' { flags &= ~CONF_AUTOCONNECT; };

clientblock: CLIENT
{
  maxlinks = 65535;
  port = 0;
}
'{' clientitems '}' ';'
{
  struct ConfItem *aconf = 0;

  if (!permitted(BLOCK_CLIENT, 1))
    ;
  else if (!c_class)
    parse_error("Invalid or missing class in Client block");
  else if (pass && strlen(pass) > PASSWDLEN)
    parse_error("Password too long in connect block");
  else {
    aconf = make_conf();
    aconf->status = CONF_CLIENT;
    aconf->host = ip;
    aconf->name = host;
    aconf->conn_class = c_class;
    aconf->maximum = maxlinks;
    aconf->passwd = pass;
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
  pass = NULL;
  port = 0;
};
clientitems: clientitem clientitems | clientitem;
clientitem: clienthost | clientip | clientclass | clientpass | clientmaxlinks | clientport;
clienthost: HOST '=' QSTRING ';'
{
  MyFree(host);
  host = $3;
};
clientip: IP '=' QSTRING ';'
{
  MyFree(ip);
  ip = $3;
};
clientclass: CLASS '=' NUMBER ';'
{
  c_class = find_class($3);
  if (!c_class)
    parse_error("No such connection class '%d' for Client block", $3);
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
  if (!permitted(BLOCK_CLASS, 1))
    ;
  else if (i_class)
  {
    add_class(i_class, tping, tconn, maxlinks, sendq);
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
};
classitems: classitem classitems | classitem;
classitem: classname | classpingfreq | classconnfreq | classmaxlinks |
           classsendq;
classname: NAME '=' NUMBER ';'
{
  i_class = $3;
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


operblock: OPER '{' operitems '}' ';'
{
  struct ConfItem *aconf = NULL;
  struct SLink *link;
  int* i;
  int iflag;
  char *m;

  if (!permitted(BLOCK_OPER, 1))
    ;
  else if (name == NULL)
    parse_error("Missing name in operator block");
  else if (pass == NULL)
    parse_error("Missing password in operator block");
  else if (hosts == NULL)
    parse_error("Missing host(s) in operator block");
  else if (c_class == NULL)
    parse_error("Invalid or missing class in operator block");
  else for (link = hosts; link != NULL; link = link->next) {
    aconf = make_conf();
    if (is_local) {
      m = "o";
      aconf->status = CONF_LOCOP;
    } else {
      m = "O";
      aconf->status = CONF_OPERATOR;
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
};
operitems: operitem | operitems operitem;
operitem: opername | operpass | operhost | operflags | operclass | operlocal;
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
operclass: CLASS '=' NUMBER ';'
{
 c_class = find_class($3);
 if (!c_class)
  parse_error("No such connection class '%d' for Operator block", $3);
};
operlocal: LOCAL '=' YES ';'
{
  is_local = 1;
} | LOCAL '=' NO ';'
{
  is_local = 0;
};


motdblock: MOTD '{' motditems '}' ';'
{
  struct SLink *link;
  if (permitted(BLOCK_MOTD, 1) && pass != NULL) {
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
  if (!permitted(BLOCK_KILL, 1))
  {
    MyFree(dconf->usermask);
    MyFree(dconf->hostmask);
    MyFree(dconf->message);
    MyFree(dconf);
  }
  else if (dconf->usermask || dconf->hostmask || (dconf->flags & DENY_FLAGS_REALNAME) ||
          (dconf->flags & DENY_FLAGS_VERSION))
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
killitem: killuhost | killversion | killreal | killusername | killreasonfile | killreason;
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
      Debug((DEBUG_DEBUG, "IPkill: %s = %08x/%i (%08x)", ipname,
             dconf->address, dconf->bits, NETMASK(dconf->bits)));
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


cruleblock: CRULE optall QSTRING optall crule_expr ';'
{
  if (permitted(BLOCK_CRULE, 1) && $5)
  {
    struct CRuleConf *p = (struct CRuleConf*) MyMalloc(sizeof(*p));
    p->hostmask = collapse($3);
    p->rule = crule_text($5);
    p->type = ($2 || $4) ? CRULE_ALL : CRULE_AUTO;
    p->node = $5;
    p->next = cruleConfList;
    cruleConfList = p;
  }
};

featuresblock: FEATURES '{' {
  (void)permitted(BLOCK_FEATURES, 1);
} featureitems '}' ';';
featureitems: featureitems featureitem | featureitem;

featureitem: QSTRING
{
  stringlist[0] = $1;
  stringno = 1;
} '=' stringlist ';' {
  int ii;
  if (permitted(BLOCK_FEATURES, 0))
    feature_set(NULL, (const char * const *)stringlist, stringno);
  for (ii = 0; ii < stringno; ++ii)
    MyFree(stringlist[ii]);
};

uworldblock: UWORLD '{' {
  (void)permitted(BLOCK_UWORLD, 1);
}  uworlditems '}' ';';
uworlditems: uworlditem uworlditems | uworlditem;
uworlditem: uworldname;
uworldname: NAME '=' QSTRING ';'
{
  if (permitted(BLOCK_UWORLD, 0))
    conf_make_uworld($3);
};

uworldblock: UWORLD QSTRING ';'
{
  if (permitted(BLOCK_UWORLD, 1))
    conf_make_uworld($2);
}


jupeblock: JUPE '{' {
  (void)permitted(BLOCK_JUPE, 1);
} jupeitems '}' ';' ;
jupeitems: jupeitem jupeitems | jupeitem;
jupeitem: jupenick;
jupenick: NICK '=' QSTRING ';'
{
  if (permitted(BLOCK_JUPE, 0))
  {
    addNickJupes($3);
    MyFree($3);
  }
};


/* The port block... */
portblock: PORT '{' portitems '}' ';'
{
  if (!permitted(BLOCK_PORT, 1))
    ;
  else {
#ifdef USE_SSL
    add_listener(port, vhost, pass, is_server, is_hidden, is_ssl, is_exempt);
#else
    add_listener(port, vhost, pass, is_server, is_hidden, is_exempt);
#endif
  }
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

portssl: SSL '=' YES ';'
{
  is_ssl = 1;
} | SSL '=' NO ';'
{
  is_ssl = 0;
};

generalblock: GENERAL
{
  if (permitted(BLOCK_GENERAL, 1))
  {
  }
} '{' generalitems '}' ';' {
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
  if (!permitted(BLOCK_GENERAL, 0))
    ;
  else if (localConf.numeric == 0)
    localConf.numeric = $3;
  else if (localConf.numeric != (unsigned int)$3)
    parse_error("Redefinition of server numeric %i (%i)", $3,
    		localConf.numeric);
};

generalname: NAME '=' QSTRING ';'
{
  if (!permitted(BLOCK_GENERAL, 0))
    MyFree($3);
  else if (localConf.name == NULL)
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
  if (!permitted(BLOCK_GENERAL, 0))
    MyFree($3);
  else
  {
    MyFree(localConf.description);
    localConf.description = $3;
    ircd_strncpy(cli_info(&me), $3, REALLEN);
  }
};

generalvhost: VHOST '=' QSTRING ';'
{
  char *vhost = $3;

  if (!permitted(BLOCK_GENERAL, 0))
    ;
  if (string_is_address(vhost)) {
    if (INADDR_NONE == (localConf.vhost_address.s_addr = inet_addr(vhost)))
      localConf.vhost_address.s_addr = INADDR_ANY;
  }

  MyFree(vhost);
};


adminblock: ADMIN
{
  if (permitted(BLOCK_ADMIN, 1))
  {
    MyFree(localConf.location1);
    MyFree(localConf.location2);
    MyFree(localConf.contact);
    localConf.location1 = localConf.location2 = localConf.contact = NULL;
  }
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
  if (!permitted(BLOCK_ADMIN, 0))
    MyFree($3);
  else if (localConf.location1 == NULL)
    localConf.location1 = $3;
  else if (localConf.location2 == NULL)
    localConf.location2 = $3;
  else /* Otherwise just drop it. -A1kmm */
    MyFree($3);
};
admincontact: CONTACT '=' QSTRING ';'
{
  if (!permitted(BLOCK_ADMIN, 0))
    MyFree($3);
  else
  {
    MyFree(localConf.contact);
    localConf.contact = $3;
  }
};


dnsblblock: DNSBL '{' dnsblitems '}' ';'
{
  struct blline *blline;

  if (permitted(BLOCK_DNSBL, 1)) {
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

  if (permitted(BLOCK_COMMAND, 1)) {
    if (!command)
      parse_error("Your Command block must contain a command.");
    else if (!service)
      parse_error("Your Command block must contain a service.");
    else {
      new_svc = (struct svcline *)MyMalloc(sizeof(struct svcline));

      DupString(new_svc->cmd, command);
      DupString(new_svc->target, service);
 
      if (prefix)
        DupString(new_svc->prepend, prefix);

      new_svc->next = GlobalServicesList;
      GlobalServicesList = new_svc;

      command = NULL;
      service = NULL;
      prefix = NULL;
    }
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

forwardblock: FORWARD '{' {
  (void)permitted(BLOCK_FORWARD, 1);
} forwarditems '}' ';';
forwarditems: forwarditems forwarditem | forwarditem;
forwarditem: QSTRING '=' QSTRING ';'
{
  if (!permitted(BLOCK_FORWARD, 0))
  {
    MyFree($1);
    MyFree($3);
  }
  else
  {
    char *fields;
    unsigned char ch = 0;

    DupString(fields, $1);
    ch = *fields;

    MyFree(GlobalForwards[ch]);
    DupString(GlobalForwards[ch], $3);
  }
};

exceptblock: EXCEPT '{' exceptitems '}' ';'
{
  struct eline *eline;

  if (permitted(BLOCK_EXCEPT, 1)) {
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

spoofhostblock: SPOOFHOST '{' spoofhostitems '}' ';'
{
  struct prefix *p;
  struct sline *sline;

  if (permitted(BLOCK_SPOOFHOST, 1)) {
    if (!hostmask && ident)
      parse_error("Spoofhost block error, if using a hostname then the username must not be empty.");
    else if (!ident && hostmask)
      parse_error("Spoofhost block error, if using a usernamen then the hostname must not be empty.");
    else {
      p = (struct prefix *) MyMalloc(sizeof(struct prefix));
      sline = (struct sline *) MyMalloc(sizeof(struct sline));
      DupString(sline->spoofhost, spoofhost);
      if (pass)
        DupString(sline->passwd, pass);
      else
        sline->passwd = NULL;
      if (hostmask) {
        DupString(sline->realhost, hostmask);
        if (check_if_ipmask(sline->realhost)) {
          if (str2prefix(sline->realhost, p) != 0) {
            sline->address = p->address;
            sline->bits = p->bits;
            sline->flags = SLINE_FLAGS_IP;
          } else {
            sline->flags = SLINE_FLAGS_HOSTNAME;
          }
        } else
          sline->flags = SLINE_FLAGS_HOSTNAME;
      } else {
        sline->realhost = NULL;
        sline->flags = 0;
      }
      if (username)
        DupString(sline->username, ident);
      else
         sline->username = NULL;

      sline->next = GlobalSList;
      GlobalSList = sline;
      MyFree(p);

      spoofhost = NULL;
      pass = NULL;
      hostmask = NULL;
      ident = NULL;
    }
  }
};
spoofhostitems: spoofhostitem | spoofhostitems spoofhostitem;
spoofhostitem: spoofhostspoof | spoofhostpass | spoofhostmask | spoofhostident;
spoofhostspoof: SPOOF '=' QSTRING ';'
{
  MyFree(spoofhost);
  spoofhost = $3;
};
spoofhostpass: PASS '=' QSTRING ';'
{
  MyFree(pass);
  pass = $3;
};
spoofhostmask: HOSTMASK '=' QSTRING ';'
{
  MyFree(host);
  hostmask = $3;
};
spoofhostident: IDENT '=' QSTRING ';'
{
  MyFree(ident);
  ident = $3;
};

redirectblock: REDIRECT '{' redirectitems '}' ';'
{
  struct csline *csline;
  if (permitted(BLOCK_REDIRECT, 1)) {
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

quarantineblock: QUARANTINE '{' {
  (void)permitted(BLOCK_QUARANTINE, 1);
} quarantineitems '}' ';';
quarantineitems: quarantineitems quarantineitem | quarantineitem;
quarantineitem: QSTRING '=' QSTRING ';'
{
  if (!permitted(BLOCK_QUARANTINE, 0))
  {
    MyFree($1);
    MyFree($3);
  }
  else
  {
    struct qline *qconf = MyCalloc(1, sizeof(*qconf));
    qconf->chname = $1;
    qconf->reason = $3;
    qconf->next = GlobalQuarantineList;
    GlobalQuarantineList = qconf;
  }
};

webircblock: WEBIRC '{' webircitems '}' ';'
{
  struct wline *wline;

  if (permitted(BLOCK_WEBIRC, 1)) {
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


filterblock: FILTER '{' filteritems '}' ';'
{
  struct fline *fline;
  regex_t tempre;

  if (permitted(BLOCK_FILTER, 1)) {
    if (!name)
      parse_error("Your Filter block must contain a filter.");
    else if (!rtype)
      parse_error("Your Filter block must contain a type");
    else if (!action)
      parse_error("Your Filter block must contain a action.");
    else if (!reason)
      parse_error("Your Filter block must contain a reason.");
    else {
      if(regcomp(&tempre, name, REG_ICASE|REG_EXTENDED) == 0) {
        fline = (struct fline *) MyMalloc(sizeof(struct fline));
        memset(fline, 0, sizeof(struct fline));

        regcomp(&fline->filter, name, REG_ICASE|REG_EXTENDED);
        DupString(fline->rawfilter, name);
        DupString(fline->wflags, rtype);
        DupString(fline->rflags, action);
        DupString(fline->reason, reason);

        fline->next = GlobalFList;
        GlobalFList = fline;

        regfree(&tempre);
        name = NULL;
        rtype = NULL;
        action = NULL;
        reason = NULL;
      } else {
        parse_error("Invalid regex format in Filter block");
      }
    }
  }
};
filteritems: filteritem | filteritems filteritem;
filteritem: filtername | filterrtype | filteraction | filterreason;
filtername: NAME '=' QSTRING ';'
{
  MyFree(name);
  name = $3;
};
filterrtype: RTYPE '=' QSTRING ';'
{
  MyFree(rtype);
  rtype = $3;
};
filteraction: ACTION '=' QSTRING ';'
{
  MyFree(action);
  action = $3;
};
filterreason: REASON '=' QSTRING ';'
{
  MyFree(reason);
  reason = $3;
};

includeblock: INCLUDE blocklimit QSTRING ';' {
  struct ConfigBlocks *child;

  child = MyCalloc(1, sizeof(*child) + strlen($3));
  strcpy(child->cb_fname, $3);
  child->cb_allowed = $2 & (includes ? includes->cb_allowed : ~0ul);
  child->cb_parent = includes;
  MyFree($3);

  if (permitted(BLOCK_INCLUDE, 1))
    lexer_include(child->cb_fname);
  else
    lexer_include(NULL);

  includes = child;
} blocks TEOF {
  struct ConfigBlocks *parent;

  parent = includes->cb_parent;
  MyFree(includes);
  includes = parent;
};


blocklimit: { $$ = ~0; } ;
blocklimit: blocktypes FROM;
blocktypes: blocktypes ',' blocktype { $$ = $1 | $3; };
blocktypes: blocktype;
blocktype: ALL { $$ = ~0; }
  | ADMIN { $$ = 1 << BLOCK_ADMIN; }
  | COMMAND { $$ = 1 << BLOCK_COMMAND; }
  | CLASS { $$ = 1 << BLOCK_CLASS; }
  | CLIENT { $$ = 1 << BLOCK_CLIENT; }
  | CONNECT { $$ = 1 << BLOCK_CONNECT; }
  | CRULE { $$ = 1 << BLOCK_CRULE; }
  | DNSBL { $$ = 1 << BLOCK_DNSBL; }
  | EXCEPT { $$ = 1 << BLOCK_EXCEPT; }
  | FEATURES { $$ = 1 << BLOCK_FEATURES; }
  | FILTER { $$ = 1 << BLOCK_FILTER; }
  | FORWARD { $$ = 1 << BLOCK_FORWARD; }
  | GENERAL { $$ = 1 << BLOCK_GENERAL; }
  | FILTER { $$ = 1 << BLOCK_FILTER; }
  | INCLUDE { $$ = 1 << BLOCK_INCLUDE; }
  | JUPE { $$ = 1 << BLOCK_JUPE; }
  | KILL { $$ = 1 << BLOCK_KILL; }
  | MOTD { $$ = 1 << BLOCK_MOTD; }
  | OPER { $$ = 1 << BLOCK_OPER; }
  | PORT { $$ = 1 << BLOCK_PORT; }
  | QUARANTINE { $$ = 1 << BLOCK_QUARANTINE; }
  | REDIRECT { $$ = 1 << BLOCK_REDIRECT; }
  | SPOOFHOST { $$ = 1 << BLOCK_SPOOFHOST; }
  | UWORLD { $$ = 1 << BLOCK_UWORLD; }
  | WEBIRC { $$ = 1 << BLOCK_WEBIRC; }
  ;
