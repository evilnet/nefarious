/*
 * ircd_parser.y: A yacc/bison parser for ircd config files.
 * This is part of ircu, an Internet Relay Chat server.
 * The contents of this file are Copyright 2001 Diane Bruce,
 * Andrew Miller, the ircd-hybrid team and the ircu team.
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
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
#include "ircd_struct.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <tre/regex.h>

#define MAX_STRINGS 80 /* Maximum number of feature params. */

  int yylex(void);
  void lexer_include(const char *filename);

  /* Now all the globals we need :/... */
  static int tping, tconn, maxlinks, sendq, port, invert, stringno, flags;
  static char *name, *pass, *host, *ip, *username, *origin, *hub_limit;
  static char *rtype, *action, *reason;
  struct SLink *hosts;
  static char *stringlist[MAX_STRINGS];
  struct fline*    GlobalFList = 0;

#define parse_error yyserror

enum ConfigBlock
{
  BLOCK_FILTER,
  BLOCK_INCLUDE,
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
    "Filter", "Include",
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
%token REASON
%token CONTACT
%token CONNECT
%token CLASS
%token PINGFREQ
%token CONNECTFREQ
%token FILTER
%token MAXLINKS
%token MAXHOPS
%token SENDQ
%token NAME
%token HOST
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
%token MASK
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
%token TOK_IPV4 TOK_IPV6
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
block: filterblock | includeblock | error ';';

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

yesorno: YES { $$ = 1; } | NO { $$ = 0; };

optall: { $$ = 0; };
  | ALL { $$ = 1; };

stringlist: stringlist extrastring | extrastring;
extrastring: QSTRING
{
  if (stringno < MAX_STRINGS)
    stringlist[stringno++] = $1;
  else
    MyFree($1);
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
  | FILTER { $$ = 1 << BLOCK_FILTER; }
  | INCLUDE { $$ = 1 << BLOCK_INCLUDE; }
  ;
