/*
 * ircd_lexer.l: A lexical scanner for ircd config files.
 * This is part of ircu, an Internet Relay Chat server.
 * Copyright 2006 Michael Poole
 *
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
 * $Id: ircd_lexer.l,v 1.33 2008/03/16 01:52:59 klmitch Exp $
 */

%option never-interactive case-insensitive warn nodefault nounput yylineno

%{

#include "config.h"
#include "fileio.h"
#include "ircd_alloc.h"
#include "ircd_string.h"
#include "y.tab.h"

extern void yyserror(const char *pattern, ...);

#define lexer_input ((FBFILE*)yyin)

#undef YY_INPUT
#define YY_INPUT(buf, res, size) res = (fbgets(buf, size, lexer_input) ? strlen(buf) : 0)

int
init_lexer(const char *configfile)
{
  yyin = (FILE*)fbopen(configfile, "r");
  if (lexer_input == NULL)
  {
#ifdef YY_FATAL_ERROR
    YY_FATAL_ERROR("Could not open the configuration file.");
#else
    fprintf(stderr, "Could not open the configuration file.");
#endif
    return 0;
  }
  return 1;
}

void
lexer_include(const char *filename)
{
  if (filename == NULL)
  {
    yypush_buffer_state(yy_scan_string(""));
    return;
  }

  yyin = fopen(filename, "r");
  if (yyin == NULL)
  {
    yyserror("Unable to open included file '%s'.", filename);
    yypush_buffer_state(yy_scan_string(""));
    return;
  }
  yypush_buffer_state(yy_create_buffer(yyin, YY_BUF_SIZE));
}

void deinit_lexer(void)
{
  if (lexer_input != NULL)
  {
    fbclose(lexer_input);
    yyin = NULL;
  }
}

%}

%%

\"[^"\n]+[\"\n]	{yytext[yyleng-1] = 0; DupString(yylval.text, yytext+1); return QSTRING;}
[0-9]+		{yylval.num = strtoul(yytext, NULL, 10); return NUMBER;}
[ \t\r\n]+	;
#.*		;
<<EOF>>		{ yypop_buffer_state(); if (YY_CURRENT_BUFFER) return TEOF; else { yy_init = 0; yyterminate(); } }

\&\&            return LOGICAL_AND;
\|\|            return LOGICAL_OR;
ACTION		return ACTION;
ADMIN		return ADMIN;
ADMINISTRATOR	return ADMIN;
ALL		return ALL;
AUTO		return AUTOCONNECT;
AUTOCONNECT	return AUTOCONNECT;
B		return BYTES;
BYTES		return BYTES;
CHNAME		return CHNAME;
CLASS		return CLASS;
CLIENT		return CLIENT;
CONNECT		return CONNECT;
CONNECTED       return CONNECTED;
CONNECTFREQ	return CONNECTFREQ;
CONTACT		return CONTACT;
CMD		return CMD;
COMMAND		return COMMAND;
CRULE		return CRULE;
DAYS		return DAYS;
DESC		return DESC;
DECADES		return DECADES;
DESCRIPTION	return DESCRIPTION;
DIRECTCON       return DIRECTCON;
DIRECTOP        return DIRECTOP;
DNS             return DNS;
DNSBL		return DNSBL;
EXEMPT          return EXEMPT;
EXCEPT		return EXCEPT;
FAST		return FAST;
FEATURES	return FEATURES;
FILE		return TFILE;
FILTER		return FILTER;
FLAGS		return FLAGS;
FROM		return FROM;
FORWARD		return FORWARD;
GB		return GBYTES;
GBYTES		return GBYTES;
GENERAL		return GENERAL;
GIGABYTES	return GBYTES;
HIDDEN		return HIDDEN;
HOST		return HOST;
HOSTMASK	return HOSTMASK;
HOURS		return HOURS;
HUB		return HUB;
IAUTH		return IAUTH;
IDENT		return IDENT;
INCLUDE		return INCLUDE;
IP		return IP;
IPV4		return TOK_IPV4;
IPV6		return TOK_IPV6;
JUPE		return JUPE;
KB		return KBYTES;
KBYTES		return KBYTES;
KILOBYTES	return KBYTES;
KILL		return KILL;
LEAF		return LEAF;
LINESYNC	return LINESYNC;
LOCAL		return LOCAL;
LOCATION	return LOCATION;
MASK		return MASK;
MAXHOPS		return MAXHOPS;
MAXLINKS	return MAXLINKS;
MB		return MBYTES;
MBYTES		return MBYTES;
MEGABYTES	return MBYTES;
MINUTES		return MINUTES;
MONTHS		return MONTHS;
MOTD		return MOTD;
NAME		return NAME;
NICK		return NICK;
NO		return NO;
NUMERIC		return NUMERIC;
OPER		return OPER;
OPERATOR	return OPER;
PASS		return PASS;
PASSWORD	return PASS;
PINGFREQ	return PINGFREQ;
PORT		return PORT;
PREFIX		return PREFIX;
PREPEND		return PREPEND;
PROGRAM		return PROGRAM;
PSEUDO		return PSEUDO;
QUARANTINE	return QUARANTINE;
RANK		return RANK;
REAL		return REAL;
REALNAME	return REAL;
REASON		return REASON;
REDIRECT	return REDIRECT;
REPLIES		return REPLIES;
REPLY		return REPLY;
RTYPE		return RTYPE;
RULE		return RULE;
SECONDS		return SECONDS;
SENDQ		return SENDQ;
SERVER		return SERVER;
SERVICE		return SERVICE;
SPOOF		return SPOOF;
SPOOFHOST	return SPOOFHOST;
SSL		return SSL;
TB		return TBYTES;
TBYTES		return TBYTES;
TERABYTES	return TBYTES;
USERMODE	return USERMODE;
USERNAME	return USERNAME;
UWORLD		return UWORLD;
VERSION		return VERSION;
VHOST		return VHOST;
VIA             return VIA;
WEBIRC		return WEBIRC;
WEEKS		return WEEKS;
YEARS		return YEARS;
YES		return YES;

. return yytext[0];
