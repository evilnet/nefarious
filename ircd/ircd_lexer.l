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

%{

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "fileio.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_string.h"
#include "s_debug.h"
#include "y.tab.h"

extern int lineno;

static struct lexer_token {
  const char *string;
  int value;
} tokens[] = {
#define TOKEN(NAME) { #NAME, NAME }
  TOKEN(ADMIN),
  TOKEN(GENERAL),
  TOKEN(LOCATION),
  TOKEN(CONTACT),
  TOKEN(CLASS),
  TOKEN(PINGFREQ),
  TOKEN(CONNECT),
  TOKEN(CONNECTFREQ),
  TOKEN(MAXLINKS),
  TOKEN(MAXHOPS),
  TOKEN(SENDQ),
  TOKEN(NAME),
  TOKEN(HOST),
  TOKEN(IP),
  TOKEN(USERNAME),
  TOKEN(PASS),
  TOKEN(SECONDS),
  TOKEN(MINUTES),
  TOKEN(HOURS),
  TOKEN(DAYS),
  TOKEN(WEEKS),
  TOKEN(MONTHS),
  TOKEN(YEARS),
  TOKEN(DECADES),
  TOKEN(BYTES),
  TOKEN(KBYTES),
  TOKEN(MBYTES),
  TOKEN(GBYTES),
  TOKEN(TBYTES),
  TOKEN(PORT),
  TOKEN(SERVER),
  TOKEN(YES),
  TOKEN(NO),
  TOKEN(HUB),
  TOKEN(LEAF),
  TOKEN(UWORLD),
  TOKEN(OPER),
  TOKEN(LOCAL),
  TOKEN(VHOST),
  TOKEN(MASK),
  TOKEN(HIDDEN),
  TOKEN(MOTD),
  TOKEN(NUMERIC),
  TOKEN(NICK),
  TOKEN(JUPE),
  TOKEN(DESCRIPTION),
  TOKEN(CLIENT),
  TOKEN(REAL),
  TOKEN(REASON),
  TOKEN(RULE),
  TOKEN(ALL),
  TOKEN(CRULE),
  TOKEN(KILL),
  TOKEN(QUARANTINE),
  TOKEN(IAUTH),
  TOKEN(FEATURES),
  TOKEN(PSEUDO),
  TOKEN(PREPEND),
  TOKEN(USERMODE),
  TOKEN(FAST),
  TOKEN(AUTOCONNECT),
  TOKEN(PROGRAM),
  TOKEN(DNS),

  TOKEN(ACTION),
  TOKEN(CHNAME),
  TOKEN(CMD),
  TOKEN(COMMAND),
  TOKEN(DESC),
  TOKEN(DNSBL),
  TOKEN(EXCEPT),
  TOKEN(FLAGS),
  TOKEN(FORWARD),
  TOKEN(HOSTMASK),
  TOKEN(IDENT),
  TOKEN(PREFIX),
  TOKEN(RANK),
  TOKEN(REDIRECT),
  TOKEN(REPLIES),
  TOKEN(REPLY),
  TOKEN(RTYPE),
  TOKEN(SERVICE),
  TOKEN(SFILTER),
  TOKEN(SPOOF),
  TOKEN(SPOOFHOST),
  TOKEN(SSL),
  TOKEN(VERSION),
  TOKEN(WEBIRC),
#undef TOKEN
  { "administrator", ADMIN },
  { "auto", AUTOCONNECT },
  { "b", BYTES },
  { "file", TFILE },
  { "gb", GBYTES },
  { "gigabytes", GBYTES },
  { "kb", KBYTES },
  { "kilobytes", KBYTES },
  { "mb", MBYTES },
  { "megabytes", MBYTES },
  { "operator", OPER },
  { "password", PASS },
  { "realname", REAL },
  { "tb", TBYTES },
  { "terabytes", TBYTES },
  { NULL, 0 }
};
static int ntokens;

static int
token_compare(const void *pa, const void *pb)
{
  const struct lexer_token *ta = pa;
  const struct lexer_token *tb = pb;
  unsigned int ii = 0;
  int res;
  while (ta->string[ii] && (ToLower(ta->string[ii]) == ToLower(tb->string[ii])))
    ii++;
  res = ToLower(tb->string[ii]) - ToLower(ta->string[ii]);
  return res;
}

static void
init_ntokens(void)
{
  for (ntokens = 0; tokens[ntokens].string; ++ntokens) ;
  qsort(tokens, ntokens, sizeof(tokens[0]), token_compare);
}

static int
find_token(char *token)
{
  struct lexer_token *tok;
  if (!ntokens)
    init_ntokens();
  tok = bsearch(&token, tokens, ntokens, sizeof(tokens[0]), token_compare);
  return tok ? tok->value : 0;
}

static FBFILE *lexer_input;

#undef YY_INPUT
#define YY_INPUT(buf, res, size) res = (fbgets(buf, size, lexer_input) ? strlen(buf) : 0)

int
init_lexer(void)
{
  lexer_input = fbopen(configfile, "r");
  if (lexer_input == NULL)
  {
#ifdef YY_FATAL_ERROR
    YY_FATAL_ERROR("Could not open the configuration file.");
#else
    fprintf(stderr, "Could not open the configuration file.");
#endif
    return 0;
  }
#ifdef YY_NEW_FILE
  YY_NEW_FILE;
#endif
  lineno = 1;
  return 1;
}

void deinit_lexer(void)
{
  if (lexer_input != NULL)
  {
    fbclose(lexer_input);
    lexer_input = NULL;
  }
}

int
yywrap(void)
{
  return 1;
}

%}

WHITE [ \t\r]+
SHCOMMENT #[^\n]*
NUMBER [0-9]+
QSTRING \"[^"\n]+[\"\n]
%%

{QSTRING} {yytext[yyleng-1] = 0; DupString(yylval.text, yytext+1); return QSTRING;}
{NUMBER} {yylval.num = strtoul(yytext, NULL, 10); return NUMBER;}
{WHITE} ;
{SHCOMMENT} ;

[a-zA-Z_][a-zA-Z_0-9]* { int res = find_token(yytext); if (res) return res; else REJECT; }
\n lineno++;
. return yytext[0];
