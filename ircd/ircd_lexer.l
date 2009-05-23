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
 * $Id$
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
  TOKEN(ACTION),
  TOKEN(ADMIN),
  TOKEN(ALL),
  TOKEN(AUTOCONNECT),
  TOKEN(BAN),
  TOKEN(BYTES),
  TOKEN(CHANNEL),
  TOKEN(CHNAME),
  TOKEN(CLASS),
  TOKEN(CLIENT),
  TOKEN(CMD),
  TOKEN(COMMAND),
  TOKEN(CONNECT),
  TOKEN(CONNECTFREQ),
  TOKEN(CONTACT),
  TOKEN(CRULE),
  TOKEN(CRYPT),
  TOKEN(DAYS),
  TOKEN(DECADES),
  TOKEN(DESC),
  TOKEN(DESCRIPTION),
  TOKEN(DNS),
  TOKEN(DNSBL),
  TOKEN(EXCEPT),
  TOKEN(EXEMPT),
  TOKEN(FAST),
  TOKEN(FEATURES),
  TOKEN(FLAGS),
  TOKEN(FORWARD),
  TOKEN(GBYTES),
  TOKEN(GENERAL),
  TOKEN(HIDDEN),
  TOKEN(HOST),
  TOKEN(HOSTMASK),
  TOKEN(HOURS),
  TOKEN(HUB),
  TOKEN(IDENT),
  TOKEN(IP),
  TOKEN(JUPE),
  TOKEN(KBYTES),
  TOKEN(KILL),
  TOKEN(KLINEPROMPT),
  TOKEN(LEAF),
  TOKEN(LENGTH),
  TOKEN(LOCAL),
  TOKEN(LOCATION),
  TOKEN(MASK),
  TOKEN(MAXHOPS),
  TOKEN(MAXLINKS),
  TOKEN(MBYTES),
  TOKEN(MINUTES),
  TOKEN(MONTHS),
  TOKEN(MOTD),
  TOKEN(NAME),
  TOKEN(NICK),
  TOKEN(NICKJUPE),
  TOKEN(NO),
  TOKEN(NUMERIC),
  TOKEN(OPER),
  TOKEN(PASS),
  TOKEN(PINGFREQ),
  TOKEN(PORT),
  TOKEN(PREFIX),
  TOKEN(PREPEND),
  TOKEN(PROGRAM),
  TOKEN(PSEUDO),
  TOKEN(QUARANTINE),
  TOKEN(RANK),
  TOKEN(REAL),
  TOKEN(REASON),
  TOKEN(REDIRECT),
  TOKEN(REGEX),
  TOKEN(REPLIES),
  TOKEN(REPLY),
  TOKEN(RTYPE),
  TOKEN(RULE),
  TOKEN(SECONDS),
  TOKEN(SENDQ),
  TOKEN(SERVER),
  TOKEN(SERVICE),
  TOKEN(SFILTER),
  TOKEN(SPOOF),
  TOKEN(SPOOFHOST),
  TOKEN(TBYTES),
  TOKEN(USERMODE),
  TOKEN(USERNAME),
  TOKEN(UWORLD),
  TOKEN(VERSION),
  TOKEN(VHOST),
  TOKEN(WEBIRC),
  TOKEN(WEEKS),
  TOKEN(YEARS),
  TOKEN(YES),
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
  { "kill", TPRIV_KILL },
  { "local_kill", TPRIV_LOCAL_KILL },
  { "jupe", TPRIV_JUPE },
  { "remoterehash", TPRIV_REMOTEREHASH },
  { "check", TPRIV_CHECK },
  { "see_secret_chan", TPRIV_SEE_SECRET_CHAN },
  { "shun", TPRIV_SHUN },
  { "local_shun", TPRIV_LOCAL_SHUN },
  { "wide_shun", TPRIV_WIDE_SHUN },
  { "zline", TPRIV_ZLINE },
  { "local_zline", TPRIV_LOCAL_ZLINE },
  { "wide_zline", TPRIV_WIDE_ZLINE },
  { "whois_notice", TPRIV_WHOIS_NOTICE },
  { "hide_idle", TPRIV_HIDE_IDLE },
  { "xtraop", TPRIV_XTRAOP },
  { "hide_channels", TPRIV_HIDE_CHANNELS },
  { "badchan", TPRIV_BADCHAN },
  { "chan_limit", TPRIV_CHAN_LIMIT },
  { "deop_lchan", TPRIV_DEOP_LCHAN },
  { "die", TPRIV_DIE },
  { "display", TPRIV_DISPLAY },
  { "force_local_opmode", TPRIV_FORCE_LOCAL_OPMODE },
  { "force_opmode", TPRIV_FORCE_OPMODE },
  { "gline", TPRIV_GLINE },
  { "list_chan", TPRIV_LIST_CHAN },
  { "local_badchan", TPRIV_LOCAL_BADCHAN },
  { "local_gline", TPRIV_LOCAL_GLINE },
  { "local_jupe", TPRIV_LOCAL_JUPE },
  { "local_kill", TPRIV_LOCAL_KILL },
  { "local_opmode", TPRIV_LOCAL_OPMODE },
  { "mode_lchan", TPRIV_MODE_LCHAN },
  { "opmode", TPRIV_OPMODE },
  { "propagate", TPRIV_PROPAGATE },
  { "rehash", TPRIV_REHASH },
  { "restart", TPRIV_RESTART },
  { "see_chan", TPRIV_SEE_CHAN },
  { "see_opers", TPRIV_SEE_OPERS },
  { "set", TPRIV_SET },
  { "freeform", TPRIV_FREEFORM },
  { "show_all_invis", TPRIV_SHOW_ALL_INVIS },
  { "show_invis", TPRIV_SHOW_INVIS },
  { "unlimit_query", TPRIV_UNLIMIT_QUERY },
  { "walk_lchan", TPRIV_WALK_LCHAN },
  { "wide_gline", TPRIV_WIDE_GLINE },
  { "whox", TPRIV_WHOX },
  { "display_mode", TPRIV_DISPLAY_MODE },
  { "remove", TPRIV_REMOVE },
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
