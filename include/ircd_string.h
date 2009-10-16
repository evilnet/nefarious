/*
 * IRC - Internet Relay Chat, include/ircd_string.h
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 * Copyright (C) 1996-1997 Carlo Wood
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
#ifndef INCLUDED_ircd_string_h
#define INCLUDED_ircd_string_h
#ifndef INCLUDED_ircd_chattr_h
#include "ircd_chattr.h"
#endif
#include <string.h>
/*
 * Macros
 */
#define EmptyString(x) (!(x) || !(*x))

/*
 * initialize recognizers
 */
extern int init_string(void);

extern int string_is_hostname(const char* str);
extern int string_is_address(const char* str);
extern int string_has_wildcards(const char* str);

extern char*       ircd_strncpy(char* dest, const char* src, size_t len);
extern int         ircd_strcmp(const char *a, const char *b);
extern int         ircd_strrcmp(const char *a, const char *b);
extern int         ircd_strncmp(const char *a, const char *b, size_t n);
extern int         unique_name_vector(char* names, char token, char** vector, int size);
extern int         token_vector(char* names, char token, char** vector, int size);
extern const char* ircd_ntoa(const char* addr);
extern const char* ircd_ntoa_r(char* buf, const char* addr);
extern char*       host_from_uh(char* buf, const char* userhost, size_t len);
extern char*       ircd_strtok(char** save, char* str, char* fs);

extern char*       canonize(char* buf);

#define DupString(x, y)  (strcpy((x = (char*) MyMalloc(strlen(y) + 1)), y))


/* String classification pseudo-functions, when others are needed add them,
   strIsXxxxx(s) is true when IsXxxxx(c) is true for every char in s */

#define strIsAlnum(s)     (strChattr(s) & NTL_ALNUM)
#define strIsAlpha(s)     (strChattr(s) & NTL_ALPHA)
#define strIsDigit(s)     (strChattr(s) & NTL_DIGIT)
#define strIsLower(s)     (strChattr(s) & NTL_LOWER)
#define strIsSpace(s)     (strChattr(s) & NTL_SPACE)
#define strIsUpper(s)     (strChattr(s) & NTL_UPPER)

#define strIsIrcCh(s)     (strChattr(s) & NTL_IRCCH)
#define strIsIrcCl(s)     (strChattr(s) & NTL_IRCCL)
#define strIsIrcNk(s)     (strChattr(s) & NTL_IRCNK)
#define strIsIrcUi(s)     (strChattr(s) & NTL_IRCUI)
#define strIsIrcHn(s)     (strChattr(s) & NTL_IRCHN)
#define strIsIrcIp(s)     (strChattr(s) & NTL_IRCIP)

/*
 * Critical small functions to inline even in separate compilation
 * when FORCEINLINE is defined (provided you have a compiler that supports
 * `inline').
 */

#define NTL_HDR_strChattr   unsigned int strChattr(const char *s)

#define NTL_SRC_strChattr   const char *rs = s; \
                            unsigned int x = ~0; \
                            while(*rs) \
                              x &= IRCD_CharAttrTab[*rs++ - CHAR_MIN]; \
                            return x;

/*
 * XXX - bleah should return 1 if different 0 if the same
 */
#define NTL_HDR_strCasediff int strCasediff(const char *a, const char *b)

#define NTL_SRC_strCasediff const char *ra = a; \
                            const char *rb = b; \
                            while(ToLower(*ra) == ToLower(*rb++)) \
                              if(!*ra++) \
                                return 0; \
                            return 1;

#ifndef FORCEINLINE
extern NTL_HDR_strChattr;
extern NTL_HDR_strCasediff;

#else /* FORCEINLINE */
#ifdef __cplusplus
inline NTL_HDR_strChattr { NTL_SRC_strChattr }
inline NTL_HDR_strCasediff { NTL_SRC_strCasediff }
#else
static __inline__ NTL_HDR_strChattr { NTL_SRC_strChattr }
static __inline__ NTL_HDR_strCasediff { NTL_SRC_strCasediff }
#endif
#endif /* FORCEINLINE */

/*
 * Proto types of other externally visible functions
 */
extern int strnChattr(const char *s, const size_t n);
extern int textban_replace(int type, char *badword, char *replace, char *line, char *buf);
extern int explode_line(char *line, int irc_colon, int argv_size, char *argv[]);
extern char *normalizeBuffer(char *);
extern char *substr(const char *pstr, int start, int numchars);
extern char *my_strcasestr(char *haystack, char *needle);
extern void doCleanBuffer(char *str);
extern void parse_word(const char *s, char **word, int *type);

#define issp(c)        ((c) == 32)
#define ArrayLength(x) (sizeof(x)/sizeof(x[0]))


#endif /* INCLUDED_ircd_string_h */

