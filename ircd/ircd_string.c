/*
 * IRC - Internet Relay Chat, ircd/ircd_string.c
 * Copyright (C) 1999 Thomas Helvey
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

#include "ircd_string.h"
#include "ircd_defs.h"
#include "ircd_chattr.h"
#include "ircd_log.h"
#include "msg.h"
#include "s_bsd.h"
#include <regex.h>
#include <stdlib.h>
/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <string.h>
#include <stdio.h>


#define TEXTBAN_WORD_LEFT       0x1
#define TEXTBAN_WORD_RIGHT      0x2
#define MAX_FIELDS 6

/*
 * include the character attribute tables here
 */
#include "chattr.tab.c"


/*
 * Disallow a hostname label to contain anything but a [-a-zA-Z0-9].
 * It may not start or end on a '.'.
 * A label may not end on a '-', the maximum length of a label is
 * 63 characters.
 * On top of that (which seems to be the RFC) we demand that the
 * top domain does not contain any digits.
 */
static const char* hostExpr = "^([-0-9A-Za-z]*[0-9A-Za-z]\\.)+[A-Za-z]+$";
static regex_t hostRegex;

static const char* addrExpr =
    "^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\\.){1,3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$";
static regex_t addrRegex;

int init_string(void)
{
  /*
   * initialize matching expressions
   * XXX - expressions MUST be correct, don't change expressions
   * without testing them. Might be a good idea to exit if these fail,
   * important code depends on them.
   * TODO: use regerror for an error message
   */
  if (regcomp(&hostRegex, hostExpr, REG_EXTENDED | REG_NOSUB))
    return 0;

  if (regcomp(&addrRegex, addrExpr, REG_EXTENDED | REG_NOSUB))
    return 0;
  return 1;
}

int string_is_hostname(const char* str)
{
  assert(0 != str);
  return (strlen(str) <= HOSTLEN && 0 == regexec(&hostRegex, str, 0, 0, 0));
}

int string_is_address(const char* str)
{
  assert(0 != str);
  return (0 == regexec(&addrRegex, str, 0, 0, 0));
}

int string_has_wildcards(const char* str)
{
  assert(0 != str);
  for ( ; *str; ++str) {
    if ('\\' == *str) {
      if ('\0' == *++str)
        break;
    }
    else if ('*' == *str || '?' == *str)
      return 1;
  }
  return 0;
}

/** Split a string on certain delimiters.
 * This is a reentrant version of normal strtok().  The first call for
 * a particular input string must use a non-NULL \a str; *save will be
 * initialized based on that.  Later calls must use a NULL \a str;
 * *save will be updated.
 * @param[in,out] save Pointer to a position indicator.
 * @param[in] str Pointer to the input string, or NULL to continue.
 * @param[in] fs String that lists token delimiters.
 * @return Next token in input string, or NULL if no tokens remain.
 */
char* ircd_strtok(char **save, char *str, char *fs)
{
  char *pos = *save;            /* keep last position across calls */
  char *tmp;

  if (str)
    pos = str;                  /* new string scan */

  while (pos && *pos && strchr(fs, *pos) != NULL)
    pos++;                      /* skip leading separators */

  if (!pos || !*pos)
    return (pos = *save = NULL);        /* string contains only sep's */

  tmp = pos;                    /* now, keep position of the token */

  while (*pos && strchr(fs, *pos) == NULL)
    pos++;                      /* skip content of the token */

  if (*pos)
    *pos++ = '\0';              /* remove first sep after the token */
  else
    pos = NULL;                 /* end of string */

  *save = pos;
  return (tmp);
}

/** Rewrite a comma-delimited list of items to remove duplicates.
 * @param[in,out] buffer Comma-delimited list.
 * @return The input buffer \a buffer.
 */
char* canonize(char* buffer)
{
  static char cbuf[BUFSIZE];
  char*       s;
  char*       t;
  char*       cp = cbuf;
  int         l = 0;
  char*       p = NULL;
  char*       p2;

  *cp = '\0';

  for (s = ircd_strtok(&p, buffer, ","); s; s = ircd_strtok(&p, NULL, ","))
  {
    if (l)
    {
      p2 = NULL;
      for (t = ircd_strtok(&p2, cbuf, ","); t; t = ircd_strtok(&p2, NULL, ","))
        if (0 == ircd_strcmp(s, t))
          break;
        else if (p2)
          p2[-1] = ',';
    }
    else
      t = NULL;
    if (!t)
    {
      if (l)
        *(cp - 1) = ',';
      else
        l = 1;
      strcpy(cp, s);
      if (p)
        cp += (p - s);
    }
    else if (p2)
      p2[-1] = ',';
  }
  return cbuf;
}

/** Copy one string to another, not to exceed a certain length.
 * @param[in] s1 Output buffer.
 * @param[in] s2 Source buffer.
 * @param[in] n Maximum number of bytes to write, plus one.
 * @return The original input buffer \a s1.
 */
char* ircd_strncpy(char* s1, const char* s2, size_t n)
{
  char* endp = s1 + n;
  char* s = s1;

  assert(0 != s1);
  assert(0 != s2);

  while (s < endp && (*s++ = *s2++))
    ;
  if (s == endp)
    *s = '\0';
  return s1;
}


#ifndef FORCEINLINE
NTL_HDR_strChattr { NTL_SRC_strChattr }
NTL_HDR_strCasediff { NTL_SRC_strCasediff }
#endif /* !FORCEINLINE */

/*
 * Other functions visible externally
 */

/** Case insensitive string comparison.
 * @param[in] a First string to compare.
 * @param[in] b Second string to compare.
 * @return Less than, equal to, or greater than zero if \a a is lexicographically less than, equal to, or greater than \a b.
 */
int ircd_strcmp(const char *a, const char *b)
{
  const char* ra = a;
  const char* rb = b;
  while (ToLower(*ra) == ToLower(*rb)) {
    if (!*ra++)
      return 0;
    else
      ++rb;
  }
  return (*ra - *rb);
}

/** Case insensitive comparison of the starts of two strings.
 * @param[in] a First string to compare.
 * @param[in] b Second string to compare.
 * @param[in] n Maximum number of characters to compare.
 * @return Less than, equal to, or greater than zero if \a a is
 * lexicographically less than, equal to, or greater than \a b.
 */
int ircd_strncmp(const char *a, const char *b, size_t n)
{
  const char* ra = a;
  const char* rb = b;
  int left = n;
  if (!left--)
    return 0;
  while (ToLower(*ra) == ToLower(*rb)) {
    if (!*ra++ || !left--)
      return 0;
    else
      ++rb;
  }
  return (*ra - *rb);
}

/** Fill a vector of distinct names from a delimited input list.
 * Empty tokens (when \a token occurs at the start or end of \a list,
 * or when \a token occurs adjacent to itself) are ignored.  When
 * \a size tokens have been written to \a vector, the rest of the
 * string is ignored.
 * Unlike token_vector(), if a token repeats an earlier token, it is
 * skipped.
 * @param[in,out] list Input buffer.
 * @param[in] token Delimiter used to split \a list.
 * @param[out] vector Output vector.
 * @param[in] size Maximum number of elements to put in \a vector.
 * @return Number of elements written to \a vector.
 */
int unique_name_vector(char* list, char token, char** vector, int size)
{
  int   i;
  int   count = 0;
  char* start = list;
  char* end;

  assert(0 != list);
  assert(0 != vector);
  assert(0 < size);
 
  /*
   * ignore spurious tokens
   */
  while (token == *start)
    ++start;

  for (end = strchr(start, token); end; end = strchr(start, token)) {
    *end++ = '\0';
    /*
     * ignore spurious tokens
     */
    while (token == *end)
      ++end;
    for (i = 0; i < count; ++i) {
      if (0 == ircd_strcmp(vector[i], start))
        break;
    }
    if (i == count) {
      vector[count++] = start;
      if (count == size)
        return count;
    }
    start = end;
  }
  if (*start) {
    for (i = 0; i < count; ++i)
      if (0 == ircd_strcmp(vector[i], start))
        return count;
    vector[count++] = start;
  }
  return count;
}

/** Fill a vector of tokens from a delimited input list.
 * Empty tokens (when \a token occurs at the start or end of \a list,
 * or when \a token occurs adjacent to itself) are ignored.  When
 * \a size tokens have been written to \a vector, the rest of the
 * string is ignored.
 * @param[in,out] list Input buffer.
 * @param[in] token Delimiter used to split \a list.
 * @param[out] vector Output vector.
 * @param[in] size Maximum number of elements to put in \a vector.
 * @return Number of elements written to \a vector.
 */
int token_vector(char* list, char token, char** vector, int size)
{
  int   count = 0;
  char* start = list;
  char* end;

  assert(0 != list);
  assert(0 != vector);
  assert(1 < size);
 
  vector[count++] = start;
  for (end = strchr(start, token); end; end = strchr(start, token)) {
    *end++ = '\0';
    start = end;
    if (*start) {
      vector[count++] = start;
      if (count < size)
        continue;
    }
    break;
  }
  return count;
} 

/** Copy all or part of the hostname in a string to another string.
 * If \a userhost contains an '\@', the remaining portion is used;
 * otherwise, the whole \a userhost is used.
 * @param[out] host Output buffer.
 * @param[in] userhost user\@hostname or hostname string.
 * @param[in] n Maximum number of bytes to write to \a host.
 * @return The output buffer \a buf.
 */
char* host_from_uh(char* host, const char* userhost, size_t n)
{
  const char* s;

  assert(0 != host);
  assert(0 != userhost);

  if ((s = strchr(userhost, '@')))
    ++s;
  else
    s = userhost;
  ircd_strncpy(host, s, n);
  host[n] = '\0';
  return host;
}

/* 
 * this new faster inet_ntoa was ripped from:
 * From: Thomas Helvey <tomh@inxpress.net>
 */
/** Array of text strings for dotted quads. */
static const char* IpQuadTab[] =
{
    "0",   "1",   "2",   "3",   "4",   "5",   "6",   "7",   "8",   "9",
   "10",  "11",  "12",  "13",  "14",  "15",  "16",  "17",  "18",  "19",
   "20",  "21",  "22",  "23",  "24",  "25",  "26",  "27",  "28",  "29",
   "30",  "31",  "32",  "33",  "34",  "35",  "36",  "37",  "38",  "39",
   "40",  "41",  "42",  "43",  "44",  "45",  "46",  "47",  "48",  "49",
   "50",  "51",  "52",  "53",  "54",  "55",  "56",  "57",  "58",  "59",
   "60",  "61",  "62",  "63",  "64",  "65",  "66",  "67",  "68",  "69",
   "70",  "71",  "72",  "73",  "74",  "75",  "76",  "77",  "78",  "79",
   "80",  "81",  "82",  "83",  "84",  "85",  "86",  "87",  "88",  "89",
   "90",  "91",  "92",  "93",  "94",  "95",  "96",  "97",  "98",  "99",
  "100", "101", "102", "103", "104", "105", "106", "107", "108", "109",
  "110", "111", "112", "113", "114", "115", "116", "117", "118", "119",
  "120", "121", "122", "123", "124", "125", "126", "127", "128", "129",
  "130", "131", "132", "133", "134", "135", "136", "137", "138", "139",
  "140", "141", "142", "143", "144", "145", "146", "147", "148", "149",
  "150", "151", "152", "153", "154", "155", "156", "157", "158", "159",
  "160", "161", "162", "163", "164", "165", "166", "167", "168", "169",
  "170", "171", "172", "173", "174", "175", "176", "177", "178", "179",
  "180", "181", "182", "183", "184", "185", "186", "187", "188", "189",
  "190", "191", "192", "193", "194", "195", "196", "197", "198", "199",
  "200", "201", "202", "203", "204", "205", "206", "207", "208", "209",
  "210", "211", "212", "213", "214", "215", "216", "217", "218", "219",
  "220", "221", "222", "223", "224", "225", "226", "227", "228", "229",
  "230", "231", "232", "233", "234", "235", "236", "237", "238", "239",
  "240", "241", "242", "243", "244", "245", "246", "247", "248", "249",
  "250", "251", "252", "253", "254", "255"
};

/** Convert an IP address to printable ASCII form.
 * This is generally deprecated in favor of ircd_ntoa_r().
 * @param[in] in Address to convert.
 * @return Pointer to a static buffer containing the readable form.
 */
const char* ircd_ntoa(const char* in)
{
  static char buf[20];
  return ircd_ntoa_r(buf, in);
}

/** Convert an IP address to printable ASCII form.
 * @param[out] buf Output buffer to write to.
 * @param[in] in Address to format.
 * @return Pointer to the output buffer \a buf.
 */
const char* ircd_ntoa_r(char* buf, const char* in)
{
  char*                p = buf;
  const unsigned char* a = (const unsigned char*)in;
  const char*          n;

  assert(0 != buf);
  assert(0 != in);

  n = IpQuadTab[*a++];
  while ((*p = *n++))
    ++p;
  *p++ = '.';
  n = IpQuadTab[*a++];
  while ((*p = *n++))
    ++p;
  *p++ = '.';
  n = IpQuadTab[*a++];
  while ((*p = *n++))
    ++p;
  *p++ = '.';
  n = IpQuadTab[*a];
  while ((*p = *n++))
    ++p;
  return buf;
}

/** Normalize buffer stripping control characters and colors
 * @param[in] buf A string to be parsed for control and color codes
 * @return A string stripped of control and color codes
 */
char *normalizeBuffer(char *buf)
{
    char *newbuf;
    int i, len, j = 0;

    if (!buf)
      return 0;

    len = strlen(buf);
    newbuf = (char *) malloc(sizeof(char) * len + 1);

    for (i = 0; i < len; i++) {
        switch (buf[i]) {
            /* ctrl char */
        case 1:
            break;
            /* Bold ctrl char */
        case 2:
            break;
            /* Color ctrl char */
        case 3:
            /* If the next character is a digit, its also removed */
            if (IsDigit(buf[i + 1])) {
                i++;

                /* not the best way to remove colors
                 * which are two digit but no worse then
                 * how the Unreal does with +S - TSL
                 */
                if (IsDigit(buf[i + 1])) {
                    i++;
                }

                /* Check for background color code
                 * and remove it as well
                 */
                if (buf[i + 1] == ',') {
                    i++;

                    if (IsDigit(buf[i + 1])) {
                        i++;
                    }
                    /* not the best way to remove colors
                     * which are two digit but no worse then
                     * how the Unreal does with +S - TSL
                     */
                    if (IsDigit(buf[i + 1])) {
                        i++;
                    }
                }
            }

            break;
            /* tabs char */
        case 9:
            break;
            /* line feed char */
        case 10:
            break;
            /* carrage returns char */
        case 13:
            break;
            /* Reverse ctrl char */
        case 22:
            break;
            /* Underline ctrl char */
        case 31:
            break;
            /* A valid char gets copied into the new buffer */
        default:
            newbuf[j] = buf[i];
            j++;
        }
    }

    /* Terminate the string */
    newbuf[j] = 0;

    return (newbuf);
}

/** Clean up the buffer for extra spaces
 * @param[in] str to clean up
 * @return void
 */
void doCleanBuffer(char *str)
{
    char *in, *out;
    char ch;

    if (!str) {
        return;
    }

    in = str;
    out = str;

    while (issp(ch = *in++));
    if (ch != '\0')
        for (;;) {
            *out++ = ch;
            ch = *in++;
            if (ch == '\0')
                break;
            if (!issp(ch))
                continue;
            while (issp(ch = *in++));
            if (ch == '\0')
                break;
            *out++ = ' ';
        }
    *out = ch;                  /* == '\0' */
}

/** Pull a string out from inside of a given string.
 * @param[in] pstr String that contains the text that will be pulled out.
 * @param[in] start Starting character number.
 * @param[in] numchars Number of characters from start that will be pulled.
 * return substr'ed string
 */
char *substr(const char *pstr, int start, int numchars)
{
  char *pnew = malloc(numchars+1);
  strncpy(pnew, pstr + start, numchars);
  pnew[numchars] = '\0';
  return pnew;
}

char *my_strcasestr(char *haystack, char *needle) {
  int i;
  int nlength = strlen (needle);
  int hlength = strlen (haystack);

  if (nlength > hlength) return NULL;
  if (hlength <= 0) return NULL;
  if (nlength <= 0) return haystack;
  for (i = 0; i <= (hlength - nlength); i++) {
    if (strncasecmp (haystack + i, needle, nlength) == 0)
      return haystack + i;
  }
  return NULL; /* not found */
}

void parse_word(const char *s, char **word, int *type)
{
  static char buf[512];
  const char *tmp;
  int len;
  int tpe = 0;
  char *o = buf;

  for (tmp = s; *tmp; tmp++)
  {
    if (*tmp != '*')
      *o++ = *tmp;
    else
    {
      if (s == tmp)
        tpe |= TEXTBAN_WORD_LEFT;
      if (*(tmp + 1) == '\0')
        tpe |= TEXTBAN_WORD_RIGHT;
    }
  }
  *o = '\0';

  *word = buf;
  *type = tpe;
}

int textban_replace(int type, char *badword, char *replace, char *line, char *buf)
{
  char *replacew;
  char *pold = line, *pnew = buf; /* Pointers to old string and new string */
  char *poldx = line;
  int replacen;
  int searchn = -1;
  char *startw, *endw;
  char *c_eol = buf + 510 - 1; /* Cached end of (new) line */
  int cleaned = 0;

  replacew = strdup(replace);
  replacen = strlen(replacew);

  while (1) {
    pold = my_strcasestr(pold, badword);
    if (!pold)
      break;
    if (searchn == -1)
      searchn = strlen(badword);
    /* Hunt for start of word */
    if (pold > line) {
      for (startw = pold; (!IsSpace(*startw) && (startw != line)); startw--);
        if (IsSpace(*startw))
          startw++; /* Don't point at the space/seperator but at the word! */
    } else {
      startw = pold;
    }

    if (!(type & TEXTBAN_WORD_LEFT) && (pold != startw)) {
      /* not matched */
      pold++;
      continue;
    }

    /* Hunt for end of word */
    for (endw = pold; ((*endw != '\0') && (!IsSpace(*endw))); endw++);

    if (!(type & TEXTBAN_WORD_RIGHT) && (pold+searchn != endw)) {
      /* not matched */
      pold++;
      continue;
    }

    cleaned = 1; /* still too soon? Syzop/20050227 */

    if (poldx != startw) {
      int tmp_n = startw - poldx;
      if (pnew + tmp_n >= c_eol) {
        /* Partial copy and return... */
        memcpy(pnew, poldx, c_eol - pnew);
        *c_eol = '\0';
        return 1;
      }

      memcpy(pnew, poldx, tmp_n);
      pnew += tmp_n;
    }
    /* Now update the word in buf (pnew is now something like startw-in-new-buffer */

    if (replacen) {
       if ((pnew + replacen) >= c_eol) {
         /* Partial copy and return... */
         memcpy(pnew, replacew, c_eol - pnew);
         *c_eol = '\0';
         return 1;
       }
       memcpy(pnew, replacew, replacen);
       pnew += replacen;
     }
     poldx = pold = endw;
  }
  /* Copy the last part */
  if (*poldx) {
    strncpy(pnew, poldx, c_eol - pnew);
    *(c_eol) = '\0';
  } else {
    *pnew = '\0';
  }
  return cleaned;
}

int explode_line(char *line, int irc_colon, int argv_size, char *argv[])
{
    int argc = 0, bail = 0;
    int n;
    char ch, *linebkp;
    char *lineb;

    while (*line && (argc < argv_size)) {
        while (*line == ':')
            *line++ = 0;
        if (!*line)
            break;
        argv[argc++] = line;

        if (argc >= argv_size)
            break;

        while (*line) {
            bail = 0;
            switch (*line) {
                case 58: /* : */
                    bail = 1;
                    break;
                case 92: /* / */
                    if (irc_colon == 0) {
                        lineb = strdup(line + 1);
                        sprintf(line, "%s", lineb);
                    }
                    line++;
                    line++;
                    break;
                default:
                    line++;
            }
            if (bail)
                break;
        }
    }

    for (n=argc; n<argv_size; n++)
        argv[n] = (char*)0xFEEDBEEF;

    return argc;
}
