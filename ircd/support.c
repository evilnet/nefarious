/*
 * IRC - Internet Relay Chat, ircd/support.c
 * Copyright (C) 1990, 1991 Armin Gruner
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
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

#include "support.h"
#include "fileio.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "ircd_snprintf.h"
#include "s_bsd.h"
#include "s_debug.h"
#include "send.h"
#include "sys.h"

#include <signal.h>   /* kill */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

int check_if_ipmask(const char *mask)
{
  int has_digit = 0;
  const char *p;

  for (p = mask; *p; ++p)
    if (*p != '*' && *p != '?' && *p != '.' && *p != '/')
    {
      if (!IsDigit(*p))
        return 0;
      has_digit = -1;
    }

  return has_digit;
}

/* Moved from logf() in whocmds.c to here. Modified a 
 * bit and used for most logging now.
 *  -Ghostwolf 12-Jul-99
 */

extern void write_log(const char *filename, const char *pattern, ...)
{
  FBFILE *logfile;
  va_list vl;
  static char logbuf[1024];

  logfile = fbopen(filename, "a");

  if (logfile)
  {
    va_start(vl, pattern);
    ircd_vsnprintf(0, logbuf, sizeof(logbuf) - 1, pattern, vl);
    va_end(vl);

    fbputs(logbuf, logfile);
    fbclose(logfile);
  }
}

/*
 * read a string terminated by \r or \n in from a fd
 *
 * Originally From: Ultimate IRCd
 * Originally Created: Sat Dec 12 06:29:58 EST 1992 by avalon
 * Returns:
 *     0 - EOF
 *     -1 - error on read
 *     >0 - number of bytes returned (<=num)
 * After opening a fd, it is necessary to init dgets() by calling it as
 *     dgets(x,y,0);
 * to mark the buffer as being empty.
 */
int    dgets(fd, buf, num)
int    fd, num;
char   *buf;
{
       static  char    dgbuf[8192];
       static  char    *head = dgbuf, *tail = dgbuf;
       register char   *s, *t;
       register int    n, nr;

       /*
        * Sanity checks.
        */
       if (head == tail)
               *head = '\0';
       if (!num)
           {
               head = tail = dgbuf;
               *head = '\0';
               return 0;
           }
       if (num > sizeof(dgbuf) - 1)
               num = sizeof(dgbuf) - 1;
dgetsagain:
       if (head > dgbuf)
           {
               for (nr = tail - head, s = head, t = dgbuf; nr > 0; nr--)
                       *t++ = *s++;
               tail = t;
               head = dgbuf;
           }
       /*
        * check input buffer for EOL and if present return string.
        */
       if (head < tail &&
           ((s = index(head, '\n')) || (s = index(head, '\r'))) && s < tail)
           {
               n = IRCD_MIN(s - head + 1, num);     /* at least 1 byte */
dgetsreturnbuf:
               bcopy(head, buf, n);
               head += n;
               if (head == tail)
                       head = tail = dgbuf;
               return n;
           }

       if (tail - head >= num)         /* dgets buf is big enough */
           {
               n = num;
               goto dgetsreturnbuf;
           }

       n = sizeof(dgbuf) - (tail - dgbuf) - 1;
       nr = read(fd, tail, n);
       if (nr == -1)
           {
               head = tail = dgbuf;
               return -1;
           }
       if (!nr)
           {
               if (head < tail)
                   {
                       n = IRCD_MIN(tail - head, num);
                       goto dgetsreturnbuf;
                   }
               head = tail = dgbuf;
               return 0;
           }
       tail += nr;
       *tail = '\0';
       for (t = head; (s = index(t, '\n')); )
           {
               if ((s > head) && (s > dgbuf))
                   {
                       t = s-1;
                       for (nr = 0; *t == '\\'; nr++)
                               t--;
                       if (nr & 1)
                           {
                               t = s+1;
                               s--;
                               nr = tail - t;
                               while (nr--)
                                       *s++ = *t++;
                               tail -= 2;
                               *tail = '\0';
                           }
                       else
                               s++;
                   }
               else
                       s++;
               t = s;
           }
       *tail = '\0';
       goto dgetsagain;
}


static long
TypeLength(char type)
{
    switch (type) {
    case 'y': return 365*24*60*60;
    case 'M': return 31*24*60*60;
    case 'w': return 7*24*60*60;
    case 'd': return 24*60*60;
    case 'h': return 60*60;
    case 'm': return 60;
    case 's': return 1;
    default: return 0;
    }
}


unsigned long
ParseInterval(const char *interval)
{
    unsigned long seconds = 0;
    int partial = 0;
    char c;

    /* process the string, resetting the count if we find a unit character */
    while ((c = *interval++)) {
        if (IsDigit((int)c)) {
            partial = partial*10 + c - '0';
        } else {
            seconds += TypeLength(c) * partial;
            partial = 0;
        }
    }
    /* assume the last chunk is seconds (the normal case) */
    return seconds + partial;
}


int is_timestamp(char *str)
{

  while ( IsDigit(*str) || *str == '.' )
    ++str;

  return *str == '\0';
}
