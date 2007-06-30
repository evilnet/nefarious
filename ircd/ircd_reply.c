/*
 * IRC - Internet Relay Chat, ircd/m_proto.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 *
 * See file AUTHORS in IRC package for additional names of
 * the programmers.
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

#include "ircd_reply.h"
#include "client.h"
#include "ircd.h"
#include "ircd_snprintf.h"
#include "msg.h"
#include "msgq.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_debug.h"
#include "send.h"

#include <assert.h>
#include <string.h>


char message[BUFSIZE + 1];  /* OUTPUT */

/* Report a protocol violation warning to anyone listening.  This can be
 * easily used to cleanup the last couple of parts of the code up.
 */
 
int protocol_violation(struct Client* cptr, const char* pattern, ...)
{
  struct VarData vd;

  assert(pattern);
  assert(cptr);

  vd.vd_format = pattern;
  va_start(vd.vd_args, pattern);

  sendwallto_group_butone(&me, WALL_DESYNCH, NULL,
			"Protocol Violation from %s: %v", cli_name(cptr), &vd);

  va_end(vd.vd_args);
  return 0;
}

int need_more_params(struct Client* cptr, const char* cmd)
{
  send_reply(cptr, ERR_NEEDMOREPARAMS, cmd);
  return 0;
}

int send_reply(struct Client *to, int reply, ...)
{
  struct VarData vd;
  struct MsgBuf *mb;
  const struct Numeric *num;

  assert(0 != to);
  assert(0 != reply);

  num = get_error_numeric(reply & ~SND_EXPLICIT); /* get reply... */

  va_start(vd.vd_args, reply);

  if (reply & SND_EXPLICIT) /* get right pattern */
    vd.vd_format = (const char *) va_arg(vd.vd_args, char *);
  else
    vd.vd_format = num->format;

  assert(0 != vd.vd_format);

  /* build buffer */
  mb = msgq_make(cli_from(to), "%:#C %s %C %v", &me, num->str, to, &vd);

  va_end(vd.vd_args);

  /* send it to the user */
  send_buffer(to, mb, 0);

  msgq_clean(mb);

  return 0; /* convenience return */
}


extern char *format_dnsbl_msg(char *dnsblip, char *dnsblhost, char *dnsbluser,
                              char *dnsblnick, char *format)
{
   unsigned short pos = 0;   /* position in format */
   unsigned short len = 0;   /* position in message */
   unsigned short size = 0;  /* temporary size buffer */

   unsigned int i;

   struct dnsbl_format_assoc table[] =
      {
         {'i',   (void *) NULL,         FORMATTYPE_STRING },
         {'h',   (void *) NULL,         FORMATTYPE_STRING },
         {'u',   (void *) NULL,         FORMATTYPE_STRING },
         {'n',   (void *) NULL,         FORMATTYPE_STRING },

      };

   table[0].data = dnsblip;
   table[1].data = dnsblhost;
   table[2].data = dnsbluser;
   table[3].data = dnsblnick;

   /*
    * Copy format to message character by character, inserting any matching
    * data after %.
    */
   while(format[pos] != '\0' && len < (BUFSIZE - 1))
   {
      switch(format[pos])
      {

         case '%':
            /* % is the last char in the string, move on */
            if(format[pos + 1] == '\0')
               continue;

            /* %% escapes % and becomes % */
            if(format[pos + 1] == '%')
            {
               message[len++] = '%';
               pos++; /* skip past the escaped % */
               break;
            }
            /* Safe to check against table now */
            for(i = 0; i < (sizeof(table) / sizeof(struct dnsbl_format_assoc)); i++)
            {
               if(table[i].key == format[pos + 1])
               {
                  switch(table[i].type)
                  {
                     case FORMATTYPE_STRING:

                        size = strlen( (char *) table[i].data);

                        /* Check if the new string can fit! */
                        if( (size + len) > BUFSIZE )
                           break;
                        else
                        {
                           strcat(message, (char *) table[i].data);
                           len += size;
                        }

                     default:
                        break;
                  }
               }
            }
            /* Skip key character */
            pos++;
            break;

         default:
            message[len++] = format[pos];
            message[len] = '\0';
            break;
      }
      /* continue to next character in format */
      pos++;
   }

  return message;
}


extern char *format_message(char *nick, char *ident, char *host, char *ip,
                            char *channel, char *format)
{
   unsigned short pos = 0;   /* position in format */
   unsigned short len = 0;   /* position in message */
   unsigned short size = 0;  /* temporary size buffer */

   unsigned int i;

   struct message_format_assoc table[] = {
     {'n',   (void *) NULL,         FORMATTYPE_STRING },
     {'i',   (void *) NULL,         FORMATTYPE_STRING },
     {'h',   (void *) NULL,         FORMATTYPE_STRING },
     {'i',   (void *) NULL,         FORMATTYPE_STRING },
     {'c',   (void *) NULL,         FORMATTYPE_STRING },
   };

   table[0].data = nick;
   table[1].data = ident;
   table[2].data = host;
   table[3].data = ip;
   table[4].data = channel;

   /*
    * Copy format to message character by character, inserting any matching
    * data after %.
    */
   while(format[pos] != '\0' && len < (BUFSIZE - 1)) {
      switch(format[pos]) {

         case '%':
            /* % is the last char in the string, move on */
            if(format[pos + 1] == '\0')
               continue;

            /* %% escapes % and becomes % */
            if(format[pos + 1] == '%') {
               message[len++] = '%';
               pos++; /* skip past the escaped % */
               break;
            }
            /* Safe to check against table now */
            for(i = 0; i < (sizeof(table) / sizeof(struct message_format_assoc)); i++) {
               if(table[i].key == format[pos + 1]) {
                  switch(table[i].type) {
                     case FORMATTYPE_STRING:

                        size = strlen( (char *) table[i].data);

                        /* Check if the new string can fit! */
                        if( (size + len) > BUFSIZE )
                           break;
                        else {
                           strcat(message, (char *) table[i].data);
                           len += size;
                        }

                     default:
                        break;
                  }
               }
            }
            /* Skip key character */
            pos++;
            break;

         default:
            message[len++] = format[pos];
            message[len] = '\0';
            break;
      }
      /* continue to next character in format */
      pos++;
   }

  return message;
}

