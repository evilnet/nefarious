/*
 * IRC - Internet Relay Chat, ircd/m_topic.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 *
 * See file AUTHORS in IRC package for additional names of
 * the programmers.
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

/*
 * m_functions execute protocol messages on this server:
 *
 *    cptr    is always NON-NULL, pointing to a *LOCAL* client
 *            structure (with an open socket connected!). This
 *            identifies the physical socket where the message
 *            originated (or which caused the m_function to be
 *            executed--some m_functions may call others...).
 *
 *    sptr    is the source of the message, defined by the
 *            prefix part of the message if present. If not
 *            or prefix not found, then sptr==cptr.
 *
 *            (!IsServer(cptr)) => (cptr == sptr), because
 *            prefixes are taken *only* from servers...
 *
 *            (IsServer(cptr))
 *                    (sptr == cptr) => the message didn't
 *                    have the prefix.
 *
 *                    (sptr != cptr && IsServer(sptr) means
 *                    the prefix specified servername. (?)
 *
 *                    (sptr != cptr && !IsServer(sptr) means
 *                    that message originated from a remote
 *                    user (not local).
 *
 *            combining
 *
 *            (!IsServer(sptr)) means that, sptr can safely
 *            taken as defining the target structure of the
 *            message in this server.
 *
 *    *Always* true (if 'parse' and others are working correct):
 *
 *    1)      sptr->from == cptr  (note: cptr->from == cptr)
 *
 *    2)      MyConnect(sptr) <=> sptr == cptr (e.g. sptr
 *            *cannot* be a local connection, unless it's
 *            actually cptr!). [MyConnect(x) should probably
 *            be defined as (x == x->from) --msa ]
 *
 *    parc    number of variable parameter strings (if zero,
 *            parv is allowed to be NULL)
 *
 *    parv    a NULL terminated list of parameter pointers,
 *
 *                    parv[0], sender (prefix string), if not present
 *                            this points to an empty string.
 *                    parv[1]...parv[parc-1]
 *                            pointers to additional parameters
 *                    parv[parc] == NULL, *always*
 *
 *            note:   it is guaranteed that parv[0]..parv[parc-1] are all
 *                    non-NULL pointers.
 */
#include "config.h"

#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"

#include <assert.h>
#include <stdlib.h>

static void do_settopic(struct Client *sptr, struct Client *cptr, 
		        struct Channel *chptr, char *topic, time_t ts, char *setter)
{
   int newtopic;
   char *nickb, *nick = NULL;
   struct Client *from;

   if (feature_bool(FEAT_HIS_BANWHO) && IsServer(sptr)) {
      from = &me;
   }
   else {
      from = sptr;
   }

   /* Note if this is just a refresh of an old topic, and don't
    * send it to all the clients to save bandwidth.  We still send
    * it to other servers as they may have split and lost the topic.
    */
   newtopic=ircd_strncmp(chptr->topic,topic,TOPICLEN)!=0;
   /* setting a topic */
   ircd_strncpy(chptr->topic, topic, TOPICLEN);
   if (setter) {
     if (feature_bool(FEAT_HOST_IN_TOPIC)) {
       ircd_strncpy(chptr->topic_nick, setter, NICKLEN+USERLEN+HOSTLEN+3);
       for (nick = strtok_r(setter, "!", &nickb);
            nick;
            nick = strtok_r(NULL, "!", &nickb))
       {
       }
     } else
       ircd_strncpy(chptr->topic_nick, setter, NICKLEN);
   } else {
     ircd_strncpy(chptr->topic_nick, cli_name(from), NICKLEN);
     if (feature_bool(FEAT_HOST_IN_TOPIC) && !IsServer(sptr)) {
       strcat(chptr->topic_nick, "!");
       strcat(chptr->topic_nick, cli_username(from));
       strcat(chptr->topic_nick, "@");
       strcat(chptr->topic_nick, cli_user(from)->host);
     }
   }
   chptr->topic_time = ts ? ts : TStime();
   /* Fixed in 2.10.11: Don't propagate local topics */
   if (!IsLocalChannel(chptr->chname))
     sendcmdto_serv_butone(sptr, CMD_TOPIC, cptr, "%H %s %Tu %Tu :%s", chptr,
			   chptr->topic_nick, chptr->creationtime, chptr->topic_time,
                           chptr->topic);

   if (newtopic) {
      if (IsServer(sptr))
        sendcmdto_channel_butserv_butone(from, CMD_TOPIC, chptr, NULL, 0,
       				         "%H :%s (%s)", chptr, chptr->topic,
                                         setter ? (nick ? nick : setter) : cli_name(from));

      else if (IsChannelService(sptr))
        sendcmdto_channel_butserv_butone(from, CMD_TOPIC, chptr, NULL, 0,
      		                         "%H :%s%s%s%s", chptr, chptr->topic,
                                         setter ? " (" : "",
                                         setter ? (nick ? nick : setter) : cli_name(from),
                                         setter ? ")" : "");
      else
        sendcmdto_channel_butserv_butone(from, CMD_TOPIC, chptr, NULL, 0,
       				         "%H :%s", chptr, chptr->topic);
      /* if this is the same topic as before we send it to the person that
       * set it (so they knew it went through ok), but don't bother sending
       * it to everyone else on the channel to save bandwidth
       */
    } else if (MyUser(sptr))
      sendcmdto_one(sptr, CMD_TOPIC, sptr, "%H :%s", chptr, chptr->topic);
}

/*
 * m_topic - generic message handler
 *
 * parv[0]        = sender prefix
 * parv[1]        = channel
 * parv[parc - 1] = topic (if parc > 2)
 */
int m_topic(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel *chptr;
  char *topic = 0, *name, *p = 0, *topicnocolour = 0;
  int hascolour = -1;
  struct Membership *member;

  if (parc < 2)
    return need_more_params(sptr, "TOPIC");

  if (parc > 2)
    topic = parv[parc - 1];

  for (; (name = ircd_strtok(&p, parv[1], ",")); parv[1] = 0)
  {
    chptr = 0;
    /* Does the channel exist */
    if (!IsChannelName(name) || !(chptr = FindChannel(name)))
    {
    	send_reply(sptr,ERR_NOSUCHCHANNEL,name);
    	continue;
    }
    member = find_channel_member(sptr, chptr);
    /* Trying to check a topic outside a secret channel */
    if ((topic || SecretChannel(chptr)) && !member)
    {
      send_reply(sptr, ERR_NOTONCHANNEL, chptr->chname);
      continue;
    }

    if (!topic)                 /* only asking for topic */
    {
      if (chptr->topic[0] == '\0')
	send_reply(sptr, RPL_NOTOPIC, chptr->chname);
      else
      {
	send_reply(sptr, RPL_TOPIC, chptr->chname, chptr->topic);
	send_reply(sptr, RPL_TOPICWHOTIME, chptr->chname, chptr->topic_nick,
		   chptr->topic_time);
      }
    }
    else {
      /* if +t and not @'d, return an error and ignore the topic */
      if ((chptr->mode.mode & MODE_TOPICLIMIT) != 0 && !IsChanOp(member)
	  && !IsHalfOp(member)) {
        send_reply(sptr, ERR_CHANOPRIVSNEEDED, chptr->chname);
        continue;
      }
      /* if chan +m and user not an exception, return error and ignore */
      if (!client_can_send_to_channel(sptr, chptr)) {
        send_reply(sptr, ERR_CANNOTSENDTOCHAN, chptr->chname, "(Moderated channel (+m))");
        continue;
      }
      if (chptr->mode.mode & MODE_NOCOLOUR) {
	if (hascolour == -1) hascolour = HasColour(topic);
	if (hascolour) {
	  send_reply(sptr, ERR_CANNOTSENDTOCHAN, chptr->chname, "(Colors are disallowed (+c))");
	  continue;
	}
      }
      else if (chptr->mode.mode & MODE_STRIP) {
	if (hascolour == -1) hascolour = HasColour(topic);
	if (hascolour) {
	  if (!topicnocolour) topicnocolour = (char*)StripColour(topic);
	  do_settopic(sptr,cptr,chptr,topicnocolour,0,0);
	  continue;
	}
      }
      /* (kind of) fallthrough */
      do_settopic(sptr,cptr,chptr,topic,0,0);
    }
  }
  return 0;
}

/*
 * ms_topic - server message handler
 *
 * parv[0]        = sender prefix
 * parv[1]        = channel
 * parv[parc - 4] = topic setter (optional)
 * parv[parc - 3] = channel timestamp (optional)
 * parv[parc - 2] = topic timestamp (optional)
 * parv[parc - 1] = topic
 */
int ms_topic(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel *chptr;
  char *topic = 0, *name, *p = 0;
  int ppoint = 4;
  time_t ts = 0;

  if (parc < 3)
    return need_more_params(sptr, "TOPIC");

  topic = parv[parc - 1];

  for (; (name = ircd_strtok(&p, parv[1], ",")); parv[1] = 0)
  {
    chptr = 0;
    /* Does the channel exist */
    if (!IsChannelName(name) || !(chptr = FindChannel(name)))
    {
    	send_reply(sptr,ERR_NOSUCHCHANNEL,name);
    	continue;
    }

    /* Ignore requests for topics from remote servers */
    if (IsLocalChannel(name) && !MyUser(sptr))
    {
      protocol_violation(sptr,"Topic request");
      continue;
    }

    /* if existing channel is older, ignore -beware */
    if (parc > 5 && (ts = atoi(parv[parc - 3])) && chptr->creationtime < ts)
      continue;

    if (parc > 4 && (ts = atoi(parv[parc - 2])) && chptr->topic_time > ts)
      continue;

    if ('#' == *parv[parc-4])
      ppoint = 3;

    do_settopic(sptr,cptr,chptr,topic,ts,parv[parc-ppoint]);
  }
  return 0;
}
