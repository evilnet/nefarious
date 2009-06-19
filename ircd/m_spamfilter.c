/*
 * IRC - Internet Relay Chat, ircd/m_spamfilter.c
 * Copyright (C) 2009 Neil Spierling <sirvulcan@sirvulcan.co.nz>
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

#include "client.h"
#include "spamfilter.h"
#include "gline.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "opercmds.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_user.h"
#include "send.h"
#include "spamfilter.h"
#include "support.h"
#include "zline.h"

#include <stdlib.h>
#include <string.h>

#ifdef PCRE_SYSTEM
#include <pcre.h>
#include <pcreposix.h>
#else
#include "pcre.h"
#include "pcreposix.h"
#endif

struct SpamFilter* GlobalSpamFilterList  = 0;

/** Deactivate a Spam Filter.
 * @param[in] regex Raw regex string thats checked against the list.
 * @param[in] rflags React flags that are check against the list.
 * @param[in] wflags Watch flags that are check against the list.
 * @return Spamfilter entry if one is found.
 */
static struct SpamFilter*
spamfilter_find(char *regex, char *rflags, char *wflags)
{
  struct SpamFilter *spamfilter;
  struct SpamFilter *sspamfilter;

  for (spamfilter = GlobalSpamFilterList; spamfilter; spamfilter = sspamfilter) {
    sspamfilter = spamfilter->sf_next;
    if ((ircd_strcmp(spamfilter->sf_rawfilter, regex) == 0) &&
        (ircd_strcmp(spamfilter->sf_rflags, rflags) == 0) &&
        (ircd_strcmp(spamfilter->sf_wflags, wflags) == 0))
      break;
  }

  return spamfilter;
}

/** Free up a spamfilter from the SpamFilter struct
 * @param[in] spamfilter Pointer to the spamfilter that needs to be free'ed
 */
void
spamfilter_free(struct SpamFilter *spamfilter)
{
  assert(0 != spamfilter);

  *spamfilter->sf_prev_p = spamfilter->sf_next; /* squeeze this spamfilter out */
  if (spamfilter->sf_next)
    spamfilter->sf_next->sf_prev_p = spamfilter->sf_prev_p;

  pcre_free(spamfilter->sf_filter);
  MyFree(spamfilter->sf_rawfilter);
  MyFree(spamfilter->sf_rflags);
  MyFree(spamfilter->sf_wflags);
  MyFree(spamfilter->sf_reason);
  if (spamfilter->sf_nchan);
    MyFree(spamfilter->sf_nchan);
  MyFree(spamfilter);
}

/** Checks through the SpamFilter struct for any filters that have expired */
void
spamfilter_check_expires()
{
  struct SpamFilter *spamfilter;
  struct SpamFilter *sspamfilter;

  for (spamfilter = GlobalSpamFilterList; spamfilter; spamfilter = sspamfilter) {
    sspamfilter = spamfilter->sf_next;
    if (spamfilter->sf_expire <= CurrentTime)
      spamfilter_free(spamfilter);
  }
}

/** Report Spam Filters to a client.
 * @param[in] sptr Client requesting statistics.
 * @param[in] sd Stats descriptor for request (ignored).
 * @param[in] param Extra parameter from user (ignored).
 */
void
spamfilter_stats(struct Client* to, const struct StatDesc *sd, char* param)
{
  struct SpamFilter *spamfilter;
  struct SpamFilter *sspamfilter;

  /* No header is sent as this function is requested just after the conf based
   * Spam Filters have been reported. */
  for (spamfilter = GlobalSpamFilterList; spamfilter; spamfilter = sspamfilter) {
    sspamfilter = spamfilter->sf_next;
    send_reply(to, RPL_STATSFILTERLINE, spamfilter->sf_rawfilter, spamfilter->sf_wflags ?
               spamfilter->sf_wflags : "", spamfilter->sf_rflags ? spamfilter->sf_rflags : "",
               spamfilter->sf_length, SpamFilterIsActive(spamfilter) ? "active" : "deactivated",
               spamfilter->sf_expire, spamfilter->sf_reason);
  }
}

/** Add a Spam Filter (from a client).
 * @param[in] sptr Client requesting the addition of the SpamFilter.
 * @param[in] regex Regex in the form of a string.
 * @param[in] rflags Reaction flags.
 * @param[in] wflags Watch flags.
 * @param[in] reason Reason given for the SpamFilter.
 * @param[in] expire Length in seconds.
 * @return spamfilter Newly created or activated entry in the SpamFilter struct.
 */
static struct SpamFilter *
spamfilter_add(struct Client* sptr, char *regex, char *rflags, char *wflags, char *reason,
               time_t expire)
{
  struct SpamFilter *spamfilter;
  char *errbuf;
  char *msg = NULL;
  const char *error;
  int erroffset;
  int activate = 0;
  int updated = 0;

  if ((errbuf = checkregex(regex,0))) {
    send_reply(sptr, ERR_INVALIDREGEX, regex, errbuf);
    return 0;
  }

  if ((spamfilter = spamfilter_find(regex, rflags, wflags))) {
    if (!SpamFilterIsActive(spamfilter)) {
      spamfilter->sf_flags |= SPAMFILTER_ACTIVE;
      msg = "activating";
      activate = 1;
    }

    if (ircd_strcmp(spamfilter->sf_reason, reason)) {
      DupString(spamfilter->sf_reason, reason);
      if (msg && strlen(msg) > 0)
        msg = "activating+updating";
      else
        msg = "updating";
      updated = 1;
    }

    if (expire > spamfilter->sf_expire) {
      spamfilter->sf_expire = expire;
      if (msg && strlen(msg) > 8)
        msg = "activating+updating";
      else
        msg = "updating";
      updated = 1;
    }

    if (!updated && !activate)
      return 0;
  } else {
    spamfilter = (struct SpamFilter *)MyMalloc(sizeof(struct SpamFilter)); /* alloc memory */
    assert(0 != spamfilter);

    spamfilter->sf_filter = pcre_compile(regex, PCRE_CASELESS|PCRE_EXTENDED, &error, &erroffset, NULL);
    DupString(spamfilter->sf_rawfilter, regex);
    DupString(spamfilter->sf_rflags, rflags);
    DupString(spamfilter->sf_wflags, wflags);
    DupString(spamfilter->sf_reason, reason);

    spamfilter->sf_flags |= SPAMFILTER_ACTIVE;

    DupString(spamfilter->sf_nchan, feature_str(FEAT_FILTER_DEFAULT_CHANNAME));
    spamfilter->sf_expire = expire;
    spamfilter->sf_length = feature_int(FEAT_FILTER_DEFAULT_LENGTH);

    spamfilter->sf_next = GlobalSpamFilterList; /* then link it into list */
    spamfilter->sf_prev_p = &GlobalSpamFilterList;
    if (GlobalSpamFilterList)
      GlobalSpamFilterList->sf_prev_p = &spamfilter->sf_next;
    GlobalSpamFilterList = spamfilter;
    msg = "adding";
  }

  if (spamfilter) {
    sendto_opmask_butone(0, SNO_GLINE, "%s %s SPAMFILTER %s, expiring at "
                         "%Tu: %s",
                         feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr) ?
                         cli_name(sptr) : cli_name((cli_user(sptr))->server),
                         msg, regex, expire, decodespace(reason));

    return spamfilter;
  } else
    return 0;
}

/** Add a Spam Filter (from a server).
 * @param[in] sptr Client requesting the addition of the SpamFilter.
 * @param[in] regex Regex in the form of a string.
 * @param[in] rflags Reaction flags.
 * @param[in] wflags Watch flags.
 * @param[in] reason Reason given for the SpamFilter.
 * @param[in] expire Length in seconds.
 * @param[in] add 1 for adding, 0 for adding a deactivated SpamFilter.
 * @return spamfilter Newly created or activated entry in the SpamFilter struct.
 */
static struct SpamFilter *
spamfilter_server_add(struct Client* sptr, char *regex, char *rflags, char *wflags, char *reason,
               time_t expire, int add)
{
  struct SpamFilter *spamfilter;
  const char *error;
  int erroffset;
  int a = 0, d = 0;
  char *msg;

  if ((spamfilter = spamfilter_find(regex, rflags, wflags))) {
    if (!SpamFilterIsActive(spamfilter) && add) {
      spamfilter->sf_flags |= SPAMFILTER_ACTIVE;
      msg = "activating";
      a = 1;
    } else if (SpamFilterIsActive(spamfilter) && !add) {
      spamfilter->sf_flags &= ~SPAMFILTER_ACTIVE;
      msg = "deactivating";
      d = 1;
    }

    if (ircd_strcmp(spamfilter->sf_reason, reason)) {
      DupString(spamfilter->sf_reason, reason);
      if (a == 1)
        msg = "activating+updating";
      else if (d == 1)
        msg = "deactivating+updating";
      else
        msg = "updating";
    }

    if (expire > spamfilter->sf_expire) {
      spamfilter->sf_expire = expire;
      if (a == 1)
        msg = "activating+updating";
      else if (d == 1)
        msg = "deactivating+updating";
      else
        msg = "updating";
    }
  } else {
    spamfilter = (struct SpamFilter *)MyMalloc(sizeof(struct SpamFilter)); /* alloc memory */
    assert(0 != spamfilter);

    spamfilter->sf_filter = pcre_compile(regex, PCRE_CASELESS|PCRE_EXTENDED, &error, &erroffset, NULL);
    DupString(spamfilter->sf_rawfilter, regex);
    DupString(spamfilter->sf_rflags, rflags);
    DupString(spamfilter->sf_wflags, wflags);
    DupString(spamfilter->sf_reason, reason);

    if (add) {
      msg = "adding";
      spamfilter->sf_flags |= SPAMFILTER_ACTIVE;
    } else {
      msg = "adding deactivated";
      spamfilter->sf_flags &= ~SPAMFILTER_ACTIVE;
    }

    DupString(spamfilter->sf_nchan, feature_str(FEAT_FILTER_DEFAULT_CHANNAME));
    spamfilter->sf_expire = expire;
    spamfilter->sf_length = feature_int(FEAT_FILTER_DEFAULT_LENGTH);

    spamfilter->sf_next = GlobalSpamFilterList; /* then link it into list */
    spamfilter->sf_prev_p = &GlobalSpamFilterList;
    if (GlobalSpamFilterList)
      GlobalSpamFilterList->sf_prev_p = &spamfilter->sf_next;
    GlobalSpamFilterList = spamfilter;
  }

  if (spamfilter) {
    sendto_opmask_butone(0, SNO_GLINE, "%s %s SPAMFILTER %s, expiring at "
                         "%Tu: %s",
                         feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr) ?
                         cli_name(sptr) : cli_name((cli_user(sptr))->server),
                         msg, regex, expire, decodespace(reason));

    return spamfilter;
  } else
    return 0;
}

/** Deactivate a Spam Filter.
 * @param[in] sptr Client that is deactivating the SpamFilter.
 * @param[in] regex Raw regex string thats checked against the list.
 * @param[in] rflags React flags that are check against the list.
 * @param[in] wflags Watch flags that are check against the list.
 */
static struct SpamFilter*
spamfilter_deactivate(struct Client* sptr, char *regex, char *rflags, char *wflags)
{
  struct SpamFilter *spamfilter;

  if ((spamfilter = spamfilter_find(regex, rflags, wflags))) {
    if (!SpamFilterIsActive(spamfilter))
      return 0;

    spamfilter->sf_flags &= ~SPAMFILTER_ACTIVE;

    sendto_opmask_butone(0, SNO_GLINE, "%s deactivating SPAMFILTER %s, expiring at "
                         "%Tu: %s",
                         feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr) ?
                         cli_name(sptr) : cli_name((cli_user(sptr))->server), regex,
                         spamfilter->sf_expire, decodespace(spamfilter->sf_reason));

    return spamfilter;
  }

  return 0;
}

/** Send out a list of all SpamFilters to a linking server
 * @param[in] cptr Client pointer to the linking server.
 */
void
spamfilter_burst(struct Client *cptr)
{
  struct SpamFilter *spamfilter;
  struct SpamFilter *sspamfilter;

  for (spamfilter = GlobalSpamFilterList; spamfilter; spamfilter = sspamfilter) { /* all spamfilters */
    sspamfilter = spamfilter->sf_next;

    if (spamfilter->sf_expire <= CurrentTime) /* expire any that need expiring */
      spamfilter_free(spamfilter);
    else
      sendcmdto_one(&me, CMD_SPAMFILTER, cptr, "* %c %s %s %Tu %s :%s",
                    SpamFilterIsActive(spamfilter) ? '+' : '-', spamfilter->sf_wflags,
                    spamfilter->sf_rflags, spamfilter->sf_expire - CurrentTime,
                    spamfilter->sf_reason, spamfilter->sf_rawfilter);
  }
}

/** Remove a SpamFilter weather its deactivated or activated.
 * @param[in] sptr Client pointer to the person removing the spamfilter.
 * @param[in] mask Regular expression that needs to be removed.
 * @param[in] reason Reason for the removal.
 * @return 0
 */
int
spamfilter_remove(struct Client* sptr, char *mask, char *reason)
{
  struct SpamFilter *spamfilter, *sspamfilter;
  reason = decodespace(reason);

  for (spamfilter = GlobalSpamFilterList; spamfilter; spamfilter = sspamfilter) {
    sspamfilter = spamfilter->sf_next;

    if (spamfilter->sf_expire <= CurrentTime) {
      spamfilter_free(spamfilter);
    } else if (ircd_strcmp(spamfilter->sf_rawfilter, mask) == 0) {
      sendto_opmask_butone(0, SNO_GLINE, "%s force removing SPAMFILTER for %s (%s)",
                           feature_bool(FEAT_HIS_SNOTICES) || IsServer(sptr) ?
                           cli_name(sptr) : cli_name((cli_user(sptr))->server),
                           mask, reason);

      log_write(LS_GLINE, L_INFO, LOG_NOSNOTICE,
                "%#C force removing spamfilter for %s (%s)", sptr, mask, reason);

      spamfilter_free(spamfilter);
    }
  }

  return 0;
}

/** Handle a SPAMFILTER message from an operator.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is either "+" or "-"
 * \li \a parv[2] is the watch flags
 * \li \a parv[3] is the react flags
 * \li \a parv[4] is the length in seconds
 * \li \a parv[5] is the reason
 * \li \a parv[\a parc - 1] is the regular expression
 *
 * All fields must be present.  Additionally, the time interval should
 * not be 0 for messages sent to "*", as that may not function
 * reliably due to buffering in the server.
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int mo_spamfilter(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  int add = 0, remove = 0, exp = 0;
  char *wflags, *rflags, *reason, *regex, *ar;
  struct SpamFilter* spamfilter = NULL;
  time_t expire;

  if (!HasPriv(sptr, PRIV_SPAMFILTER))
    return send_reply(sptr, ERR_NOPRIVILEGES);

  if (parc <= 1)
    return need_more_params(sptr, "SPAMFILTER");

  ar = parv[1];
  if (*ar == '+')
    add = 1;
  else if (*ar == '-')
    remove = 1;

  if ((parc < 6) && (add))
    return need_more_params(sptr, "SPAMFILTER");

  if ((parc < 4) && (remove))
    return need_more_params(sptr, "SPAMFILTER");

  if (!add && !remove)
    return need_more_params(sptr, "SPAMFILTER");

  wflags = parv[2];
  rflags = parv[3];

  if (strlen(rflags) > 1)
    return send_reply(sptr, ERR_SPAMREACT);
  if (react_check(rflags) == 1)
    return send_reply(sptr, ERR_BADFLAGS, "react");
  if (watch_check(wflags) == 1)
    return send_reply(sptr, ERR_BADFLAGS, "watch");

  regex = parv[parc-1];

  if (add) {
    if (is_timestamp(parv[4])) {
      exp = atoi(parv[4]);
    } else {
      exp = ParseInterval(parv[4]);
    }

    if ((exp > SPAMFILTER_MAX_EXPIRE) || (exp == 0))  {
      send_reply(sptr, ERR_BADEXPIRE, exp);
      return 0;
    }

    expire = CurrentTime + exp;
    reason = parv[5];

    spamfilter = spamfilter_add(sptr, regex, rflags, wflags, reason, expire);
  } else if (remove)
    spamfilter = spamfilter_deactivate(sptr, regex, rflags, wflags);

  if (spamfilter)
    sendcmdto_serv_butone(sptr, CMD_SPAMFILTER, cptr, "%C %c %s %s %Tu %s :%s", sptr,
                          SpamFilterIsActive(spamfilter) ? '+' : '-', spamfilter->sf_wflags,
                          spamfilter->sf_rflags, spamfilter->sf_expire - CurrentTime,
                          spamfilter->sf_reason, spamfilter->sf_rawfilter);
  return 0;
}


/** Handle a SPAMFILTER message from an operator.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the target server, or "*" for all.
 * \li \a parv[2] is either "+" or "-"
 * \li \a parv[3] is the watch flags
 * \li \a parv[4] is the react flags
 * \li \a parv[5] is the length in seconds
 * \li \a parv[6] is the reason
 * \li \a parv[\a parc - 1] is the regular expression
 *
 * All fields must be present.  Additionally, the time interval should
 * not be 0 for messages sent to "*", as that may not function
 * reliably due to buffering in the server.
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_spamfilter(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  int add = 0, exp = 0;
  time_t expire;
  char *wflags, *rflags, *reason, *regex, *ar;
  struct SpamFilter* spamfilter;

  ar = parv[2];
  if (*ar == '+')
    add = 1;
  else if (*ar == '-')
    add = 0;

  if ((parc < 8) && (add))
    return need_more_params(sptr, "SPAMFILTER");

  wflags = parv[3];
  rflags = parv[4];

  exp = atoi(parv[5]);
  expire = CurrentTime + exp;
  reason = parv[6];
  regex = parv[parc-1];

  spamfilter = spamfilter_server_add(sptr, regex, rflags, wflags, reason, expire, add);

  if (spamfilter)
    sendcmdto_serv_butone(sptr, CMD_SPAMFILTER, cptr, "%C %c %s %s %Tu %s :%s", sptr,
                          SpamFilterIsActive(spamfilter) ? '+' : '-', spamfilter->sf_wflags,
                          spamfilter->sf_rflags, spamfilter->sf_expire - CurrentTime,
                          spamfilter->sf_reason, spamfilter->sf_rawfilter);

  return 0;
}

