#ifndef INCLUDED_spamfilter_h
#define INCLUDED_spamfilter_h
/*
 * IRC - Internet Relay Chat, include/spamfilter.h
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 * Copyright (C) 2009 Neil Spierling <sirvulcan@sirvulcan.co.nz>
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
 */
/** @file
 * @brief Structures and APIs for G-line manipulation.
 * @version $Id: spamfilter.h 2486 2009-05-23 03:54:52Z sirvulcan $
 */
#ifndef INCLUDED_config_h
#include "config.h"
#endif
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif
#ifdef PCRE_SYSTEM
#include <pcre.h>
#include <pcreposix.h>
#else
#include "pcre.h"
#include "pcreposix.h"
#endif

struct SpamFilter {
  struct SpamFilter *sf_next;        /**< Next SpamFilter in linked list. */
  struct SpamFilter **sf_prev_p;     /**< Previous pointer to this SpamFilter. */
  pcre *sf_filter;                   /**< Regex in PCRE format */
  char *sf_rawfilter;                /**< Raw copy of the filter */
  char *sf_rflags;                   /**< Reaction flags */
  char *sf_wflags;                   /**< Watch flags */
  char *sf_reason;                   /**< Reason */
  char *sf_nchan;                    /**< Notice channel */
  unsigned int sf_flags;             /**< active/deactivated */
  int sf_length;                     /**< Gline/Shun/Zline length */
  time_t sf_expire;                  /**< Expiration time */
};

#define SPAMFILTER_MAX_EXPIRE 604800 /**< max expire: 7 days */

#define SPAMFILTER_ACTIVE     0x0001

/** Test whether \a spamfilter is active. */
#define SpamFilterIsActive(s)     ((s)->sf_flags & SPAMFILTER_ACTIVE)

extern void spamfilter_check_expires();
extern void spamfilter_stats(struct Client* to, const struct StatDesc *sd, char* param);
extern void spamfilter_burst(struct Client *cptr);
extern void spamfilter_free(struct SpamFilter *spamfilter);
extern int spamfilter_remove(struct Client* sptr, char *mask, char *reason);

#endif /* INCLUDED_spamfilter_h */

