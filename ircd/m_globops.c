/*
 * IRC - Internet Relay Chat, ircd/m_globops.c
 * Copyright (C) 2003-2005 Progs
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
 */
/** @file
 * @brief GLOBOPS command
 * @version $Id$
 */

 #include "config.h"

#include "client.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "send.h"

#include <stdlib.h>

/*
 * ms_globops 
 *
 * parv[2] = msg
 */
int mo_globops(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char *message;

  message = parc > 1 ? parv[1] : 0;

  if (EmptyString(message))
    return need_more_params(sptr, "GLOBOPS");

  sendto_allusers_butserv(cptr, sptr, "o", "[GLOBOPS] %s", message);
  return 0;
}
