/*
 * IRC - Internet Relay Chat, ircd/check.h
 * Copyright (C) 1990 University of Oulu, Computing Center
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

/*
 * - ASUKA ---------------------------------------------------------------------
 * These are the declarations of the CHECK functions for Asuka.
 * Some of this code is from previous QuakeNet ircds, and some of it is my own.
 * The old code was written by Durzel (durzel@quakenet.org).
 * 
 * qoreQ (qoreQ@quakenet.org) - 08/14/2002
 * -----------------------------------------------------------------------------
 */

#ifndef INCLUDED_check_h
#define INCLUDED_check_h

#define HEADERLINE "--------------------------------------------------------------------"
#define COLOR_OFF  '\017'

extern void checkChannel(struct Client *sptr, struct Channel *chptr);
extern void checkUsers(struct Client *sptr, struct Channel *chptr, int flags);
extern void checkClient(struct Client *sptr, struct Client *acptr);
extern void checkServer(struct Client *sptr, struct Client *acptr);
extern signed int checkHostmask(struct Client *sptr, char *hoststr, int flags);

#endif /* INCLUDED_check_h */
