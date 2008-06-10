#ifndef INCLUDED_cloak_h
#define INCLUDED_cloak_h
/*
 * IRC - Internet Relay Chat, include/cloak.h
 * Copyright (C) 2004 Reed Loden <reed@reedloden.com>
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
 * $Id: cloak.h 654 2004-06-04 21:50:12Z r33d $
 */

extern char *hidehost_normalhost(char *host);
extern char *hidehost_ipv4(char *host);

#endif /* INCLUDED_cloak_h */
