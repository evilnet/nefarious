#ifndef INCLUDED_hosthiding_h
#define INCLUDED_hosthiding_h
/*
 * IRC - Internet Relay Chat, include/hosthiding.h
 * Copyright (C) 2004 Reed Loden <reed@reedloden.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
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
 * Proto types
 */

extern int str2arr (char **, char *, char *);
extern unsigned long crc32 (const unsigned char *, unsigned int);
extern void make_virthost (char *curr, char *host, char *new, char *virt);
extern void make_virtip (char *curr, char *host, char *new);
extern int cloakrand();

#endif /* INCLUDED_hosthiding_h */
