#ifndef INCLUDED_mark_h
#define INCLUDED_mark_h
/*
 * IRC - Internet Relay Chat, include/mark.h
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 * Copyright (C) 2005 Neil Spierling <sirvulcan@sirvulcan.co.nz>
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
/** @file mark.h
 * @brief Mark define's.
 * @version $Id$
 */

#define MARK_DNSBL		"DNSBL"           /**< DNSBL mark */
#define MARK_DNSBL_DATA		"DNSBL_DATA"      /**< DNSBL data mark */
#define MARK_EXEMPT_UPDATE	"EXEMPT"          /**< DNSBL Exempt mark */
#define MARK_CVERSION		"CVERSION"        /**< Client Version mark */
#define MARK_WEBIRC		"WEBIRC"          /**< WEBIRC mark */
#define MARK_SSLCLIFP           "SSLCLIFP"        /**< SSLCLIFP mark */
#define MARK_SFILTER            "SFILTER"         /**< Spam filter mark */
#define MARK_KILL               "KILL"            /**< KILL mark */

#endif /* INCLUDED_mark_h */

