/*
 * IRC - Internet Relay Chat, include/crule.h
 * Copyright (C) Tony Vencill <vencill@bga.com>
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
/** @file crule.h
 * @brief Interfaces and declarations for connection rule checking.
 * @version $Id$
 */
#ifndef INCLUDED_crule_h
#define INCLUDED_crule_h

/*
 * opaque node pointer
 */
struct CRuleNode;

extern int crule_eval(struct CRuleNode* rule);
extern char *crule_text(struct CRuleNode *rule);

extern struct CRuleNode* crule_make_and(struct CRuleNode *left,
                                        struct CRuleNode *right);
extern struct CRuleNode* crule_make_or(struct CRuleNode *left,
                                       struct CRuleNode *right);
extern struct CRuleNode* crule_make_not(struct CRuleNode *arg);
extern struct CRuleNode* crule_make_connected(char *arg);
extern struct CRuleNode* crule_make_directcon(char *arg);
extern struct CRuleNode* crule_make_via(char *neighbor,
                                        char *server);
extern struct CRuleNode* crule_make_directop(void);
extern void crule_free(struct CRuleNode* elem);

#endif /* INCLUDED_crule_h */
