/*
 * support.h
 *
 * $Id$
 */
#ifndef INCLUDED_support_h
#define INCLUDED_support_h

/*
 * Given a number of bits, make a netmask out of it.
 */
#define NETMASK(bits) htonl((bits) ? -(1 << (32 - (bits))) : 0)

/*
 * Prototypes
 */

int dgets(int, char*, int);
  
extern int check_if_ipmask(const char *mask);
extern void write_log(const char *filename, const char *pattern, ...);
extern unsigned long ParseInterval(const char *interval);
extern int is_timestamp(char *str);

#endif /* INCLUDED_support_h */
