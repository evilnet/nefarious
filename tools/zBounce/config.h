/* config.h */

#ifndef __CONFIG_H
#define __CONFIG_H "$Id$"

/**
 * Define this if you want debugging to a log file.
 */
#define DEBUG

/**
 * The maximum receive/send packet size.
 */
#define MTU 64512

/**
 * The type of compression to use.
 */
#define COMP_TYPE Z_BEST_COMPRESSION

/**
 * Frequency of packets at which statistics are reported.
 */
#define STAT_FREQ 50

#endif // __CONFIG_H
