#!/bin/sh
#
# $Id$
#
# aid in converting S: and F:lines from old lain configs
# to the new "super S:line" format of asuka.
#
# When       Who				What
# 2003-01-05 froo@quakenet.org	Created.

PATH=/bin:/usr/bin
PROG=`basename $0`
USAGE="Usage: $PROG </path/to/ircd.cfg>"

if [ $# -lt 1 ]; then
	echo $USAGE
	exit
fi

CONFIG=$1

if [ ! -f $CONFIG ]; then
	echo "Can't open \"$CONFIG\", bailing out."
	exit
fi

{
for LINE in `grep -E "^F:" $CONFIG`
do
	IDENT=`echo $LINE | cut -f2 -d:`
	REALHOST=`echo $LINE | cut -f3 -d:`
	SPOOFHOST=`echo $LINE | cut -f4 -d:`

	IDENT=`echo $IDENT | sed -e 's,^~,\*,'`

	echo "S:$SPOOFHOST::$REALHOST:$IDENT"
done

for LINE in `grep -E "^S:" $CONFIG`
do
	SPOOFHOST=`echo $LINE | cut -f2 -d:`
	PASSWD=`echo $LINE | cut -f3 -d:`

	IDENT=`echo $IDENT | sed -e 's,^~,\*,'`

	echo "S:$SPOOFHOST:$PASSWD::"
done
} | sort

exit 0
