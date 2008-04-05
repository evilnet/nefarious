# $Id: Makefile.in 33 2005-10-02 20:50:00Z knight $

CC = gcc
LIBS = -lcrypto
CFLAGS = -g -O2 -Wall -g
INCLUDES = -I/usr/include

all: respond

respond: respond.c
	$(CC) $(CFLAGS) -o respond respond.c ${INCLUDES} ${LDFLAGS} ${LIBS}

clean:
	rm -f respond *.core *~ *.exe

distclean: clean
	rm -f Makefile config.status config.log
	rm -rf autom4te.cache
