dnl $Id$
dnl ----------------------------------------------------------

echo Configuring zBounce...
echo

AC_REVISION($Revision$)
AC_INIT(Bounce.cpp)
AM_INIT_AUTOMAKE(zbounce,0.0)
AM_CONFIG_HEADER(defs.h)

CXXFLAGS="-g -Wall -O0 -pipe"
CXX="g++"

AC_PROG_CC 
AC_PROG_CXX
AC_PROG_CPP
dnl AC_LANG([C++]

AC_PROG_MAKE_SET(gmake)
AC_DISABLE_SHARED 
AC_ISC_POSIX 

AM_MAINTAINER_MODE
AC_HEADER_STDC
AC_HEADER_TIME
AC_TYPE_SIGNAL
AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UID_T

prefix=`pwd`
bindir=`pwd`
libdir=`pwd`

found_socklen_t=no
AC_EGREP_HEADER(socklen_t,sys/socket.h, AC_DEFINE(HAVE_SOCKLEN_T) found_socklen_t=yes)

if test $found_socklen_t = yes; then
  AC_EGREP_HEADER(socklen_t,bits/socket.h,
	AC_DEFINE([HAVE_SOCKLEN_T],[],[Socket length type]))
fi

if test $found_socklen_t = yes; then
  AC_MSG_CHECKING(for socklen_t)
  AC_MSG_RESULT(yes)
else
  AC_CHECK_TYPE(socklen_t,int)
fi

found_inaddr_none=no
AC_EGREP_HEADER(INADDR_NONE,
	netinet/in.h,
	AC_DEFINE([HAVE_INADDR_NONE],[],
		[Failed result from inet_addr])
	found_inaddr_none=yes)

AC_CHECK_LIB(z,deflate, [], AC_MSG_ERROR(libz required))
AC_CHECK_LIB(socket,socket) 
AC_CHECK_LIB(nsl,gethostbyname)
AC_CHECK_LIB(resolv,hstrerror)

AC_ARG_WITH(debug,
	AC_HELP_STRING([--without-debug],
		       [Disable debugging in the executables]),
	[dummy=true],
	[CXXFLAGS="$CXXFLAGS -g"]
)

AC_ARG_WITH(pedantic,
	AC_HELP_STRING([--with-pedantic],
			[Add -pedantic to compile options]),
	[CXXFLAGS="$CXXFLAGS -pedantic"]
)

AC_ARG_WITH(optimization,
	AC_HELP_STRING([--with-optimization],
			[Optimize the executables]),
	[CXXFLAGS="$CXXFLAGS -O"],
	[CXXFLAGS="$CXXFLAGS -O0"]
)

AC_ARG_WITH(prof,
	AC_HELP_STRING([--with-prof],
			[Generate profiling information]),
	[CXXFLAGS="$CXXFLAGS -pg"]
)

dnl ----------------------------------------------------------
dnl
dnl svr3's getpgrp() didnt take arguments.  BSD's did.
dnl POSIX said that there wasnt any usefulness to giving arguments
dnl to getpgrp(), so that was forbidden.  So svr4 made a new syscall
dnl getpgid() to fill in this functionality gap (grrrr).  BSD still
dnl doesnt have any way to do it, even though they were the ones that
dnl originally wanted to have it around, but svr3 insisted not so. (grrr)
dnl

dnl AC_CHECK_FUNC(getpgid, AC_DEFINE(HAVE_GETPGID),)
dnl AC_CHECK_FUNC(getpgrp, AC_FUNC_GETPGRP,)

AC_SUBST(LDFLAGS)

AC_SUBST(CXXFLAGS)

AC_OUTPUT(Makefile)
