# -*- buffer-read-only: t -*- vi: set ro:
# DO NOT EDIT! GENERATED AUTOMATICALLY!
# socklen.m4 serial 8
dnl Copyright (C) 2005-2007, 2009-2011 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

dnl From Albert Chin, Windows fixes from Simon Josefsson.

dnl Check for socklen_t: historically on BSD it is an int, and in
dnl POSIX 1g it is a type of its own, but some platforms use different
dnl types for the argument to getsockopt, getpeername, etc.:
dnl HP-UX 10.20, IRIX 6.5, Interix 3.5, BeOS.
dnl So we have to test to find something that will work.

dnl On mingw32, socklen_t is in ws2tcpip.h ('int'), so we try to find
dnl it there first.  That file is included by gnulib's sys_socket.in.h, which
dnl all users of this module should include.  Cygwin must not include
dnl ws2tcpip.h.
AC_DEFUN([gl_TYPE_SOCKLEN_T],
  [AC_REQUIRE([gl_HEADER_SYS_SOCKET])dnl
   AC_CHECK_TYPE([socklen_t], ,
     [AC_MSG_CHECKING([for socklen_t equivalent])
      AC_CACHE_VAL([gl_cv_socklen_t_equiv],
        [# Systems have either "struct sockaddr *" or
         # "void *" as the second argument to getpeername
         gl_cv_socklen_t_equiv=
         for arg2 in "struct sockaddr" void; do
           for t in int size_t "unsigned int" "long int" "unsigned long int"; do
             AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
                 [[#include <sys/types.h>
                   #include <sys/socket.h>

                   int getpeername (int, $arg2 *, $t *);]],
                 [[$t len;
                  getpeername (0, 0, &len);]])],
               [gl_cv_socklen_t_equiv="$t"])
             test "$gl_cv_socklen_t_equiv" != "" && break
           done
           test "$gl_cv_socklen_t_equiv" != "" && break
         done
      ])
      if test "$gl_cv_socklen_t_equiv" = ""; then
        AC_MSG_ERROR([Cannot find a type to use in place of socklen_t])
      fi
      AC_MSG_RESULT([$gl_cv_socklen_t_equiv])
      AC_DEFINE_UNQUOTED([socklen_t], [$gl_cv_socklen_t_equiv],
        [type to use in place of socklen_t if not defined])],
     [#include <sys/types.h>
      #if HAVE_SYS_SOCKET_H
      # include <sys/socket.h>
      #elif HAVE_WS2TCPIP_H
      # include <ws2tcpip.h>
      #endif])])
