# -*- buffer-read-only: t -*- vi: set ro:
# DO NOT EDIT! GENERATED AUTOMATICALLY!
# stdlib_h.m4 serial 27
dnl Copyright (C) 2007-2010 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

AC_DEFUN([gl_STDLIB_H],
[
  AC_REQUIRE([gl_STDLIB_H_DEFAULTS])
  gl_CHECK_NEXT_HEADERS([stdlib.h])
  AC_CHECK_HEADERS([random.h], [], [], [AC_INCLUDES_DEFAULT])
  if test $ac_cv_header_random_h = yes; then
    HAVE_RANDOM_H=1
  else
    HAVE_RANDOM_H=0
  fi
  AC_SUBST([HAVE_RANDOM_H])
  AC_CHECK_TYPES([struct random_data],
    [], [HAVE_STRUCT_RANDOM_DATA=0],
    [[#include <stdlib.h>
      #if HAVE_RANDOM_H
      # include <random.h>
      #endif
    ]])

  dnl Check for declarations of anything we want to poison if the
  dnl corresponding gnulib module is not in use, and which is not
  dnl guaranteed by C89.
  gl_WARN_ON_USE_PREPARE([[#include <stdlib.h>
#if HAVE_SYS_LOADAVG_H
# include <sys/loadavg.h>
#endif
#if HAVE_RANDOM_H
# include <random.h>
#endif
    ]], [atoll canonicalize_file_name getloadavg getsubopt grantpt mkdtemp
    mkostemp mkostemps mkstemp mkstemps ptsname random_r initstat_r srandom_r
    setstate_r realpath rpmatch setenv strtod strtoll strtoull unlockpt
    unsetenv])
])

AC_DEFUN([gl_STDLIB_MODULE_INDICATOR],
[
  dnl Use AC_REQUIRE here, so that the default settings are expanded once only.
  AC_REQUIRE([gl_STDLIB_H_DEFAULTS])
  gl_MODULE_INDICATOR_SET_VARIABLE([$1])
  dnl Define it also as a C macro, for the benefit of the unit tests.
  gl_MODULE_INDICATOR_FOR_TESTS([$1])
])

AC_DEFUN([gl_STDLIB_H_DEFAULTS],
[
  GNULIB_ATOLL=0;         AC_SUBST([GNULIB_ATOLL])
  GNULIB_CALLOC_POSIX=0;  AC_SUBST([GNULIB_CALLOC_POSIX])
  GNULIB_CANONICALIZE_FILE_NAME=0;  AC_SUBST([GNULIB_CANONICALIZE_FILE_NAME])
  GNULIB_GETLOADAVG=0;    AC_SUBST([GNULIB_GETLOADAVG])
  GNULIB_GETSUBOPT=0;     AC_SUBST([GNULIB_GETSUBOPT])
  GNULIB_GRANTPT=0;       AC_SUBST([GNULIB_GRANTPT])
  GNULIB_MALLOC_POSIX=0;  AC_SUBST([GNULIB_MALLOC_POSIX])
  GNULIB_MKDTEMP=0;       AC_SUBST([GNULIB_MKDTEMP])
  GNULIB_MKOSTEMP=0;      AC_SUBST([GNULIB_MKOSTEMP])
  GNULIB_MKOSTEMPS=0;     AC_SUBST([GNULIB_MKOSTEMPS])
  GNULIB_MKSTEMP=0;       AC_SUBST([GNULIB_MKSTEMP])
  GNULIB_MKSTEMPS=0;      AC_SUBST([GNULIB_MKSTEMPS])
  GNULIB_PTSNAME=0;       AC_SUBST([GNULIB_PTSNAME])
  GNULIB_PUTENV=0;        AC_SUBST([GNULIB_PUTENV])
  GNULIB_RANDOM_R=0;      AC_SUBST([GNULIB_RANDOM_R])
  GNULIB_REALLOC_POSIX=0; AC_SUBST([GNULIB_REALLOC_POSIX])
  GNULIB_REALPATH=0;      AC_SUBST([GNULIB_REALPATH])
  GNULIB_RPMATCH=0;       AC_SUBST([GNULIB_RPMATCH])
  GNULIB_SETENV=0;        AC_SUBST([GNULIB_SETENV])
  GNULIB_STRTOD=0;        AC_SUBST([GNULIB_STRTOD])
  GNULIB_STRTOLL=0;       AC_SUBST([GNULIB_STRTOLL])
  GNULIB_STRTOULL=0;      AC_SUBST([GNULIB_STRTOULL])
  GNULIB_UNLOCKPT=0;      AC_SUBST([GNULIB_UNLOCKPT])
  GNULIB_UNSETENV=0;      AC_SUBST([GNULIB_UNSETENV])
  dnl Assume proper GNU behavior unless another module says otherwise.
  HAVE_ATOLL=1;              AC_SUBST([HAVE_ATOLL])
  HAVE_CALLOC_POSIX=1;       AC_SUBST([HAVE_CALLOC_POSIX])
  HAVE_CANONICALIZE_FILE_NAME=1;  AC_SUBST([HAVE_CANONICALIZE_FILE_NAME])
  HAVE_DECL_GETLOADAVG=1;    AC_SUBST([HAVE_DECL_GETLOADAVG])
  HAVE_GETSUBOPT=1;          AC_SUBST([HAVE_GETSUBOPT])
  HAVE_GRANTPT=1;            AC_SUBST([HAVE_GRANTPT])
  HAVE_MALLOC_POSIX=1;       AC_SUBST([HAVE_MALLOC_POSIX])
  HAVE_MKDTEMP=1;            AC_SUBST([HAVE_MKDTEMP])
  HAVE_MKOSTEMP=1;           AC_SUBST([HAVE_MKOSTEMP])
  HAVE_MKOSTEMPS=1;          AC_SUBST([HAVE_MKOSTEMPS])
  HAVE_MKSTEMPS=1;           AC_SUBST([HAVE_MKSTEMPS])
  HAVE_PTSNAME=1;            AC_SUBST([HAVE_PTSNAME])
  HAVE_RANDOM_R=1;           AC_SUBST([HAVE_RANDOM_R])
  HAVE_REALLOC_POSIX=1;      AC_SUBST([HAVE_REALLOC_POSIX])
  HAVE_REALPATH=1;           AC_SUBST([HAVE_REALPATH])
  HAVE_RPMATCH=1;            AC_SUBST([HAVE_RPMATCH])
  HAVE_SETENV=1;             AC_SUBST([HAVE_SETENV])
  HAVE_STRTOD=1;             AC_SUBST([HAVE_STRTOD])
  HAVE_STRTOLL=1;            AC_SUBST([HAVE_STRTOLL])
  HAVE_STRTOULL=1;           AC_SUBST([HAVE_STRTOULL])
  HAVE_STRUCT_RANDOM_DATA=1; AC_SUBST([HAVE_STRUCT_RANDOM_DATA])
  HAVE_SYS_LOADAVG_H=0;      AC_SUBST([HAVE_SYS_LOADAVG_H])
  HAVE_UNLOCKPT=1;           AC_SUBST([HAVE_UNLOCKPT])
  HAVE_UNSETENV=1;           AC_SUBST([HAVE_UNSETENV])
  REPLACE_CANONICALIZE_FILE_NAME=0;  AC_SUBST([REPLACE_CANONICALIZE_FILE_NAME])
  REPLACE_MKSTEMP=0;         AC_SUBST([REPLACE_MKSTEMP])
  REPLACE_PUTENV=0;          AC_SUBST([REPLACE_PUTENV])
  REPLACE_REALPATH=0;        AC_SUBST([REPLACE_REALPATH])
  REPLACE_SETENV=0;          AC_SUBST([REPLACE_SETENV])
  REPLACE_STRTOD=0;          AC_SUBST([REPLACE_STRTOD])
  REPLACE_UNSETENV=0;        AC_SUBST([REPLACE_UNSETENV])
])
