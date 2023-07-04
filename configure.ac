dnl Process this file with autoconf to produce a configure script.
AC_INIT([Icecast], [2.4.0-kh22], [karl@kheyes.plus.com])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign])

AC_PREREQ([2.71])
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_HEADERS(config.h)
AC_CONFIG_MACRO_DIR([m4])

AM_MAINTAINER_MODE
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
dnl  use make V=1 to show rules

LT_INIT

AC_PROG_CXX
AC_PROG_CC
AC_CANONICAL_HOST
AC_SYS_LARGEFILE
XIPH_C_ATTRIBUTE

dnl Set some options based on environment

DEBUG="-g"
if test -z "$GCC"; then
    XIPH_CPPFLAGS="-D_REENTRANT"
    PROFILE="-g -p"
else
    XIPH_CPPFLAGS="-Wall -ffast-math -fsigned-char"
    PROFILE="-pg -g"
    AC_DEFINE([_GNU_SOURCE], 1, [Define to include GNU extensions to POSIX])
fi
AM_CONDITIONAL([WINDOWS], [test x$host_os = xmingw32])
if test x$host_os = xmingw32; then
AC_DEFINE([_POSIX], 1, [Define to use C99 routines on MS])
fi

AC_ARG_VAR([ICY_CHARSET], [Character set used for ICY metadata, default is UTF8])
if test -n "$ICY_CHARSET"; then
   AC_DEFINE_UNQUOTED([ICY_DEFAULT_CHARSET], ["$ICY_CHARSET"], ["Character set for ICY metadata"])
fi

dnl Checks for programs.

dnl Checks for libraries.

dnl Checks for header files.
AC_CHECK_HEADERS_ONCE([sys/time.h])

AC_CHECK_HEADERS([fcntl.h fnmatch.h sys/timeb.h sys/wait.h alloca.h malloc.h glob.h winsock2.h windows.h stdbool.h signal.h])
AC_CHECK_HEADERS(pwd.h, AC_DEFINE(CHUID, 1, [Define if you have pwd.h]),,)

dnl Checks for typedefs, structures, and compiler characteristics.
XIPH_C__FUNC__

dnl Check for types
AC_TYPE_OFF_T
AC_CHECK_TYPES([struct timespec])

dnl Checks for library functions.
AC_CHECK_FUNCS([localtime_r gmtime_r FindFirstFile memmem sigaction])
AC_CHECK_FUNCS([fseeko fnmatch chroot fork poll atoll strtoll strsep strcasecmp strncasecmp])
AC_CHECK_FUNCS([getrlimit gettimeofday ftime fsync glob pread pipe2 setresuid setresgid])
AC_CHECK_TYPES([struct signalfd_siginfo],
               [AC_DEFINE(HAVE_SIGNALFD, 1 ,[Define if signalfd exists])], [],
               [#include <sys/signalfd.h>])
AC_CHECK_TYPES([uint32_t], [], [], [
#include <inttypes.h>
#include <stdint.h>
])
AC_CHECK_TYPES([SOCKET*],
        [AC_DEFINE([FD_t], [SOCKET], [socket type for Windows])],
        [AC_DEFINE([FD_t], [int], [socket type for the rest])], [
#include <winsock2.h>
])
if test "x$ac_cv_func_fnmatch" != "xyes"
then
AC_CHECK_LIB(fnmatch, fnmatch, [XIPH_VAR_APPEND([XIPH_LIBS],["-lfnmatch"])],
        [ AC_CHECK_LIB(iberty, fnmatch, [XIPH_VAR_APPEND([XIPH_LIBS],["-liberty"])],
        [])])
AC_DEFINE(HAVE_FNMATCH_H, 1, [Define if using a local fnmatch])
fi
AM_CONDITIONAL([BUILD_FNMATCH], [test "x$ac_cv_func_fnmatch" != "xyes" ])
AC_SEARCH_LIBS(nanosleep, rt posix4,
        AC_DEFINE(HAVE_NANOSLEEP, 1, [Define if you have nanosleep]))
AC_SEARCH_LIBS(clock_gettime, rt posix4,
        AC_DEFINE(HAVE_CLOCK_GETTIME, 1, [Define if you have clock_gettime]))
XIPH_NET

dnl -- configure options --

XIPH_PATH_XSLT
XIPH_VAR_APPEND([XIPH_CPPFLAGS],[$XSLT_CFLAGS])
XIPH_VAR_PREPEND([XIPH_LIBS],[$XSLT_LIBS])

XIPH_PATH_VORBIS([
    XIPH_VAR_APPEND([XIPH_CPPFLAGS],[$VORBIS_CFLAGS])
    XIPH_VAR_PREPEND([XIPH_LIBS],[$VORBIS_LIBS])
    XIPH_VAR_APPEND([XIPH_LDFLAGS],[$VORBIS_LDFLAGS])
    build_vorbis="yes"
    ],
    [AC_MSG_ERROR([must have Ogg Vorbis v1.0 or above installed])
    ])
AM_CONDITIONAL([BUILD_VORBIS], [test "x$build_vorbis" = "xyes" ])

XIPH_PATH_THEORA([
    XIPH_VAR_APPEND([XIPH_CPPFLAGS],[$THEORA_CFLAGS])
    XIPH_VAR_APPEND([XIPH_LDFLAGS],[$THEORA_LDFLAGS])
    XIPH_VAR_PREPEND([XIPH_LIBS],[$THEORA_LIBS])
    build_theora="yes"
    ],
    [ AC_MSG_WARN([Theora disabled!])
    ])
AM_CONDITIONAL([BUILD_THEORA], [test "x$build_theora" = "xyes" ])

XIPH_PATH_SPEEX(
    [ XIPH_VAR_APPEND([XIPH_CPPFLAGS],[$SPEEX_CFLAGS])
    XIPH_VAR_PREPEND([XIPH_LIBS],[$SPEEX_LIBS])
    XIPH_VAR_APPEND([XIPH_LDFLAGS],[$SPEEX_LDFLAGS])
    build_speex="yes"
    ],
    [ AC_MSG_WARN([Speex support disabled!])
    ])
AM_CONDITIONAL([BUILD_SPEEX], [test "x$build_speex" = "xyes" ])

AC_CHECK_LIB(kate, kate_decode_init,[have_kate=yes],[have_kate=no], -logg)
if test "x$have_kate" = "xyes"
then
  AC_CHECK_LIB(oggkate, kate_ogg_decode_headerin,[have_kate=yes],[have_kate=no],-lkate -logg)
  if test "x$have_kate" = "xyes"
  then
    KATE_LIBS="-loggkate -lkate -logg"
    AC_DEFINE([HAVE_KATE],[1],[Define if you have libkate])
  fi
fi
dnl we still use format_kate as it doesn't need libkate to work

ACX_PTHREAD(, AC_MSG_ERROR([POSIX threads missing]))
XIPH_VAR_APPEND([XIPH_CFLAGS],[$PTHREAD_CFLAGS])
XIPH_VAR_APPEND([XIPH_CPPFLAGS],[$PTHREAD_CPPFLAGS])
XIPH_VAR_PREPEND([XIPH_LIBS],[$PTHREAD_LIBS])

XIPH_PATH_CURL([
    AC_CHECK_DECL([CURLOPT_NOSIGNAL],
        [ AC_DEFINE([HAVE_AUTH_URL], 1, [Define to compile in auth URL support code])
        AC_CHECK_FUNCS([curl_global_init])
        enable_curl="yes"
        XIPH_VAR_APPEND([XIPH_CPPFLAGS],[$CURL_CFLAGS])
        XIPH_VAR_PREPEND([XIPH_LIBS],[$CURL_LIBS])
        ], [ AC_MSG_NOTICE([Your curl dev files are too old (7.10 or above required)])
        ], [#include <curl/curl.h>
        ])
    ],[ AC_MSG_NOTICE([libcurl not found])
    ])
dnl -- YP support --
AC_ARG_ENABLE([yp],
        AS_HELP_STRING([--disable-yp],[disable YP directory support]),
        enable_yp="$enableval",
        enable_yp="yes")
if test "x$enable_yp" = "xyes" -a "x$enable_curl" = xyes
then
    AC_DEFINE([USE_YP], 1, [Define to compile in YP support code])
else
    AC_MSG_NOTICE([YP support disabled])
fi
AM_CONDITIONAL([BUILD_YP], [test "x$enable_yp" = "xyes" -a "x$enable_curl" = xyes])

XIPH_PATH_OPENSSL([
    XIPH_VAR_APPEND([XIPH_CPPFLAGS],[$OPENSSL_CFLAGS])
    XIPH_VAR_APPEND([XIPH_LDFLAGS],[$OPENSSL_LDFLAGS])
    XIPH_VAR_PREPEND([XIPH_LIBS],[$OPENSSL_LIBS])
    ],
    [ AC_MSG_NOTICE([SSL disabled!])
    ])

AM_CONDITIONAL([BUILD_AUTHCMD], [ test "x$ac_cv_func_fork" = "xyes"])

dnl Make substitutions

AC_SUBST(XIPH_CPPFLAGS)
AC_SUBST(XIPH_CFLAGS)
AC_SUBST(XIPH_LIBS)
AC_SUBST(XIPH_LDFLAGS)
AC_SUBST(PTHREAD_CPPFLAGS)
AC_SUBST(PTHREAD_CFLAGS)
AC_SUBST(PTHREAD_LIBS)
AC_SUBST(LIBTOOL_DEPS)
AC_SUBST(LIBS)
AC_SUBST(DEBUG)
AC_SUBST(CFLAGS)
AC_SUBST(PROFILE)
AC_SUBST(HAVE_KATE)
AC_SUBST(KATE_LIBS)

AC_CONFIG_FILES([
   Makefile
   conf/Makefile
   src/Makefile
   src/avl/Makefile
   src/httpp/Makefile
   src/thread/Makefile
   src/log/Makefile
   src/net/Makefile
   src/timing/Makefile
   doc/Makefile
   web/Makefile
   web/images/Makefile
   admin/Makefile
   windows/Makefile
])
AM_COND_IF([WINDOWS], [AC_CONFIG_FILES([icecast.nsis:conf/$host.nsis.in])])
AC_OUTPUT
