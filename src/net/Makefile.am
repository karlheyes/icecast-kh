## Process this with automake to create Makefile.in

AUTOMAKE_OPTIONS = foreign

EXTRA_DIST = BUILDING COPYING README TODO test_resolver.c

noinst_LTLIBRARIES = libicenet.la
noinst_HEADERS = resolver.h sock.h

libicenet_la_SOURCES = sock.c resolver.c
libicenet_la_CFLAGS = @XIPH_CFLAGS@ -static
AM_CPPFLAGS = @XIPH_CPPFLAGS@ -I$(top_srcdir)/src

debug:
	$(MAKE) all CFLAGS="@DEBUG@"

profile:
	$(MAKE) all CFLAGS="@PROFILE@

