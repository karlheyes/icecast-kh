## Process this with automake to create Makefile.in

SUBDIRS = avl thread httpp net log timing

noinst_HEADERS = admin.h cfgfile.h logging.h sighandler.h connection.h \
    global.h util.h slave.h source.h stats.h refbuf.h client.h \
    compat.h fserve.h xslt.h yp.h event.h md5.h params.h \
    auth.h auth_htpasswd.h auth_cmd.h auth_url.h \
    fnmatch_loop.c fnmatch.h \
    format.h format_ogg.h format_mp3.h format_ebml.h \
    format_vorbis.h format_theora.h format_flac.h format_speex.h format_midi.h format_opus.h \
    format_kate.h format_skeleton.h mpeg.h flv.h
icecast_SOURCES = cfgfile.c main.c logging.c sighandler.c connection.c global.c \
    util.c slave.c source.c stats.c refbuf.c client.c params.c \
    xslt.c fserve.c event.c admin.c md5.c \
    format.c format_ogg.c format_mp3.c format_midi.c format_flac.c format_ebml.c format_opus.c \
    auth.c auth_htpasswd.c auth_url.c format_kate.c format_skeleton.c mpeg.c flv.c

icecast_DEPENDENCIES = \
    net/libicenet.la \
    thread/libicethread.la \
    httpp/libicehttpp.la \
    log/libicelog.la \
    avl/libiceavl.la \
    timing/libicetiming.la

if BUILD_FNMATCH
icecast_SOURCES += fnmatch.c
endif
if BUILD_YP
icecast_SOURCES += yp.c
endif
if BUILD_VORBIS
icecast_SOURCES += format_vorbis.c
endif
if BUILD_SPEEX
icecast_SOURCES += format_speex.c
endif
if BUILD_THEORA
icecast_SOURCES += format_theora.c
endif
if BUILD_AUTHCMD
icecast_SOURCES += auth_cmd.c
endif

if WINDOWS
noinst_LTLIBRARIES = libicecast.la
libicecast_la_SOURCES = $(icecast_SOURCES)
libicecast_la_CFLAGS = -static
libicecast_la_LIBADD = $(icecast_DEPENDENCIES) @XIPH_LIBS@ @KATE_LIBS@
libicecast_la_DEPENDENCIES = $(icecast_DEPENDENCIES)
else
bin_PROGRAMS = icecast
icecast_LDADD = $(icecast_DEPENDENCIES) @XIPH_LIBS@ @KATE_LIBS@
endif

AM_CFLAGS = @XIPH_CFLAGS@
AM_CPPFLAGS = @XIPH_CPPFLAGS@
AM_LDFLAGS = @XIPH_LDFLAGS@ @KATE_LIBS@


debug:
	$(MAKE) all CFLAGS="@DEBUG@"

profile:
	$(MAKE) all CFLAGS="@PROFILE@"

