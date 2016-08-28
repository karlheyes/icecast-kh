## Process this file with automake to produce Makefile.in

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = conf doc web admin src
if WIN32
SUBDIRS += win32
endif

BUILT_SOURCES = git_hash.h
dist_check_SCRIPTS = GIT-VERSION-GEN
CLEANFILES = git_hash.h

EXTRA_DIST = HACKING config.h.vc6 m4/acx_pthread.m4 m4/ogg.m4 \
    m4/theora.m4 m4/vorbis.m4 m4/speex.m4\
    m4/xiph_compiler.m4 m4/xiph_curl.m4 m4/xiph_net.m4 \
    m4/xiph_types.m4 m4/xiph_xml2.m4 m4/xiph_openssl.m4 icecast.spec

docdir = $(datadir)/doc/$(PACKAGE)
doc_DATA = README AUTHORS COPYING NEWS TODO

git_hash.h: FORCE
	@$(SHELL_PATH) $(srcdir)/GIT-VERSION-GEN
FORCE:

debug:
	$(MAKE) all CFLAGS="-Wno-unused-parameter @DEBUG@"

profile:
	$(MAKE) all CFLAGS="@PROFILE@"

staticdebug:
	$(MAKE) all CFLAGS="-g -DLIBXML_STATIC -DCURL_STATICLIB" LDFLAGS="${LDFLAGS} -all-static"
static:
	$(MAKE) all CFLAGS="-O2 -DLIBXML_STATIC -DCURL_STATICLIB" LDFLAGS="${LDFLAGS} -static-libstdc++" CXXFLAGS=
