SUBDIRS = seccomp

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src

# Build library (shared and/or static based on configure options)
lib_LTLIBRARIES = libpseudo_handlers.la

libpseudo_handlers_la_SOURCES = \
    idtrack.c \
    idtrack.h \
    virtid.c \
    virtid.h

# Compiler flags
libpseudo_handlers_la_CFLAGS = $(AM_CFLAGS)

# Link against libpseudo and seccomp handlers
libpseudo_handlers_la_LIBADD = \
    seccomp/libpseudo_seccomp.la \
    $(top_builddir)/src/libpseudo/libpseudo.la

# Libtool version info
libpseudo_handlers_la_LDFLAGS = -version-info 0:0:0

# Install handler headers
handlers_includedir = $(includedir)/handlers
handlers_include_HEADERS = \
    idtrack.h \
    virtid.h

# Ensure .deps and .libs are removed on distclean
distclean-local:
	-rm -rf .deps .libs Makefile.in