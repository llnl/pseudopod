AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src

# Build library (shared and/or static based on configure options)
lib_LTLIBRARIES = libpseudo_seccomp.la

libpseudo_seccomp_la_SOURCES = \
    seccomp.c \
    seccomp.h \
    filter_trace.c \
    filter_fakechown.c \
    filter_fakeroot.c

# Compiler flags
libpseudo_seccomp_la_CFLAGS = $(AM_CFLAGS)

# Link against libpseudo
libpseudo_seccomp_la_LIBADD = \
    $(top_builddir)/src/libpseudo/libpseudo.la

# Libtool version info
libpseudo_seccomp_la_LDFLAGS = -version-info 0:0:0

# Install seccomp handler header
seccomp_includedir = $(includedir)/handlers/seccomp
seccomp_include_HEADERS = seccomp.h

# Ensure .deps and .libs are removed on distclean
distclean-local:
	-rm -rf .deps .libs Makefile.in