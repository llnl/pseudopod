AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src

# Build and install the main library
lib_LTLIBRARIES = libpseudo.la

libpseudo_la_SOURCES = \
    cbmanage.c \
    pseudo.c \
    log.c \
    syscall.c \
    emulation.c \
    internal/emulation.h

libpseudo_la_CFLAGS = $(AM_CFLAGS) -fPIC

# Libtool version info: current:revision:age
# See: https://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
libpseudo_la_LDFLAGS = -version-info 0:0:0

# Install public headers
libpseudo_includedir = $(includedir)/pseudo
libpseudo_include_HEADERS = \
    $(top_srcdir)/include/pseudo/log.h \
    $(top_srcdir)/include/pseudo/pseudo.h \
    $(top_srcdir)/include/pseudo/syscall.h

# Ensure .deps and .libs are removed on distclean
distclean-local:
	-rm -rf .deps .libs