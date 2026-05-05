if ENABLE_CLI_TOOLS
AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src

bin_PROGRAMS = pseudo

pseudo_SOURCES = pseudo-cli.c

# Link against installed libraries
pseudo_LDADD = \
    $(top_builddir)/src/handlers/libpseudo_handlers.la \
    $(top_builddir)/src/handlers/seccomp/libpseudo_seccomp.la \
    $(top_builddir)/src/libpseudo/libpseudo.la

pseudo_LDFLAGS = $(STATIC_LIBGCC_LDFLAGS)
pseudo_CFLAGS = $(AM_CFLAGS)

# Ensure .deps and .libs are removed on distclean
distclean-local:
	-rm -rf .deps .libs
	-rm -f Makefile.in
endif