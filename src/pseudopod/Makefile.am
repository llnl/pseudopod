if ENABLE_CLI_TOOLS
AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src

bin_PROGRAMS = pseudopod

pseudopod_SOURCES = \
    pseudopod-cli.cpp \
    userns.c \
    userns.h

# Link against installed libraries
pseudopod_LDADD = \
    $(top_builddir)/src/handlers/libpseudo_handlers.la \
    $(top_builddir)/src/handlers/seccomp/libpseudo_seccomp.la \
    $(top_builddir)/src/libpseudo/libpseudo.la \
    $(LIBCAP_LIBS)

pseudopod_LDFLAGS = \
    $(STATIC_LIBGCC_LDFLAGS) \
    $(STATIC_LIBSTDCXX_LDFLAGS)

pseudopod_CXXFLAGS = $(AM_CXXFLAGS) -std=c++17

# Ensure .deps and .libs are removed on distclean
distclean-local:
	-rm -rf .deps .libs
	-rm -f Makefile.in
endif