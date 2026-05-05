if ENABLE_TESTS
noinst_PROGRAMS = test-syscalls test-res-overlap test-res-unaligned test-apt

AM_CPPFLAGS = -I$(top_srcdir)/include
LDADD = $(top_builddir)/src/libpseudo/libpseudo.la

test_syscalls_SOURCES = test-syscalls.c
test_res_overlap_SOURCES = test-res-overlap.c
test_res_unaligned_SOURCES = test-res-unaligned.c
test_apt_SOURCES = test-apt.c

# Ensure .deps and .libs are removed on distclean
distclean-local:
	-rm -rf .deps .libs
	-rm -f Makefile.in
endif