if ENABLE_TESTS
SUBDIRS = virtid

# Ensure tests are built with 'make all'
all-local:
	@cd virtid && $(MAKE) $(AM_MAKEFLAGS) all
endif

# Ensure .deps and .libs are removed on distclean
if ENABLE_TESTS
distclean-local:
	-rm -rf .deps .libs
	-rm -f Makefile.in
endif