SUBDIRS = src

# Conditionally add tests
if ENABLE_TESTS
SUBDIRS += tests
DIST_SUBDIRS = src tests
else
DIST_SUBDIRS = src
endif

EXTRA_DIST = README.md LICENSE NOTICE CONTRIBUTING SECURITY.md

# Files to remove on 'make distclean'
DISTCLEANFILES = config.log \
                 config.status \
                 stamp-h1

# Copy built binaries to bin/ directory for testing and convenience
if ENABLE_CLI_TOOLS
all-local:
	@mkdir -p bin
	@if [ -f src/pseudo/pseudo ]; then \
		cp -f src/pseudo/pseudo bin/pseudo; \
		echo "Copied pseudo to bin/"; \
	fi
	@if [ -f src/pseudopod/pseudopod ]; then \
		cp -f src/pseudopod/pseudopod bin/pseudopod; \
		echo "Copied pseudopod to bin/"; \
	fi

clean-local:
	rm -f bin/pseudo bin/pseudopod
endif

# Remove libtool and build directories
# This runs after subdirectories have done their distclean
distclean-local:
	-rm -rf bin/pseudo bin/pseudopod
	-rm -rf .deps .libs libtool m4 aclocal.m4 build-aux autom4te.cache
	-rm -f config.* configure Makefile.in
	@echo
	@echo "make distclean complete; need to run ./autogen.sh"