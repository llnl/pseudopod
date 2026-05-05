# Always build libpseudo and handlers
SUBDIRS = libpseudo handlers

# Conditionally build CLI tools
if ENABLE_CLI_TOOLS
SUBDIRS += pseudo pseudopod
DIST_SUBDIRS = libpseudo handlers pseudo pseudopod
else
DIST_SUBDIRS = libpseudo handlers
endif

# Ensure .deps and .libs are removed on distclean
distclean-local:
	-rm -rf .deps .libs Makefile.in