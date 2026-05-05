#!/bin/sh
# Bootstrap script to generate autotools build files

set -e

# Check for required tools
for tool in autoconf automake aclocal libtool; do
    if ! command -v $tool >/dev/null 2>&1; then
        echo "Error: $tool is required but not found"
        echo "Please install GNU autotools:"
        echo "  Debian/Ubuntu: apt-get install aclocal autoconf automake libtool"
        echo "  RHEL/CentOS:   yum install aclocal autoconf automake libtool"
        exit 1
    fi
done

# Clean everything.
rm -f configure config.* stamp-h1 2>/dev/null || true
rm -rf aclocal.m4 autom4te.cache build-aux libtool m4 2>/dev/null || true
find . -name 'Makefile.in' -type f -delete 2>/dev/null || true
find . -name '.libs' -o -name '.deps' -type d -exec rm -rf {} + 2>/dev/null || true

# Create necessary directories
mkdir -p m4 build-aux

# Run autoreconf
echo "Running autoreconf..."
autoreconf --install --verbose --force

echo
echo "You can now build pseudopod:"
echo "  ./configure [OPTIONS]"
echo "  make"
echo "To build only libpseudo (no CLI tools):"
echo "  ./configure --disable-cli-tools"
echo "  make"
echo "  make install"
echo
echo "Configuration options:"
echo "  --prefix=DIR              Install to DIR [/usr/local]"
echo "  --disable-cli-tools       Build only libpseudo library (implies --disable-tests)"
echo "  --disable-tests           Disable test suite"
echo "  --with-libcap             Enable libcap support"
echo "  --without-libcap          Disable libcap support"
echo "  --enable-static-libgcc    Link libgcc statically"
echo "  --enable-static-libstdcxx Link libstdc++ statically"
echo "  --enable-static-libs      Link both libgcc and libstdc++ statically"
echo
echo "For more options: ./configure --help"
echo