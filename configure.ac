AC_INIT([pseudopod], [0.1.0], [green97@llnl.gov])
AC_CONFIG_SRCDIR([src/libpseudo/pseudo.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([foreign subdir-objects -Wall -Werror])
AM_MAINTAINER_MODE([disable])
AM_SILENT_RULES([yes])

# Option to control library type
AC_ARG_ENABLE([shared],
    [AS_HELP_STRING([--disable-shared], [Do not build shared libraries @<:@default=enabled@:>@])],
    [],
    [enable_shared=yes])

AC_ARG_ENABLE([static],
    [AS_HELP_STRING([--enable-static], [Build static libraries @<:@default=disabled@:>@])],
    [],
    [enable_static=no])

# Checks for programs
AM_PROG_AR
AC_PROG_CC
AC_PROG_CXX
AC_PROG_CC_C99
AC_PROG_INSTALL

# Enable libtool with shared libraries by default
LT_INIT

# Checks for required headers
AC_CHECK_HEADERS([unistd.h \
                  sys/types.h \
                  sys/ptrace.h \
                  sys/wait.h \
                  errno.h \
                  sys/syscall.h \
                  sys/prctl.h \
                  sys/mman.h \
                  sched.h \
                  signal.h], [],
    [AC_MSG_ERROR([Required system headers not found])])

# Checks for required functions
AC_CHECK_FUNCS([ptrace waitpid clone execvpe getpid prctl mmap syscall], [],
    [AC_MSG_ERROR([Required system functions not found])])

# Check for process_vm_writev (Linux 3.2+)
AC_CHECK_FUNCS([process_vm_writev])

# Architecture detection
AC_CANONICAL_HOST
case $host_cpu in
    x86_64)
        AC_DEFINE([ARCH_X86_64], [1], [Define if building for x86_64])
        ARCH_NAME="x86_64"
        ;;
    aarch64)
        AC_DEFINE([ARCH_AARCH64], [1], [Define if building for aarch64])
        ARCH_NAME="aarch64"
        ;;
    powerpc64le)
        AC_DEFINE([ARCH_PPC64LE], [1], [Define if building for ppc64le])
        ARCH_NAME="ppc64le"
        ;;
    *)
        AC_MSG_WARN([Unsupported architecture: $host_cpu - build may fail])
        ARCH_NAME="unknown"
        ;;
esac
AC_SUBST([ARCH_NAME])

# Option to build CLI tools - ON by default
AC_ARG_ENABLE([cli-tools],
    [AS_HELP_STRING([--disable-cli-tools], [libpseudo only; do not build CLI tools (pseudo, pseudopod) @<:@default=enabled@:>@])],
    [enable_cli_tools=$enableval],
    [enable_cli_tools=yes])

# Only check for C++17 if building CLI tools
AS_IF([test "x$enable_cli_tools" = xyes], [
    AC_LANG_PUSH([C++])
    saved_CXXFLAGS="$CXXFLAGS"
    CXXFLAGS="$CXXFLAGS -std=c++17"
    AC_MSG_CHECKING([whether $CXX supports C++17])
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([
        #if __cplusplus < 201703L
        #error C++17 support required
        #endif
    ])],
    [AC_MSG_RESULT([yes])],
    [AC_MSG_RESULT([no])
     AC_MSG_ERROR([C++17 support is required for building CLI tools. Use --disable-cli-tools to build library only.])])
    CXXFLAGS="$saved_CXXFLAGS"
    AC_SUBST([CXX17_CXXFLAGS], [-std=c++17])
    AC_LANG_POP([C++])
])

AM_CONDITIONAL([ENABLE_CLI_TOOLS], [test "x$enable_cli_tools" = xyes])

# Optional libcap support for subuid detection (only needed for pseudopod)
AC_ARG_WITH([libcap],
    [AS_HELP_STRING([--with-libcap], [Enable libcap support for subuid detection @<:@default=check@:>@])],
    [],
    [with_libcap=check])

# Only check for libcap if building CLI tools
have_libcap=no
AS_IF([test "x$enable_cli_tools" = xyes && test "x$with_libcap" != xno],
    [AC_CHECK_HEADER([sys/capability.h],
        [AC_CHECK_LIB([cap], [cap_get_file],
            [have_libcap=yes
             AC_DEFINE([USE_LIBCAP], [1], [Define if libcap is available])],
            [if test "x$with_libcap" = xyes; then
                AC_MSG_ERROR([--with-libcap was given, but libcap not found])
             fi
             have_libcap=no])],
        [if test "x$with_libcap" = xyes; then
            AC_MSG_ERROR([--with-libcap was given, but sys/capability.h not found])
         fi
         have_libcap=no])])

# Warn if libcap requested but CLI tools disabled
AS_IF([test "x$enable_cli_tools" = xno && test "x$with_libcap" = xyes],
    [AC_MSG_WARN([--with-libcap ignored when CLI tools are disabled])])

AM_CONDITIONAL([HAVE_LIBCAP], [test "x$have_libcap" = xyes])
AS_IF([test "x$have_libcap" = xyes],
    [LIBCAP_LIBS="-lcap"],
    [LIBCAP_LIBS=""])
AC_SUBST([LIBCAP_LIBS])

# Optional tests - ON by default
AC_ARG_ENABLE([tests],
    [AS_HELP_STRING([--disable-tests], [Do not build test suite @<:@default=enabled@:>@])],
    [enable_tests=$enableval],
    [enable_tests=yes])

# Tests require pseudo CLI tool
# If CLI tools are disabled, tests must also be disabled
AS_IF([test "x$enable_cli_tools" = xno],
    [AS_IF([test "x$enable_tests" != xno],
        [AC_MSG_WARN([Tests automatically disabled when CLI tools are disabled])])
     enable_tests=no])

# Error if user explicitly tries to enable tests without CLI tools
AS_IF([test "x$enable_tests" = xyes && test "x$enable_cli_tools" = xno],
    [AC_MSG_ERROR([--enable-tests requires CLI tools (cannot use with --disable-cli-tools)])])

AM_CONDITIONAL([ENABLE_TESTS], [test "x$enable_tests" = xyes])

# Static linking options for CLI binaries - OFF by default (only relevant for CLI tools)
AC_ARG_ENABLE([static-libgcc],
    [AS_HELP_STRING([--enable-static-libgcc], [Link CLI tools with libgcc statically @<:@default=no@:>@])],
    [static_libgcc=$enableval],
    [static_libgcc=no])

AC_ARG_ENABLE([static-libstdcxx],
    [AS_HELP_STRING([--enable-static-libstdcxx], [Link CLI tools with libstdc++ statically @<:@default=no@:>@])],
    [static_libstdcxx=$enableval],
    [static_libstdcxx=no])

# Warn if static linking requested but CLI tools disabled
AS_IF([test "x$enable_cli_tools" = xno && test "x$static_libgcc" = xyes],
    [AC_MSG_WARN([--enable-static-libgcc ignored when CLI tools are disabled])])
AS_IF([test "x$enable_cli_tools" = xno && test "x$static_libstdcxx" = xyes],
    [AC_MSG_WARN([--enable-static-libstdcxx ignored when CLI tools are disabled])])

AS_IF([test "x$static_libgcc" = xyes],
    [STATIC_LIBGCC_LDFLAGS="-static-libgcc"],
    [STATIC_LIBGCC_LDFLAGS=""])
AC_SUBST([STATIC_LIBGCC_LDFLAGS])

AS_IF([test "x$static_libstdcxx" = xyes],
    [STATIC_LIBSTDCXX_LDFLAGS="-static-libstdc++"],
    [STATIC_LIBSTDCXX_LDFLAGS=""])
AC_SUBST([STATIC_LIBSTDCXX_LDFLAGS])

# Convenience option to enable both static libs at once (for CLI binaries)
AC_ARG_ENABLE([static-libs],
    [AS_HELP_STRING([--enable-static-libs], [Link CLI tools with both libgcc and libstdc++ statically @<:@default=no@:>@])],
    [if test "x$enableval" = xyes; then
        static_libgcc=yes
        static_libstdcxx=yes
        STATIC_LIBGCC_LDFLAGS="-static-libgcc"
        STATIC_LIBSTDCXX_LDFLAGS="-static-libstdc++"
     fi])

# Check for seccomp support
AC_CHECK_HEADERS([linux/seccomp.h linux/filter.h linux/audit.h])

# Output files
AC_CONFIG_FILES([
    Makefile
    src/Makefile
    src/libpseudo/Makefile
    src/handlers/Makefile
    src/handlers/seccomp/Makefile
])

# Only configure CLI tool directories if enabled
AS_IF([test "x$enable_cli_tools" = xyes],
    [AC_CONFIG_FILES([
        src/pseudo/Makefile
        src/pseudopod/Makefile
    ])])

# Only configure tests if enabled
AS_IF([test "x$enable_tests" = xyes],
    [AC_CONFIG_FILES([
        tests/Makefile
        tests/virtid/Makefile
    ])])

AC_OUTPUT

# Summary
AC_MSG_RESULT([
    $PACKAGE_NAME $VERSION

    Configuration:
    --------------
    prefix:                 ${prefix}
    exec_prefix:            ${exec_prefix}
    bindir:                 ${bindir}
    libdir:                 ${libdir}
    includedir:             ${includedir}
    
    Compiler:
    ---------
    CC:                     ${CC}
    CFLAGS:                 ${CFLAGS}
])

AS_IF([test "x$enable_cli_tools" = xyes],
    [AC_MSG_RESULT([    CXX:                    ${CXX}
    CXXFLAGS:               ${CXXFLAGS}])])

AC_MSG_RESULT([    LDFLAGS:                ${LDFLAGS}
    
    Components:
    -----------
    architecture:           ${ARCH_NAME}
    libpseudo library:      yes
    shared libraries:       ${enable_shared}
    static libraries:       ${enable_static}
    handlers library:       yes
    CLI tools:              ${enable_cli_tools}])

AS_IF([test "x$enable_cli_tools" = xyes],
    [AC_MSG_RESULT([    libcap support:         ${have_libcap}
    static libgcc:          ${static_libgcc}
    static libstdc++:       ${static_libstdcxx}])])

AC_MSG_RESULT([    build tests:            ${enable_tests}
])

# Build instructions
AS_IF([test "x$enable_cli_tools" = xyes],
    [AS_IF([test "x$enable_tests" = xyes],
        [AC_MSG_RESULT([    Now type 'make' to build pseudopod and tests.])],
        [AC_MSG_RESULT([    Now type 'make' to build pseudopod.])])],
    [AC_MSG_RESULT([    Now type 'make' to build libpseudo only.])])
