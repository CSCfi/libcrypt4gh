# -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([crypt4gh], [1.0], [silverdaz@gmail.com])

AC_CONFIG_SRCDIR([lib/payload.c])

# AC_CONFIG_AUX_DIR([build-aux])

# Checks for programs.
AC_PROG_CC #([cc clang gcc])
AC_PROG_RANLIB
AC_CHECK_TOOLS([AR], [ar], [install])
# AC_PROG_INSTALL
# AC_PROG_MKDIR_P

# First of all, we need libsodium
dnl define(SECTION_TITLE, [	echo '===== $1 =====' >&AS_MESSAGE_FD ])
dnl SECTION_TITLE([Checking for libsodium])
AC_SEARCH_LIBS([sodium_malloc], [sodium], [], [AC_ERROR("libsodium is required. Install it from https://libsodium.org/.")])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stddef.h stdint.h stdlib.h stdio.h string.h unistd.h sys/ctypes.h sys/stat.h errno.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_CHECK_FUNCS([memcpy strerror])
AC_FUNC_MALLOC

dnl # Check for Endianness
dnl AC_C_BIGENDIAN(
dnl   AC_DEFINE(NATIVE_BIG_ENDIAN, 1, [machine is big-endian]),
dnl   AC_DEFINE(NATIVE_LITTLE_ENDIAN, 1, [machine is little-endian]),
dnl   AC_MSG_ERROR([unknown endianness]),
dnl   AC_MSG_ERROR([universal endianness is not supported - compile separately and use lipo(1)])
dnl )


AC_CONFIG_FILES([Makefile
		 lib/Makefile
		 src/Makefile])


AC_OUTPUT
