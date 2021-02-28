# -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([crypt4gh], [1.0], [silverdaz@gmail.com])

AC_CONFIG_SRCDIR([crypt4gh.c])

AC_LANG([C])

AC_CONFIG_HEADER([config.h])
AC_PROG_CC([cc gcc])
AC_PROG_CC #([cc clang gcc])
# AC_C_BIGENDIAN

# Checks for programs.
AC_PROG_CPP
AC_PROG_RANLIB
AC_CHECK_TOOLS([AR], [ar])

# System features
if test -z "$AR" ; then
   AC_MSG_ERROR([*** 'ar' missing, please install or fix your \$PATH ***])
fi

AC_C_INLINE

# First of all, we need libsodium
AC_SEARCH_LIBS([sodium_malloc], [sodium], [], [AC_ERROR("libsodium is required. Install it from https://libsodium.org/.")])
#CFLAGS="${CFLAGS} $(pkg-config --cflags libsodium)"
#LDFLAGS="$LDFLAGS $(pkg-config --libs libsodium)"


if test "$GCC" = "yes"; then
   AC_MSG_CHECKING([if $CC accepts -fno-builtin-memset])
   saved_CFLAGS="$CFLAGS"
   CFLAGS="$CFLAGS -fno-builtin-memset"
   AC_LINK_IFELSE([AC_LANG_PROGRAM([[ #include <string.h> ]],
		[[ char b[10]; memset(b, 0, sizeof(b)); ]])],
	[ AC_MSG_RESULT([yes]) ],
	[ AC_MSG_RESULT([no])
	  CFLAGS="$saved_CFLAGS" ]
	)
fi


#######################################################

AC_MSG_CHECKING([if compiler allows __attribute__ on return types])
AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM([[
#include <stdlib.h>
__attribute__((__unused__)) static void foo(void){return;}]],
    [[ exit(0); ]])],
    [ AC_MSG_RESULT([yes]) ],
    [ AC_MSG_RESULT([no])
      AC_DEFINE(NO_ATTRIBUTE_ON_RETURN_TYPE, 1,
	 [compiler does not accept __attribute__ on return types]) ]
)

AC_MSG_CHECKING([if compiler allows __attribute__ prototype args])
AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM([[
#include <stdlib.h>
typedef void foo(const char *, ...) __attribute__((format(printf, 1, 2)));]],
    [[ exit(0); ]])],
    [ AC_MSG_RESULT([yes]) ],
    [ AC_MSG_RESULT([no])
      AC_DEFINE(NO_ATTRIBUTE_ON_PROTOTYPE_ARGS, 1,
	 [compiler does not accept __attribute__ on prototype args]) ]
)

# Miscellaneous checks
AC_CACHE_CHECK([whether $CC implements __FUNCTION__], ac_cv_cc_implements___FUNCTION__, [
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[ #include <stdio.h> ]],
		[[ printf("%s", __FUNCTION__); ]])],
	[ ac_cv_cc_implements___FUNCTION__="yes" ],
	[ ac_cv_cc_implements___FUNCTION__="no"
	])
])
if test "x$ac_cv_cc_implements___FUNCTION__" = "xyes" ; then
	AC_DEFINE([HAVE___FUNCTION__], [1],
		[Define if compiler implements __FUNCTION__])
fi

#######################################################

# Checks for header files.
AC_CHECK_HEADERS([ \
	endian.h \
	stdint.h \
	string.h \
	unistd.h \
])

# Check for Endianness
AC_C_BIGENDIAN(
  AC_DEFINE(NATIVE_BIG_ENDIAN, 1, [machine is big-endian]),
  AC_DEFINE(NATIVE_LITTLE_ENDIAN, 1, [machine is little-endian]),
  AC_MSG_ERROR([unknown endianness]),
  AC_MSG_ERROR([universal endianness is not supported - compile separately and use lipo(1)])
)

# "Particular Function Checks"
# see https://www.gnu.org/software/autoconf/manual/autoconf-2.69/html_node/Particular-Functions.html
AC_FUNC_MEMCMP
AC_FUNC_MALLOC

#######################################################

# Check for  long long datatypes
AC_TYPE_OFF_T
AC_CHECK_TYPES([unsigned long long])

AC_CHECK_SIZEOF([int])

# More checks for data types
AC_CACHE_CHECK([for uintXX_t types], ac_cv_have_uintxx_t, [
		AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <sys/types.h>
			]], [[
	uint8_t a;
	uint32_t c;
	a = b = c = 1;
			]])],
		[ ac_cv_have_uintxx_t="yes" ], [ ac_cv_have_uintxx_t="no"
		])
	])
if test "x$ac_cv_have_uintxx_t" = "xyes" ; then
	AC_DEFINE([HAVE_UINTXX_T], [1],
		[define if you have uintxx_t data type])
fi

if (test -z "$have_uintxx_t" && \
	   test "x$ac_cv_header_stdint_h" = "xyes")
then
    AC_MSG_CHECKING([for uintXX_t types in stdint.h])
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[ #include <stdint.h> ]],
	[[ uint8_t a; uint32_t b; a = b = 1;]])],
		[
			AC_DEFINE([HAVE_UINTXX_T])
			AC_MSG_RESULT([yes])
		], [ AC_MSG_RESULT([no])
	])
fi

AC_CACHE_CHECK([for size_t], ac_cv_have_size_t, [
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[ #include <sys/types.h> ]],
	[[ size_t foo; foo = 1235; ]])],
	[ ac_cv_have_size_t="yes" ], [ ac_cv_have_size_t="no"
	])
])
if test "x$ac_cv_have_size_t" = "xyes" ; then
	AC_DEFINE([HAVE_SIZE_T], [1], [define if you have size_t data type])
fi

#######################################################

AC_ARG_WITH([debug],
	[  --with-debug            Build main code with -g -DDEBUG=xxx],
	[
		if test -n "$withval"  &&  test "x$withval" != "xno"; then
			case  "x${withval}" in
			    x1|x2|x3)
 			        DEFS="$DEFS -DDEBUG=${withval}"
				CFLAGS="-g $CFLAGS"
				;;
				*)
				CFLAGS="-g $CFLAGS"
				;;
			esac
		fi
	]
)


#######################################################

AC_SUBST([DEPEND], [$(cat $srcdir/.depend)])

AC_CONFIG_FILES([Makefile
                libcrypt4gh.pc])

CFLAGS="$debug_flag $CFLAGS"

AC_OUTPUT

# Print summary of options

echo ""
echo "            Compiler: ${CC}"
echo "      Compiler flags: ${CFLAGS}"
echo "  Preprocessor flags: ${CPPFLAGS}"
echo "                LIBS: ${LIBS}"

echo ""
