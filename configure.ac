AC_PREREQ([2.59])
AC_INIT([bind-dyndb-ldap], [11.2], [freeipa-devel@redhat.com])

AM_INIT_AUTOMAKE([-Wall foreign dist-bzip2])

AC_CONFIG_SRCDIR([src/ldap_driver.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# Disable static libraries
AC_DISABLE_STATIC

# Checks for programs.
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
AC_PROG_CC
AC_PROG_LIBTOOL

# Checks for header files.
AC_CHECK_HEADERS([stddef.h stdlib.h string.h strings.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_CHECK_FUNCS([memset strcasecmp strncasecmp])

# Check if build chain supports symbol visibility
AC_MSG_CHECKING([for -fvisibility=hidden compiler flag])
SAVED_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS -fvisibility=hidden"
AC_TRY_COMPILE([
	extern __attribute__((__visibility__("hidden"))) int hidden;
	extern __attribute__((__visibility__("default"))) int def;
	extern __attribute__((__visibility__("hidden"))) int fhidden(void);
	extern __attribute__((__visibility__("default"))) int fdef(void);
],[],
[AC_MSG_RESULT([yes])
 AC_DEFINE([HAVE_VISIBILITY], 1, [Define if compiler supports -fvisibility])],
[CFLAGS="$SAVED_CFLAGS"
 AC_MSG_RESULT([no])])

# Check if build chain supports -fno-delete-null-pointer-checks
# this flag avoids too agressive optimizations which would remove some asserts
# BIND 9 did the same in its commit 603a78708343f063b44affb882ef93bb19a5142a
AC_MSG_CHECKING([for -fno-delete-null-pointer-checks compiler flag])
SAVED_CFLAGS="$CFLAGS"
CFLAGS="-fno-delete-null-pointer-checks -Werror"
AC_TRY_COMPILE([
	extern int fdef(void);
],[],
[AC_MSG_RESULT([yes])
 CFLAGS="$SAVED_CFLAGS -fno-delete-null-pointer-checks"],
[CFLAGS="$SAVED_CFLAGS"
 AC_MSG_RESULT([no])])

# Get CFLAGS from isc-config.sh
AC_ARG_VAR([BIND9_CFLAGS],
           [C compiler flags for bind9, overriding isc-config.sh])
AC_SUBST(BIND9_CFLAGS)

dnl do not override enviroment variables BIND9_CFLAGS
if test -z "$BIND9_CFLAGS"; then
	AC_PATH_PROG(ISC_CONFIG, [isc-config.sh])
	AC_MSG_CHECKING([for working isc-config])
	if test -x "$ISC_CONFIG"; then
		AC_MSG_RESULT([yes]);
		BIND9_CFLAGS=`$ISC_CONFIG --cflags dns`
		dnl We do not need all libraries suggested by isc-config.sh
		dnl {-lcrypto, -lcap} are useless
		dnl BIND9_LIBS=`$ISC_CONFIG --libs dns`
	else
		AC_MSG_RESULT([no])
		AC_MSG_WARN([
	Could not detect script isc-config.sh. Compilation may fail.
	Defining variable BIND9_CFLAGS will fix this problem.
	])
	fi
fi
CFLAGS="$BIND9_CFLAGS $CFLAGS"

# Checks for libraries.
AC_CHECK_LIB([isc], [isc_dir_open], [],
	AC_MSG_ERROR([Install BIND9 ISC development files]))
AC_CHECK_LIB([dns], [dns_name_init], [],
	AC_MSG_ERROR([Install BIND9 development files]))
AC_CHECK_LIB([ldap], [ldap_initialize], [],
	AC_MSG_ERROR([Install OpenLDAP development files]))
AC_CHECK_LIB([krb5], [krb5_cc_initialize], [],
	AC_MSG_ERROR([Install Kerberos 5 development files]))
AC_CHECK_LIB([uuid], [uuid_unparse], [],
	AC_MSG_ERROR([Install UUID library development files]))

# Check version of libdns
AC_MSG_CHECKING([libdns version])
AC_TRY_RUN([
#include <stdio.h>
#include <dns/version.h>
int main(void) {
	printf("%d\n", dns_libinterface);
	return 0;
}],[LIBDNS_VERSION_MAJOR=`./conftest$ac_exeext`
    AC_DEFINE_UNQUOTED([LIBDNS_VERSION_MAJOR], [$LIBDNS_VERSION_MAJOR],
    [Define libdns version])],
[AC_MSG_ERROR([Can't obtain libdns version.])],
[AC_MSG_ERROR([Cross compiling is not supported.])]
)

dnl isc_errno_toresult() was not available in older header files
AC_MSG_CHECKING([isc_errno_toresult availability])
AC_TRY_RUN([
#include <isc/errno.h>
int main(void) {
	isc_errno_toresult(0);
	return 0;
}],
[AC_MSG_RESULT([yes])],
[AC_MSG_ERROR([
 Can't find isc_errno_toresult() or header isc/errno.h:
 Please install bind-devel package or similar.])],
[AC_MSG_ERROR([Cross compiling is not supported.])]
)

dnl Older autoconf (2.59, for example) doesn't define docdir
[[ ! -n "$docdir" ]] && docdir='${datadir}/doc/${PACKAGE_TARNAME}'
AC_SUBST([docdir])

AC_ARG_ENABLE([werror],
	AC_HELP_STRING([--disable-werror],
		[Disable compilation with -Werror flag]),
	[WERROR="$enableval"], [WERROR=yes]
)

if test "x$WERROR" = xyes; then
	WERROR=-Werror
else
	WERROR=
fi
AC_SUBST([WERROR])

AC_CONFIG_FILES([Makefile doc/Makefile src/Makefile])
AC_OUTPUT
