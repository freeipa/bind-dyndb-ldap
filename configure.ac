AC_PREREQ([2.59])
AC_INIT([bind-dyndb-ldap], [0.2.0], [freeipa-devel@redhat.com])

AM_INIT_AUTOMAKE([-Wall foreign dist-bzip2])

AC_CONFIG_SRCDIR([src/zone_manager.h])
AC_CONFIG_HEADERS([config.h])

# Disable static libraries
AC_DISABLE_STATIC

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL

# Checks for libraries.
AC_CHECK_LIB([dns], [dns_name_init], [],
	AC_MSG_ERROR([Install BIND9 development files]))
AC_CHECK_LIB([ldap], [ldap_initialize], [],
	AC_MSG_ERROR([Install OpenLDAP development files]))

# Checks for header files.
AC_CHECK_HEADERS([stddef.h stdlib.h string.h strings.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_CHECK_FUNCS([memset strcasecmp strncasecmp])

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

# Older autoconf (2.59, for example) doesn't define docdir
[[ ! -n "$docdir" ]] && docdir='${datadir}/doc/${PACKAGE_TARNAME}'
AC_SUBST([docdir])

AC_CONFIG_FILES([Makefile doc/Makefile src/Makefile])
AC_OUTPUT
