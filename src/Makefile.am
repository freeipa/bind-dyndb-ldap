lib_LTLIBRARIES = libdnsldap.la

LIBMAJOR = 1
LIBMINOR = 0

HDRS =  cache.h ldap_convert.h ldap_helper.h log.h rdlist.h semaphore.h \
	settings.h str.h util.h zone_manager.h

libdnsldap_la_SOURCES = $(HDRS) cache.c ldap_convert.c ldap_driver.c \
	ldap_helper.c log.c rdlist.c semaphore.c settings.c str.c \
	zone_manager.c

libdnsldap_la_CFLAGS = -Wall -Wextra -pedantic -std=c99

libdnsldap_la_LDFLAGS = -version-info $(LIBMAJOR):$(LIBMINOR):0
