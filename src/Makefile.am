bindplugin_LTLIBRARIES = ldap.la
bindplugindir=$(libdir)/bind

HDRS =				\
	acl.h			\
	cache.h			\
	ldap_convert.h		\
	ldap_helper.h		\
	log.h			\
	rdlist.h		\
	semaphore.h		\
	settings.h		\
	str.h			\
	util.h			\
	zone_manager.h

ldap_la_SOURCES =		\
	$(HDRS)			\
	acl.c			\
	cache.c			\
	ldap_convert.c		\
	ldap_driver.c		\
	ldap_helper.c		\
	log.c			\
	rdlist.c		\
	semaphore.c		\
	settings.c		\
	str.c			\
	zone_manager.c

ldap_la_CFLAGS = -Wall -Wextra -pedantic -std=c99 -O2

ldap_la_LDFLAGS = -module -avoid-version
