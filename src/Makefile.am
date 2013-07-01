bindplugin_LTLIBRARIES = ldap.la
bindplugindir=$(libdir)/bind

HDRS =				\
	acl.h			\
	compat.h		\
	fwd_register.h		\
	krb5_helper.h		\
	ldap_convert.h		\
	ldap_driver.h		\
	ldap_entry.h		\
	ldap_helper.h		\
	log.h			\
	rbt_helper.h		\
	rdlist.h		\
	semaphore.h		\
	settings.h		\
	str.h			\
	types.h			\
	util.h			\
	zone_manager.h		\
	zone_register.h

ldap_la_SOURCES =		\
	$(HDRS)			\
	acl.c			\
	fwd_register.c		\
	krb5_helper.c		\
	ldap_convert.c		\
	ldap_driver.c		\
	ldap_entry.c		\
	ldap_helper.c		\
	log.c			\
	rbt_helper.c		\
	rdlist.c		\
	semaphore.c		\
	settings.c		\
	str.c			\
	zone_manager.c		\
	zone_register.c

ldap_la_CFLAGS = -Wall -Wextra @WERROR@ -std=gnu99 -O2

ldap_la_LDFLAGS = -module -avoid-version -Wl,-z,relro,-z,now,-z,noexecstack
