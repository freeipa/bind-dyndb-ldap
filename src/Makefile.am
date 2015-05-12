bindplugin_LTLIBRARIES = ldap.la
bindplugindir=$(libdir)/bind

HDRS =				\
	acl.h			\
	compat.h		\
	fs.h			\
	fwd_register.h		\
	krb5_helper.h		\
	ldap_convert.h		\
	ldap_driver.h		\
	ldap_entry.h		\
	ldap_helper.h		\
	lock.h			\
	log.h			\
	metadb.h		\
	mldap.h			\
	rbt_helper.h		\
	semaphore.h		\
	settings.h		\
	syncptr.h		\
	syncrepl.h		\
	str.h			\
	types.h			\
	util.h			\
	zone.h			\
	zone_manager.h		\
	zone_register.h

ldap_la_SOURCES =		\
	$(HDRS)			\
	acl.c			\
	fwd_register.c		\
	fs.c			\
	krb5_helper.c		\
	ldap_convert.c		\
	ldap_driver.c		\
	ldap_entry.c		\
	ldap_helper.c		\
	lock.c			\
	log.c			\
	metadb.c		\
	mldap.c			\
	rbt_helper.c		\
	semaphore.c		\
	settings.c		\
	syncptr.c		\
	syncrepl.c		\
	str.c			\
	zone.c			\
	zone_manager.c		\
	zone_register.c

ldap_la_CFLAGS = -Wall -Wextra @WERROR@ -std=gnu99 -O2

ldap_la_LDFLAGS = -module -avoid-version -Wl,-z,relro,-z,now,-z,noexecstack
