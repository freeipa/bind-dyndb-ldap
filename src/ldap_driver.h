/*
 * Copyright (C) 2013  bind-dyndb-ldap authors; see COPYING for license
 */

#ifndef LDAP_DRIVER_H_
#define LDAP_DRIVER_H_

#include <dns/diff.h>
#include <dns/types.h>

#include "util.h"

/* values shared by all LDAP database instances */
#define LDAP_DB_TYPE		dns_dbtype_zone
#define LDAP_DB_RDATACLASS	dns_rdataclass_in
#define LDAP_DB_ARGC		1

typedef struct ldapdb ldapdb_t;

isc_result_t
ldapdb_create(isc_mem_t *mctx, dns_name_t *name, dns_dbtype_t type,
	      dns_rdataclass_t rdclass, void *driverarg, dns_db_t **dbp)
	      ATTR_NONNULL(1,2,5,6);

isc_result_t
ldapdb_associate(isc_mem_t *mctx, const dns_name_t *name, dns_dbtype_t type,
		 dns_rdataclass_t rdclass, unsigned int argc, char *argv[],
		 void *driverarg, dns_db_t **dbp) ATTR_NONNULL(1,2,7,8);
dns_db_t *
ldapdb_get_rbtdb(dns_db_t *db) ATTR_NONNULLS;

#endif /* LDAP_DRIVER_H_ */
