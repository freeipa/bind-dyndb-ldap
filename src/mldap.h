/*
 * Copyright (C) 2015  bind-dyndb-ldap authors; see COPYING for license
 */

#ifndef SRC_MLDAP_H_
#define SRC_MLDAP_H_

#include <ldap.h>

#include "metadb.h"
#include "types.h"
#include "util.h"


isc_result_t ATTR_CHECKRESULT ATTR_NONNULLS
mldap_new(isc_mem_t *mctx, mldapdb_t **dbp);

void
mldap_destroy(mldapdb_t **dbp);

isc_result_t ATTR_CHECKRESULT ATTR_NONNULLS
mldap_newversion(mldapdb_t *mldap);

void ATTR_NONNULLS
mldap_closeversion(mldapdb_t *mldap, isc_boolean_t commit);

isc_result_t ATTR_CHECKRESULT ATTR_NONNULLS
mldap_entry_read(mldapdb_t *mldap, struct berval *uuid, metadb_node_t **nodep);

isc_result_t ATTR_CHECKRESULT ATTR_NONNULLS
mldap_entry_create(ldap_entry_t *entry, mldapdb_t *mldap, metadb_node_t **nodep);

isc_result_t ATTR_CHECKRESULT ATTR_NONNULLS
mldap_class_get(metadb_node_t *node, ldap_entryclass_t *class);

isc_result_t ATTR_CHECKRESULT ATTR_NONNULLS
mldap_dnsname_get(metadb_node_t *node, dns_name_t *fqdn, dns_name_t *zone);

isc_result_t ATTR_CHECKRESULT ATTR_NONNULLS
mldap_dnsname_store(dns_name_t *fqdn, dns_name_t *zone, metadb_node_t *node);

#endif /* SRC_MLDAP_H_ */
