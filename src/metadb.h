/*
 * Copyright (C) 2015  bind-dyndb-ldap authors; see COPYING for license
 *
 * Meta-database for information which are not represented in DNS data.
 */

#ifndef SRC_METADB_H_
#define SRC_METADB_H_

#include "util.h"


/**
 * All-in-one structure for metaDB operations. Version guarantees that node
 * content visible to metadb_node user will not change asynchronously
 * as long as metaDB 'version' is modified in the same thread.
 */
struct metadb_node {
	isc_mem_t			*mctx;
	dns_db_t			*rbtdb;
	dns_dbversion_t			*version;
	dns_dbnode_t			*dbnode;
};

typedef struct metadb_node metadb_node_t;
typedef struct metadb metadb_t;

isc_result_t
metadb_new(isc_mem_t *mctx, metadb_t **dbp) ATTR_CHECKRESULT ATTR_NONNULLS;

void
metadb_destroy(metadb_t **dbp);

isc_result_t ATTR_CHECKRESULT ATTR_NONNULLS
metadb_newversion(metadb_t *mdb);

void ATTR_NONNULLS
metadb_closeversion(metadb_t *mdb, isc_boolean_t commit);

isc_result_t ATTR_CHECKRESULT ATTR_NONNULLS
metadb_readnode_open(metadb_t *mdb, dns_name_t *mname, metadb_node_t **nodep);

isc_result_t ATTR_CHECKRESULT ATTR_NONNULLS
metadb_writenode_create(metadb_t *mdb, dns_name_t *mname, metadb_node_t **nodep);

isc_result_t ATTR_CHECKRESULT ATTR_NONNULLS
metadb_writenode_open(metadb_t *mdb, dns_name_t *mname, metadb_node_t **nodep);

isc_result_t ATTR_CHECKRESULT ATTR_NONNULLS
metadb_rdata_store(dns_rdata_t *rdata, metadb_node_t *node);

isc_result_t ATTR_CHECKRESULT ATTR_NONNULLS
metadb_rdataset_get(metadb_node_t *node, dns_rdatatype_t rrtype,
		    dns_rdataset_t *rdataset);

void ATTR_NONNULLS
metadb_node_close(metadb_node_t **nodep);

isc_result_t ATTR_NONNULLS
metadb_node_delete(metadb_node_t **nodep);

#endif /* SRC_METADB_H_ */
