/*
 * Copyright (C) 2015  bind-dyndb-ldap authors; see COPYING for license
 *
 * Meta-database for information which are not represented in DNS data.
 */

#include <isc/mutex.h>
#include <isc/util.h>

#include <dns/db.h>
#include <dns/dbiterator.h>
#include <dns/rdatalist.h>
#include <dns/rdatasetiter.h>

#include "metadb.h"
#include "util.h"

struct metadb {
	isc_mem_t			*mctx;
	dns_db_t			*rbtdb;

	/** Upcoming RBTDB version. */
	dns_dbversion_t			*newversion;

	/**
	 * Guard for newversion. Only one RBTDB version can be open
	 * for writing at any time. See functions newversion and closeversion.
	 */
	isc_mutex_t			newversion_lock;
};

/**
 * Initialize new empty meta-database backed by RBT DB.
 */
isc_result_t
metadb_new(isc_mem_t *mctx, metadb_t **mdbp) {
	isc_result_t result;
	metadb_t *mdb = NULL;
	bool lock_ready = false;

	REQUIRE(mdbp != NULL && *mdbp == NULL);

	CHECKED_MEM_GET_PTR(mctx, mdb);
	ZERO_PTR(mdb);

	isc_mem_attach(mctx, &mdb->mctx);

	/* isc_mutex_init and isc_condition_init failures are now fatal */
	isc_mutex_init(&mdb->newversion_lock);
	lock_ready = true;
	CHECK(dns_db_create(mctx, "rbt", dns_rootname, dns_dbtype_zone,
			    dns_rdataclass_in, 0, NULL, &mdb->rbtdb));

	*mdbp = mdb;
	return result;

cleanup:
	if (mdb != NULL) {
		if (lock_ready == true) {
			/* isc_mutex_destroy errors are now fatal */
			isc_mutex_destroy(&mdb->newversion_lock);
		}
		MEM_PUT_AND_DETACH(mdb);
	}
	return result;
}

/**
 * Destroy meta-database.
 * All write-able versions have to be closed before calling destroy().
 */
void
metadb_destroy(metadb_t **mdbp) {
	metadb_t *mdb;

	REQUIRE(mdbp != NULL && *mdbp != NULL);

	mdb = *mdbp;

#ifdef METADB_DEBUG
	dns_db_dump(mdb->rbtdb, NULL, "/tmp/mdb.db");
#endif
	dns_db_detach(&mdb->rbtdb);
	/* isc_mutex_destroy errors are now fatal */
	isc_mutex_destroy(&mdb->newversion_lock);
	MEM_PUT_AND_DETACH(mdb);

	*mdbp = NULL;
}

/**
 * Open new metaDB version for writing.
 *
 * @warning metaDB should be modified only from single thread!
 *
 * @waning Only one writeable version can be open at any time. Purpose of the
 *         lock is to detect misuse and prevent immediate crashes
 *         but it does not change properties of underlying RBT DB.
 */
isc_result_t
metadb_newversion(metadb_t *mdb) {
	isc_result_t result;

	if (isc_mutex_trylock(&mdb->newversion_lock) != ISC_R_SUCCESS) {
		log_bug("mdb newversion_lock is not open");
		LOCK(&mdb->newversion_lock);
	}
	CHECK(dns_db_newversion(mdb->rbtdb, &mdb->newversion));

cleanup:
	if (result != ISC_R_SUCCESS)
		UNLOCK(&mdb->newversion_lock);
	return result;
}

/**
 * Close writeable metaDB version and commit/discard all changes.
 *
 * @pre All metaDB nodes have to be closed before calling
 *      closeversion(commit = true).
 */
void
metadb_closeversion(metadb_t *mdb, bool commit) {
	UNLOCK(&mdb->newversion_lock);
	dns_db_closeversion(mdb->rbtdb, &mdb->newversion, commit);
}

void
metadb_iterator_destroy(metadb_iter_t **miterp) {
	metadb_iter_t *miter = NULL;

	REQUIRE(miterp != NULL);
	miter = *miterp;
	if (miter == NULL)
		return;

	/* user has to deallocate state before calling destroy() */
	INSIST(miter->state == NULL);

	if (miter->iter != NULL)
		dns_dbiterator_destroy(&miter->iter);

	if (miter->rbtdb != NULL) {
		if (miter->version != NULL)
			dns_db_closeversion(miter->rbtdb,
					    &miter->version,
					    false);
		dns_db_detach(&miter->rbtdb);
	}

	MEM_PUT_AND_DETACH(miter);
	*miterp = NULL;
}

/**
 * Create an iterator for current read-only version of metaDB.
 */
isc_result_t
metadb_iterator_create(metadb_t *mdb, metadb_iter_t **miterp) {
	isc_result_t result;
	metadb_iter_t *miter = NULL;

	REQUIRE(mdb != NULL);
	REQUIRE(miterp != NULL && *miterp == NULL);

	CHECKED_MEM_GET_PTR(mdb->mctx, miter);
	ZERO_PTR(miter);

	isc_mem_attach(mdb->mctx, &miter->mctx);
	dns_db_attach(mdb->rbtdb, &miter->rbtdb);
	dns_db_currentversion(miter->rbtdb, &miter->version);
	CHECK(dns_db_createiterator(mdb->rbtdb, 0, &miter->iter));

	*miterp = miter;
	return ISC_R_SUCCESS;

cleanup:
	metadb_iterator_destroy(&miter);
	return result;
}

/**
 * Close metaDB node and detach associated DB version. All changes will be lost
 * if this was the last reference to particular metaDB version.
 */
void
metadb_node_close(metadb_node_t **nodep) {
	metadb_node_t *node;

	REQUIRE(nodep != NULL);

	node = *nodep;
	if (node == NULL)
		return;

	if (node->rbtdb != NULL) {
		if (node->dbnode != NULL)
			dns_db_detachnode(node->rbtdb, &node->dbnode);
		if (node->version != NULL)
			dns_db_closeversion(node->rbtdb, &node->version,
					    false);
		dns_db_detach(&node->rbtdb);
	}
	MEM_PUT_AND_DETACH(node);
	*nodep = NULL;
}

/**
 * Delete all RRsets in given metaDB node.
 */
isc_result_t
metadb_node_delete(metadb_node_t **nodep) {
	isc_result_t result;
	metadb_node_t *node;
	dns_rdatasetiter_t *iter = NULL;
	dns_rdataset_t rdataset;

	REQUIRE(nodep != NULL && *nodep != NULL);
	node = *nodep;

	dns_rdataset_init(&rdataset);
	CHECK(dns_db_allrdatasets(node->rbtdb, node->dbnode, node->version, 0,
				  &iter));

	for (result = dns_rdatasetiter_first(iter);
	     result == ISC_R_SUCCESS;
	     result = dns_rdatasetiter_next(iter)) {

		dns_rdatasetiter_current(iter, &rdataset);
		CHECK(dns_db_deleterdataset(node->rbtdb, node->dbnode,
					    node->version, rdataset.type, 0));
		dns_rdataset_disassociate(&rdataset);
	}
	if (result == ISC_R_NOMORE)
		result = ISC_R_SUCCESS;

cleanup:
	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	if (iter != NULL)
		dns_rdatasetiter_destroy(&iter);
	if (result == ISC_R_SUCCESS)
		metadb_node_close(nodep);
	return result;
}

/**
 * Create new "metaDB node" structure and attach underlying RBT DB node to it.
 *
 * @param[in]  version Underlying RBTDB version to use.
 * @param[in]  mname   Name of the node in metaDB. E.g. '1234.uuid.ldap.'
 * @param[in]  create  RBTDB node will be created if it does not exist.
 * @param[out] nodep   Resulting "metaDB node" structure. It has to be freed
 *                     using metadb_node_close().
 */
static isc_result_t
metadb_node_init(metadb_t *mdb, dns_dbversion_t *ver, dns_name_t *mname,
		 bool create, metadb_node_t **nodep) {
	isc_result_t result;
	metadb_node_t *node = NULL;

	REQUIRE(nodep != NULL && *nodep == NULL);

	CHECKED_MEM_GET_PTR(mdb->mctx, node);
	ZERO_PTR(node);

	isc_mem_attach(mdb->mctx, &node->mctx);
	dns_db_attach(mdb->rbtdb, &node->rbtdb);
	dns_db_attachversion(mdb->rbtdb, ver, &node->version);
	CHECK(dns_db_findnode(mdb->rbtdb, mname, create, &node->dbnode));

	*nodep = node;
	return ISC_R_SUCCESS;

cleanup:
	metadb_node_close(&node);
	return result;
}

/**
 * Associate "metaDB node" structure with existing node in current read-only
 * version of RBT DB.
 *
 * @param[in]  mname Name of the node in metaDB. E.g. '1234.uuid.ldap.'
 * @param[out] nodep Resulting "metaDB node" structure. Node has to be freed
 *                   using metadb_node_close().
 */
isc_result_t
metadb_readnode_open(metadb_t *mdb, dns_name_t *mname, metadb_node_t **nodep) {
	isc_result_t result;
	dns_dbversion_t *ver = NULL;

	dns_db_currentversion(mdb->rbtdb, &ver);
	CHECK(metadb_node_init(mdb, ver, mname, false, nodep));

cleanup:
	dns_db_closeversion(mdb->rbtdb, &ver, false);
	return result;
}

/**
 * Create new "metaDB node" in current writeable version of metaDB.
 *
 * @param[in]  mname Name of the node in metaDB. E.g. '1234.uuid.ldap.'
 * @param[out] nodep Resulting "metaDB node" structure. Node has to be freed
 *                   using metadb_node_close().
 *
 * @pre MetaDB was opened by newversion().
 */
isc_result_t
metadb_writenode_create(metadb_t *mdb, dns_name_t *mname, metadb_node_t **nodep) {
	isc_result_t result;
	dns_dbversion_t *ver = NULL;

	INSIST(mdb->newversion != NULL);
	dns_db_attachversion(mdb->rbtdb, mdb->newversion, &ver);
	CHECK(metadb_node_init(mdb, ver, mname, true, nodep));

cleanup:
	dns_db_closeversion(mdb->rbtdb, &ver, false);
	return result;
}

/**
 * Open existing "metaDB node" in current writeable version of metaDB.
 *
 * @param[in]  mname Name of the node in metaDB. E.g. '1234.uuid.ldap.'
 * @param[out] nodep Resulting "metaDB node" structure. Node has to be freed
 *                   using metadb_node_close().
 *
 * @pre MetaDB was opened by newversion().
 */
isc_result_t
metadb_writenode_open(metadb_t *mdb, dns_name_t *mname, metadb_node_t **nodep) {
	isc_result_t result;
	dns_dbversion_t *ver = NULL;

	INSIST(mdb->newversion != NULL);
	dns_db_attachversion(mdb->rbtdb, mdb->newversion, &ver);
	CHECK(metadb_node_init(mdb, ver, mname, false, nodep));

cleanup:
	dns_db_closeversion(mdb->rbtdb, &ver, false);
	return result;
}

/**
 * Store rdata into metaDB node and overwrite all existing values for RR type
 * specified in rdata.
 *
 * @pre Node was created by metadb_writenode_create().
 */
isc_result_t
metadb_rdata_store(dns_rdata_t *rdata, metadb_node_t *node) {
	isc_result_t result;
	dns_rdatalist_t rdatalist;
	dns_rdataset_t rdataset;

	dns_rdatalist_init(&rdatalist);
	rdatalist.rdclass = rdata->rdclass;
	rdatalist.type = rdata->type;
	dns_rdataset_init(&rdataset);
	APPEND(rdatalist.rdata, rdata, link);

	RUNTIME_CHECK(dns_rdatalist_tordataset(&rdatalist, &rdataset)
		      == ISC_R_SUCCESS);
	/* DNS_DBADD_MERGE flag is not set - old rdataset will be replaced. */
	CHECK(dns_db_addrdataset(node->rbtdb, node->dbnode, node->version, 0, &rdataset, 0, NULL));

cleanup:
	if (dns_rdataset_isassociated(&rdataset))
		dns_rdataset_disassociate(&rdataset);
	if (result == DNS_R_UNCHANGED)
		result = ISC_R_SUCCESS;
	return result;
}

/**
 * Get rdataset of given type from metaDB.
 *
 * Caller has to call dns_rdataset_dissociate() on the returned rdataset.
 * Rdata will become invalid after dns_rdataset_dissociate() call.
 *
 * Note: It is not possible to directly return rdata without rdataset because
 *       there would be no way how to dissociate rdataset.
 *
 * @pre Node was created by metadb_writenode_create() or metadb_readnode_open().
 * @pre rdatataset is valid diassociated rdataset.
 *
 * @post Rdataset is an associated rdataset with exactly one rdata instance.
 *       Rdata can be obtained using dns_rdadaset_current().
 */
isc_result_t
metadb_rdataset_get(metadb_node_t *node, dns_rdatatype_t rrtype,
		    dns_rdataset_t *rdataset) {
	isc_result_t result;

	REQUIRE(dns_rdataset_isassociated(rdataset) == false);

	CHECK(dns_db_findrdataset(node->rbtdb, node->dbnode, node->version,
				  rrtype, 0, 0, rdataset, NULL));
	/* Exactly one RR is expected in metaDB. */
	INSIST(dns_rdataset_count(rdataset) == 1);
	INSIST(dns_rdataset_first(rdataset) == ISC_R_SUCCESS);

cleanup:
	if (result != ISC_R_SUCCESS && dns_rdataset_isassociated(rdataset))
		dns_rdataset_disassociate(rdataset);
	return result;
}
