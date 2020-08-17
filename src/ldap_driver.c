/*
 * Copyright (C) 2008-2014  bind-dyndb-ldap authors; see COPYING for license
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#else
#error "Can't compile without config.h"
#endif

#include <isc/buffer.h>
#include <isc/commandline.h>
#include <isc/hash.h>
#include <isc/lib.h>
#include <isc/mem.h>
#include <isc/once.h>
#include <isc/refcount.h>
#include <isc/util.h>

#include <dns/db.h>
#include <dns/diff.h>
#include <dns/dyndb.h>
#include <dns/dbiterator.h>
#include <dns/rdata.h>
#include <dns/rdataclass.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/rdatasetiter.h>
#include <dns/rdatatype.h>
#include <dns/result.h>
#include <dns/soa.h>
#include <dns/types.h>
#include <dns/rpz.h>

#include <string.h> /* For memcpy */

#include "bindcfg.h"
#include "ldap_driver.h"
#include "ldap_helper.h"
#include "ldap_convert.h"
#include "log.h"
#include "util.h"
#include "zone_register.h"

#ifdef HAVE_VISIBILITY
#define VISIBLE __attribute__((__visibility__("default")))
#else
#define VISIBLE
#endif

#define LDAPDB_MAGIC			ISC_MAGIC('L', 'D', 'P', 'D')
#define VALID_LDAPDB(ldapdb) \
	((ldapdb) != NULL && (ldapdb)->common.impmagic == LDAPDB_MAGIC)

#if LIBDNS_VERSION_MAJOR < 1600
typedef dns_name_t       node_name_t;
#else
typedef const dns_name_t node_name_t;
#endif

isc_result_t
ldapdb_associate(isc_mem_t *mctx, node_name_t *name, dns_dbtype_t type,
		 dns_rdataclass_t rdclass, unsigned int argc, char *argv[],
		 void *driverarg, dns_db_t **dbp) ATTR_NONNULL(1,2,7,8);

struct ldapdb {
	dns_db_t			common;
	isc_refcount_t			refs;
	ldap_instance_t			*ldap_inst;

	/**
	 * Internal RBT database implementation provided by BIND 9.
	 * Most of read only dns_db_*  calls (find(), createiterator(), etc.)
	 * are blindly forwarded to this RBTDB.
	 * Data modification calls (like addrdataset() etc.) are intercepted
	 * by this driver, data manipulation is done in LDAP
	 * and then the same modification is done in internal RBTDB. */
	dns_db_t			*rbtdb;

	/**
	 * Guard for newversion. Only one new version can be open at any time.
	 * newversion(ldapdb, newver) locks the lock
	 * and closeversion(ldapdb, newver) unlocks the lock. */
	isc_mutex_t			newversion_lock;

	/**
	 * Upcoming RBTDB version. It is automatically updated
	 * by newversion(ldapdb) and closeversion(ldapdb).
	 * The purpose is to detect moment when the new version is closed.
	 * That is the right time for unlocking newversion_lock. */
	dns_dbversion_t			*newversion;
};

dns_db_t * ATTR_NONNULLS
ldapdb_get_rbtdb(dns_db_t *db) {
	ldapdb_t *ldapdb = (ldapdb_t *)db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return ldapdb->rbtdb;
}

/**
 * Get full DNS name from the node.
 *
 * @warning
 * The code silently expects that "node" came from RBTDB and thus
 * assumption dns_dbnode_t (from RBTDB) == dns_rbtnode_t is correct.
 *
 * This should work as long as we use only RBTDB and nothing else.
 */
static isc_result_t
ldapdb_name_fromnode(dns_dbnode_t *node, dns_name_t *name) {
	dns_rbtnode_t *rbtnode = (dns_rbtnode_t *) node;
	return dns_rbt_fullnamefromnode(rbtnode, name);
}

/*
 * Functions.
 *
 * Most of them don't need db parameter but we are checking if it is valid.
 * Invalid db parameter indicates bug in code.
 */

/* !!! Verify that omitting internal RBTDB will not cause havoc. */
static void
attach(dns_db_t *source, dns_db_t **targetp)
{
	ldapdb_t *ldapdb = (ldapdb_t *)source;

	REQUIRE(VALID_LDAPDB(ldapdb));

#if LIBDNS_VERSION_MAJOR < 1600
	isc_refcount_increment(&ldapdb->refs, NULL);
#else
	isc_refcount_increment(&ldapdb->refs);
#endif
	*targetp = source;
}

/* !!! Verify that internal RBTDB cannot leak somehow. */
static void ATTR_NONNULLS
free_ldapdb(ldapdb_t *ldapdb)
{
	REQUIRE(VALID_LDAPDB(ldapdb));

#ifdef RBTDB_DEBUG
	isc_result_t result;
	dns_dbversion_t *version = NULL;
	dns_name_t *zone_name = dns_db_origin(&ldapdb->common);
	ld_string_t *file_name = NULL;

	CHECK(zr_get_zone_path(ldapdb->common.mctx,
			       ldap_instance_getsettings_local(ldapdb->ldap_inst),
			       zone_name, "ldapdb.dump", &file_name));
	dns_db_currentversion(ldapdb->rbtdb, &version);
	log_info("dump to '%s' started", str_buf(file_name));
	result = dns_db_dump2(ldapdb->rbtdb, version, str_buf(file_name),
			      dns_masterformat_text);
	log_info("dump to '%s' finished: %s", str_buf(file_name),
		 isc_result_totext(result));
	dns_db_closeversion(ldapdb->rbtdb, &version, false);

cleanup:
	if (result != ISC_R_SUCCESS) {
		log_error_r("dump to '%s' failed",
				(file_name && str_buf(file_name)) ?
				str_buf(file_name) : "<NULL>");
	}
	str_destroy(&file_name);
#endif
	dns_db_detach(&ldapdb->rbtdb);
	dns_name_free(&ldapdb->common.origin, ldapdb->common.mctx);
	/* isc_mutex_destroy is failing fatal now */
	isc_mutex_destroy(&ldapdb->newversion_lock);
	isc_mem_putanddetach(&ldapdb->common.mctx, ldapdb, sizeof(*ldapdb));
}

/* !!! Verify that omitting internal RBTDB will not cause havoc. */
static void
detach(dns_db_t **dbp)
{
	REQUIRE(dbp != NULL && VALID_LDAPDB((ldapdb_t *)(*dbp)));
	ldapdb_t *ldapdb = (ldapdb_t *)(*dbp);
	unsigned int refs;
#if LIBDNS_VERSION_MAJOR < 1600
	isc_refcount_decrement(&ldapdb->refs, &refs);
#else
	/* isc_refcount_decrement only has one argument now */
	refs = isc_refcount_decrement(&ldapdb->refs);
#endif

	if (refs == 1) {
		free_ldapdb(ldapdb);
	}
}



/**
 * This method should never be called, because LDAP DB is "persistent".
 * See ispersistent() function.
 */

/* !!! This could be required for optimizations (like on-disk cache). */
static isc_result_t
beginload(dns_db_t *db, dns_rdatacallbacks_t *callbacks) {
	UNUSED(db);
	UNUSED(callbacks);

	fatal_error("ldapdb: method beginload() should never be called");

	/* Not reached */
	return ISC_R_SUCCESS;
}

/**
 * This method should never be called, because LDAP DB is "persistent".
 * See ispersistent() function.
 */

/* !!! This could be required for optimizations (like on-disk cache). */
static isc_result_t
endload(dns_db_t *db, dns_rdatacallbacks_t *callbacks) {
	UNUSED(db);
	UNUSED(callbacks);

	fatal_error("ldapdb: method endload() should never be called");

	/* Not reached */
	return ISC_R_SUCCESS;
}

static isc_result_t
serialize(dns_db_t *db, dns_dbversion_t *version, FILE *file)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return dns_db_serialize(ldapdb->rbtdb, version, file);
}

/* !!! This could be required for optimizations (like on-disk cache). */
static isc_result_t
dump(dns_db_t *db, dns_dbversion_t *version, const char *filename,
     dns_masterformat_t masterformat)
{

	UNUSED(db);
	UNUSED(version);
	UNUSED(filename);
	UNUSED(masterformat);

	fatal_error("ldapdb: method dump() should never be called");

	/* Not reached */
	return ISC_R_SUCCESS;
}

static void
currentversion(dns_db_t *db, dns_dbversion_t **versionp)
{
	ldapdb_t *ldapdb = (ldapdb_t *)db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	dns_db_currentversion(ldapdb->rbtdb, versionp);
}

/**
 * @brief Allocate and open new RBTDB version.
 *
 * New version is compatible with LDAPDB and RBTDB.
 * Only one new version can be open at any time. This limitation is enforced
 * by ldapdb->newversion_lock.
 *
 * @warning This function has to be used for all newversion() calls for LDAPDB
 *          AND also internal RBTDB (ldapdb->rbtdb). This ensures proper
 *          serialization and prevents assertion failures in newversion().
 *
 * How to work with internal RBTDB versions in safe way (note ldapdb vs. rbtdb):
 * @verbatim
	CHECK(dns_db_newversion(ldapdb, &newversion));
	// do whatevent you need with the newversion, e.g.:
	CHECK(dns_diff_apply(diff, rbtdb, newversion));

cleanup:
	if (newversion != NULL)
		dns_db_closeversion(ldapdb, &newversion, true);
   @endverbatim
 */
static isc_result_t
newversion(dns_db_t *db, dns_dbversion_t **versionp)
{
	ldapdb_t *ldapdb = (ldapdb_t *)db;
	isc_result_t result;

	REQUIRE(VALID_LDAPDB(ldapdb));

	LOCK(&ldapdb->newversion_lock);
	result = dns_db_newversion(ldapdb->rbtdb, versionp);
	if (result == ISC_R_SUCCESS) {
		INSIST(*versionp != NULL);
		ldapdb->newversion = *versionp;
	} else {
		INSIST(*versionp == NULL);
		UNLOCK(&ldapdb->newversion_lock);
	}
	return result;
}

static void
attachversion(dns_db_t *db, dns_dbversion_t *source,
	      dns_dbversion_t **targetp)
{
	ldapdb_t *ldapdb = (ldapdb_t *)db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	dns_db_attachversion(ldapdb->rbtdb, source, targetp);
}

/**
 * @brief Close LDAPDB and internal RBTDB version.
 *
 * @see newversion for related warnings and examples.
 */
static void
closeversion(dns_db_t *db, dns_dbversion_t **versionp, bool commit)
{
	ldapdb_t *ldapdb = (ldapdb_t *)db;
	dns_dbversion_t *closed_version = *versionp;

	REQUIRE(VALID_LDAPDB(ldapdb));

	dns_db_closeversion(ldapdb->rbtdb, versionp, commit);
	if (closed_version == ldapdb->newversion) {
		ldapdb->newversion = NULL;
		UNLOCK(&ldapdb->newversion_lock);
	}
}

static isc_result_t
findnode(dns_db_t *db, node_name_t *name, bool create,
	 dns_dbnode_t **nodep)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return dns_db_findnode(ldapdb->rbtdb, name, create, nodep);
}

static isc_result_t
find(dns_db_t *db, node_name_t *name, dns_dbversion_t *version,
     dns_rdatatype_t type, unsigned int options, isc_stdtime_t now,
     dns_dbnode_t **nodep, dns_name_t *foundname, dns_rdataset_t *rdataset,
     dns_rdataset_t *sigrdataset)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return dns_db_find(ldapdb->rbtdb, name, version, type,
			   options, now, nodep, foundname, rdataset,
			   sigrdataset);
}

static isc_result_t
findzonecut(dns_db_t *db, node_name_t *name, unsigned int options,
	    isc_stdtime_t now, dns_dbnode_t **nodep, dns_name_t *foundname,
#if LIBDNS_VERSION_MAJOR >= 1600
	    dns_name_t *dcname,
#endif
	    dns_rdataset_t *rdataset, dns_rdataset_t *sigrdataset)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return dns_db_findzonecut(ldapdb->rbtdb, name, options,
				  now, nodep, foundname,
#if LIBDNS_VERSION_MAJOR >= 1600
				  dcname,
#endif
				  rdataset, sigrdataset);
}

static void
attachnode(dns_db_t *db, dns_dbnode_t *source, dns_dbnode_t **targetp)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	dns_db_attachnode(ldapdb->rbtdb, source, targetp);

}

static void
detachnode(dns_db_t *db, dns_dbnode_t **targetp)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	dns_db_detachnode(ldapdb->rbtdb, targetp);
}

static isc_result_t
expirenode(dns_db_t *db, dns_dbnode_t *node, isc_stdtime_t now)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return dns_db_expirenode(ldapdb->rbtdb, node, now);
}

static void
printnode(dns_db_t *db, dns_dbnode_t *node, FILE *out)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return dns_db_printnode(ldapdb->rbtdb, node, out);
}

static isc_result_t
createiterator(dns_db_t *db,  unsigned int options,
	       dns_dbiterator_t **iteratorp)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return dns_db_createiterator(ldapdb->rbtdb, options, iteratorp);
}

static isc_result_t
findrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	     dns_rdatatype_t type, dns_rdatatype_t covers, isc_stdtime_t now,
	     dns_rdataset_t *rdataset, dns_rdataset_t *sigrdataset)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return dns_db_findrdataset(ldapdb->rbtdb, node, version, type, covers,
				   now, rdataset, sigrdataset);
}

static isc_result_t
allrdatasets(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	     isc_stdtime_t now, dns_rdatasetiter_t **iteratorp)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return dns_db_allrdatasets(ldapdb->rbtdb, node, version, now, iteratorp);
}

/* TODO: Add 'tainted' flag to the LDAP instance if something went wrong. */
static isc_result_t
addrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	    isc_stdtime_t now, dns_rdataset_t *rdataset, unsigned int options,
	    dns_rdataset_t *addedrdataset)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;
	dns_fixedname_t fname;
	dns_name_t *zname = NULL;
	dns_rdatalist_t *rdlist = NULL;
	isc_result_t result;

	REQUIRE(VALID_LDAPDB(ldapdb));

	dns_fixedname_init(&fname);
	zname = dns_db_origin(ldapdb->rbtdb);

	CHECK(dns_db_addrdataset(ldapdb->rbtdb, node, version, now,
				  rdataset, options, addedrdataset));

	CHECK(ldapdb_name_fromnode(node, dns_fixedname_name(&fname)));
	result = dns_rdatalist_fromrdataset(rdataset, &rdlist);
	INSIST(result == ISC_R_SUCCESS);
	CHECK(write_to_ldap(dns_fixedname_name(&fname), zname, ldapdb->ldap_inst, rdlist));

cleanup:
	return result;

}

static isc_result_t
node_isempty(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	     isc_stdtime_t now, bool *isempty) {
	dns_rdatasetiter_t *rds_iter = NULL;
	dns_fixedname_t fname;
	char buff[DNS_NAME_FORMATSIZE];
	isc_result_t result;

	CHECK(ldapdb_name_fromnode(node, dns_fixedname_initname(&fname)));

	result = dns_db_allrdatasets(db, node, version, now, &rds_iter);
	if (result == ISC_R_NOTFOUND) {
		*isempty = true;
	} else if (result == ISC_R_SUCCESS) {
		result = dns_rdatasetiter_first(rds_iter);
		if (result == ISC_R_NOMORE) {
			*isempty = true;
			result = ISC_R_SUCCESS;
		} else if (result == ISC_R_SUCCESS) {
			*isempty = false;
			result = ISC_R_SUCCESS;
		} else if (result != ISC_R_SUCCESS) {
			dns_name_format(dns_fixedname_name(&fname),
					buff, DNS_NAME_FORMATSIZE);
			log_error_r("dns_rdatasetiter_first() failed during "
				    "node_isempty() for name '%s'", buff);
		}
		dns_rdatasetiter_destroy(&rds_iter);
	} else {
		dns_name_format(dns_fixedname_name(&fname),
				buff, DNS_NAME_FORMATSIZE);
		log_error_r("dns_db_allrdatasets() failed during "
			    "node_isempty() for name '%s'", buff);
	}

cleanup:
	return result;
}

/* TODO: Add 'tainted' flag to the LDAP instance if something went wrong. */
static isc_result_t
subtractrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
		 dns_rdataset_t *rdataset, unsigned int options,
		 dns_rdataset_t *newrdataset)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;
	dns_fixedname_t fname;
	dns_name_t *zname = NULL;
	dns_rdatalist_t *rdlist = NULL;
	bool empty_node = false;
	isc_result_t substract_result;
	isc_result_t result;

	REQUIRE(VALID_LDAPDB(ldapdb));

	dns_fixedname_init(&fname);
	zname = dns_db_origin(ldapdb->rbtdb);

	result = dns_db_subtractrdataset(ldapdb->rbtdb, node, version,
					 rdataset, options, newrdataset);
	/* DNS_R_NXRRSET mean that whole RRset was deleted. */
	if (result != ISC_R_SUCCESS && result != DNS_R_NXRRSET)
		goto cleanup;

	substract_result = result;
	/* TODO: Could it create some race-condition? What about unprocessed
	 * changes in synrepl queue? */
	if (substract_result == DNS_R_NXRRSET) {
		CHECK(node_isempty(ldapdb->rbtdb, node, version, 0,
				   &empty_node));
	}

	result = dns_rdatalist_fromrdataset(rdataset, &rdlist);
	INSIST(result == ISC_R_SUCCESS);
	CHECK(ldapdb_name_fromnode(node, dns_fixedname_name(&fname)));
	CHECK(remove_values_from_ldap(dns_fixedname_name(&fname), zname, ldapdb->ldap_inst,
				      rdlist, empty_node));

cleanup:
	if (result == ISC_R_SUCCESS)
		result = substract_result;
	return result;
}

/* This function is usually not called for non-cache DBs, so we don't need to
 * care about performance.
 * TODO: Add 'tainted' flag to the LDAP instance if something went wrong. */
static isc_result_t
deleterdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	       dns_rdatatype_t type, dns_rdatatype_t covers)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;
	dns_fixedname_t fname;
	dns_name_t *zname = NULL;
	bool empty_node;
	isc_result_t result;

	REQUIRE(VALID_LDAPDB(ldapdb));

	dns_fixedname_init(&fname);
	zname = dns_db_origin(ldapdb->rbtdb);

	result = dns_db_deleterdataset(ldapdb->rbtdb, node, version, type,
				       covers);
	/* DNS_R_UNCHANGED mean that there was no RRset with given type. */
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	/* TODO: Could it create some race-condition? What about unprocessed
	 * changes in synrepl queue? */
	CHECK(node_isempty(ldapdb->rbtdb, node, version, 0, &empty_node));
	CHECK(ldapdb_name_fromnode(node, dns_fixedname_name(&fname)));

	if (empty_node == true) {
		CHECK(remove_entry_from_ldap(dns_fixedname_name(&fname), zname,
					     ldapdb->ldap_inst));
	} else {
		CHECK(remove_rdtype_from_ldap(dns_fixedname_name(&fname), zname,
					    ldapdb->ldap_inst, type));
	}

cleanup:
	return result;
}

static bool
issecure(dns_db_t *db)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return dns_db_issecure(ldapdb->rbtdb);
}

static unsigned int
nodecount(dns_db_t *db)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return dns_db_nodecount(ldapdb->rbtdb);
}

/**
 * Return TRUE, because database does not need to be loaded from disk
 * or written to disk.
 *
 * !!! This could be required for optimizations (like on-disk cache).
 */
static bool
ispersistent(dns_db_t *db)
{
	UNUSED(db);

	return true;
}

static void
overmem(dns_db_t *db, bool overmem)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	dns_db_overmem(ldapdb->rbtdb, overmem);
}

static void
settask(dns_db_t *db, isc_task_t *task)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	dns_db_settask(ldapdb->rbtdb, task);
}

static isc_result_t
getoriginnode(dns_db_t *db, dns_dbnode_t **nodep)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return dns_db_getoriginnode(ldapdb->rbtdb, nodep);
}

static void
transfernode(dns_db_t *db, dns_dbnode_t **sourcep, dns_dbnode_t **targetp)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	dns_db_transfernode(ldapdb->rbtdb, sourcep, targetp);

}

static isc_result_t
getnsec3parameters(dns_db_t *db, dns_dbversion_t *version,
			  dns_hash_t *hash, uint8_t *flags,
			  uint16_t *iterations,
			  unsigned char *salt, size_t *salt_length)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return dns_db_getnsec3parameters(ldapdb->rbtdb, version, hash, flags,
					 iterations, salt, salt_length);

}

static isc_result_t
findnsec3node(dns_db_t *db, node_name_t *name, bool create,
	      dns_dbnode_t **nodep)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return dns_db_findnsec3node(ldapdb->rbtdb, name, create, nodep);
}

static isc_result_t
setsigningtime(dns_db_t *db, dns_rdataset_t *rdataset, isc_stdtime_t resign)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return dns_db_setsigningtime(ldapdb->rbtdb, rdataset, resign);
}

static isc_result_t
getsigningtime(dns_db_t *db, dns_rdataset_t *rdataset, dns_name_t *name)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return dns_db_getsigningtime(ldapdb->rbtdb, rdataset, name);
}

static void
resigned(dns_db_t *db, dns_rdataset_t *rdataset,
		dns_dbversion_t *version)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	dns_db_resigned(ldapdb->rbtdb, rdataset, version);
}

static bool
isdnssec(dns_db_t *db)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return dns_db_isdnssec(ldapdb->rbtdb);
}

static dns_stats_t *
getrrsetstats(dns_db_t *db) {
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return dns_db_getrrsetstats(ldapdb->rbtdb);

}

#if LIBDNS_VERSION_MAJOR < 1600
void
rpz_attach(dns_db_t *db, dns_rpz_zones_t *rpzs, uint8_t rpz_num)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	dns_db_rpz_attach(ldapdb->rbtdb, rpzs, rpz_num);
}
#else
void
rpz_attach(dns_db_t *db, void *void_rpzs, uint8_t rpz_num)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;
	dns_rpz_zones_t *rpzs = (dns_rpz_zones_t *) void_rpzs;
	isc_result_t result;

	REQUIRE(VALID_LDAPDB(ldapdb));

	rpzs->zones[rpz_num]->db_registered = true;
	result = dns_db_updatenotify_register(ldapdb->rbtdb,
					      dns_rpz_dbupdate_callback,
					      rpzs->zones[rpz_num]);
	REQUIRE(result == ISC_R_SUCCESS);
}
#endif

/*
isc_result_t
rpz_ready(dns_db_t *db)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return dns_db_rpz_ready(ldapdb->rbtdb);
}
*/

static isc_result_t
findnodeext(dns_db_t *db, node_name_t *name,
		   bool create, dns_clientinfomethods_t *methods,
		   dns_clientinfo_t *clientinfo, dns_dbnode_t **nodep)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return dns_db_findnodeext(ldapdb->rbtdb, name, create, methods,
				  clientinfo, nodep);
}

static isc_result_t
findext(dns_db_t *db, node_name_t *name, dns_dbversion_t *version,
	       dns_rdatatype_t type, unsigned int options, isc_stdtime_t now,
	       dns_dbnode_t **nodep, dns_name_t *foundname,
	       dns_clientinfomethods_t *methods, dns_clientinfo_t *clientinfo,
	       dns_rdataset_t *rdataset, dns_rdataset_t *sigrdataset)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return dns_db_findext(ldapdb->rbtdb, name, version, type, options, now,
			      nodep, foundname, methods, clientinfo, rdataset,
			      sigrdataset);
}

isc_result_t
setcachestats(dns_db_t *db, isc_stats_t *stats)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return dns_db_setcachestats(ldapdb->rbtdb, stats);
}

size_t
hashsize(dns_db_t *db)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return dns_db_hashsize(ldapdb->rbtdb);
}

isc_result_t
nodefullname(dns_db_t *db, dns_dbnode_t *node, dns_name_t *name)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return dns_db_nodefullname(ldapdb->rbtdb, node, name);
}

#ifdef HAVE_DNS_SERVESTALE
static isc_result_t
setservestalettl(dns_db_t *db, dns_ttl_t ttl) {
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return dns_db_setservestalettl(ldapdb->rbtdb, ttl);
}

static isc_result_t
getservestalettl(dns_db_t *db, dns_ttl_t *ttl) {
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return dns_db_getservestalettl(ldapdb->rbtdb, ttl);
}
#endif

static dns_dbmethods_t ldapdb_methods = {
	attach,
	detach,
	beginload,
	endload,
	serialize, /* see dns_db_serialize(), implementation is not mandatory */
	dump,
	currentversion,
	newversion,
	attachversion,
	closeversion,
	findnode,
	find,
	findzonecut,
	attachnode,
	detachnode,
	expirenode,
	printnode,
	createiterator,
	findrdataset,
	allrdatasets,
	addrdataset,
	subtractrdataset,
	deleterdataset,
	issecure,
	nodecount,
	ispersistent,
	overmem,
	settask,
	getoriginnode,
	transfernode,
	getnsec3parameters,
	findnsec3node,
	setsigningtime,
	getsigningtime,
	resigned,
	isdnssec,
	getrrsetstats,
	rpz_attach,
	NULL, /* rpz_ready */
	findnodeext,
	findext,
	setcachestats,
	hashsize,
	nodefullname,
	NULL, // getsize method not implemented (related BZ1353563)
#ifdef HAVE_DNS_SERVESTALE
	setservestalettl,
	getservestalettl,
#endif
#if LIBDNS_VERSION_MAJOR >= 1600
	NULL, /* setgluecachestats */
#endif
};

isc_result_t ATTR_NONNULLS
dns_ns_buildrdata(dns_name_t *origin, dns_name_t *ns_name,
		   dns_rdataclass_t rdclass,
		   unsigned char *buffer,
		   dns_rdata_t *rdata) {
	dns_rdata_ns_t ns;
	isc_buffer_t rdatabuf;

	REQUIRE(origin != NULL);
	REQUIRE(ns_name != NULL);

	memset(buffer, 0, DNS_SOA_BUFFERSIZE);
	isc_buffer_init(&rdatabuf, buffer, DNS_SOA_BUFFERSIZE);

	ns.common.rdtype = dns_rdatatype_ns;
	ns.common.rdclass = rdclass;
	ns.mctx = NULL;
	dns_name_init(&ns.name, NULL);
	dns_name_clone(ns_name, &ns.name);

	return (dns_rdata_fromstruct(rdata, rdclass, dns_rdatatype_ns,
				      &ns, &rdatabuf));
}

/**
 * Associate a pre-existing LDAP DB instance with a new DNS zone.
 *
 * @warning This is a hack.
 *
 * Normally, an empty database is created by dns_db_create() call during
 * dns_zone_load().
 *
 * In our case, we need to create and populate databases on-the-fly
 * as we process data from LDAP.
 * We create an empty LDAP DB (which encapsulates internal RBT DB)
 * for each zone when the zone is being added to zone_register.
 *
 * The database in zone register is modified on-the-fly and subsequent
 * dns_db_create() call associates this populated database with the DNS zone.
 *
 * This allows us to call dns_zone_load() later when all the data are in place,
 * so dns_zone_load() can be postponed until synchronization state sync_finish
 * is reached.
 *
 * @param[in] argv [0] is database instance name
 */
isc_result_t
ldapdb_associate(isc_mem_t *mctx, node_name_t *name, dns_dbtype_t type,
		 dns_rdataclass_t rdclass, unsigned int argc, char *argv[],
		 void *driverarg, dns_db_t **dbp) {

	isc_result_t result;
	ldap_instance_t *ldap_inst = driverarg;
	zone_register_t *zr = NULL;

	REQUIRE(ISCAPI_MCTX_VALID(mctx));
	REQUIRE(type == LDAP_DB_TYPE);
	REQUIRE(rdclass == LDAP_DB_RDATACLASS);
	REQUIRE(argc == 0);
	UNUSED(argv);
	REQUIRE(driverarg != NULL);
	REQUIRE(dbp != NULL && *dbp == NULL);

	zr = ldap_instance_getzr(ldap_inst);
	if (zr == NULL)
		CLEANUP_WITH(ISC_R_NOTFOUND);

	CHECK(zr_get_zone_dbs(zr, name, dbp, NULL));

cleanup:
	return result;
}

isc_result_t
ldapdb_create(isc_mem_t *mctx, dns_name_t *name, dns_dbtype_t type,
	      dns_rdataclass_t rdclass, void *driverarg, dns_db_t **dbp)
{
	ldapdb_t *ldapdb = NULL;
	isc_result_t result;
	bool lock_ready = false;

	/* Database instance name. */
	REQUIRE(type == LDAP_DB_TYPE);
	REQUIRE(rdclass == LDAP_DB_RDATACLASS);
	REQUIRE(driverarg != NULL);
	REQUIRE(dbp != NULL && *dbp == NULL);

	ldapdb = isc_mem_get(mctx, sizeof(*(ldapdb)));
	ZERO_PTR(ldapdb);

	isc_mem_attach(mctx, &ldapdb->common.mctx);
	/* isc_mutex_init and isc_condition_init failures are now fatal */
	isc_mutex_init(&ldapdb->newversion_lock);
	lock_ready = true;
	dns_name_init(&ldapdb->common.origin, NULL);

	ldapdb->common.magic = DNS_DB_MAGIC;
	ldapdb->common.impmagic = LDAPDB_MAGIC;

	ldapdb->common.methods = &ldapdb_methods;
	ldapdb->common.attributes = 0;
	ldapdb->common.rdclass = rdclass;

	CHECK(dns_name_dupwithoffsets(name, mctx, &ldapdb->common.origin));

	isc_refcount_init(&ldapdb->refs, 1);
	ldapdb->ldap_inst = driverarg;

	CHECK(dns_db_create(mctx, "rbt", name, dns_dbtype_zone,
			    dns_rdataclass_in, 0, NULL, &ldapdb->rbtdb));

	*dbp = (dns_db_t *)ldapdb;

	return ISC_R_SUCCESS;

cleanup:
	if (ldapdb != NULL) {
		if (lock_ready == true) {
			/* isc_mutex_destroy errors are now fatal */
			isc_mutex_destroy(&ldapdb->newversion_lock);
		}
		if (dns_name_dynamic(&ldapdb->common.origin))
			dns_name_free(&ldapdb->common.origin, mctx);

		isc_mem_putanddetach(&ldapdb->common.mctx, ldapdb,
				     sizeof(*ldapdb));
	}

	return result;
}

static void
library_init(void)
{
       log_info("bind-dyndb-ldap version " VERSION
                " compiled at " __TIME__ " " __DATE__
                ", compiler " __VERSION__);
       cfg_init_types();
}

/*
 * Driver version is called when loading the driver to ensure there
 * is no API mismatch betwen the driver and the caller.
 */
VISIBLE int
dyndb_version(unsigned int *flags) {
	UNUSED(flags);

	return (DNS_DYNDB_VERSION);
}

/*
 * Driver init is called for each dyndb section in named.conf
 * once during startup and then again on every reload.
 *
 * @code
 * dyndb example-name "sample.so" { param1 param2 };
 * @endcode
 *
 * @param[in] name        User-defined string from dyndb "name" {}; definition
 *                        in named.conf.
 *                        The example above will have name = "example-name".
 * @param[in] parameters  User-defined parameters from dyndb section as one
 *                        string. The example above will have
 *                        params = "param1 param2";
 * @param[out] instp      Pointer to instance-specific data
 *                        (for one dyndb section).
 */
VISIBLE isc_result_t
dyndb_init(isc_mem_t *mctx, const char *name, const char *parameters,
	   const char *file, unsigned long line, const dns_dyndbctx_t *dctx,
	   void **instp)
{
	ldap_instance_t *inst = NULL;
	isc_result_t result;
	static isc_once_t library_init_once = ISC_ONCE_INIT;

	REQUIRE(name != NULL);
	REQUIRE(parameters != NULL);
	REQUIRE(dctx != NULL);
	REQUIRE(instp != NULL && *instp == NULL);

	RUNTIME_CHECK(isc_once_do(&library_init_once, library_init)
		      == ISC_R_SUCCESS);

	/*
	 * Depending on how dlopen() was called, we may not have
	 * access to named's global namespace, in which case we need
	 * to initialize libisc/libdns
	 */
	if (dctx->refvar != &isc_bind9) {
		isc_lib_register();
		isc_log_setcontext(dctx->lctx);
		dns_log_setcontext(dctx->lctx);
		isc_hash_set_initializer(dctx->hashinit);
		log_debug(5, "registering library from dynamic ldap driver, %p != %p.", dctx->refvar, &isc_bind9);
	}

	log_debug(2, "registering dynamic ldap driver for %s.", name);

	/* Finally, create the instance. */
	CHECK(new_ldap_instance(mctx, name, parameters, file, line, dctx,
				&inst));
	*instp = inst;

cleanup:
	return result;
}

/*
 * Driver destroy is called for every instance on every reload and then once
 * during shutdown.
 *
 * @param[out] instp Pointer to instance-specific data (for one dyndb section).
 */
VISIBLE void
dyndb_destroy(void **instp) {
	destroy_ldap_instance((ldap_instance_t **)instp);
}
