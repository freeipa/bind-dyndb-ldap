/*
 * Authors: Martin Nagy <mnagy@redhat.com>
 *          Adam Tkac   <atkac@redhat.com>
 *
 * Copyright (C) 2008, 2009  Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 2 or later
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#else
#error "Can't compile without config.h"
#endif

#include <isc/buffer.h>
#include <isc/mem.h>
#include <isc/refcount.h>
#include <isc/util.h>

#include <dns/db.h>
#include <dns/diff.h>
#include <dns/dynamic_db.h>
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

#include <string.h> /* For memcpy */

#include "compat.h"
#include "ldap_driver.h"
#include "ldap_helper.h"
#include "ldap_convert.h"
#include "log.h"
#include "rdlist.h"
#include "util.h"
#include "zone_manager.h"

#ifdef HAVE_VISIBILITY
#define VISIBLE __attribute__((__visibility__("default")))
#else
#define VISIBLE
#endif

#define LDAPDB_MAGIC			ISC_MAGIC('L', 'D', 'P', 'D')
#define VALID_LDAPDB(ldapdb) \
	((ldapdb) != NULL && (ldapdb)->common.impmagic == LDAPDB_MAGIC)

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

	isc_refcount_increment(&ldapdb->refs, NULL);
	*targetp = source;
}

/* !!! Verify that internal RBTDB cannot leak somehow. */
static void ATTR_NONNULLS
free_ldapdb(ldapdb_t *ldapdb)
{
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
	dns_db_closeversion(ldapdb->rbtdb, &version, ISC_FALSE);

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
	RUNTIME_CHECK(isc_mutex_destroy(&ldapdb->newversion_lock)
		      == ISC_R_SUCCESS);
	isc_mem_putanddetach(&ldapdb->common.mctx, ldapdb, sizeof(*ldapdb));
}

/* !!! Verify that omitting internal RBTDB will not cause havoc. */
static void
detach(dns_db_t **dbp)
{
	ldapdb_t *ldapdb = (ldapdb_t *)(*dbp);
	unsigned int refs;

	REQUIRE(VALID_LDAPDB(ldapdb));

	isc_refcount_decrement(&ldapdb->refs, &refs);

	if (refs == 0)
		free_ldapdb(ldapdb);

	*dbp = NULL;
}



/**
 * This method should never be called, because LDAP DB is "persistent".
 * See ispersistent() function.
 */

/* !!! This could be required for optimizations (like on-disk cache). */
static isc_result_t
#if LIBDNS_VERSION_MAJOR < 140
beginload(dns_db_t *db, dns_addrdatasetfunc_t *addp, dns_dbload_t **dbloadp)
{

	UNUSED(db);
	UNUSED(addp);
	UNUSED(dbloadp);
#else /* LIBDNS_VERSION_MAJOR >= 140 */
beginload(dns_db_t *db, dns_rdatacallbacks_t *callbacks) {
	UNUSED(db);
	UNUSED(callbacks);
#endif /* LIBDNS_VERSION_MAJOR >= 140 */

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
#if LIBDNS_VERSION_MAJOR < 140
endload(dns_db_t *db, dns_dbload_t **dbloadp)
{

	UNUSED(db);
	UNUSED(dbloadp);
#else /* LIBDNS_VERSION_MAJOR >= 140 */
endload(dns_db_t *db, dns_rdatacallbacks_t *callbacks) {
	UNUSED(db);
	UNUSED(callbacks);
#endif /* LIBDNS_VERSION_MAJOR >= 140 */

	fatal_error("ldapdb: method endload() should never be called");

	/* Not reached */
	return ISC_R_SUCCESS;
}

#if LIBDNS_VERSION_MAJOR >= 140
static isc_result_t
serialize(dns_db_t *db, dns_dbversion_t *version, FILE *file)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return dns_db_serialize(ldapdb->rbtdb, version, file);
}
#endif /* LIBDNS_VERSION_MAJOR >= 140 */

/* !!! This could be required for optimizations (like on-disk cache). */
static isc_result_t
dump(dns_db_t *db, dns_dbversion_t *version, const char *filename
#if LIBDNS_VERSION_MAJOR >= 31
     , dns_masterformat_t masterformat
#endif
     )
{

	UNUSED(db);
	UNUSED(version);
	UNUSED(filename);
#if LIBDNS_VERSION_MAJOR >= 31
	UNUSED(masterformat);
#endif

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
		dns_db_closeversion(ldapdb, &newversion, ISC_TRUE);
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
closeversion(dns_db_t *db, dns_dbversion_t **versionp, isc_boolean_t commit)
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
findnode(dns_db_t *db, dns_name_t *name, isc_boolean_t create,
	 dns_dbnode_t **nodep)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return dns_db_findnode(ldapdb->rbtdb, name, create, nodep);
}

static isc_result_t
find(dns_db_t *db, dns_name_t *name, dns_dbversion_t *version,
     dns_rdatatype_t type, unsigned int options, isc_stdtime_t now,
     dns_dbnode_t **nodep, dns_name_t *foundname, dns_rdataset_t *rdataset,
     dns_rdataset_t *sigrdataset)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return dns_db_find(ldapdb->rbtdb, name, version, type, options, now,
			   nodep, foundname, rdataset, sigrdataset);
}

static isc_result_t
findzonecut(dns_db_t *db, dns_name_t *name, unsigned int options,
	    isc_stdtime_t now, dns_dbnode_t **nodep, dns_name_t *foundname,
	    dns_rdataset_t *rdataset, dns_rdataset_t *sigrdataset)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return dns_db_findzonecut(ldapdb->rbtdb, name, options, now, nodep,
				  foundname, rdataset, sigrdataset);
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
createiterator(dns_db_t *db,
#if LIBDNS_VERSION_MAJOR >= 50
	       unsigned int options,
#else
	       isc_boolean_t relative_names,
#endif
	       dns_dbiterator_t **iteratorp)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));
#if LIBDNS_VERSION_MAJOR >= 50
	return dns_db_createiterator(ldapdb->rbtdb, options, iteratorp);
#else
	return dns_db_createiterator(ldapdb->rbtdb, relative_names, iteratorp);
#endif
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
	     isc_stdtime_t now, isc_boolean_t *isempty) {
	dns_rdatasetiter_t *rds_iter = NULL;
	dns_fixedname_t fname;
	char buff[DNS_NAME_FORMATSIZE];
	isc_result_t result;

	dns_fixedname_init(&fname);

	CHECK(ldapdb_name_fromnode(node, dns_fixedname_name(&fname)));

	result = dns_db_allrdatasets(db, node, version, now, &rds_iter);
	if (result == ISC_R_NOTFOUND) {
		*isempty = ISC_TRUE;
	} else if (result == ISC_R_SUCCESS) {
		result = dns_rdatasetiter_first(rds_iter);
		if (result == ISC_R_NOMORE) {
			*isempty = ISC_TRUE;
			result = ISC_R_SUCCESS;
		} else if (result == ISC_R_SUCCESS) {
			*isempty = ISC_FALSE;
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
	isc_boolean_t empty_node = ISC_FALSE;
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
	isc_boolean_t empty_node;
	char attr_name[LDAP_ATTR_FORMATSIZE];
	dns_rdatalist_t fake_rdlist; /* required by remove_values_from_ldap */
	isc_result_t result;

	REQUIRE(VALID_LDAPDB(ldapdb));

	dns_fixedname_init(&fname);
	dns_rdatalist_init(&fake_rdlist);
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

	if (empty_node == ISC_TRUE) {
		CHECK(remove_entry_from_ldap(dns_fixedname_name(&fname), zname,
					     ldapdb->ldap_inst));
	} else {
		CHECK(rdatatype_to_ldap_attribute(type, attr_name,
						  LDAP_ATTR_FORMATSIZE));
		CHECK(remove_attr_from_ldap(dns_fixedname_name(&fname), zname,
					    ldapdb->ldap_inst, attr_name));
	}

cleanup:
	return result;
}

static isc_boolean_t
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
static isc_boolean_t
ispersistent(dns_db_t *db)
{
	UNUSED(db);

	return ISC_TRUE;
}

static void
overmem(dns_db_t *db, isc_boolean_t overmem)
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

#if LIBDNS_VERSION_MAJOR >= 31
static isc_result_t
getoriginnode(dns_db_t *db, dns_dbnode_t **nodep)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return dns_db_getoriginnode(ldapdb->rbtdb, nodep);
}
#endif /* LIBDNS_VERSION_MAJOR >= 31 */

#if LIBDNS_VERSION_MAJOR >= 45
static void
transfernode(dns_db_t *db, dns_dbnode_t **sourcep, dns_dbnode_t **targetp)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	dns_db_transfernode(ldapdb->rbtdb, sourcep, targetp);

}
#endif /* LIBDNS_VERSION_MAJOR >= 45 */

#if LIBDNS_VERSION_MAJOR >= 50
static isc_result_t
getnsec3parameters(dns_db_t *db, dns_dbversion_t *version,
			  dns_hash_t *hash, isc_uint8_t *flags,
			  isc_uint16_t *iterations,
			  unsigned char *salt, size_t *salt_length)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return dns_db_getnsec3parameters(ldapdb->rbtdb, version, hash, flags,
					 iterations, salt, salt_length);

}

static isc_result_t
findnsec3node(dns_db_t *db, dns_name_t *name, isc_boolean_t create,
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

static isc_boolean_t
isdnssec(dns_db_t *db)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return dns_db_isdnssec(ldapdb->rbtdb);
}
#endif /* LIBDNS_VERSION_MAJOR >= 50 */

#if LIBDNS_VERSION_MAJOR >= 45
static dns_stats_t *
getrrsetstats(dns_db_t *db) {
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return dns_db_getrrsetstats(ldapdb->rbtdb);

}
#endif /* LIBDNS_VERSION_MAJOR >= 45 */

#if LIBDNS_VERSION_MAJOR >= 82 && LIBDNS_VERSION_MAJOR < 140
static isc_result_t
rpz_enabled(dns_db_t *db, dns_rpz_st_t *st)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return dns_db_rpz_enabled(ldapdb->rbtdb, st);
}

static void
rpz_findips(dns_rpz_zone_t *rpz, dns_rpz_type_t rpz_type,
		   dns_zone_t *zone, dns_db_t *db, dns_dbversion_t *version,
		   dns_rdataset_t *ardataset, dns_rpz_st_t *st,
		   dns_name_t *query_qname)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	dns_db_rpz_findips(rpz, rpz_type, zone, ldapdb->rbtdb, version,
			   ardataset, st, query_qname);
}
#endif /* LIBDNS_VERSION_MAJOR >= 82 && LIBDNS_VERSION_MAJOR < 140 */

#if LIBDNS_VERSION_MAJOR >= 140
void
rpz_attach(dns_db_t *db, dns_rpz_zones_t *rpzs, dns_rpz_num_t rpz_num)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	dns_db_rpz_attach(ldapdb->rbtdb, rpzs, rpz_num);
}

isc_result_t
rpz_ready(dns_db_t *db)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return dns_db_rpz_ready(ldapdb->rbtdb);
}
#endif /* LIBDNS_VERSION_MAJOR >= 140 */

#if LIBDNS_VERSION_MAJOR >= 90
static isc_result_t
findnodeext(dns_db_t *db, dns_name_t *name,
		   isc_boolean_t create, dns_clientinfomethods_t *methods,
		   dns_clientinfo_t *clientinfo, dns_dbnode_t **nodep)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return dns_db_findnodeext(ldapdb->rbtdb, name, create, methods,
				  clientinfo, nodep);
}

static isc_result_t
findext(dns_db_t *db, dns_name_t *name, dns_dbversion_t *version,
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
#endif /* LIBDNS_VERSION_MAJOR >= 90 */

#if LIBDNS_VERSION_MAJOR >= 140
isc_result_t
setcachestats(dns_db_t *db, isc_stats_t *stats)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return dns_db_setcachestats(ldapdb->rbtdb, stats);
}

unsigned int
hashsize(dns_db_t *db)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	return dns_db_hashsize(ldapdb->rbtdb);
}
#endif /* LIBDNS_VERSION_MAJOR >= 140 */

static dns_dbmethods_t ldapdb_methods = {
	attach,
	detach,
	beginload,
	endload,
#if LIBDNS_VERSION_MAJOR >= 140
	serialize, /* see dns_db_serialize(), implementation is not mandatory */
#endif /* LIBDNS_VERSION_MAJOR >= 140 */
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
#if LIBDNS_VERSION_MAJOR >= 31
	getoriginnode,
#endif /* LIBDNS_VERSION_MAJOR >= 31 */
#if LIBDNS_VERSION_MAJOR >= 45
	transfernode,
#if LIBDNS_VERSION_MAJOR >= 50
	getnsec3parameters,
	findnsec3node,
	setsigningtime,
	getsigningtime,
	resigned,
	isdnssec,
#endif /* LIBDNS_VERSION_MAJOR >= 50 */
	getrrsetstats,
#endif /* LIBDNS_VERSION_MAJOR >= 45 */
#if LIBDNS_VERSION_MAJOR >= 82 && LIBDNS_VERSION_MAJOR < 140
	rpz_enabled,
	rpz_findips,
#endif /* LIBDNS_VERSION_MAJOR >= 82 && LIBDNS_VERSION_MAJOR < 140 */
#if LIBDNS_VERSION_MAJOR >= 140
	rpz_attach,
	rpz_ready,
#endif /* LIBDNS_VERSION_MAJOR >= 140 */
#if LIBDNS_VERSION_MAJOR >= 90
	findnodeext,
	findext,
#endif /* LIBDNS_VERSION_MAJOR >= 90 */
#if LIBDNS_VERSION_MAJOR >= 140
	setcachestats,
	hashsize
#endif /* LIBDNS_VERSION_MAJOR >= 140 */
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
ldapdb_associate(isc_mem_t *mctx, dns_name_t *name, dns_dbtype_t type,
		 dns_rdataclass_t rdclass, unsigned int argc, char *argv[],
		 void *driverarg, dns_db_t **dbp) {

	isc_result_t result;
	ldap_instance_t *ldap_inst = NULL;
	zone_register_t *zr = NULL;

	UNUSED(driverarg); /* Currently we don't need any data */

	REQUIRE(ISCAPI_MCTX_VALID(mctx));
	REQUIRE(argc == LDAP_DB_ARGC);
	REQUIRE(type == LDAP_DB_TYPE);
	REQUIRE(rdclass == LDAP_DB_RDATACLASS);
	REQUIRE(dbp != NULL && *dbp == NULL);

	CHECK(manager_get_ldap_instance(argv[0], &ldap_inst));
	zr = ldap_instance_getzr(ldap_inst);
	if (zr == NULL)
		CLEANUP_WITH(ISC_R_NOTFOUND);

	CHECK(zr_get_zone_dbs(zr, name, dbp, NULL));

cleanup:
	return result;
}

isc_result_t
ldapdb_create(isc_mem_t *mctx, dns_name_t *name, dns_dbtype_t type,
	      dns_rdataclass_t rdclass, unsigned int argc, char *argv[],
	      void *driverarg, dns_db_t **dbp)
{
	ldapdb_t *ldapdb = NULL;
	isc_result_t result;
	isc_boolean_t lock_ready = ISC_FALSE;

	UNUSED(driverarg); /* Currently we don't need any data */

	/* Database instance name. */
	REQUIRE(argc == LDAP_DB_ARGC);
	REQUIRE(type == LDAP_DB_TYPE);
	REQUIRE(rdclass == LDAP_DB_RDATACLASS);
	REQUIRE(dbp != NULL && *dbp == NULL);

	CHECKED_MEM_GET_PTR(mctx, ldapdb);
	ZERO_PTR(ldapdb);

	isc_mem_attach(mctx, &ldapdb->common.mctx);
	CHECK(isc_mutex_init(&ldapdb->newversion_lock));
	lock_ready = ISC_TRUE;
	dns_name_init(&ldapdb->common.origin, NULL);
	isc_ondestroy_init(&ldapdb->common.ondest);

	ldapdb->common.magic = DNS_DB_MAGIC;
	ldapdb->common.impmagic = LDAPDB_MAGIC;

	ldapdb->common.methods = &ldapdb_methods;
	ldapdb->common.attributes = 0;
	ldapdb->common.rdclass = rdclass;

	CHECK(dns_name_dupwithoffsets(name, mctx, &ldapdb->common.origin));

	CHECK(isc_refcount_init(&ldapdb->refs, 1));
	CHECK(manager_get_ldap_instance(argv[0], &ldapdb->ldap_inst));

	CHECK(dns_db_create(mctx, "rbt", name, dns_dbtype_zone,
			    dns_rdataclass_in, 0, NULL, &ldapdb->rbtdb));

	*dbp = (dns_db_t *)ldapdb;

	return ISC_R_SUCCESS;

cleanup:
	if (ldapdb != NULL) {
		if (lock_ready == ISC_TRUE)
			RUNTIME_CHECK(isc_mutex_destroy(&ldapdb->newversion_lock)
				      == ISC_R_SUCCESS);
		if (dns_name_dynamic(&ldapdb->common.origin))
			dns_name_free(&ldapdb->common.origin, mctx);

		isc_mem_putanddetach(&ldapdb->common.mctx, ldapdb,
				     sizeof(*ldapdb));
	}

	return result;
}

static dns_dbimplementation_t *ldapdb_imp;
const char *ldapdb_impname = "dynamic-ldap";


VISIBLE isc_result_t
dynamic_driver_init(isc_mem_t *mctx, const char *name, const char * const *argv,
		    dns_dyndb_arguments_t *dyndb_args)
{
	dns_dbimplementation_t *ldapdb_imp_new = NULL;
	isc_result_t result;

	REQUIRE(name != NULL);
	REQUIRE(argv != NULL);
	REQUIRE(dyndb_args != NULL);

	log_debug(2, "registering dynamic ldap driver for %s.", name);

	/*
	 * We need to discover what rdataset methods does
	 * dns_rdatalist_tordataset use. We then make a copy for ourselves
	 * with the exception that we modify the disassociate method to free
	 * the rdlist we allocate for it in clone_rdatalist_to_rdataset().
	 */

	/* Register new DNS DB implementation. */
	result = dns_db_register(ldapdb_impname, &ldapdb_associate, NULL, mctx,
				 &ldapdb_imp_new);
	if (result != ISC_R_SUCCESS && result != ISC_R_EXISTS)
		return result;
	else if (result == ISC_R_SUCCESS)
		ldapdb_imp = ldapdb_imp_new;

	/* Finally, create the instance. */
	result = manager_create_db_instance(mctx, name, argv, dyndb_args);

	return result;
}

VISIBLE void
dynamic_driver_destroy(void)
{
	/* Only unregister the implementation if it was registered by us. */
	if (ldapdb_imp != NULL)
		dns_db_unregister(&ldapdb_imp);

	destroy_manager();
}
