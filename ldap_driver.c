/* Authors: Martin Nagy <mnagy@redhat.com>
 *          Adam Tkac   <atkac@redhat.com>
 *
 * Copyright (C) 2008, 2009  Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 2 only
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

#include <isc/buffer.h>
#include <isc/mem.h>
#include <isc/refcount.h>
#include <isc/util.h>

#include <dns/db.h>
#include <dns/rdata.h>
#include <dns/rdataclass.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/rdatatype.h>
#include <dns/result.h>
#include <dns/types.h>

#include <string.h> /* For memcpy */

#include "cache.h"
#include "ldap_helper.h"
#include "log.h"
#include "rdlist.h"
#include "util.h"
#include "zone_manager.h"

#define LDAPDB_MAGIC			ISC_MAGIC('L', 'D', 'P', 'D')
#define VALID_LDAPDB(ldapdb) \
	((ldapdb) != NULL && (ldapdb)->common.impmagic == LDAPDB_MAGIC)

#define LDAPDBNODE_MAGIC		ISC_MAGIC('L', 'D', 'P', 'N')
#define VALID_LDAPDBNODE(ldapdbnode)	ISC_MAGIC_VALID(ldapdbnode, \
							LDAPDBNODE_MAGIC)

static dns_rdatasetmethods_t rdataset_methods;

typedef struct {
	dns_db_t			common;
	isc_refcount_t			refs;
	isc_mutex_t			lock; /* convert to isc_rwlock_t ? */
	ldap_db_t			*ldap_db;
	ldap_cache_t			*ldap_cache;
} ldapdb_t;

typedef struct {
	unsigned int			magic;
	isc_refcount_t			refs;
	dns_name_t			owner;
	ldapdb_rdatalist_t		rdatalist;
} ldapdbnode_t;

static int dummy;
static void *ldapdb_version = &dummy;

static void free_ldapdb(ldapdb_t *ldapdb);
static void detachnode(dns_db_t *db, dns_dbnode_t **targetp);
static unsigned int rdatalist_length(const dns_rdatalist_t *rdlist);

/* ldapdbnode_t functions */
static isc_result_t
ldapdbnode_create(isc_mem_t *mctx, dns_name_t *owner, ldapdbnode_t **nodep)
{
	ldapdbnode_t *node = NULL;
	isc_result_t result;

	REQUIRE(nodep != NULL && *nodep == NULL);

	CHECKED_MEM_GET_PTR(mctx, node);
	CHECK(isc_refcount_init(&node->refs, 1));

	dns_name_init(&node->owner, NULL);
	CHECK(dns_name_dup(owner, mctx, &node->owner));

	node->magic = LDAPDBNODE_MAGIC;

	ISC_LIST_INIT(node->rdatalist);

	*nodep = node;

	return ISC_R_SUCCESS;

cleanup:
	SAFE_MEM_PUT_PTR(mctx, node);

	return result;
}

/*
 * Clone rdlist and convert it into rdataset.
 */
static isc_result_t
clone_rdatalist_to_rdataset(isc_mem_t *mctx, dns_rdatalist_t *rdlist,
			    dns_rdataset_t *rdataset)
{
	isc_result_t result;
	dns_rdatalist_t *new_rdlist = NULL;

	REQUIRE(mctx != NULL);

	CHECK(rdatalist_clone(mctx, rdlist, &new_rdlist));

	CHECK(dns_rdatalist_tordataset(new_rdlist, rdataset));
	rdataset->methods = &rdataset_methods;
	isc_mem_attach(mctx, (isc_mem_t **)&rdataset->private5);

	return result;

cleanup:
	if (new_rdlist != NULL) {
		free_rdatalist(mctx, rdlist);
		isc_mem_put(mctx, new_rdlist, sizeof(*new_rdlist));
	}

	return result;
}

/*
 * Our own function for disassociating rdatasets. We will also free the
 * rdatalist that we put inside from clone_rdatalist_to_rdataset.
 */
void
ldapdb_rdataset_disassociate(dns_rdataset_t *rdataset)
{
	dns_rdatalist_t *rdlist;
	isc_mem_t *mctx;

	REQUIRE(rdataset != NULL);

	rdlist = rdataset->private1;
	mctx = rdataset->private5;
	if (rdlist == NULL)
		return;
	rdataset->private1 = NULL;
	rdataset->private5 = NULL;

	free_rdatalist(mctx, rdlist);
	SAFE_MEM_PUT_PTR(mctx, rdlist);

	isc_mem_detach(&mctx);
}

/*
 * Functions.
 *
 * Most of them don't need db parameter but we are checking if it is valid.
 * Invalid db parameter indicates bug in code.
 */

static void
attach(dns_db_t *source, dns_db_t **targetp)
{
	ldapdb_t *ldapdb = (ldapdb_t *)source;

	REQUIRE(VALID_LDAPDB(ldapdb));

	isc_refcount_increment(&ldapdb->refs, NULL);
	*targetp = source;
}

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

static void
free_ldapdb(ldapdb_t *ldapdb)
{
	DESTROYLOCK(&ldapdb->lock);
	dns_name_free(&ldapdb->common.origin, ldapdb->common.mctx);
	isc_mem_putanddetach(&ldapdb->common.mctx, ldapdb, sizeof(*ldapdb));
}

static isc_result_t
beginload(dns_db_t *db, dns_addrdatasetfunc_t *addp, dns_dbload_t **dbloadp)
{

	UNUSED(db);
	UNUSED(addp);
	UNUSED(dbloadp);

	fatal_error("ldapdb: method beginload() should never be called");

	/* Not reached */
	return ISC_R_SUCCESS;
}

static isc_result_t
endload(dns_db_t *db, dns_dbload_t **dbloadp)
{

	UNUSED(db);
	UNUSED(dbloadp);

	fatal_error("ldapdb: method endload() should never be called");

	/* Not reached */
	return ISC_R_SUCCESS;
}

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
	REQUIRE(versionp != NULL && *versionp == NULL);

	*versionp = ldapdb_version;
}

static isc_result_t
newversion(dns_db_t *db, dns_dbversion_t **versionp)
{
	ldapdb_t *ldapdb = (ldapdb_t *)db;

	REQUIRE(VALID_LDAPDB(ldapdb));
	REQUIRE(versionp != NULL && *versionp == NULL);

	*versionp = ldapdb_version;
	return ISC_R_SUCCESS;
}

static void
attachversion(dns_db_t *db, dns_dbversion_t *source,
	      dns_dbversion_t **targetp)
{
	ldapdb_t *ldapdb = (ldapdb_t *)db;

	REQUIRE(VALID_LDAPDB(ldapdb));
	REQUIRE(source == ldapdb_version);
	REQUIRE(targetp != NULL && *targetp == NULL);

	*targetp = ldapdb_version;
}

static void
closeversion(dns_db_t *db, dns_dbversion_t **versionp, isc_boolean_t commit)
{
	ldapdb_t *ldapdb = (ldapdb_t *)db;

	UNUSED(commit);

	REQUIRE(VALID_LDAPDB(ldapdb));
	REQUIRE(versionp != NULL && *versionp == ldapdb_version);

	*versionp = NULL;
}

static isc_result_t
findnode(dns_db_t *db, dns_name_t *name, isc_boolean_t create,
	 dns_dbnode_t **nodep)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;
	isc_result_t result;
	ldapdb_rdatalist_t rdatalist;
	ldapdbnode_t *node = NULL;

	REQUIRE(VALID_LDAPDB(ldapdb));

	result = cached_ldap_rdatalist_get(ldapdb->common.mctx,
					   ldapdb->ldap_cache, ldapdb->ldap_db,
					   name, &rdatalist);

	if (result == ISC_R_NOMEMORY)
		return ISC_R_NOMEMORY;

	if (create == ISC_FALSE) {
		/* No partial matches are allowed in this function */
		if (result == DNS_R_PARTIALMATCH) {
			result = ISC_R_NOTFOUND;
			goto cleanup;
		} else if (result != ISC_R_SUCCESS) {
			return result;
		}
	}

	CHECK(ldapdbnode_create(ldapdb->common.mctx, name, &node));

	memcpy(&node->rdatalist, &rdatalist, sizeof(rdatalist));

	*nodep = node;

	return ISC_R_SUCCESS;

cleanup:
	ldapdb_rdatalist_destroy(ldapdb->common.mctx, &rdatalist);

	return result;
}

/* XXX add support for DNAME redirection */
static isc_result_t
find(dns_db_t *db, dns_name_t *name, dns_dbversion_t *version,
     dns_rdatatype_t type, unsigned int options, isc_stdtime_t now,
     dns_dbnode_t **nodep, dns_name_t *foundname, dns_rdataset_t *rdataset,
     dns_rdataset_t *sigrdataset)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;
	isc_result_t result;
	ldapdbnode_t *node = NULL;
	dns_rdatalist_t *rdlist = NULL;
	isc_boolean_t is_cname = ISC_FALSE;
	ldapdb_rdatalist_t rdatalist;

	UNUSED(now);
	UNUSED(options);
	UNUSED(sigrdataset);

	REQUIRE(VALID_LDAPDB(ldapdb));
	REQUIRE(!(node != NULL && type == dns_rdatatype_any));
	//REQUIRE(!(node == NULL && rdataset != NULL));

	if (version != NULL) {
		REQUIRE(version == ldapdb_version);
	}

	result = cached_ldap_rdatalist_get(ldapdb->common.mctx,
					   ldapdb->ldap_cache, ldapdb->ldap_db,
					   name, &rdatalist);
	INSIST(result != DNS_R_PARTIALMATCH); /* XXX Not yet implemented */

	if (result != ISC_R_SUCCESS && result != DNS_R_PARTIALMATCH)
		return (result == ISC_R_NOTFOUND) ? DNS_R_NXDOMAIN : result;

	result = ldapdb_rdatalist_findrdatatype(&rdatalist, type, &rdlist);
	if (result != ISC_R_SUCCESS) {
		/* No exact rdtype match. Check CNAME */

		rdlist = HEAD(rdatalist);
		while (rdlist != NULL && rdlist->type != dns_rdatatype_cname)
			rdlist = NEXT(rdlist, link);

		/* CNAME was found */
		if (rdlist != NULL) {
			result = ISC_R_SUCCESS;
			is_cname = ISC_TRUE;
		}
	}

	if (result != ISC_R_SUCCESS) {
		result = DNS_R_NXRRSET;
		goto cleanup;
	}

	/* XXX currently we implemented only exact authoritative matches */
	CHECK(dns_name_copy(name, foundname, NULL));

	if (rdataset != NULL && type != dns_rdatatype_any) {
		/* dns_rdatalist_tordataset returns success only */
		CHECK(clone_rdatalist_to_rdataset(ldapdb->common.mctx, rdlist,
						  rdataset));
	}

	if (nodep != NULL) {
		CHECK(ldapdbnode_create(ldapdb->common.mctx, name, &node));
		memcpy(&node->rdatalist, &rdatalist, sizeof(rdatalist));
		*nodep = node;
	} else {
		ldapdb_rdatalist_destroy(ldapdb->common.mctx, &rdatalist);
	}

	return (is_cname == ISC_TRUE) ? DNS_R_CNAME : ISC_R_SUCCESS;

cleanup:
	ldapdb_rdatalist_destroy(ldapdb->common.mctx, &rdatalist);
	return result;
}

static isc_result_t
findzonecut(dns_db_t *db, dns_name_t *name, unsigned int options,
	    isc_stdtime_t now, dns_dbnode_t **nodep, dns_name_t *foundname,
	    dns_rdataset_t *rdataset, dns_rdataset_t *sigrdataset)
{
	UNUSED(db);
	UNUSED(name);
	UNUSED(options);
	UNUSED(now);
	UNUSED(nodep);
	UNUSED(foundname);
	UNUSED(rdataset);
	UNUSED(sigrdataset);

	return ISC_R_NOTIMPLEMENTED;
}

static void
attachnode(dns_db_t *db, dns_dbnode_t *source, dns_dbnode_t **targetp)
{
	ldapdbnode_t *node = (ldapdbnode_t *) source;

	REQUIRE(VALID_LDAPDBNODE(node));

	UNUSED(db);

	isc_refcount_increment(&node->refs, NULL);
	*targetp = source;
}

static void
detachnode(dns_db_t *db, dns_dbnode_t **targetp)
{
	ldapdbnode_t *node = (ldapdbnode_t *)(*targetp);
	ldapdb_t *ldapdb = (ldapdb_t *) db;
	unsigned int refs;

	/*
	 * Don't check for db and targetp validity, it's done in
	 * dns_db_detachnode
	 */

	REQUIRE(VALID_LDAPDBNODE(node));
	isc_refcount_decrement(&node->refs, &refs);
	if (refs == 0) {
		ldapdb_rdatalist_destroy(ldapdb->common.mctx, &node->rdatalist);
		dns_name_free(&node->owner, ldapdb->common.mctx);
		SAFE_MEM_PUT_PTR(ldapdb->common.mctx, node);
	}

	*targetp = NULL;
}

static isc_result_t
expirenode(dns_db_t *db, dns_dbnode_t *node, isc_stdtime_t now)
{
	UNUSED(db);
	UNUSED(node);
	UNUSED(now);

	return ISC_R_NOTIMPLEMENTED;
}

static void
printnode(dns_db_t *db, dns_dbnode_t *node, FILE *out)
{
	UNUSED(db);
	UNUSED(node);
	UNUSED(out);
}

static isc_result_t
createiterator(dns_db_t *db, unsigned int options,
	       dns_dbiterator_t **iteratorp)
{
	UNUSED(db);
	UNUSED(options);
	UNUSED(iteratorp);

	return ISC_R_NOTIMPLEMENTED;
}

static isc_result_t
findrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	     dns_rdatatype_t type, dns_rdatatype_t covers, isc_stdtime_t now,
	     dns_rdataset_t *rdataset, dns_rdataset_t *sigrdataset)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;
	ldapdbnode_t *ldapdbnode = (ldapdbnode_t *) node;
	dns_rdatalist_t *rdlist = NULL;
	isc_result_t result;

	UNUSED(db);
	UNUSED(now);
	UNUSED(sigrdataset);

	REQUIRE(covers == 0); /* Only meaningful with DNSSEC capable DB*/
	REQUIRE(VALID_LDAPDBNODE(ldapdbnode));

	if (version != NULL) {
		REQUIRE(version == ldapdb_version);
	}

	result = ldapdb_rdatalist_findrdatatype(&ldapdbnode->rdatalist, type,
						&rdlist);
	if (result != ISC_R_SUCCESS)
		return result;

	result = clone_rdatalist_to_rdataset(ldapdb->common.mctx, rdlist,
					     rdataset);

	return result;
}

static isc_result_t
allrdatasets(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	     isc_stdtime_t now, dns_rdatasetiter_t **iteratorp)
{
	UNUSED(db);
	UNUSED(node);
	UNUSED(version);
	UNUSED(now);
	UNUSED(iteratorp);

	return ISC_R_NOTIMPLEMENTED;
}

/*
 * Remove duplicates between rdlists. If rm_from1 == true then remove rdata
 * from the first rdatalist. same rdata are removed from rdlist1 or 2 and are
 * returned in diff.
 */
static void
rdatalist_removedups(dns_rdatalist_t *rdlist1, dns_rdatalist_t *rdlist2,
		     isc_boolean_t rm_from1,
		     dns_rdatalist_t *diff)
{
	dns_rdata_t *rdata1, *rdata2;

	rdata1 = HEAD(rdlist1->rdata);
	while (rdata1 != NULL) {
		rdata2 = HEAD(rdlist2->rdata);
		while (rdata2 != NULL) {
			if (dns_rdata_compare(rdata1, rdata2) != 0) {
				rdata2 = NEXT(rdata2, link);
				continue;
			}
			/* same rdata has been found */
			if (rm_from1) {
				ISC_LIST_UNLINK(rdlist1->rdata, rdata1, link);
				APPEND(diff->rdata, rdata1, link);
			} else {
				ISC_LIST_UNLINK(rdlist2->rdata, rdata2, link);
				APPEND(diff->rdata, rdata2, link);
			}
			break;
		}
		rdata1 = NEXT(rdata1, link);
	}
}

static isc_result_t
addrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	    isc_stdtime_t now, dns_rdataset_t *rdataset, unsigned int options,
	    dns_rdataset_t *addedrdataset)
{
	ldapdbnode_t *ldapdbnode = (ldapdbnode_t *) node;
	ldapdb_t *ldapdb = (ldapdb_t *) db;
	dns_rdatalist_t *rdlist = NULL, *new_rdlist = NULL;
	dns_rdatalist_t *found_rdlist = NULL;
	dns_rdatalist_t diff;
	isc_result_t result;
	isc_boolean_t rdatalist_exists = ISC_FALSE;

	UNUSED(now);
	UNUSED(db);
	UNUSED(addedrdataset);

	REQUIRE(VALID_LDAPDBNODE(ldapdbnode));
	/* version == NULL is valid only for cache databases */
	REQUIRE(version == ldapdb_version);
	REQUIRE((options & DNS_DBADD_FORCE) == 0);

	dns_rdatalist_init(&diff);

	result = dns_rdatalist_fromrdataset(rdataset, &rdlist);
	INSIST(result == ISC_R_SUCCESS);
	INSIST(rdlist->rdclass == dns_rdataclass_in);

	CHECK(rdatalist_clone(ldapdb->common.mctx, rdlist, &new_rdlist));

	result = ldapdb_rdatalist_findrdatatype(&ldapdbnode->rdatalist,
						rdlist->type, &found_rdlist);
	if (result == ISC_R_SUCCESS) {
		rdatalist_exists = ISC_TRUE;

		if (rdlist->ttl != found_rdlist->ttl) {
			/*
			 * TODO: support it. When supported handle
			 * DNS_DBADD_EXACTTTL option well.
			 */
			log_error("Multiple TTLs for one name are not "
				  "supported");
			result = ISC_R_NOTIMPLEMENTED;
			goto cleanup;
		}

		if ((options & DNS_DBADD_MERGE) != 0 ||
		    (options & DNS_DBADD_EXACT) != 0) {
			rdatalist_removedups(found_rdlist, new_rdlist,
					     ISC_FALSE, &diff);

			if ((options & DNS_DBADD_MERGE) != 0)
				free_rdatalist(ldapdb->common.mctx, &diff);
			else if (rdatalist_length(&diff) != 0) {
				free_rdatalist(ldapdb->common.mctx, &diff);
				result = DNS_R_NOTEXACT;
				goto cleanup;
			}
		} else {
			/* Replace existing rdataset */
			free_rdatalist(ldapdb->common.mctx, found_rdlist);
		}
	}

	CHECK(write_to_ldap(&ldapdbnode->owner, ldapdb->ldap_db, new_rdlist));
	CHECK(discard_from_cache(ldapdb->ldap_cache, &ldapdbnode->owner));

	if (addedrdataset != NULL) {
		result = dns_rdatalist_tordataset(new_rdlist, addedrdataset);
		/* Use strong condition here, returns only SUCCESS */
		INSIST(result == ISC_R_SUCCESS);
	}

	if (rdatalist_exists) {
		ISC_LIST_APPENDLIST(found_rdlist->rdata, new_rdlist->rdata,
				    link);
		SAFE_MEM_PUT_PTR(ldapdb->common.mctx, new_rdlist);
	} else
		APPEND(ldapdbnode->rdatalist, new_rdlist, link);


	return ISC_R_SUCCESS;

cleanup:
	if (new_rdlist != NULL) {
		free_rdatalist(ldapdb->common.mctx, new_rdlist);
		SAFE_MEM_PUT_PTR(ldapdb->common.mctx, new_rdlist);
	}

	return result;
}

static unsigned int
rdatalist_length(const dns_rdatalist_t *rdlist)
{
	dns_rdata_t *ptr = HEAD(rdlist->rdata);
	unsigned int length = 0;

	while (ptr != NULL) {
		length++;
		ptr = NEXT(ptr, link);
	}

	return length;
}

static isc_result_t
subtractrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
		 dns_rdataset_t *rdataset, unsigned int options,
		 dns_rdataset_t *newrdataset)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;
	ldapdbnode_t *ldapdbnode = (ldapdbnode_t *) node;
	dns_rdatalist_t *found_rdlist = NULL;
	dns_rdatalist_t *rdlist;
	dns_rdatalist_t diff;
	isc_result_t result;

	REQUIRE(version == ldapdb_version);

	result = dns_rdatalist_fromrdataset(rdataset, &rdlist);
	/* Use strong condition here, no other value is returned */
	INSIST(result == ISC_R_SUCCESS);

	/* Do we want to use memcpy here? */
	dns_rdatalist_init(&diff);
	diff.rdclass = rdlist->rdclass;
	diff.type = rdlist->type;
	diff.covers = rdlist->covers;
	diff.ttl = rdlist->ttl;

	result = ldapdb_rdatalist_findrdatatype(&ldapdbnode->rdatalist,
						rdlist->type, &found_rdlist);

	if (result == ISC_R_NOTFOUND)
		return DNS_R_NXRRSET;

	/* We found correct type, remove maching rdata */
	rdatalist_removedups(rdlist, found_rdlist, ISC_FALSE, &diff);

	if ((options & DNS_DBSUB_EXACT) != 0 &&
	     rdatalist_length(&diff) != rdatalist_length(rdlist)) {
		/* Not exact match, rollback */
		result = DNS_R_NOTEXACT;
		goto cleanup;
	}

	if (rdatalist_length(&diff) == 0) {
		result = DNS_R_UNCHANGED;
		goto cleanup;
	}

	CHECK(remove_from_ldap(&ldapdbnode->owner, ldapdb->ldap_db, &diff));

	if (newrdataset != NULL) {
		result = dns_rdatalist_tordataset(found_rdlist, newrdataset);
		/* Use strong condition here, no other value is returned */
		INSIST(result == ISC_R_SUCCESS);
	}

	free_rdatalist(ldapdb->common.mctx, &diff);

	return ISC_R_SUCCESS;

cleanup:
	/* Roll back changes */
	ISC_LIST_APPENDLIST(found_rdlist->rdata, diff.rdata, link);

	return result;
}

static isc_result_t
deleterdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	       dns_rdatatype_t type, dns_rdatatype_t covers)
{
	UNUSED(db);
	UNUSED(node);
	UNUSED(version);
	UNUSED(type);
	UNUSED(covers);

	REQUIRE("deleterdataset" == NULL);

	return ISC_R_NOTIMPLEMENTED;
}

static isc_boolean_t
issecure(dns_db_t *db)
{
	UNUSED(db);

	return ISC_FALSE;
}

static unsigned int
nodecount(dns_db_t *db)
{
	UNUSED(db);

	return ISC_R_NOTIMPLEMENTED;
}

static isc_boolean_t
ispersistent(dns_db_t *db)
{
	UNUSED(db);

	return ISC_R_NOTIMPLEMENTED;
}

static void
overmem(dns_db_t *db, isc_boolean_t overmem)
{
	UNUSED(db);
	UNUSED(overmem);
}

static void
settask(dns_db_t *db, isc_task_t *task)
{
	UNUSED(db);
	UNUSED(task);
}

static isc_result_t
getoriginnode(dns_db_t *db, dns_dbnode_t **nodep)
{
	ldapdb_t *ldapdb = (ldapdb_t *) db;

	return findnode(db, &ldapdb->common.origin, ISC_FALSE, nodep);
}

static void
transfernode(dns_db_t *db, dns_dbnode_t **sourcep, dns_dbnode_t **targetp)
{
	UNUSED(db);
	UNUSED(sourcep);
	UNUSED(targetp);
}

static isc_result_t
getnsec3parameters(dns_db_t *db, dns_dbversion_t *version, dns_hash_t *hash,
		   isc_uint8_t *flags, isc_uint16_t *iterations,
		   unsigned char *salt, size_t *salt_len)
{
	UNUSED(db);
	UNUSED(version);
	UNUSED(hash);
	UNUSED(flags);
	UNUSED(iterations);
	UNUSED(salt);
	UNUSED(salt_len);

	return ISC_R_NOTIMPLEMENTED;
}

static isc_result_t
findnsec3node(dns_db_t *db, dns_name_t *name, isc_boolean_t create,
	      dns_dbnode_t **nodep)
{
	UNUSED(db);
	UNUSED(name);
	UNUSED(create);
	UNUSED(nodep);

	return ISC_R_NOTIMPLEMENTED;
}

static isc_result_t
setsigningtime(dns_db_t *db, dns_rdataset_t *rdataset, isc_stdtime_t resign)
{
	UNUSED(db);
	UNUSED(rdataset);
	UNUSED(resign);

	return ISC_R_NOTIMPLEMENTED;
}

static isc_result_t
getsigningtime(dns_db_t *db, dns_rdataset_t *rdataset, dns_name_t *name)
{
	UNUSED(db);
	UNUSED(rdataset);
	UNUSED(name);

	return ISC_R_NOTIMPLEMENTED;
}

static void
resigned(dns_db_t *db, dns_rdataset_t *rdataset, dns_dbversion_t *version)
{
	UNUSED(db);
	UNUSED(rdataset);
	UNUSED(version);
}

static isc_boolean_t
isdnssec(dns_db_t *db)
{
	UNUSED(db);

	return ISC_R_NOTIMPLEMENTED;
}

static dns_stats_t *
getrrsetstats(dns_db_t *db)
{
	UNUSED(db);

	return NULL;
}

static dns_dbmethods_t ldapdb_methods = {
	attach,
	detach,
	beginload,
	endload,
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
	getrrsetstats
};

static isc_result_t
ldapdb_create(isc_mem_t *mctx, dns_name_t *name, dns_dbtype_t type,
	      dns_rdataclass_t rdclass, unsigned int argc, char *argv[],
	      void *driverarg, dns_db_t **dbp)
{
	ldapdb_t *ldapdb;
	isc_result_t result;

	UNUSED(driverarg); /* Currently we don't need any data */

	/* Database implementation name and name pointing to ldap_db_t */
	REQUIRE(argc > 0);

	REQUIRE(type == dns_dbtype_zone);
	REQUIRE(rdclass == dns_rdataclass_in);
	REQUIRE(dbp != NULL && *dbp == NULL);

	ldapdb = isc_mem_get(mctx, sizeof(*ldapdb));
	if (ldapdb == NULL)
		return ISC_R_NOMEMORY;

	ldapdb->common.methods = &ldapdb_methods;
	ldapdb->common.attributes = 0;
	ldapdb->common.rdclass = rdclass;

	dns_name_init(&ldapdb->common.origin, NULL);
	result = dns_name_dupwithoffsets(name, mctx, &ldapdb->common.origin);
	if (result != ISC_R_SUCCESS)
		goto clean_ldapdb;

	isc_ondestroy_init(&ldapdb->common.ondest);
	ldapdb->common.mctx = NULL;
	isc_mem_attach(mctx, &ldapdb->common.mctx);

	result = isc_mutex_init(&ldapdb->lock);
	if (result != ISC_R_SUCCESS)
		goto clean_origin;

	result = isc_refcount_init(&ldapdb->refs, 1);
	if (result != ISC_R_SUCCESS)
		goto clean_lock;

	result = manager_get_ldap_db_and_cache(argv[0], &ldapdb->ldap_db,
					       &ldapdb->ldap_cache);
	if (result != ISC_R_SUCCESS)
		goto clean_lock;

	ldapdb->common.magic = DNS_DB_MAGIC;
	ldapdb->common.impmagic = LDAPDB_MAGIC;

	*dbp = (dns_db_t *)ldapdb;

	return ISC_R_SUCCESS;

clean_lock:
	DESTROYLOCK(&ldapdb->lock);
clean_origin:
	dns_name_free(&ldapdb->common.origin, mctx);
clean_ldapdb:
	isc_mem_putanddetach(&ldapdb->common.mctx, ldapdb, sizeof(*ldapdb));

	return result;
}

static dns_dbimplementation_t *ldapdb_imp;
const char *ldapdb_impname = "dynamic-ldap";


isc_result_t
dynamic_driver_init(isc_mem_t *mctx, const char *name, const char * const *argv,
		    dns_view_t *view, dns_zonemgr_t *zmgr)
{
	isc_result_t result;
	ldap_db_t *ldap_db = NULL;
	ldap_cache_t *ldap_cache = NULL;

	REQUIRE(mctx != NULL);
	REQUIRE(name != NULL);
	REQUIRE(argv != NULL);
	REQUIRE(view != NULL);

	log_debug(2, "Registering dynamic ldap driver for %s.", name);

	/* Test argv. */
	int i = 0;
	while (argv[i] != NULL) {
		log_debug(2, "Arg: %s", argv[i]);
		i++;
	}

	/*
	 * We need to discover what rdataset methods does
	 * dns_rdatalist_tordataset use. We then make a copy for ourselves
	 * with the exception that we modify the disassociate method to free
	 * the rdlist we allocate for it in clone_rdatalist_to_rdataset().
	 */
	if (rdataset_methods.disassociate == NULL) {
		dns_rdataset_t rdset;
		dns_rdatalist_t rdatalist;

		dns_rdataset_init(&rdset);
		dns_rdatalist_tordataset(&rdatalist, &rdset);
		memcpy(&rdataset_methods, rdset.methods,
		       sizeof(dns_rdatasetmethods_t));
		rdataset_methods.disassociate = ldapdb_rdataset_disassociate;
	}

	/* Register new DNS DB implementation. */
	result = dns_db_register(ldapdb_impname, &ldapdb_create, NULL, mctx,
				 &ldapdb_imp);
	if (result != ISC_R_SUCCESS && result != ISC_R_EXISTS)
		return result;

	CHECK(new_ldap_db(mctx, view, &ldap_db, argv));
	CHECK(new_ldap_cache(mctx, &ldap_cache, argv));
	CHECK(manager_add_db_instance(mctx, name, ldap_db, ldap_cache, zmgr));

	/*
	 * XXX now fetch all zones and initialize ldap zone manager
	 * (periodically check for new zones)
	 * - manager has to share server zonemgr (ns_g_server->zonemgr)
	 *
	 * XXX manager has to this this for each zone:
	 * - dns_zone_create
	 * - dns_zone_setorigin
	 * - dns_zone_setview
	 * - dns_zone_setacache (probably not needed)
	 * - dns_zone_setclass
	 * - dns_zone_settype
	 * - dns_zone_setdbtype (note: pass all connection arguments etc here -
	 *   will be used by ldapdb_create)
	 * - continue as in bin/server.c - ns_zone_configure()
	 * - dns_zonemgr_managezone
	 *
	 * zone has to be bind-ed to specified view:
	 * - dns_view_findzone (check if zone already exists)
	 * - dns_view_addzone
	 */

	return ISC_R_SUCCESS;

cleanup:
	if (ldap_db != NULL)
		destroy_ldap_db(&ldap_db);

	return result;
}

void
dynamic_driver_destroy(void)
{
	dns_db_unregister(&ldapdb_imp);
	destroy_manager();
}
