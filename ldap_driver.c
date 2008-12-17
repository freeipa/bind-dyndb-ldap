/* Authors: Martin Nagy <mnagy@redhat.com>
 *          Adam Tkac   <atkac@redhat.com>
 *
 * Copyright (C) 2008  Red Hat
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

#include <isc/mem.h>
#include <isc/refcount.h>
#include <isc/util.h>

#include <dns/db.h>
#include <dns/result.h>

#include "log.h"

#define CHECK(op)						\
	do { result = (op);					\
		if (result != ISC_R_SUCCESS) goto cleanup;	\
	} while (0)

#define LDAPDB_MAGIC			ISC_MAGIC('L', 'D', 'P', 'D')
#define VALID_LDAPDB(ldapdb) \
	((ldapdb) != NULL && (ldapdb)->common.impmagic == LDAPDB_MAGIC)

#define LDAPDBNODE_MAGIC		ISC_MAGIC('L', 'D', 'P', 'N')
#define VALID_LDAPDBNODE(ldapdbnode)	ISC_MAGIC_VALID(ldapdbnode, \
							LDAPDBNODE_MAGIC)

typedef struct {
	dns_db_t			common;
	isc_refcount_t			refs;
	isc_mem_t			*mctx;
} ldapdb_t;

typedef struct {
	unsigned int			magic;
	isc_refcount_t			refs;
	dns_name_t			*owner;
} ldapdbnode_t;

static int dummy;
static void *ldapdb_version = &dummy;

/* ldapdbnode_t functions */
static isc_result_t
ldapdbnode_create(isc_mem_t *mctx, ldapdbnode_t **nodep)
{
	ldapdbnode_t *node;
	isc_result_t result;

	REQUIRE(nodep != NULL && *nodep == NULL);

	node = isc_mem_get(mctx, sizeof(*node));
	if (node == NULL)
		return ISC_R_NOMEMORY;

	node->magic = LDAPDBNODE_MAGIC;
	CHECK(isc_refcount_init(&node->refs, 1));

	dns_name_init(node->owner, NULL);

	return ISC_R_SUCCESS;

cleanup:
	isc_mem_put(mctx, node, sizeof(*node));
	return result;
}

static void
ldapdbnode_destroy(isc_mem_t *mctx, ldapdbnode_t **nodep)
{
	UNUSED(mctx);
	UNUSED(nodep);
	/* XXX Do it */
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
	ldapdb_t *ldapdb = (ldapdb_t *)dbp;
	unsigned int refs;

	REQUIRE(VALID_LDAPDB(ldapdb));

	isc_refcount_decrement(&ldapdb->refs, &refs);

	if (refs != 0) {
		*dbp = NULL;
		return;
	}

	/* Clean all ldapdb_t stuff here */
}

static isc_result_t
beginload(dns_db_t *db, dns_addrdatasetfunc_t *addp, dns_dbload_t **dbloadp)
{

	UNUSED(db);
	UNUSED(addp);
	UNUSED(dbloadp);

	/* Should be never called */
	fatal_error("ldapdb: method beginload() should never be called");

	/* Not reached */
	return ISC_R_SUCCESS;
}

static isc_result_t
endload(dns_db_t *db, dns_dbload_t **dbloadp)
{

	UNUSED(db);
	UNUSED(dbloadp);

	/* Should be never called */
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

	/* Should be never called */
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
	ldapdb_t *ldapdb = (ldapdb_t *)db;

	REQUIRE(VALID_LDAPDB(ldapdb));

	UNUSED(name);
	UNUSED(create);
	UNUSED(nodep);

	/* XXX LDAP:
	 *
	 * Query to ldap: find all RRs with supplied name
	 */

	/* XXX Do it */

	return ISC_R_NOTIMPLEMENTED;
}

static isc_result_t
find(dns_db_t *db, dns_name_t *name, dns_dbversion_t *version,
     dns_rdatatype_t type, unsigned int options, isc_stdtime_t now,
     dns_dbnode_t **nodep, dns_name_t *foundname, dns_rdataset_t *rdataset,
     dns_rdataset_t *sigrdataset)
{
	UNUSED(db);
	UNUSED(name);
	UNUSED(version);
	UNUSED(type);
	UNUSED(options);
	UNUSED(now);
	UNUSED(nodep);
	UNUSED(foundname);
	UNUSED(rdataset);
	UNUSED(sigrdataset);

	return ISC_R_NOTIMPLEMENTED;
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
	UNUSED(db);
	UNUSED(source);
	UNUSED(targetp);
}

static void
detachnode(dns_db_t *db, dns_dbnode_t **targetp)
{
	UNUSED(db);
	UNUSED(targetp);
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
	UNUSED(db);
	UNUSED(node);
	UNUSED(version);
	UNUSED(type);
	UNUSED(covers);
	UNUSED(now);
	UNUSED(rdataset);
	UNUSED(sigrdataset);

	return ISC_R_NOTIMPLEMENTED;
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

static isc_result_t
addrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	    isc_stdtime_t now, dns_rdataset_t *rdataset, unsigned int options,
	    dns_rdataset_t *addedrdataset)
{
	UNUSED(db);
	UNUSED(node);
	UNUSED(version);
	UNUSED(now);
	UNUSED(rdataset);
	UNUSED(options);
	UNUSED(addedrdataset);

	return ISC_R_NOTIMPLEMENTED;
}

static isc_result_t
subtractrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
		 dns_rdataset_t *rdataset, unsigned int options,
		 dns_rdataset_t *newrdataset)
{
	UNUSED(db);
	UNUSED(node);
	UNUSED(version);
	UNUSED(rdataset);
	UNUSED(options);
	UNUSED(newrdataset);

	return ISC_R_NOTIMPLEMENTED;
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

	return ISC_R_NOTIMPLEMENTED;
}

static isc_boolean_t
issecure(dns_db_t *db)
{
	UNUSED(db);

	return ISC_R_NOTIMPLEMENTED;
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
	UNUSED(db);
	UNUSED(nodep);

	return ISC_R_NOTIMPLEMENTED;
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

static dns_dbimplementation_t *ldapdb_imp;
static const char *ldapdb_impname = "dynamic-ldap";

isc_result_t
dynamic_driver_init(isc_mem_t *mctx, const char *name, const char * const *argv,
		    dns_view_t *view)
{
	isc_result_t result;

	UNUSED(mctx);
	UNUSED(view);

	log_debug(2, "Registering dynamic ldap driver for %s.", name);

	/* Test argv. */
	while (*argv != NULL) {
		log_debug(2, "Arg: %s", *argv);
		argv++;
	}

	result = dns_db_register(ldapdb_impname, NULL, NULL, mctx, &ldapdb_imp);
	if (result == ISC_R_EXISTS)
		result = ISC_R_SUCCESS;

	if (result != ISC_R_SUCCESS)
		return result;

	/* XXX now fetch all zones and initialize ldap zone manager
	 * (periodically check for new zones) */

	return ISC_R_SUCCESS;
}

void
dynamic_driver_destroy(void)
{
	dns_db_unregister(&ldapdb_imp);
}
