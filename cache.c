/* Authors: Martin Nagy <mnagy@redhat.com>
 *
 * Copyright (C) 2009  Red Hat
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
#include <isc/result.h>
#include <isc/util.h>

#include <dns/rbt.h>
#include <dns/result.h>

#include <string.h>

#include "cache.h"
#include "ldap_helper.h"
#include "log.h"
#include "rdlist.h"
#include "settings.h"
#include "util.h"

/* XXX: Locking? */
struct ldap_cache {
	isc_mem_t	*mctx;
	dns_rbt_t	*rbt;
	/* TODO: Add a timeout period setting. */
};

typedef struct {
	isc_mem_t		*mctx;
	ldapdb_rdatalist_t	rdatalist;
	/* TODO: Add time of creation for expiration purposes. */
} cache_node_t;

static void
cache_node_deleter(void *data, void *deleter_arg)
{
	cache_node_t *node = (cache_node_t *)data;

	UNUSED(deleter_arg);
	REQUIRE(data != NULL);

	ldapdb_rdatalist_destroy(node->mctx, &node->rdatalist);
	MEM_PUT_AND_DETACH(node);
}

static isc_result_t
cache_node_create(isc_mem_t *mctx, ldapdb_rdatalist_t rdatalist,
		  cache_node_t **nodep)
{
	isc_result_t result;
	cache_node_t *node;

	REQUIRE(mctx != NULL);
	REQUIRE(nodep != NULL && *nodep == NULL);

	CHECKED_MEM_GET_PTR(mctx, node);
	ZERO_PTR(node);
	isc_mem_attach(mctx, &node->mctx);
	node->rdatalist = rdatalist;

	*nodep = node;
	return ISC_R_SUCCESS;

cleanup:
	SAFE_MEM_PUT_PTR(mctx, node);

	return result;
}

/*
 * TODO: Add setting saying if we want to enable cache, if not, then
 * cache->rbt must be set to NULL.
 */
isc_result_t
new_ldap_cache(isc_mem_t *mctx, ldap_cache_t **cachep,
	       const char * const *argv)
{
	isc_result_t result;
	ldap_cache_t *cache = NULL;

	UNUSED(argv);

	REQUIRE(cachep != NULL && *cachep == NULL);

	CHECKED_MEM_GET_PTR(mctx, cache);
	ZERO_PTR(cache);
	isc_mem_attach(mctx, &cache->mctx);

	if (1) {
		CHECK(dns_rbt_create(mctx, cache_node_deleter, NULL,
				     &cache->rbt));
	}


	*cachep = cache;
	return ISC_R_SUCCESS;

cleanup:
	if (cache != NULL)
		destroy_ldap_cache(&cache);

	return result;
}

void
destroy_ldap_cache(ldap_cache_t **cachep)
{
	ldap_cache_t *cache;

	REQUIRE(cachep != NULL && *cachep != NULL);

	cache = *cachep;

	if (cache->rbt)
		dns_rbt_destroy(&cache->rbt);

	MEM_PUT_AND_DETACH(cache);

	*cachep = NULL;
}

/* TODO: Implement expiration. */
isc_result_t
cached_ldap_rdatalist_get(isc_mem_t *mctx, ldap_cache_t *cache,
			  ldap_db_t *ldap_db, dns_name_t *name,
			  ldapdb_rdatalist_t *rdatalist)
{
	isc_result_t result;
	ldapdb_rdatalist_t rdlist;
	cache_node_t *node = NULL;
	void *data = NULL;
	int found = 0;
	int expired = 0;

	REQUIRE(cache != NULL);

	INIT_LIST(*rdatalist);
	INIT_LIST(rdlist);

	if (cache->rbt == NULL)
		return ldapdb_rdatalist_get(mctx, ldap_db, name, rdatalist);

	result = dns_rbt_findname(cache->rbt, name, 0, NULL, &data);
	if (result == ISC_R_SUCCESS) {
		found = 1;
		expired = 0; /* find out if we are expired */
		node = (cache_node_t *)data;
		rdlist = node->rdatalist;
	} else if (result != ISC_R_NOTFOUND && result != DNS_R_PARTIALMATCH) {
		goto cleanup;
	}

	if ((found && expired) || !found) {
		if (found) {
			CHECK(dns_rbt_deletename(cache->rbt, name, ISC_FALSE));
			data = NULL; /* ? */
		}
		INIT_LIST(rdlist);
		result = ldapdb_rdatalist_get(mctx, ldap_db, name, &rdlist);
		if (result != ISC_R_SUCCESS && result != ISC_R_NOTFOUND)
			goto cleanup;
		CHECK(cache_node_create(mctx, rdlist, &node));
		data = (void *)node;
		CHECK(dns_rbt_addname(cache->rbt, name, data));
	}
	CHECK(ldap_rdatalist_copy(mctx, rdlist, rdatalist));

	if (EMPTY(*rdatalist))
		return ISC_R_NOTFOUND;
	else
		return ISC_R_SUCCESS;

cleanup:
	return result;
}
