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
#include <isc/time.h>
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
	isc_interval_t	cache_ttl;
};

typedef struct {
	isc_mem_t		*mctx;
	ldapdb_rdatalist_t	rdatalist;
	isc_time_t		valid_until;
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
cache_node_create(ldap_cache_t *cache, ldapdb_rdatalist_t rdatalist,
		  cache_node_t **nodep)
{
	isc_result_t result;
	cache_node_t *node;

	REQUIRE(cache != NULL);
	REQUIRE(nodep != NULL && *nodep == NULL);

	CHECKED_MEM_GET_PTR(cache->mctx, node);
	ZERO_PTR(node);
	isc_mem_attach(cache->mctx, &node->mctx);
	node->rdatalist = rdatalist;
	CHECK(isc_time_nowplusinterval(&node->valid_until, &cache->cache_ttl));

	*nodep = node;
	return ISC_R_SUCCESS;

cleanup:
	SAFE_MEM_PUT_PTR(cache->mctx, node);

	return result;
}

isc_result_t
new_ldap_cache(isc_mem_t *mctx, ldap_cache_t **cachep,
	       const char * const *argv)
{
	isc_result_t result;
	ldap_cache_t *cache = NULL;
	unsigned int cache_ttl;
	setting_t cache_settings[] = {
		{ "cache_ttl", default_uint(120) },
		end_of_settings
	};

	REQUIRE(cachep != NULL && *cachep == NULL);

	cache_settings[0].target = &cache_ttl;
	CHECK(set_settings(cache_settings, argv));

	CHECKED_MEM_GET_PTR(mctx, cache);
	ZERO_PTR(cache);
	isc_mem_attach(mctx, &cache->mctx);

	isc_interval_set(&cache->cache_ttl, cache_ttl, 0);

	if (cache_ttl) {
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

isc_result_t
cached_ldap_rdatalist_get(isc_mem_t *mctx, ldap_cache_t *cache,
			  ldap_db_t *ldap_db, dns_name_t *name,
			  ldapdb_rdatalist_t *rdatalist)
{
	isc_result_t result;
	ldapdb_rdatalist_t rdlist;
	cache_node_t *node = NULL;
	int in_cache = 0;

	REQUIRE(cache != NULL);

	if (cache->rbt == NULL)
		return ldapdb_rdatalist_get(mctx, ldap_db, name, rdatalist);

	result = dns_rbt_findname(cache->rbt, name, 0, NULL, (void *)&node);
	if (result == ISC_R_SUCCESS) {
		isc_time_t now;

		CHECK(isc_time_now(&now));

		/* Check if the record is still valid. */
		if (isc_time_compare(&now, &node->valid_until) > 0) {
			CHECK(dns_rbt_deletename(cache->rbt, name, ISC_FALSE));
			node = NULL;
			in_cache = 0;
		} else {
			rdlist = node->rdatalist;
			in_cache = 1;
		}
	} else if (result != ISC_R_NOTFOUND && result != DNS_R_PARTIALMATCH) {
		goto cleanup;
	} else {
		node = NULL;
	}

	if (!in_cache) {
		INIT_LIST(rdlist);
		result = ldapdb_rdatalist_get(mctx, ldap_db, name, &rdlist);
		if (result != ISC_R_SUCCESS && result != ISC_R_NOTFOUND)
			goto cleanup;
		CHECK(cache_node_create(cache, rdlist, &node));
		CHECK(dns_rbt_addname(cache->rbt, name, (void *)node));
	}

	CHECK(ldap_rdatalist_copy(mctx, rdlist, rdatalist));

	if (EMPTY(*rdatalist))
		result = ISC_R_NOTFOUND;

cleanup:
	return result;
}
