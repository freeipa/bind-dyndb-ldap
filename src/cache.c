/*
 * Authors: Martin Nagy <mnagy@redhat.com>
 *
 * Copyright (C) 2009  Red Hat
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

#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/result.h>
#include <isc/time.h>
#include <isc/util.h>

#include <dns/rbt.h>
#include <dns/result.h>
#include <dns/log.h>

#include <string.h>

#include "cache.h"
#include "ldap_helper.h"
#include "log.h"
#include "rdlist.h"
#include "settings.h"
#include "util.h"

struct ldap_cache {
	isc_mutex_t	mutex;
	isc_mem_t	*mctx;
	dns_rbt_t	*rbt;
	isc_interval_t	cache_ttl;
	isc_boolean_t	psearch;
};

typedef struct {
	isc_mem_t		*mctx;
	ldapdb_rdatalist_t	rdatalist;
	isc_time_t		valid_until;
} cache_node_t;

static void
cache_node_deleter(void *data, void *deleter_arg)
{
	cache_node_t *node = data;

	UNUSED(deleter_arg);
	REQUIRE(data != NULL);

	ldapdb_rdatalist_destroy(node->mctx, &node->rdatalist);
	MEM_PUT_AND_DETACH(node);
}

/* TODO: Remove the rdatalist parameter */
static isc_result_t
cache_node_create(ldap_cache_t *cache, cache_node_t **nodep)
{
	isc_result_t result;
	cache_node_t *node;

	REQUIRE(cache != NULL);
	REQUIRE(nodep != NULL && *nodep == NULL);

	CHECKED_MEM_GET_PTR(cache->mctx, node);
	ZERO_PTR(node);
	isc_mem_attach(cache->mctx, &node->mctx);
	ZERO_PTR(&node->rdatalist);
	/* Do not set the ttl when psearch is enabled. */
	if (!cache->psearch)
		CHECK(isc_time_nowplusinterval(&node->valid_until, &cache->cache_ttl));

	*nodep = node;
	return ISC_R_SUCCESS;

cleanup:
	SAFE_MEM_PUT_PTR(cache->mctx, node);

	return result;
}

isc_result_t
new_ldap_cache(isc_mem_t *mctx, const char *const *argv, ldap_cache_t **cachep, isc_boolean_t psearch)
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
		CHECK(isc_mutex_init(&cache->mutex));
	}

	cache->psearch = psearch;
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

	if (cache->rbt) {
		LOCK(&cache->mutex);
		dns_rbt_destroy(&cache->rbt);
		cache->rbt = NULL;
		UNLOCK(&cache->mutex);
		DESTROYLOCK(&cache->mutex);
	}

	MEM_PUT_AND_DETACH(cache);

	*cachep = NULL;
}

/**
* @brief Get record from cache.
*
* @param mctx Memory.
* @param cache Internal LDAP cache structure. 
* @param name DNS name (key). 
* @param rdatalist Found value or NULL.
*
* @return ISC_R_SUCCESS when found,
*         ISC_R_NOTFOUND not in cache,
*         ISC_R_FAILURE other error.
*/
isc_result_t
ldap_cache_getrdatalist(isc_mem_t *mctx, ldap_cache_t *cache,
			dns_name_t *name, ldapdb_rdatalist_t *rdatalist)
{
	isc_result_t result;
	ldapdb_rdatalist_t rdlist;
	cache_node_t *node = NULL;
	isc_time_t now;

	REQUIRE(cache != NULL);

	/* Return NOTFOUND if caching is disabled */
	if (!ldap_cache_enabled(cache))
		return ISC_R_NOTFOUND;

	LOCK(&cache->mutex);
	result = dns_rbt_findname(cache->rbt, name, 0, NULL, (void *)&node);
	switch (result) {
	case ISC_R_SUCCESS:
		/* Check cache TTL only when psearch is disabled. */
		if (!cache->psearch) {
			CHECK(isc_time_now(&now));
			if (isc_time_compare(&now, &node->valid_until) > 0) {
				/* Delete expired records and treat them as NOTFOUND */
				CHECK(dns_rbt_deletename(cache->rbt, name, ISC_FALSE));
				result = ISC_R_NOTFOUND;
				goto cleanup;
			}
		}
		rdlist = node->rdatalist;
		CHECK(ldap_rdatalist_copy(mctx, rdlist, rdatalist));
		INSIST(!EMPTY(*rdatalist)); /* Empty rdatalist indicates a bug */
		break;
	case DNS_R_PARTIALMATCH:
		result = ISC_R_NOTFOUND;
		/* Fall through */
	case ISC_R_NOTFOUND:
		goto cleanup;
		/* Not reached */
	default:
		result = ISC_R_FAILURE;
	}

cleanup:
	UNLOCK(&cache->mutex);

	if (isc_log_getdebuglevel(dns_lctx) >= 20) {
		char dns_str[DNS_NAME_FORMATSIZE];
		dns_name_format(name, dns_str, sizeof(dns_str));
		log_debug(20, "cache search for '%s': %s", dns_str,
					isc_result_totext(result));
	}

	return result;
}

isc_boolean_t
ldap_cache_enabled(ldap_cache_t *cache)
{
	return (cache->rbt != NULL) ? ISC_TRUE : ISC_FALSE;
}

/**
* @brief Insert rdatalist to the cache.
*
* If a record with the name exists in the cache,
* it is replaced by newer version.
*
* @param cache Internal LDAP cache structure.
* @param name DNS name (key).
* @param rdatalist Value to be stored in cache. 
*
* @return ISC_R_SUCCESS or error ISC_R_*
*/
isc_result_t
ldap_cache_addrdatalist(ldap_cache_t *cache, dns_name_t *name,
			ldapdb_rdatalist_t *rdatalist)
{
	isc_result_t result;
	isc_boolean_t free_rdlist = ISC_FALSE;
	isc_boolean_t unlock = ISC_FALSE;
	cache_node_t *node = NULL;

	REQUIRE(cache != NULL);
	REQUIRE(rdatalist != NULL && !EMPTY(*rdatalist));

	if (!ldap_cache_enabled(cache))
		return ISC_R_SUCCESS; /* Caching is disabled */

	CHECK(cache_node_create(cache, &node));
	CHECK(ldap_rdatalist_copy(cache->mctx, *rdatalist, &node->rdatalist));
	free_rdlist = ISC_TRUE;

	LOCK(&cache->mutex);
	unlock = ISC_TRUE;
retry:
	result = dns_rbt_addname(cache->rbt, name, (void *)node);
	if (result == ISC_R_EXISTS) {
		/* Replace it */
		CHECK(dns_rbt_deletename(cache->rbt, name, ISC_FALSE));
		goto retry;
	} else if (result != ISC_R_SUCCESS)
		goto cleanup;

	result = ISC_R_SUCCESS;

cleanup:
	if (unlock)
		UNLOCK(&cache->mutex);
	if (result != ISC_R_SUCCESS) {
		if (free_rdlist)
			ldapdb_rdatalist_destroy(cache->mctx, &node->rdatalist);
		if (node != NULL)
			MEM_PUT_AND_DETACH(node);
	}
		
	return result;
}

isc_result_t
discard_from_cache(ldap_cache_t *cache, dns_name_t *name)
{
	isc_result_t result;

	REQUIRE(cache != NULL);
	REQUIRE(name != NULL);

	if (cache->rbt == NULL) {
		result = ISC_R_SUCCESS;
	} else {
		LOCK(&cache->mutex);
		result = dns_rbt_deletename(cache->rbt, name, ISC_FALSE);
		UNLOCK(&cache->mutex);
	}

	if (result == ISC_R_NOTFOUND)
		result = ISC_R_SUCCESS;

	return result;
}
