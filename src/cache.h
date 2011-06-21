/*
 * Authors: Martin Nagy <mnagy@redhat.com>
 * 	    Adam Tkac <atkac@redhat.com>
 *
 * Copyright (C) 2009 - 2011  Red Hat
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

#ifndef _LD_CACHE_H_
#define _LD_CACHE_H_

#include "ldap_helper.h"

typedef struct ldap_cache ldap_cache_t;

/*
 * Create a new cache.
 */
isc_result_t
new_ldap_cache(isc_mem_t *mctx, const char * const *argv, ldap_cache_t **cachep);

/*
 * Free all resources used up by the cache.
 */
void
destroy_ldap_cache(ldap_cache_t **cachep);


/*
 * If caching is enabled, lookup 'name' in 'cache'. If the record is found and
 * is not expired, make a copy and return it. If the record is not found or is
 * expired, look it up in LDAP and cache it.
 */
isc_result_t
cached_ldap_rdatalist_get(isc_mem_t *mctx, ldap_cache_t *cache,
			  ldap_instance_t *ldap_inst, dns_name_t *name,
			  dns_name_t *origin, ldapdb_rdatalist_t *rdatalist);

/*
 * Get rdatalist from cache.
 *
 * Returns ISC_R_SUCCESS, ISC_R_NOTFOUND or ISC_R_FAILURE.
 */
isc_result_t
ldap_cache_getrdatalist(isc_mem_t *mctx, ldap_cache_t *cache,
			dns_name_t *name, ldapdb_rdatalist_t *rdatalist);

/*
 * Add rdatalist to the cache.
 *
 * Note: No rdatalist can be bound to the name.
 *
 * Returns ISC_R_SUCCESS, ISC_R_NOMEMORY and ISC_R_FAILURE.
 */
isc_result_t
ldap_cache_addrdatalist(ldap_cache_t *cache, dns_name_t *name,
			ldapdb_rdatalist_t *rdatalist);

/*
 * Returns ISC_TRUE when cache is enabled.
 */
isc_boolean_t
ldap_cache_enabled(ldap_cache_t *cache);

/*
 * Discard 'name' from the cache. If caching is not really turned on or 'name'
 * is not cached, this function will still return ISC_R_SUCCESS.
 */
isc_result_t
discard_from_cache(ldap_cache_t *cache, dns_name_t *name);

#endif /* !_LD_CACHE_H_ */
