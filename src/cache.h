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

#ifndef _LD_CACHE_H_
#define _LD_CACHE_H_

#include "ldap_helper.h"

typedef struct ldap_cache ldap_cache_t;

/*
 * Create a new cache.
 */
isc_result_t
new_ldap_cache(isc_mem_t *mctx, ldap_cache_t **cachep,
	       const char * const *argv);

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
			  ldap_db_t *ldap_db, dns_name_t *name,
			  dns_name_t *origin, ldapdb_rdatalist_t *rdatalist);

/*
 * Discard 'name' from the cache. If caching is not really turned on or 'name'
 * is not cached, this function will still return ISC_R_SUCCESS.
 */
isc_result_t
discard_from_cache(ldap_cache_t *cache, dns_name_t *name);

#endif /* !_LD_CACHE_H_ */
