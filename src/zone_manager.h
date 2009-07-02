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

#ifndef _LD_ZONE_MANAGER_H_
#define _LD_ZONE_MANAGER_H_

#include <dns/types.h>

#include "cache.h"
#include "ldap_helper.h"

typedef struct db_instance db_instance_t;

void destroy_manager(void);

isc_result_t
manager_add_db_instance(isc_mem_t *mctx, const char *name, ldap_instance_t *ldap_inst,
			ldap_cache_t *ldap_cache, dns_zonemgr_t *zmgr);

isc_result_t
manager_get_ldap_instance_and_cache(const char *name, ldap_instance_t **ldap_inst,
			      ldap_cache_t **ldap_cache);

#endif /* !_LD_ZONE_MANAGER_H_ */
