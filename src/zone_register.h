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

#ifndef _LD_ZONE_REGISTER_H_
#define _LD_ZONE_REGISTER_H_

#include "cache.h"
#include "settings.h"
#include "rbt_helper.h"
#include "ldap_helper.h"

typedef struct zone_register zone_register_t;

isc_result_t
zr_create(isc_mem_t *mctx, ldap_instance_t *ldap_inst,
	  settings_set_t *glob_settings, zone_register_t **zrp);

void
zr_destroy(zone_register_t **zrp);

isc_result_t
zr_add_zone(zone_register_t *zr, dns_zone_t *zone, const char *dn);

isc_result_t
zr_del_zone(zone_register_t *zr, dns_name_t *origin);

isc_result_t
zr_flush_all_caches(zone_register_t *zr);

isc_result_t
zr_get_zone_cache(zone_register_t *zr, dns_name_t *name, ldap_cache_t **cachep);

isc_result_t
zr_get_zone_dn(zone_register_t *zr, dns_name_t *name, const char **dn,
	       dns_name_t *matched_name);

isc_result_t
zr_get_zone_ptr(zone_register_t *zr, dns_name_t *name, dns_zone_t **zonep);

isc_result_t
zr_get_zone_settings(zone_register_t *zr, dns_name_t *name, settings_set_t **set);

isc_result_t
zr_rbt_iter_init(zone_register_t *zr, rbt_iterator_t *iter,
		 dns_name_t *nodename);

dns_rbt_t *
zr_get_rbt(zone_register_t *zr);

isc_mem_t *
zr_get_mctx(zone_register_t *zr);

isc_result_t
zr_set_zone_serial_digest(zone_register_t *zr, dns_name_t *name,
		isc_uint32_t serial, unsigned char *digest);

isc_result_t
zr_get_zone_serial_digest(zone_register_t *zr, dns_name_t *name,
		isc_uint32_t *serialp, unsigned char ** digestp);

#endif /* !_LD_ZONE_REGISTER_H_ */
