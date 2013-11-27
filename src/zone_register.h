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

#include "settings.h"
#include "rbt_helper.h"
#include "ldap_helper.h"

isc_result_t
zr_create(isc_mem_t *mctx, ldap_instance_t *ldap_inst,
	  settings_set_t *glob_settings, zone_register_t **zrp) ATTR_NONNULLS;

void
zr_destroy(zone_register_t **zrp) ATTR_NONNULLS;

isc_result_t
zr_add_zone(zone_register_t *zr, dns_zone_t *zone, const char *dn) ATTR_NONNULLS;

isc_result_t
zr_del_zone(zone_register_t *zr, dns_name_t *origin) ATTR_NONNULLS;

isc_result_t
zr_get_zone_dbs(zone_register_t *zr, dns_name_t *name, dns_db_t **ldapdbp,
		dns_db_t **rbtdbp);

isc_result_t
zr_get_zone_dn(zone_register_t *zr, dns_name_t *name, const char **dn,
	       dns_name_t *matched_name) ATTR_NONNULLS;

isc_result_t
zr_get_zone_ptr(zone_register_t *zr, dns_name_t *name, dns_zone_t **zonep) ATTR_NONNULLS;

isc_result_t
zr_get_zone_settings(zone_register_t *zr, dns_name_t *name, settings_set_t **set) ATTR_NONNULLS;

isc_result_t
zr_get_zone_path(isc_mem_t *mctx, settings_set_t *settings,
		 dns_name_t *zone_name, const char *last_component,
		 ld_string_t **path);

isc_result_t
zr_rbt_iter_init(zone_register_t *zr, rbt_iterator_t **iter,
		 dns_name_t *nodename) ATTR_NONNULLS;

isc_mem_t *
zr_get_mctx(zone_register_t *zr) ATTR_NONNULLS;

#endif /* !_LD_ZONE_REGISTER_H_ */
