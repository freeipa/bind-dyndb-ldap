/*
 * Copyright (C) 2009-2014  bind-dyndb-ldap authors; see COPYING for license
 */

#ifndef _LD_ZONE_REGISTER_H_
#define _LD_ZONE_REGISTER_H_

#include <dns/zt.h>

#include "settings.h"
#include "rbt_helper.h"
#include "ldap_helper.h"

isc_result_t
zr_create(isc_mem_t *mctx, ldap_instance_t *ldap_inst,
	  settings_set_t *glob_settings, zone_register_t **zrp) ATTR_NONNULLS;

void
zr_destroy(zone_register_t **zrp) ATTR_NONNULLS;

isc_result_t
zr_add_zone(zone_register_t * const zr, dns_db_t * const ldapdb,
	    dns_zone_t * const raw, dns_zone_t * const secure,
	    const char * const dn)
	    ATTR_NONNULL(1,3,5) ATTR_CHECKRESULT;

isc_result_t
zr_del_zone(zone_register_t *zr, dns_name_t *origin) ATTR_NONNULLS ATTR_CHECKRESULT;

isc_result_t
zr_get_zone_dbs(zone_register_t *zr, const dns_name_t *name, dns_db_t **ldapdbp,
		dns_db_t **rbtdbp) ATTR_NONNULL(1, 2) ATTR_CHECKRESULT;

isc_result_t
zr_get_zone_dn(zone_register_t *zr, dns_name_t *name, const char **dn) ATTR_NONNULLS ATTR_CHECKRESULT;

isc_result_t
zr_get_zone_ptr(zone_register_t * const zr, dns_name_t * const name,
		dns_zone_t ** const rawp, dns_zone_t ** const securep)
		ATTR_NONNULL(1,2,3) ATTR_CHECKRESULT;

isc_result_t
zr_get_zone_settings(zone_register_t *zr, const dns_name_t *name, settings_set_t **set) ATTR_NONNULLS ATTR_CHECKRESULT;

isc_result_t
zr_get_zone_path(isc_mem_t *mctx, settings_set_t *settings,
		 dns_name_t *zone_name, const char *last_component,
		 ld_string_t **path) ATTR_NONNULL(1,2,3,5) ATTR_CHECKRESULT;

isc_result_t
zr_rbt_iter_init(zone_register_t *zr, rbt_iterator_t **iter,
		 dns_name_t *nodename) ATTR_NONNULLS ATTR_CHECKRESULT;

isc_mem_t *
zr_get_mctx(zone_register_t *zr) ATTR_NONNULLS ATTR_CHECKRESULT;

isc_result_t
delete_bind_zone(dns_zt_t *zt, dns_zone_t **zonep) ATTR_NONNULLS ATTR_CHECKRESULT;

bool
zone_isempty(dns_zone_t *zone) ATTR_NONNULLS ATTR_CHECKRESULT;

#endif /* !_LD_ZONE_REGISTER_H_ */
