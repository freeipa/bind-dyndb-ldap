/*
 * Copyright (C) 2014-2015  bind-dyndb-ldap authors; see COPYING for license
 */

#ifndef SRC_ZONE_H_
#define SRC_ZONE_H_

#include "util.h"

isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
zone_journal_adddiff(isc_mem_t *mctx, dns_zone_t *zone, dns_diff_t *diff);

isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
zone_soaserial_updatetuple(dns_updatemethod_t method, dns_difftuple_t *soa_tuple,
		  isc_uint32_t *new_serial);

isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
zone_soaserial_addtuple(isc_mem_t *mctx, dns_db_t *db,
			dns_dbversion_t *version, dns_diff_t *diff,
			isc_uint32_t *new_serial);

#endif /* SRC_ZONE_H_ */
