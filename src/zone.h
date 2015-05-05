/*
 * Copyright (C) 2014-2015  bind-dyndb-ldap authors; see COPYING for license
 */

#ifndef SRC_ZONE_H_
#define SRC_ZONE_H_

#include <isc/int.h>
#include <isc/types.h>

#include <dns/diff.h>
#include <dns/name.h>
#include <dns/types.h>

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

isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
rdatalist_to_diff(isc_mem_t *mctx, dns_diffop_t op, dns_name_t *name,
		  dns_rdatalist_t *rdatalist, dns_diff_t *diff);

isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
rdataset_to_diff(isc_mem_t *mctx, dns_diffop_t op, dns_name_t *name,
		dns_rdataset_t *rds, dns_diff_t *diff);

#endif /* SRC_ZONE_H_ */
