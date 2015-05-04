/*
 * Copyright (C) 2014-2015  bind-dyndb-ldap authors; see COPYING for license
 */

#ifndef SRC_ZONE_H_
#define SRC_ZONE_H_

#include "util.h"

isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
zone_journal_adddiff(isc_mem_t *mctx, dns_zone_t *zone, dns_diff_t *diff);

#endif /* SRC_ZONE_H_ */
