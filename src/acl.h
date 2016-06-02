/*
 * Copyright (C) 2009-2014  bind-dyndb-ldap authors; see COPYING for license
 */

#ifndef _LD_ACL_H_
#define _LD_ACL_H_

#include "config.h"

#include "ldap_entry.h"
#include "types.h"

#include <dns/acl.h>

typedef enum acl_type {
	acl_type_query,
	acl_type_transfer
} acl_type_t;

extern const enum_txt_assoc_t acl_type_txts[];

isc_result_t
acl_configure_zone_ssutable(const char *policy_str, dns_zone_t *zone) ATTR_NONNULLS ATTR_CHECKRESULT;

isc_result_t
acl_from_ldap(isc_mem_t *mctx, const char *aclstr, acl_type_t type,
	      dns_acl_t **aclp) ATTR_NONNULLS ATTR_CHECKRESULT;
/*
 * Converts multiple ACL element.
 *
 * Please refer to BIND 9 ARM (Administrator Reference Manual) about ACLs.
 */

#endif /* !_LD_ACL_H_ */
