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

#ifndef _LD_ACL_H_
#define _LD_ACL_H_

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

isc_result_t
acl_parse_forwarder(const char *forwarders_str, isc_mem_t *mctx,
#if LIBDNS_VERSION_MAJOR < 140
		isc_sockaddr_t **fw)
#else /* LIBDNS_VERSION_MAJOR >= 140 */
		dns_forwarder_t **fw)
#endif
ATTR_NONNULLS ATTR_CHECKRESULT;

#endif /* !_LD_ACL_H_ */
