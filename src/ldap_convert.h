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

#ifndef _LD_LDAP_CONVERT_H_
#define _LD_LDAP_CONVERT_H_

#include <dns/types.h>
#include <dns/rbt.h>
#include <dns/rdatatype.h>

#include "str.h"
#include "types.h"

#define LDAP_ATTR_FORMATSIZE 32 /* "expected" maximum attribute name length */
#define LDAP_RDATATYPE_SUFFIX     "Record"
#define LDAP_RDATATYPE_SUFFIX_LEN (sizeof(LDAP_RDATATYPE_SUFFIX) - 1)

/*
 * Convert LDAP DN 'dn', to dns_name_t 'target'. 'target' needs to be
 * initialized with dns_name_init() before the call and freed by the caller
 * after it using dns_name_free(). If origin is not NULL, then origin name of
 * that DNS name is returned.
 */
isc_result_t dn_to_dnsname(isc_mem_t *mctx, const char *dn,
			   dns_name_t *target, dns_name_t *origin,
			   isc_boolean_t *iszone)
			   ATTR_NONNULL(1, 2, 3) ATTR_CHECKRESULT;

isc_result_t dn_want_zone(const char * const prefix, const char * const dn,
			  isc_boolean_t dniszone, isc_boolean_t classiszone)
			  ATTR_NONNULLS ATTR_CHECKRESULT;

isc_result_t dnsname_to_dn(zone_register_t *zr, dns_name_t *name, dns_name_t *zone,
			   ld_string_t *target) ATTR_NONNULLS ATTR_CHECKRESULT;

isc_result_t ldap_attribute_to_rdatatype(const char *ldap_record,
				      dns_rdatatype_t *rdtype) ATTR_NONNULLS ATTR_CHECKRESULT;

isc_result_t
rdatatype_to_ldap_attribute(dns_rdatatype_t rdtype, char *target,
			    unsigned int size) ATTR_NONNULLS ATTR_CHECKRESULT;

isc_result_t dn_to_text(const char *dn, ld_string_t *target,
			ld_string_t *origin) ATTR_NONNULL(1, 2) ATTR_CHECKRESULT;

#endif /* !_LD_LDAP_CONVERT_H_ */
