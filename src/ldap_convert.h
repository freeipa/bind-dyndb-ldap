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

#ifndef _LD_LDAP_CONVERT_H_
#define _LD_LDAP_CONVERT_H_

#include <dns/types.h>

#include "str.h"
#include "ldap_helper.h"

/*
 * Convert LDAP DN 'dn', to dns_name_t 'target'. 'target' needs to be
 * initialized with dns_name_init() before the call and freed by the caller
 * after it using dns_name_free().
 */
isc_result_t dn_to_dnsname(isc_mem_t *mctx, const char *dn,
			   dns_name_t *target);

isc_result_t dnsname_to_dn(ldap_instance_t *ldap_inst, dns_name_t *name,
			   ld_string_t *target);

isc_result_t ldap_attribute_to_rdatatype(const char *ldap_record,
				      dns_rdatatype_t *rdtype);

isc_result_t rdatatype_to_ldap_attribute(dns_rdatatype_t rdtype,
					 const char **target);

#endif /* !_LD_LDAP_CONVERT_H_ */
