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

#include "ldap_helper.h"

#include <dns/acl.h>

isc_result_t
acl_configure_zone_ssutable(const char *policy_str, dns_zone_t *zone);

isc_result_t
acl_from_ldap(isc_mem_t *mctx, const ldap_value_list_t *vals, dns_acl_t **aclp);
/*
 * Converts multiple ACL elements to the zone ACL.
 *
 * Allowed elements are:
 *
 * IPv4/IPv6 net prefix - 192.168.1.0/24
 * IPv4/IPv6 address - 192.168.1.1
 * any and none keywords
 * "!" prefix means negation
 */

#endif /* !_LD_ACL_H_ */
