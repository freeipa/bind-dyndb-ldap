/*
 * Authors: Adam Tkac <atkac@redhat.com>
 *
 * Copyright (C) 2011 Red Hat
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

#ifndef _LD_TYPES_H_
#define _LD_TYPES_H_

#include <isc/refcount.h>
#include <dns/name.h>

/*
 * some nice words about ldapdb_rdatalist_t:
 * - it is list of all RRs which have same owner name
 * - rdata buffer is reachable only via dns_rdata_toregion()
 *
 * structure:
 *
 * class1                               class2
 * type1                                type2
 * ttl1                                 ttl2
 * rdata1 -> rdata2 -> rdata3           rdata4 -> rdata5
 * next_rdatalist              ->       next_rdatalist  ...
 */
typedef LIST(dns_rdatalist_t) ldapdb_rdatalist_t;

typedef struct ldapdb_node ldapdb_node_t;
typedef LIST(ldapdb_node_t) ldapdb_nodelist_t;
struct ldapdb_node {
	unsigned int		magic;
	isc_refcount_t		refs;
	dns_name_t		owner;
	ldapdb_rdatalist_t	rdatalist;
	ISC_LINK(ldapdb_node_t)	link;
};

typedef struct enum_txt_assoc {
	int		value;
	const char	*description;
} enum_txt_assoc_t;

isc_result_t
ldapdbnode_create(isc_mem_t *mctx, dns_name_t *owner, ldapdb_node_t **nodep);
#endif /* !_LD_TYPES_H_ */
