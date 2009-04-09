/* Authors: Martin Nagy <mnagy@redhat.com>
 *          Adam Tkac <atkac@redhat.com>
 *
 * Copyright (C) 2008, 2009  Red Hat
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

#ifndef _LD_LDAP_HELPER_H_
#define _LD_LDAP_HELPER_H_

#include <isc/util.h>

typedef struct ldap_db		ldap_db_t;
typedef struct ldap_instance	ldap_instance_t;

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

isc_result_t ldapdb_rdatalist_findrdatatype(ldapdb_rdatalist_t *rdatalist,
					    dns_rdatatype_t rdtype,
					    dns_rdatalist_t **rdlistp);
/*
 * ldapdb_rdatalist_findrdatatype
 *
 * find rdatalist in rdatalist which matches rdtype and return it in rdlistp.
 *
 * Returns ISC_R_SUCCESS or ISC_R_NOTFOUND
 */

void ldapdb_rdatalist_destroy(isc_mem_t *mctx, ldapdb_rdatalist_t *rdatalist);
/*
 * ldapdb_rdatalist_destroy
 *
 * Free rdatalist list and free all associated rdata buffers.
 */

void free_rdatalist(isc_mem_t *mctx, dns_rdatalist_t *rdlist);
/*
 * free_rdatalist
 *
 * Free all dynamically allocated memory inside rdlist.
 */

isc_result_t ldapdb_rdatalist_get(isc_mem_t *mctx, ldap_db_t *ldap_db,
				  dns_name_t *name, dns_name_t *origin,
				  ldapdb_rdatalist_t *rdatalist);
/*
 * ldapdb_rdatalist_get
 *
 * Find all RRs in ldap database with specified name and return them in
 * rdatalist.
 *
 * XXX Add partial match handling.
 *
 * Possible errors include:
 *
 * ISC_R_NOMEMORY
 * ISC_R_NOTFOUND
 * DNS_R_PARTIALMATCH
 */

isc_result_t new_ldap_db(isc_mem_t *mctx, dns_view_t *view, ldap_db_t **ldap_dbp,
			 const char * const *argv);
void destroy_ldap_db(ldap_db_t **ldap_db);
isc_result_t refresh_zones_from_ldap(ldap_db_t *ldap_db, const char *name,
				     dns_zonemgr_t *zmgr);

isc_result_t
get_zone_dn(ldap_db_t *ldap_db, dns_name_t *name, const char **dn,
	    dns_name_t *matched_name);

/* Functions for writing to LDAP. */
isc_result_t write_to_ldap(dns_name_t *owner, ldap_db_t *ldap_db,
		dns_rdatalist_t *rdlist);
isc_result_t remove_from_ldap(dns_name_t *owner, ldap_db_t *ldap_db,
		dns_rdatalist_t *rdlist);

#endif /* !_LD_LDAP_HELPER_H_ */
