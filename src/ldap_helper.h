/*
 * Authors: Martin Nagy <mnagy@redhat.com>
 *          Adam Tkac <atkac@redhat.com>
 *
 * Copyright (C) 2008 - 2011 Red Hat
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

#ifndef _LD_LDAP_HELPER_H_
#define _LD_LDAP_HELPER_H_

#include "settings.h"
#include "types.h"
#include "zone_register.h"

#include <isc/util.h>

#define LDAPDB_EVENTCLASS 		ISC_EVENTCLASS(0xDDDD)

isc_result_t ldapdb_rdatalist_findrdatatype(ldapdb_rdatalist_t *rdatalist,
					    dns_rdatatype_t rdtype,
					    dns_rdatalist_t **rdlistp) ATTR_NONNULLS ATTR_CHECKRESULT;
/*
 * ldapdb_rdatalist_findrdatatype
 *
 * find rdatalist in rdatalist which matches rdtype and return it in rdlistp.
 *
 * Returns ISC_R_SUCCESS or ISC_R_NOTFOUND
 */

void ldapdb_rdatalist_destroy(isc_mem_t *mctx, ldapdb_rdatalist_t *rdatalist) ATTR_NONNULLS;
/*
 * ldapdb_rdatalist_destroy
 *
 * Free rdatalist list and free all associated rdata buffers.
 */

void free_rdatalist(isc_mem_t *mctx, dns_rdatalist_t *rdlist) ATTR_NONNULLS;
/*
 * free_rdatalist
 *
 * Free all dynamically allocated memory inside rdlist.
 */

isc_result_t ldapdb_rdatalist_get(isc_mem_t *mctx, ldap_instance_t *ldap_inst,
				  dns_name_t *name, dns_name_t *origin,
				  ldapdb_rdatalist_t *rdatalist)
				  ATTR_NONNULL(1, 2, 3, 5);
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

isc_result_t
new_ldap_instance(isc_mem_t *mctx, const char *db_name,
		  const char * const *argv, dns_dyndb_arguments_t *dyndb_args,
		  isc_task_t *task, ldap_instance_t **ldap_instp) ATTR_NONNULLS;
void destroy_ldap_instance(ldap_instance_t **ldap_inst) ATTR_NONNULLS;

isc_result_t
ldap_delete_zone2(ldap_instance_t *inst, dns_name_t *name,
		  isc_boolean_t lock, isc_boolean_t preserve_forwarding)
		  ATTR_NONNULLS;

/* Functions for writing to LDAP. */
isc_result_t write_to_ldap(dns_name_t *owner, ldap_instance_t *ldap_inst,
		dns_rdatalist_t *rdlist) ATTR_NONNULLS;
isc_result_t remove_values_from_ldap(dns_name_t *owner, ldap_instance_t *ldap_inst,
		dns_rdatalist_t *rdlist, isc_boolean_t delete_node) ATTR_NONNULLS;

isc_result_t
remove_attr_from_ldap(dns_name_t *owner, ldap_instance_t *ldap_inst,
		      const char *attr) ATTR_NONNULLS;

isc_result_t
remove_entry_from_ldap(dns_name_t *owner, ldap_instance_t *ldap_inst) ATTR_NONNULLS;

settings_set_t * ldap_instance_getsettings_local(ldap_instance_t *ldap_inst) ATTR_NONNULLS;

const char * ldap_instance_getdbname(ldap_instance_t *ldap_inst) ATTR_NONNULLS;

zone_register_t * ldap_instance_getzr(ldap_instance_t *ldap_inst) ATTR_NONNULLS;

isc_result_t activate_zones(isc_task_t *task, ldap_instance_t *inst) ATTR_NONNULLS;

isc_task_t * ldap_instance_gettask(ldap_instance_t *ldap_inst);

#endif /* !_LD_LDAP_HELPER_H_ */
