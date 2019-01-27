/*
 * Copyright (C) 2009-2015  bind-dyndb-ldap authors; see COPYING for license
 */

#ifndef _LD_LDAP_HELPER_H_
#define _LD_LDAP_HELPER_H_

#include "types.h"

#include <isc/boolean.h>
#include <isc/eventclass.h>
#include <isc/util.h>
#include <isccfg/cfg.h>

#include <ldap.h>

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

isc_result_t
new_ldap_instance(isc_mem_t *mctx, const char *db_name, const char *parameters,
		  const char *file, unsigned long line,
		  const dns_dyndbctx_t *dctx, ldap_instance_t **ldap_instp) ATTR_NONNULLS;
void destroy_ldap_instance(ldap_instance_t **ldap_inst) ATTR_NONNULLS;

isc_result_t
ldap_delete_zone2(ldap_instance_t *inst, dns_name_t *name, isc_boolean_t lock)
		  ATTR_NONNULLS;

/* Functions for writing to LDAP. */
isc_result_t write_to_ldap(dns_name_t *owner, dns_name_t *zone, ldap_instance_t *ldap_inst,
		dns_rdatalist_t *rdlist) ATTR_NONNULLS;

isc_result_t
remove_values_from_ldap(dns_name_t *owner, dns_name_t *zone, ldap_instance_t *ldap_inst,
		dns_rdatalist_t *rdlist, isc_boolean_t delete_node) ATTR_NONNULLS;

isc_result_t
remove_rdtype_from_ldap(dns_name_t *owner, dns_name_t *zone,
		      ldap_instance_t *ldap_inst, dns_rdatatype_t type)
		      ATTR_NONNULLS;

isc_result_t
remove_entry_from_ldap(dns_name_t *owner, dns_name_t *zone, ldap_instance_t *ldap_inst) ATTR_NONNULLS;

isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
ldap_mod_create(isc_mem_t *mctx, LDAPMod **changep);

isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
ldap_modify_do(ldap_instance_t *ldap_inst, const char *dn, LDAPMod **mods,
		isc_boolean_t delete_node);

void ATTR_NONNULLS
ldap_mod_free(isc_mem_t *mctx, LDAPMod **changep);

settings_set_t * ldap_instance_getsettings_local(ldap_instance_t *ldap_inst) ATTR_NONNULLS;

settings_set_t * ldap_instance_getsettings_server(ldap_instance_t *ldap_inst) ATTR_NONNULLS;

const char * ldap_instance_getdbname(ldap_instance_t *ldap_inst) ATTR_NONNULLS;

zone_register_t * ldap_instance_getzr(ldap_instance_t *ldap_inst) ATTR_NONNULLS;

isc_result_t activate_zones(isc_task_t *task, ldap_instance_t *inst) ATTR_NONNULLS;

isc_task_t * ldap_instance_gettask(ldap_instance_t *ldap_inst);

isc_boolean_t ldap_instance_isexiting(ldap_instance_t *ldap_inst) ATTR_NONNULLS ATTR_CHECKRESULT;

void ldap_instance_taint(ldap_instance_t *ldap_inst) ATTR_NONNULLS;

unsigned int
ldap_instance_untaint_start(ldap_instance_t *ldap_inst);

isc_result_t
ldap_instance_untaint_finish(ldap_instance_t *ldap_inst, unsigned int count);

void
ldap_instance_attachview(ldap_instance_t *ldap_inst, dns_view_t **view) ATTR_NONNULLS;

void
ldap_instance_attachmem(ldap_instance_t *ldap_inst, isc_mem_t **mctx)
			ATTR_NONNULLS;

#endif /* !_LD_LDAP_HELPER_H_ */
