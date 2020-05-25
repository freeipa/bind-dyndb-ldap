/*
 * DNS forwarding utilities.
 */

#ifndef _LD_FWD_H_
#define _LD_FWD_H_

#include "config.h"
#include "ldap_entry.h"
#include "util.h"

extern const enum_txt_assoc_t forwarder_policy_txts[];

isc_result_t
fwd_print_list_buff(isc_mem_t *mctx, dns_forwarders_t *fwdrs,
		    isc_buffer_t **out_buf)
		    ATTR_NONNULLS ATTR_CHECKRESULT;

isc_result_t
fwd_print_bracketed_values_buf(isc_mem_t *mctx, ldap_valuelist_t *values,
			       isc_buffer_t **string)
			       ATTR_NONNULLS ATTR_CHECKRESULT;

isc_result_t
fwd_parse_ldap(ldap_entry_t *entry, settings_set_t *set)
	       ATTR_NONNULLS ATTR_CHECKRESULT;

isc_result_t
fwd_configure_zone(const settings_set_t *set, ldap_instance_t *inst, const dns_name_t *name)
		   ATTR_NONNULLS ATTR_CHECKRESULT;

isc_result_t
fwd_delete_table(dns_view_t *view, const dns_name_t *name,
		 const char *msg_obj_type, const char *logname)
		 ATTR_NONNULLS ATTR_CHECKRESULT;

isc_result_t
fwd_reconfig_global(ldap_instance_t *inst)
		    ATTR_NONNULLS ATTR_CHECKRESULT;

#endif /* _LD_FWD_H_ */
