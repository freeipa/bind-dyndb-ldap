/**
 * Copyright (C) 2016  bind-dyndb-ldap authors; see COPYING for license
 *
 * DNS forwarding helpers.
 */

#include "config.h"

#include <isccfg/grammar.h>

#include <dns/forward.h>
#include <dns/fixedname.h>
#include <dns/view.h>

#include "bindcfg.h"
#include "empty_zones.h"
#include "fwd.h"
#include "ldap_helper.h"
#include "lock.h"
#include "settings.h"
#include "zone_register.h"

const enum_txt_assoc_t forwarder_policy_txts[] = {
	{ dns_fwdpolicy_none,	"none"	},
	{ dns_fwdpolicy_first,	"first"	},
	{ dns_fwdpolicy_only,	"only"	},
	{ -1,			NULL	} /* end marker */
};

/**
 * @pre closure points to a valid isc_buffer
 * @pre isc_buffer has non-NULL mctx
 * @pre isc_buffer has NULL buffer OR a buffer allocated from mctx
 *
 * @post closure contains \0 terminated string which is concatenation
 *       of previous context and input text
 */
static void
buffer_append_str(void *closure, const char *text, int textlen) {
	isc_buffer_t *out_buf = closure;
	isc_region_t new_space;
	isc_region_t old_space;

	REQUIRE(ISC_BUFFER_VALID(out_buf));
	REQUIRE(out_buf->mctx != NULL);
	REQUIRE(text != NULL);

	/* Allocate sufficiently long output buffer. */
	isc_buffer_region(out_buf, &old_space);
	new_space.length = isc_buffer_length(out_buf) + textlen + 1;
	new_space.base = isc_mem_get(out_buf->mctx, new_space.length);
	RUNTIME_CHECK(new_space.base != NULL);
	isc_buffer_reinit(out_buf, new_space.base, new_space.length);
	if (old_space.base != NULL)
		isc_mem_put(out_buf->mctx, old_space.base, old_space.length);

	/* Append output text and \0-terminate it.
	 * Overwrite \0 at the end if needed. */
	if (isc_buffer_usedlength(out_buf) != 0)
		/* Previous string is \0 terminated, chop \0. */
		isc_buffer_subtract(out_buf, 1);
	isc_buffer_putstr(out_buf, text);
	isc_buffer_putuint8(out_buf, '\0');
}

static size_t
fwd_list_len(dns_forwarders_t *fwdrs) {
	size_t len = 0;

	REQUIRE(fwdrs != NULL);

	for (dns_forwarder_t *fwdr = ISC_LIST_HEAD(fwdrs->fwdrs);
	     fwdr != NULL;
	     fwdr = ISC_LIST_NEXT(fwdr, link)) {
		len++;
	}
	return len;
}

/**
 * Generate dummy string which looks like list of forwarders
 * with list_len elements. This string might be fed into cfg parser.
 *
 * Caller has to deallocate resulting dummy_string.
 */
static isc_result_t
fwd_list_gen_dummy_config_string(isc_mem_t *mctx, size_t list_len,
				 isc_buffer_t **dummy_string) {
	isc_result_t result;
	const char prefix[] = "{ ";
	const char suffix[] = "} // dummy string, please ignore";
	const char fill[] = "127.0.0.1; ";
	size_t target_size = sizeof(prefix) \
			     + list_len*sizeof(fill)
			     + sizeof(suffix)
			     + 1; /* \0 */
	isc_buffer_t *output = NULL;

	REQUIRE(dummy_string != NULL && *dummy_string == NULL);

	CHECK(isc_buffer_allocate(mctx, &output, target_size));
	isc_buffer_putstr(output, prefix);
	for (size_t i = 0; i < list_len; i++)
		isc_buffer_putstr(output, fill);
	isc_buffer_putstr(output, suffix);
	isc_buffer_putuint8(output, '\0');
	*dummy_string = output;

cleanup:
	if (result != ISC_R_SUCCESS && output != NULL)
		isc_buffer_free(&output);

	return result;
}

/**
 * Generate list of all values as bracketed list.
 * This string might be fed into cfg parser.
 *
 * Caller has to deallocate resulting output buffer.
 */
isc_result_t
fwd_print_bracketed_values_buf(isc_mem_t *mctx, ldap_valuelist_t *values,
			      isc_buffer_t **string) {
	isc_result_t result;
	ldap_value_t *value;
	const char prefix[] = "{ ";
	const char suffix[] = "}";
	isc_buffer_t tmp_buf; /* hack: only the base buffer is allocated */

	REQUIRE(string != NULL && *string == NULL);

	isc_buffer_initnull(&tmp_buf);
	tmp_buf.mctx = mctx;

	buffer_append_str(&tmp_buf, prefix, 2);
	for (value = HEAD(*values);
	     value != NULL && value->value != NULL;
	     value = NEXT(value, link)) {
		buffer_append_str(&tmp_buf, value->value, strlen(value->value));
		buffer_append_str(&tmp_buf, "; ", 2);
	}
	buffer_append_str(&tmp_buf, suffix, 2);

	/* create and copy string from tmp to output buffer */
	CHECK(isc_buffer_allocate(mctx, string, tmp_buf.used));
	isc_buffer_putmem(*string, isc_buffer_base(&tmp_buf), tmp_buf.used);

cleanup:
	if (tmp_buf.base != NULL)
		isc_mem_put(mctx, tmp_buf.base, tmp_buf.length);
	return result;
}

isc_result_t
fwd_print_list_buff(isc_mem_t *mctx, dns_forwarders_t *fwdrs,
			 isc_buffer_t **out_buf) {
	isc_result_t result;
	size_t list_len;
	isc_buffer_t *dummy_fwdr_buf = NULL; /* fully dynamic allocation */
	isc_buffer_t tmp_buf; /* hack: only the base buffer is allocated */

	cfg_parser_t *parser = NULL;
	cfg_obj_t *forwarders_cfg = NULL;
	const cfg_obj_t *faddresses;
	const cfg_listelt_t *fwdr_cfg; /* config representation */
	/* internal representation */
	dns_forwarder_t *fwdr_int;

	isc_buffer_initnull(&tmp_buf);
	tmp_buf.mctx = mctx;
	CHECK(cfg_parser_create(mctx, dns_lctx, &parser));

	/* Create dummy string with list of IP addresses of the same length
	 * as the original list of forwarders. Parse this string to obtain
	 * nested cfg structures which will be filled with data for actual
	 * forwarders.
	 *
	 * This is nasty hack but it is easiest way to create list of cfg_objs
	 * I found.
	 */
	list_len = fwd_list_len(fwdrs);
	CHECK(fwd_list_gen_dummy_config_string(mctx,
					       list_len, &dummy_fwdr_buf));
	CHECK(cfg_parse_buffer(parser, dummy_fwdr_buf, NULL, 0,
			       cfg_type_forwarders, 0, &forwarders_cfg));

	/* Walk through internal representation and cfg representation and copy
	 * data from the internal one to cfg data structures.*/
	faddresses = cfg_tuple_get(forwarders_cfg, "addresses");
	for (fwdr_int = ISC_LIST_HEAD(
			fwdrs->fwdrs
			), fwdr_cfg = cfg_list_first(faddresses);
	     INSIST((fwdr_int == NULL) == (fwdr_cfg == NULL)), fwdr_int != NULL;
	     fwdr_int = ISC_LIST_NEXT(fwdr_int, link), fwdr_cfg = cfg_list_next(fwdr_cfg)) {
		fwdr_cfg->obj->value.sockaddrdscp.sockaddr = fwdr_int->addr;
		fwdr_cfg->obj->value.sockaddrdscp.dscp = fwdr_int->dscp;
	}
	cfg_print(faddresses, buffer_append_str, &tmp_buf);

	/* create and copy string from tmp to output buffer */
	CHECK(isc_buffer_allocate(mctx, out_buf, tmp_buf.used));
	isc_buffer_putmem(*out_buf, isc_buffer_base(&tmp_buf),
			  isc_buffer_usedlength(&tmp_buf));

cleanup:
	if (forwarders_cfg != NULL)
		cfg_obj_destroy(parser, &forwarders_cfg);
	if (parser != NULL)
		cfg_parser_destroy(&parser);
	if (dummy_fwdr_buf != NULL) {
		if (tmp_buf.base != NULL)
			isc_mem_put(mctx, tmp_buf.base, tmp_buf.length);
		isc_buffer_free(&dummy_fwdr_buf);
	}

	return result;
}

/**
 * Parse list of nameserver IP addresses with or without port specified
 * in BIND9 syntax. IPv4 and IPv6 addresses are supported, see examples.
 *
 * @param[in]  forwarder_str String with IP addresses and optionally port.
 * @param[in]  mctx	     Memory for allocating list of forwarders.
 * @param[out] fwdrs	     Pointer to list of newly allocated forwarders.
 *
 * @return ISC_R_SUCCESS if parsing was successful
 *
 * @pre list of forwarders pointed to by fwdrs is empty
 *
 * @example
 * "{ 192.168.0.100; }" -> { address:192.168.0.100, port:53 }
 * "{ 192.168.0.100 port 553;} " -> { address:192.168.0.100, port:553 }
 * "{ 0102:0304:0506:0708:090A:0B0C:0D0E:0FAA; }"
 * 		-> { address:0102:0304:0506:0708:090A:0B0C:0D0E:0FAA, port:53 }
 * "{ 0102:0304:0506:0708:090A:0B0C:0D0E:0FAA port 553; }" ->
 * 		-> { address:0102:0304:0506:0708:090A:0B0C:0D0E:0FAA, port:553 }
 * "{ 192.168.0.100; 0102:0304:0506:0708:090A:0B0C:0D0E:0FAA port 553; }"
 * 		-> { address:192.168.0.100, port:53;
 * 		     address:0102:0304:0506:0708:090A:0B0C:0D0E:0FAA, port:553 }
 */

static isc_result_t
fwd_parse_str(const char *fwdrs_str, isc_mem_t *mctx,
	      dns_forwarderlist_t *fwdrs)
{
	isc_result_t result = ISC_R_SUCCESS;
	cfg_parser_t *parser = NULL;

	cfg_obj_t *fwdrs_cfg = NULL;
	const cfg_obj_t *faddresses;
	const cfg_listelt_t *listel;
	const cfg_obj_t *fwdr_cfg;
	isc_sockaddr_t addr;
	dns_forwarder_t *fwdr;

	in_port_t port = 53;

	REQUIRE(fwdrs_str != NULL);
	REQUIRE(fwdrs != NULL);
	REQUIRE(ISC_LIST_EMPTY(*fwdrs));

	/* parse string like { ip; ip port dscp; } to list of cfg objects */
	CHECK(cfg_parser_create(mctx, dns_lctx, &parser));
	CHECK(cfg_parse_strbuf(parser, fwdrs_str,
			       &cfg_type_forwarders, &fwdrs_cfg));
	faddresses = cfg_tuple_get(fwdrs_cfg, "addresses");

	/* transform list of cfg objects to linked list of forwarders */
	for (listel = cfg_list_first(faddresses);
	     listel != NULL;
	     listel = cfg_list_next(listel)) {
		fwdr_cfg = cfg_listelt_value(listel);
		addr = *cfg_obj_assockaddr(fwdr_cfg);
		if (isc_sockaddr_getport(&addr) == 0)
			isc_sockaddr_setport(&addr, port);
		CHECKED_MEM_GET_PTR(mctx, fwdr);
		fwdr->addr = addr;
		fwdr->dscp = cfg_obj_getdscp(fwdr_cfg);
		ISC_LINK_INIT(fwdr, link);
		ISC_LIST_APPEND(*fwdrs, fwdr, link);
	}

cleanup:
	if (fwdrs_cfg != NULL)
		cfg_obj_destroy(parser, &fwdrs_cfg);
	if (parser != NULL)
		cfg_parser_destroy(&parser);
	return result;
}

static void
fwdr_list_free(isc_mem_t *mctx, dns_forwarderlist_t *fwdrs) {
	dns_forwarder_t *fwdr;
	while (!ISC_LIST_EMPTY(*fwdrs)) {
		fwdr = ISC_LIST_HEAD(*fwdrs);
		ISC_LIST_UNLINK(*fwdrs, fwdr, link);
		SAFE_MEM_PUT_PTR(mctx, fwdr);
	}
}

/**
 * Detect if given set of settings contains explicit forwarding configuration.
 * Explicit configuration is either:
 * a) policy = none
 * b) (policy != none) && (non-empty list of forwarders)
 *
 * @param[out] isexplicit true if conditions for explicit configuration
 *                        are met, false otherwise
 *
 * @retval ISC_R_SUCCESS isexplicit is set appropriately
 * @retval other         memory allocation or parsing errors etc.
 */
static isc_result_t
fwd_setting_isexplicit(isc_mem_t *mctx, const settings_set_t *set,
		       bool *isexplicit) {
	isc_result_t result;
	setting_t *setting = NULL;
	dns_fwdpolicy_t	fwdpolicy;
	dns_forwarderlist_t fwdrs;

	REQUIRE(isexplicit != NULL);
	ISC_LIST_INIT(fwdrs);

	CHECK(setting_find("forward_policy", set, false, true, &setting));
	INSIST(get_enum_value(forwarder_policy_txts, setting->value.value_char,
			      (int *)&fwdpolicy) == ISC_R_SUCCESS);
	if (fwdpolicy == dns_fwdpolicy_none) {
		*isexplicit = true;
		return ISC_R_SUCCESS;
	}

	setting = NULL;
	CHECK(setting_find("forwarders", set, false, true, &setting));
	CHECK(fwd_parse_str(setting->value.value_char, mctx, &fwdrs));

cleanup:
	*isexplicit = (result == ISC_R_SUCCESS && !ISC_LIST_EMPTY(fwdrs));
	if (result == ISC_R_NOTFOUND)
		result = ISC_R_SUCCESS;
	fwdr_list_free(mctx, &fwdrs);
	return result;
}

/**
 * Walk through tree of sets of settings from bottom up and find
 * most specific set which contains explicit forwarding configuration.
 *
 * @retval ISC_R_SUCCESS  setting set with explicit configuration is in *found
 * @retval ISC_R_NOTFOUND setting set with explicit configuration does not exist
 */
static isc_result_t
fwd_setting_find_explicit(isc_mem_t *mctx, const settings_set_t *start_set,
			  const settings_set_t **found) {
	isc_result_t result;
	bool isexplicit;

	REQUIRE(found != NULL && *found == NULL);

	for (const settings_set_t *set = start_set;
	     set != NULL;
	     set = set->parent_set)
	{
		CHECK(fwd_setting_isexplicit(mctx, set, &isexplicit));
		if (isexplicit == true) {
			*found = set;
			CLEANUP_WITH(ISC_R_SUCCESS);
		}
	}
	result = ISC_R_NOTFOUND;

cleanup:
	return result;
}

/**
 * Read forwarding policy (from idnsForwardingPolicy attribute) and
 * list of forwarders (from idnsForwarders multi-value attribute)
 * and update settings (forward_policy and forwarders) in given set of settings.
 *
 * This function does not change actual forwarding configuration.
 * @see configure_zone_forwarders
 *
 * @post Forward_policy is always non-empty because default value is stored
 *       if nothing is found in the LDAP entry.
 *       Setting forwarders may be left unset if no forwarders are specified.
 *
 * @retval ISC_R_SUCCESS         Config was parsed and stored in settings
 * @retval errors                Forwarding policy is invalid
 *                               or specified forwarders are invalid.
 */
isc_result_t
fwd_parse_ldap(ldap_entry_t *entry, settings_set_t *set) {
	isc_result_t result;
	isc_result_t first;
	ldap_valuelist_t values;
	ldap_value_t *value;
	isc_buffer_t *tmp_buf = NULL; /* hack: only the base buffer is allocated */
	dns_forwarderlist_t fwdrs;
	const char *setting_str = NULL;

	/**
	 * BIND forward policies are "first" (default) or "only".
	 * We invented option "none" which disables forwarding for zone
	 * regardless idnsForwarders attribute and global forwarders.
	 */
	dns_fwdpolicy_t fwdpolicy;

	REQUIRE(entry != NULL);
	REQUIRE(set != NULL);

	ISC_LIST_INIT(fwdrs);

	/* forward policy */
	result = ldap_entry_getvalues(entry, "idnsForwardPolicy", &values);
	/* validate LDAP entry before copying it into settings set */
	if (result == ISC_R_SUCCESS
	    && HEAD(values) != NULL
	    && HEAD(values)->value != NULL) {
		value = HEAD(values);
		if (get_enum_value(forwarder_policy_txts, value->value,
				   (int *)&fwdpolicy) != ISC_R_SUCCESS)
		{
			log_error("%s: invalid value '%s' in idnsForwardPolicy "
				  "attribute; valid values: first, only, none",
				  ldap_entry_logname(entry), value->value);
			CLEANUP_WITH(ISC_R_UNEXPECTEDTOKEN);
		}
	}
	result = setting_update_from_ldap_entry("forward_policy", set,
						"idnsForwardPolicy",
						entry);
	first = result;
	if (result != ISC_R_SUCCESS && result != ISC_R_IGNORE)
		goto cleanup;
	result = setting_find("forward_policy", set, false, true, NULL);
	if (result == ISC_R_NOTFOUND) {
		log_debug(2, "defaulting to forward policy 'first' for "
			  "%s", ldap_entry_logname(entry));
		CHECK(setting_set("forward_policy", set, "first"));
	}

	/* forwarders */
	result = ldap_entry_getvalues(entry, "idnsForwarders", &values);
	if (result == ISC_R_SUCCESS
	    && HEAD(values) != NULL && HEAD(values)->value != NULL) {
		/* Forwarders: concatenate IP addresses to one { string; } */
		CHECK(fwd_print_bracketed_values_buf(entry->mctx, &values,
						    &tmp_buf));
		setting_str = isc_buffer_base(tmp_buf);
		/* just sanity check, the result is unused */
		CHECK(fwd_parse_str(setting_str, entry->mctx, &fwdrs));
	}
	if (!ISC_LIST_EMPTY(fwdrs)) {
		result = setting_set("forwarders", set, setting_str);
		if (result == ISC_R_SUCCESS)
			log_debug(2, "setting 'forwarders' (idnsFowarders) was changed "
				  "to '%s' in %s", setting_str, ldap_entry_logname(entry));
		else if (result != ISC_R_IGNORE)
				goto cleanup;
	} else {
		result = setting_unset("forwarders", set);
	}

	/* return "ignore" only if no change was done in any of the settings */
	result = (result == ISC_R_IGNORE) ? first : result;

cleanup:
	if (result != ISC_R_SUCCESS && result != ISC_R_IGNORE
	    && setting_str != NULL)
		log_error_r("unable to parse forwarders '%s'", setting_str);
	if (tmp_buf != NULL)
		isc_buffer_free(&tmp_buf);
	fwdr_list_free(entry->mctx, &fwdrs);
	return result;
}

/**
 * Read forwarding policy and list of forwarders from set of settings
 * and update actual forwarding configuration.
 *
 * Enable forwarding if forwarders are specified and policy is not 'none'.
 * Disable forwarding if forwarding policy is 'none'.
 * Remove explicit configuration if list of forwarders is empty
 * and policy != none.
 *
 * Global forwarders use configuration in following priority order:
 * root zone > global LDAP config > named.conf
 *
 * @retval ISC_R_SUCCESS  Forwarding configuration was updated.
 * @retval ISC_R_NOMEMORY
 * @retval others	  Some RBT manipulation errors including ISC_R_FAILURE.
 */
isc_result_t
fwd_configure_zone(const settings_set_t *set, ldap_instance_t *inst,
		   dns_name_t *name)
{
	isc_result_t result;
	isc_mem_t *mctx = NULL;
	dns_view_t *view = NULL;
	isc_result_t lock_state = ISC_R_IGNORE;
	dns_forwarderlist_t fwdrs;
	bool is_global_config;
	dns_fixedname_t foundname;
	const char *msg_use_global_fwds;
	const char *msg_obj_type;
	/**
	 * BIND forward policies are "first" (default) or "only".
	 * We invented option "none" which disables forwarding for zone
	 * regardless idnsForwarders attribute and global forwarders.
	 */
	dns_fwdpolicy_t fwdpolicy;
	const char *fwdpolicy_str = NULL;
	const char *forwarders_str = NULL;
	bool isconfigured;
	const settings_set_t *explicit_set = NULL;

	REQUIRE(inst != NULL && name != NULL);
	ldap_instance_attachmem(inst, &mctx);
	ldap_instance_attachview(inst, &view);

	dns_fixedname_init(&foundname);
	ISC_LIST_INIT(fwdrs);

	if (dns_name_equal(name, dns_rootname)) {
		is_global_config = true;
		msg_obj_type = "global forwarding configuration";
		msg_use_global_fwds = "; global forwarders will be disabled";
	} else {
		is_global_config = false;
		msg_obj_type = "zone";
		msg_use_global_fwds = "; global forwarders will be used "
				      "(if they are configured)";
	}

	/* Fetch forwarders configured for particular zone.
	 * Global config (root zone) is special case because it can be set in
	 * named.conf, LDAP global object or root zone in LDAP so inheritance
	 * is necessary.
	 * For all other zones (non-root) zones *do not* use recursive getter
	 * and let BIND to handle inheritance in fwdtable itself. */
	CHECK(fwd_setting_isexplicit(mctx, set, &isconfigured));
	if (isconfigured == false && is_global_config == true) {
		result = fwd_setting_find_explicit(mctx, set, &explicit_set);
		if (result == ISC_R_SUCCESS) {
			isconfigured = true;
			if (set != explicit_set) {
				log_debug(5, "%s was inherited from %s",
					  msg_obj_type, explicit_set->name);
				set = explicit_set;
			}
		} else if (result != ISC_R_NOTFOUND)
			goto cleanup;
	}

	if (isconfigured == true) {
		CHECK(setting_get_str("forward_policy", set, &fwdpolicy_str));
		result = get_enum_value(forwarder_policy_txts,
					fwdpolicy_str, (int *)&fwdpolicy);
		INSIST(result == ISC_R_SUCCESS);
		log_debug(5, "%s %s: forward policy is '%s'", msg_obj_type,
			  set->name, fwdpolicy_str);
		if (fwdpolicy == dns_fwdpolicy_none) {
			log_debug(5, "%s %s: forwarding explicitly disabled "
				  "(policy 'none', ignoring all forwarders)",
				  msg_obj_type, set->name);
			ISC_LIST_INIT(fwdrs);
		} else {
			CHECK(setting_get_str("forwarders", set, &forwarders_str));
			CHECK(fwd_parse_str(forwarders_str, mctx, &fwdrs));
		}
	} else {
		log_debug(5, "%s %s: no explicit configuration found%s",
			  msg_obj_type, set->name, msg_use_global_fwds);
	}

	/* update forwarding table */
	run_exclusive_enter(inst, &lock_state);
	CHECK(fwd_delete_table(view, name, msg_obj_type, set->name));
	if (isconfigured == true) {
		CHECK(dns_fwdtable_addfwd(view->fwdtable, name, &fwdrs,
					  fwdpolicy));
	}
	dns_view_flushcache(view);
	run_exclusive_exit(inst, lock_state);
	lock_state = ISC_R_IGNORE; /* prevent double-unlock */
	log_debug(5, "%s %s: forwarder table was updated: %s",
		  msg_obj_type, set->name,
		  dns_result_totext(result));

	/* Handle collisions with automatic empty zones. */
	if (isconfigured == true)
		CHECK(empty_zone_handle_conflicts(name,
						  view->zonetable,
						  (fwdpolicy == dns_fwdpolicy_first)));

cleanup:
	run_exclusive_exit(inst, lock_state);
	if (result != ISC_R_SUCCESS)
		log_error_r("%s %s: forwarding table update failed",
			    msg_obj_type, set->name);
	fwdr_list_free(mctx, &fwdrs);
	dns_view_detach(&view);
	isc_mem_detach(&mctx);
	return result;
}

isc_result_t
fwd_delete_table(dns_view_t *view, dns_name_t *name,
		 const char *msg_obj_type, const char *logname) {
	isc_result_t result;

	result = dns_fwdtable_delete(view->fwdtable, name);
	if (result != ISC_R_SUCCESS && result != ISC_R_NOTFOUND) {
		log_error_r("%s %s: failed to delete forwarders",
			    msg_obj_type, logname);
		return result;
	} else {
		return ISC_R_SUCCESS; /* ISC_R_NOTFOUND = nothing to delete */
	}
}

/**
 * Reconfigure global forwarder using latest configuration in priority order:
 * - root zone (if it is active)
 * - server LDAP config
 * - global LDAP config (inheritance is handled by settings tree)
 * - named.conf (inheritance is handled by settings tree)
 */
isc_result_t
fwd_reconfig_global(ldap_instance_t *inst) {
	isc_result_t result;
	settings_set_t *toplevel_settings = NULL;
	bool root_zone_is_active = false;

	/* we have to respect forwarding configuration for root zone */
	result = zr_get_zone_settings(ldap_instance_getzr(inst), dns_rootname,
				      &toplevel_settings);
	if (result == ISC_R_SUCCESS)
		/* is root zone active? */
		CHECK(setting_get_bool("active", toplevel_settings,
				       &root_zone_is_active));
	else if (result != ISC_R_NOTFOUND)
		goto cleanup;

	if (root_zone_is_active == false)
		toplevel_settings = ldap_instance_getsettings_server(inst);

	CHECK(fwd_configure_zone(toplevel_settings, inst, dns_rootname));
	if (result != ISC_R_SUCCESS)
		log_error_r("global forwarder could not be set up using %s",
			    toplevel_settings->name);

cleanup:
	return result;
}
