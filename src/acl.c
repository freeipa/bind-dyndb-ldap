/*
 * Copyright (C) 2009-2014  bind-dyndb-ldap authors; see COPYING for license
 */

#include "config.h"

#include <isccfg/aclconf.h>
#include <isccfg/cfg.h>
#include <isccfg/grammar.h>

#include <isc/buffer.h>
#include <isc/log.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/types.h>
#include <isc/util.h>

#include <dns/fixedname.h>
#include <dns/forward.h>
#include <dns/log.h>
#include <dns/rdatatype.h>
#include <dns/ssu.h>
#include <dns/zone.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "acl.h"
#include "bindcfg.h"
#include "str.h"
#include "util.h"
#include "log.h"
#include "types.h"

/* Following definitions are necessary for context ("map" configuration object)
 * required during ACL parsing. */
static cfg_clausedef_t * empty_map_clausesets[] = {
	NULL
};

static cfg_type_t cfg_type_empty_map = {
	"empty_map", cfg_parse_map, cfg_print_map, cfg_doc_map, &cfg_rep_map,
	empty_map_clausesets
};

static cfg_type_t *empty_map_p = &cfg_type_empty_map;

const enum_txt_assoc_t acl_type_txts[] = {
	{ acl_type_query,	"query"		},
	{ acl_type_transfer,	"transfer"	},
	{ -1,			NULL		} /* end marker */
};

/*
 * The rest of the code in this file is either copied from, or based on code
 * from ISC BIND, file bin/named/config.c.
 */

#define MATCH(string_rep, return_val)					\
	do {								\
		if (!strcasecmp(str, string_rep)) {			\
			*value = return_val;				\
			return ISC_R_SUCCESS;				\
		}							\
	} while (0)

static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
get_mode(const cfg_obj_t *obj, bool *value)
{
	const char *str;

	if (!cfg_obj_istuple(obj)) {
		log_bug("tuple is expected");
		return ISC_R_UNEXPECTED;
	}
	obj = cfg_tuple_get(obj, "mode");
	if (!cfg_obj_isstring(obj)) {
		log_bug("mode is not defined");
		return ISC_R_UNEXPECTED;
	}
	str = cfg_obj_asstring(obj);

	MATCH("grant", true);
	MATCH("deny", false);

	log_bug("unsupported ACL mode '%s'", str);
	return ISC_R_NOTIMPLEMENTED;
}

static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
get_match_type(const cfg_obj_t *obj, unsigned int *value)
{
	const char *str;

	if (!cfg_obj_istuple(obj)) {
		log_bug("tuple is expected");
		return ISC_R_UNEXPECTED;
	}
	obj = cfg_tuple_get(obj, "matchtype");
	if (!cfg_obj_isstring(obj)) {
		log_bug("matchtype is not defined");
		return ISC_R_UNEXPECTED;
	}
	str = cfg_obj_asstring(obj);

	MATCH("name", dns_ssumatchtype_name);
	MATCH("subdomain", dns_ssumatchtype_subdomain);
	MATCH("zonesub", dns_ssumatchtype_subdomain);
	MATCH("wildcard", dns_ssumatchtype_wildcard);
	MATCH("self", dns_ssumatchtype_self);
	MATCH("selfsub", dns_ssumatchtype_selfsub);
	MATCH("selfwild", dns_ssumatchtype_selfwild);
	MATCH("ms-self", dns_ssumatchtype_selfms);
	MATCH("krb5-self", dns_ssumatchtype_selfkrb5);
	/* At least bind 9.11.5 or 9.12.3 is required for it
	 * as these match types are part of CVE-2018-5741 fixes */
	MATCH("ms-selfsub", dns_ssumatchtype_selfsubms);
	MATCH("krb5-selfsub", dns_ssumatchtype_selfsubkrb5);

	MATCH("ms-subdomain", dns_ssumatchtype_subdomainms);
	MATCH("krb5-subdomain", dns_ssumatchtype_subdomainkrb5);
	MATCH("tcp-self", dns_ssumatchtype_tcpself);
	MATCH("6to4-self", dns_ssumatchtype_6to4self);
	MATCH("external", dns_ssumatchtype_external);

	log_bug("unsupported match type '%s'", str);
	return ISC_R_NOTIMPLEMENTED;
}

static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
get_fixed_name(const cfg_obj_t *obj, const char *name, dns_fixedname_t *fname)
{
	isc_result_t result;
	isc_buffer_t buf;
	const char *str;
	size_t len;

	REQUIRE(fname != NULL);

	if (!cfg_obj_istuple(obj)) {
		log_bug("configuration object is not a tuple");
		return ISC_R_UNEXPECTED;
	}
	obj = cfg_tuple_get(obj, name);

	if (!cfg_obj_isstring(obj))
		return ISC_R_NOTFOUND;
	str = cfg_obj_asstring(obj);

	len = strlen(str);
	isc_buffer_init(&buf, (char *)str, len);

	/*
	 * Workaround for https://bugzilla.redhat.com/show_bug.cgi?id=728925
	 *
	 * ipa-server-install script could create SSU rules with
	 * double-dot-ending FQDNs. Silently "adjust" such wrong FQDNs.
	 */
	if (str[len - 1] == '.' && str[len - 2] == '.')
		isc_buffer_add(&buf, len - 1);
	else
		isc_buffer_add(&buf, len);

	result = dns_name_fromtext(dns_fixedname_initname(fname), &buf,
				   dns_rootname, false, NULL);
	if (result != ISC_R_SUCCESS)
		log_error("'%s' is not a valid name", str);

	return result;
}

static unsigned int ATTR_NONNULLS ATTR_CHECKRESULT
count_list_elements(const cfg_obj_t *list)
{
	const cfg_listelt_t *el;
	unsigned int ret = 0;

	for (el = cfg_list_first(list); el != NULL; el = cfg_list_next(el))
		ret++;

	return ret;
}

static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
get_types(isc_mem_t *mctx, const cfg_obj_t *obj, dns_rdatatype_t **typesp,
	  unsigned int *np)
{
	isc_result_t result = ISC_R_SUCCESS;
	unsigned int i;
	unsigned int n = 0;
	const cfg_listelt_t *el;
	dns_rdatatype_t *types = NULL;

	REQUIRE(obj != NULL);
	REQUIRE(typesp != NULL && *typesp == NULL);
	REQUIRE(np != NULL);

	obj = cfg_tuple_get(obj, "types");

	n = count_list_elements(obj);
	if (n > 0) {
		types = isc_mem_get(mctx, n * sizeof(dns_rdatatype_t));
	}
	i = 0;
	for (el = cfg_list_first(obj); el != NULL; el = cfg_list_next(el)) {
		const cfg_obj_t *typeobj;
		const char *str;
		isc_textregion_t r;

		INSIST(i < n);

		typeobj = cfg_listelt_value(el);
		str = cfg_obj_asstring(typeobj);
		DE_CONST(str, r.base);
		r.length = strlen(str);

		result = dns_rdatatype_fromtext(&types[i++], &r);
		if (result != ISC_R_SUCCESS) {
			log_error("'%s' is not a valid type", str);
			goto cleanup;
		}
	}
	INSIST(i == n);

	*typesp = types;
	*np = n;
	return result;

cleanup:
	SAFE_MEM_PUT(mctx, types, n * sizeof(dns_rdatatype_t));

	return result;
}

static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
bracket_str(isc_mem_t *mctx, const char *str, ld_string_t **bracket_strp)
{
	ld_string_t *tmp = NULL;
	isc_result_t result;

	CHECK(str_new(mctx, &tmp));
	CHECK(str_sprintf(tmp, "{ %s }", str));

	*bracket_strp = tmp;

	return ISC_R_SUCCESS;

cleanup:
	str_destroy(&tmp);
	return result;
}

isc_result_t
acl_configure_zone_ssutable(const char *policy_str, dns_zone_t *zone)
{
	isc_result_t result = ISC_R_SUCCESS;
	cfg_parser_t *parser = NULL;
	const cfg_listelt_t *el;
	cfg_obj_t *policy = NULL;
	dns_ssutable_t *table = NULL;
	ld_string_t *new_policy_str = NULL;
	isc_mem_t *mctx;

	REQUIRE(zone != NULL);

	mctx = dns_zone_getmctx(zone);

	if (policy_str == NULL)
		goto cleanup;

	CHECK(bracket_str(mctx, policy_str, &new_policy_str));

	CHECK(cfg_parser_create(mctx, dns_lctx, &parser));
	result = cfg_parse_strbuf(parser, str_buf(new_policy_str), &cfg_type_update_policy, &policy);

	if (result != ISC_R_SUCCESS) {
		dns_zone_log(zone, ISC_LOG_ERROR,
			     "failed to parse policy string");
		goto cleanup;
	}

	CHECK(dns_ssutable_create(mctx, &table));

	for (el = cfg_list_first(policy); el != NULL; el = cfg_list_next(el)) {
		const cfg_obj_t *stmt;
		bool grant;
		unsigned int match_type;
		dns_fixedname_t fname, fident;
		dns_rdatatype_t *types;
		unsigned int n;

		types = NULL;

		stmt = cfg_listelt_value(el);
		CHECK(get_mode(stmt, &grant));
		CHECK(get_match_type(stmt, &match_type));

		CHECK(get_fixed_name(stmt, "identity", &fident));

		/* Use zone name for 'zonesub' match type */
		result = get_fixed_name(stmt, "name", &fname);
		if (result == ISC_R_NOTFOUND &&
		    match_type == dns_ssumatchtype_subdomain) {
			CHECK(dns_name_copy(dns_zone_getorigin(zone),
					    dns_fixedname_initname(&fname),
					    &fname.buffer));
		}
		else if (result != ISC_R_SUCCESS)
			goto cleanup;

		CHECK(get_types(mctx, stmt, &types, &n));

		if (match_type == dns_ssumatchtype_wildcard &&
		    !dns_name_iswildcard(dns_fixedname_name(&fname))) {
			char name[DNS_NAME_FORMATSIZE];
			dns_name_format(dns_fixedname_name(&fname), name,
					DNS_NAME_FORMATSIZE);
			dns_zone_log(zone, ISC_LOG_ERROR,
				     "invalid update policy: "
				     "name '%s' is expected to be a wildcard",
				     name);
			CLEANUP_WITH(DNS_R_BADNAME);
		}

		result = dns_ssutable_addrule(table, grant,
					      dns_fixedname_name(&fident),
					      match_type,
					      dns_fixedname_name(&fname),
					      n, types);

		SAFE_MEM_PUT(mctx, types, n * sizeof(dns_rdatatype_t));
		if (result != ISC_R_SUCCESS)
			goto cleanup;

	}

 cleanup:
	if (result == ISC_R_SUCCESS)
		dns_zone_setssutable(zone, table);

	str_destroy(&new_policy_str);
	if (policy != NULL)
		cfg_obj_destroy(parser, &policy);
	if (parser != NULL)
		cfg_parser_destroy(&parser);
	if (table != NULL)
		dns_ssutable_detach(&table);

	return result;
}

isc_result_t
acl_from_ldap(isc_mem_t *mctx, const char *aclstr, acl_type_t type,
	      dns_acl_t **aclp)
{
	dns_acl_t *acl = NULL;
	isc_result_t result;
	ld_string_t *new_aclstr = NULL;
	cfg_parser_t *parser = NULL;
	cfg_obj_t *aclobj = NULL;
	cfg_aclconfctx_t *aclctx = NULL;
	/* ACL parser requires "configuration context". The parser looks for
	 * undefined names in this context. We create empty context ("map" type),
	 * i.e. only built-in named lists "any", "none" etc. are supported. */
	cfg_obj_t *cctx = NULL;
	cfg_parser_t *parser_empty = NULL;

	REQUIRE(aclp != NULL && *aclp == NULL);

	CHECK(bracket_str(mctx, aclstr, &new_aclstr));

	CHECK(cfg_parser_create(mctx, dns_lctx, &parser));
	CHECK(cfg_parser_create(mctx, dns_lctx, &parser_empty));
	CHECK(cfg_parse_strbuf(parser_empty, "{}", &empty_map_p, &cctx));

	switch (type) {
	case acl_type_query:
		CHECK(cfg_parse_strbuf(parser, str_buf(new_aclstr), &cfg_type_allow_query,
			    &aclobj));
		break;
	case acl_type_transfer:
		CHECK(cfg_parse_strbuf(parser, str_buf(new_aclstr), &cfg_type_allow_transfer,
			    &aclobj));
		break;
	default:
		/* This is a bug */
		REQUIRE("Unhandled ACL type in acl_from_ldap" == NULL);
	}

	CHECK(cfg_aclconfctx_create(mctx, &aclctx));
	CHECK(cfg_acl_fromconfig(aclobj, cctx, dns_lctx, aclctx, mctx, 0, &acl));

	*aclp = acl;
	result = ISC_R_SUCCESS;

cleanup:
	if (result != ISC_R_SUCCESS)
		log_error_r("%s ACL parsing failed: '%s'",
			    type == acl_type_query ? "query" : "transfer",
			    aclstr);

	if (aclctx != NULL)
		cfg_aclconfctx_detach(&aclctx);
	if (aclobj != NULL)
		cfg_obj_destroy(parser, &aclobj);
	if (parser != NULL)
		cfg_parser_destroy(&parser);
	if (cctx != NULL)
		cfg_obj_destroy(parser_empty, &cctx);
	if (parser_empty != NULL)
		cfg_parser_destroy(&parser_empty);
	str_destroy(&new_aclstr);

	return result;
}
