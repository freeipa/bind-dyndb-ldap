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

/*
 * For portions of the code (see bellow):
 *
 * Copyright (C) 2004-2008  Internet Systems Consortium, Inc. ("ISC")
 * Copyright (C) 2001-2003  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include <isccfg/aclconf.h>
#include <isccfg/cfg.h>
#include <isccfg/namedconf.h>
#include <isccfg/grammar.h>

#include <isc/buffer.h>
#include <isc/log.h>
#include <isc/mem.h>
#include <isc/once.h>
#include <isc/result.h>
#include <isc/util.h>

#include <dns/fixedname.h>
#include <dns/log.h>
#include <dns/rdatatype.h>
#include <dns/ssu.h>
#include <dns/zone.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "acl.h"
#include "str.h"
#include "util.h"
#include "log.h"

static isc_once_t once = ISC_ONCE_INIT;
static cfg_type_t *update_policy;
static cfg_type_t *allow_query;
static cfg_type_t *allow_transfer;
static cfg_type_t *forwarders;

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

static cfg_type_t *
get_type_from_tuplefield(const cfg_type_t *cfg_type, const char *name)
{
	cfg_type_t *ret = NULL;
	const cfg_tuplefielddef_t *field;

	REQUIRE(cfg_type != NULL && cfg_type->of != NULL);
	REQUIRE(name != NULL);

	field = (cfg_tuplefielddef_t *)cfg_type->of;
	for (int i = 0; field[i].name != NULL; i++) {
		if (!strcmp(field[i].name, name)) {
			ret = field[i].type;
			break;
		}
	}

	return ret;
}

static cfg_type_t *
get_type_from_clause(const cfg_clausedef_t *clause, const char *name)
{
	cfg_type_t *ret = NULL;

	REQUIRE(clause != NULL);
	REQUIRE(name != NULL);

	for (int i = 0; clause[i].name != NULL; i++) {
		if (!strcmp(clause[i].name, name)) {
			ret = clause[i].type;
			break;
		}
	}

	return ret;
}

static cfg_type_t *
get_type_from_clause_array(const cfg_type_t *cfg_type, const char *name)
{
	cfg_type_t *ret = NULL;
	const cfg_clausedef_t **clauses;

	REQUIRE(cfg_type != NULL && cfg_type->of != NULL);
	REQUIRE(name != NULL);

	clauses = (const cfg_clausedef_t **)cfg_type->of;
	for (int i = 0; clauses[i] != NULL; i++) {
		ret = get_type_from_clause(clauses[i], name);
		if (ret != NULL)
			break;
	}

	return ret;
}

static void
init_cfgtypes(void)
{
	cfg_type_t *zoneopts;

	zoneopts = &cfg_type_namedconf;
	zoneopts = get_type_from_clause_array(zoneopts, "zone");
	zoneopts = get_type_from_tuplefield(zoneopts, "options");

	update_policy = get_type_from_clause_array(zoneopts, "update-policy");
	allow_query = get_type_from_clause_array(zoneopts, "allow-query");
	allow_transfer = get_type_from_clause_array(zoneopts, "allow-transfer");
	forwarders = get_type_from_clause_array(zoneopts, "forwarders");
}

static isc_result_t
parse(cfg_parser_t *parser, const char *string, cfg_type_t **type,
      cfg_obj_t **objp)
{
	isc_result_t result;
	isc_buffer_t buffer;
	size_t string_len;
	cfg_obj_t *ret = NULL;

	REQUIRE(parser != NULL);
	REQUIRE(string != NULL);
	REQUIRE(objp != NULL && *objp == NULL);

	RUNTIME_CHECK(isc_once_do(&once, init_cfgtypes) == ISC_R_SUCCESS);

	string_len = strlen(string);
	isc_buffer_init(&buffer, string, string_len);
	isc_buffer_add(&buffer, string_len);

	result = cfg_parse_buffer(parser, &buffer, *type, &ret);

	if (result == ISC_R_SUCCESS)
		*objp = ret;

	return result;
}

/*
 * The rest of the code in this file is either copied from, or based on code
 * from ISC BIND, file bin/named/config.c.
 */

#define MATCH(string_rep, return_val)					\
	do {								\
		if (!strcasecmp(str, string_rep)) {			\
			return return_val;				\
		}							\
	} while (0)

static isc_boolean_t
get_mode(const cfg_obj_t *obj)
{
	const char *str;

	obj = cfg_tuple_get(obj, "mode");
	str = cfg_obj_asstring(obj);

	MATCH("grant", ISC_TRUE);
	MATCH("deny", ISC_FALSE);

	INSIST(0);
	/* Not reached. */
	return ISC_FALSE;
}

static unsigned int
get_match_type(const cfg_obj_t *obj)
{
	const char *str;

	obj = cfg_tuple_get(obj, "matchtype");
	str = cfg_obj_asstring(obj);

	MATCH("name", DNS_SSUMATCHTYPE_NAME);
	MATCH("subdomain", DNS_SSUMATCHTYPE_SUBDOMAIN);
	MATCH("zonesub", DNS_SSUMATCHTYPE_SUBDOMAIN);
	MATCH("wildcard", DNS_SSUMATCHTYPE_WILDCARD);
	MATCH("self", DNS_SSUMATCHTYPE_SELF);
#if defined(DNS_SSUMATCHTYPE_SELFSUB) && defined(DNS_SSUMATCHTYPE_SELFWILD)
	MATCH("selfsub", DNS_SSUMATCHTYPE_SELFSUB);
	MATCH("selfwild", DNS_SSUMATCHTYPE_SELFWILD);
#endif
#ifdef DNS_SSUMATCHTYPE_SELFMS
	MATCH("ms-self", DNS_SSUMATCHTYPE_SELFMS);
#endif
#ifdef DNS_SSUMATCHTYPE_SELFKRB5
	MATCH("krb5-self", DNS_SSUMATCHTYPE_SELFKRB5);
#endif
#ifdef DNS_SSUMATCHTYPE_SUBDOMAINMS
	MATCH("ms-subdomain", DNS_SSUMATCHTYPE_SUBDOMAINMS);
#endif
#ifdef DNS_SSUMATCHTYPE_SUBDOMAINKRB5
	MATCH("krb5-subdomain", DNS_SSUMATCHTYPE_SUBDOMAINKRB5);
#endif
#if defined(DNS_SSUMATCHTYPE_TCPSELF) && defined(DNS_SSUMATCHTYPE_6TO4SELF)
	MATCH("tcp-self", DNS_SSUMATCHTYPE_TCPSELF);
	MATCH("6to4-self", DNS_SSUMATCHTYPE_6TO4SELF);
#endif

	INSIST(0);
	/* Not reached. */
	return DNS_SSUMATCHTYPE_NAME;
}

static isc_result_t
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
	isc_buffer_init(&buf, str, len);

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

	dns_fixedname_init(fname);

	result = dns_name_fromtext(dns_fixedname_name(fname), &buf,
				   dns_rootname, ISC_FALSE, NULL);
	if (result != ISC_R_SUCCESS)
		log_error("'%s' is not a valid name", str);

	return result;
}

static unsigned int
count_list_elements(const cfg_obj_t *list)
{
	const cfg_listelt_t *el;
	unsigned int ret = 0;

	for (el = cfg_list_first(list); el != NULL; el = cfg_list_next(el))
		ret++;

	return ret;
}

static isc_result_t
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
	if (n > 0)
		CHECKED_MEM_GET(mctx, types, n * sizeof(dns_rdatatype_t));

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

static isc_result_t
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

static isc_result_t
semicolon_bracket_str(isc_mem_t *mctx, const char *str, ld_string_t **bracket_strp)
{
	ld_string_t *tmp = NULL;
	isc_result_t result;

	CHECK(str_new(mctx, &tmp));
	CHECK(str_sprintf(tmp, "{ %s; }", str));

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
	result = parse(parser, str_buf(new_policy_str), &update_policy, &policy);

	if (result != ISC_R_SUCCESS) {
		dns_zone_log(zone, ISC_LOG_ERROR,
			     "failed to parse policy string");
		goto cleanup;
	}

	CHECK(dns_ssutable_create(mctx, &table));

	for (el = cfg_list_first(policy); el != NULL; el = cfg_list_next(el)) {
		const cfg_obj_t *stmt;
		isc_boolean_t grant;
		unsigned int match_type;
		dns_fixedname_t fname, fident;
		dns_rdatatype_t *types;
		unsigned int n;

		types = NULL;

		stmt = cfg_listelt_value(el);
		grant = get_mode(stmt);
		match_type = get_match_type(stmt);

		CHECK(get_fixed_name(stmt, "identity", &fident));

		/* Use zone name for 'zonesub' match type */
		result = get_fixed_name(stmt, "name", &fname);
		if (result == ISC_R_NOTFOUND &&
		    match_type == DNS_SSUMATCHTYPE_SUBDOMAIN) {
			dns_fixedname_init(&fname);
			CHECK(dns_name_copy(dns_zone_getorigin(zone),
					    dns_fixedname_name(&fname),
					    &fname.buffer));
		}
		else if (result != ISC_R_SUCCESS)
			goto cleanup;

		CHECK(get_types(mctx, stmt, &types, &n));

		if (match_type == DNS_SSUMATCHTYPE_WILDCARD &&
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
	CHECK(parse(parser_empty, "{}", &empty_map_p, &cctx));

	switch (type) {
	case acl_type_query:
		CHECK(parse(parser, str_buf(new_aclstr), &allow_query,
			    &aclobj));
		break;
	case acl_type_transfer:
		CHECK(parse(parser, str_buf(new_aclstr), &allow_transfer,
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


/**
 * Parse nameserver IP address with or without port specified in BIND9 syntax.
 * IPv4 and IPv6 addresses are supported, see examples.
 *
 * @param[in] forwarder_str String with IP address and optionally port.
 * @param[in] mctx Memory for allocating temporary and sa structure.
 * @param[out] sa Socket address structure.
 *
 * @return Pointer to newly allocated isc_sockaddr_t structure.
 *
 * @example
 * "192.168.0.100" -> { address:192.168.0.100, port:53 }
 * "192.168.0.100 port 553" -> { address:192.168.0.100, port:553 }
 * "0102:0304:0506:0708:090A:0B0C:0D0E:0FAA" ->
 * 		{ address:0102:0304:0506:0708:090A:0B0C:0D0E:0FAA, port:53 }
 * "0102:0304:0506:0708:090A:0B0C:0D0E:0FAA port 553" ->
 * 		{ address:0102:0304:0506:0708:090A:0B0C:0D0E:0FAA, port:553 }
 *
 */
isc_result_t
acl_parse_forwarder(const char *forwarder_str, isc_mem_t *mctx, isc_sockaddr_t **sa)
{
	isc_result_t result = ISC_R_SUCCESS;
	cfg_parser_t *parser = NULL;

	cfg_obj_t *forwarders_cfg = NULL;
	ld_string_t *new_forwarder_str = NULL;
	const cfg_obj_t *faddresses;
	const cfg_listelt_t *element;

	in_port_t port = 53;

	REQUIRE(forwarder_str != NULL);
	REQUIRE(sa != NULL && *sa == NULL);

	/* add semicolon and brackets as necessary for parser */
	if (!index(forwarder_str, ';'))
		CHECK(semicolon_bracket_str(mctx, forwarder_str, &new_forwarder_str));
	else
		CHECK(bracket_str(mctx, forwarder_str, &new_forwarder_str));

	CHECK(cfg_parser_create(mctx, dns_lctx, &parser));
	CHECK(parse(parser, str_buf(new_forwarder_str), &forwarders, &forwarders_cfg));

	faddresses = cfg_tuple_get(forwarders_cfg, "addresses");
	element = cfg_list_first(faddresses);
	if (!element) {
		result = ISC_R_FAILURE;
		goto cleanup;
	}

	const cfg_obj_t *forwarder = cfg_listelt_value(element);
	CHECKED_MEM_GET_PTR(mctx, *sa);
	**sa = *cfg_obj_assockaddr(forwarder);
	if (isc_sockaddr_getport(*sa) == 0)
		isc_sockaddr_setport(*sa, port);

cleanup:
	if (forwarders_cfg != NULL)
		cfg_obj_destroy(parser, &forwarders_cfg);
	if (parser != NULL)
		cfg_parser_destroy(&parser);
	str_destroy(&new_forwarder_str);
	return result;
}
