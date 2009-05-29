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

#include "str.h"
#include "util.h"
#include "log.h"

static cfg_type_t *update_policy;

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

static cfg_type_t *
get_update_policy_type(void)
{
	cfg_type_t *type;

	type = &cfg_type_namedconf;
	type = get_type_from_clause_array(type, "zone");
	type = get_type_from_tuplefield(type, "options");
	type = get_type_from_clause_array(type, "update-policy");
	//type = (cfg_type_t *)type->of;

	return type;
}

static isc_result_t
parse(cfg_parser_t *parser, const char *string, cfg_obj_t **objp)
{
	isc_result_t result;
	isc_buffer_t buffer;
	size_t string_len;
	cfg_obj_t *ret = NULL;

	REQUIRE(parser != NULL);
	REQUIRE(string != NULL);
	REQUIRE(objp != NULL && *objp == NULL);

	/* FIXME: Only do this once. */
	update_policy = get_update_policy_type();

	string_len = strlen(string);
	isc_buffer_init(&buffer, string, string_len);
	isc_buffer_add(&buffer, string_len);

	result = cfg_parse_buffer(parser, &buffer, update_policy, &ret);

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

	REQUIRE(fname != NULL);

	obj = cfg_tuple_get(obj, name);
	str = cfg_obj_asstring(obj);

	isc_buffer_init(&buf, str, strlen(str));
	isc_buffer_add(&buf, strlen(str));

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
	isc_result_t result;
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

	CHECK(str_new(mctx, &new_policy_str));
	CHECK(str_sprintf(new_policy_str, "{ %s }", policy_str));

	CHECK(cfg_parser_create(mctx, dns_lctx, &parser));
	result = parse(parser, str_buf(new_policy_str), &policy);

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
		CHECK(get_fixed_name(stmt, "name", &fname));
		CHECK(get_types(mctx, stmt, &types, &n));

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
