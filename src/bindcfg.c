/*
 * Copyright (C) 2009-2016  bind-dyndb-ldap authors; see COPYING for license
 *
 * Utilities for BIND configuration parsers.
 */

#include "config.h"

#include <isc/util.h>
#include <isccfg/grammar.h>
#include <isccfg/namedconf.h>

#include <util.h>

#include "bindcfg.h"

cfg_type_t *cfg_type_update_policy;
cfg_type_t *cfg_type_allow_query;
cfg_type_t *cfg_type_allow_transfer;
cfg_type_t *cfg_type_forwarders;

static cfg_type_t * ATTR_NONNULLS ATTR_CHECKRESULT
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

static cfg_type_t * ATTR_NONNULLS ATTR_CHECKRESULT
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

static cfg_type_t * ATTR_NONNULLS ATTR_CHECKRESULT
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

void
cfg_init_types(void)
{
	cfg_type_t *zoneopts;

	zoneopts = &cfg_type_namedconf;
	zoneopts = get_type_from_clause_array(zoneopts, "zone");
	zoneopts = get_type_from_tuplefield(zoneopts, "options");

	cfg_type_update_policy = get_type_from_clause_array(zoneopts, "update-policy");
	cfg_type_allow_query = get_type_from_clause_array(zoneopts, "allow-query");
	cfg_type_allow_transfer = get_type_from_clause_array(zoneopts, "allow-transfer");
	cfg_type_forwarders = get_type_from_clause_array(zoneopts, "forwarders");
}

isc_result_t
cfg_parse_strbuf(cfg_parser_t *parser, const char *string, cfg_type_t **type,
		 cfg_obj_t **objp)
{
	isc_result_t result;
	isc_buffer_t buffer;
	size_t string_len;
	cfg_obj_t *ret = NULL;

	REQUIRE(parser != NULL);
	REQUIRE(string != NULL);
	REQUIRE(objp != NULL && *objp == NULL);

	string_len = strlen(string);
	isc_buffer_init(&buffer, (char *)string, string_len);
	isc_buffer_add(&buffer, string_len);

	result = cfg_parse_buffer(parser, &buffer, NULL, 0, *type, 0, &ret);

	if (result == ISC_R_SUCCESS)
		*objp = ret;

	return result;
}
