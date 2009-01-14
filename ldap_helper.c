/* Authors: Martin Nagy <mnagy@redhat.com>
 *
 * Copyright (C) 2008  Red Hat
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

#include <dns/result.h>

#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/util.h>

#define LDAP_DEPRECATED 1
#include <ldap.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>

#include "ldap_helper.h"
#include "log.h"
#include "semaphore.h"
#include "settings.h"
#include "str.h"
#include "util.h"


/*
 * LDAP related typedefs and structs.
 */

typedef struct ldap_auth_pair	ldap_auth_pair_t;
typedef struct settings		settings_t;

/* Authentication method. */
typedef enum ldap_auth {
	AUTH_INVALID = 0,
	AUTH_NONE,
	AUTH_SIMPLE,
	AUTH_SASL,
} ldap_auth_t;

struct ldap_auth_pair {
	enum ldap_auth value;	/* Value actually passed to ldap_bind(). */
	char *name;	/* String representation used in configuration file */
};

/* These are typedefed in ldap_helper.h */
struct ldap_db {
	isc_mem_t		*mctx;
	/* List of LDAP connections. */
	semaphore_t		conn_semaphore;
	LIST(ldap_instance_t)	conn_list;
	/* Settings. */
	ld_string_t		*host;
	ld_string_t		*base;
	unsigned int		connections;
	ldap_auth_t		auth_method;
};

struct ldap_instance {
	ldap_db_t		*database;
	isc_mutex_t		lock;
	LINK(ldap_instance_t)	link;
	LDAP			*ldap_handle;
	LDAPMessage		*result;
	ld_string_t		*query_string;
	ld_string_t		*base;
};

/*
 * Constants.
 */

/* Supported authentication types. */
const ldap_auth_pair_t supported_ldap_auth[] = {
	{ AUTH_NONE,	"none"		},
#if 0
	{ AUTH_SIMPLE,	"simple"	},
	{ AUTH_SASL,	"sasl"		},
#endif
	{ AUTH_INVALID, NULL		},
};

/*
 * Forward declarations.
 */

static isc_result_t new_ldap_instance(ldap_db_t *ldap_db,
		ldap_instance_t **ldap_instp);
static void destroy_ldap_instance(ldap_instance_t **ldap_instp);
static ldap_instance_t * get_connection(ldap_db_t *ldap_db);
static void put_connection(ldap_instance_t *ldap_inst);
static isc_result_t ldap_connect(ldap_instance_t *ldap_inst);
static isc_result_t ldap_query(ldap_instance_t *ldap_inst, int scope,
		char **attrs, int attrsonly, const char *filter, ...);


isc_result_t
new_ldap_db(isc_mem_t *mctx, ldap_db_t **ldap_dbp, const char * const *argv)
{
	unsigned int i;
	isc_result_t result;
	ldap_db_t *ldap_db;
	ldap_instance_t *ldap_inst;
	setting_t ldap_settings[] = {
		{ "host",	 no_default_string, NULL },
		{ "connections", default_uint(1),   NULL },
		{ "base",	 no_default_string, NULL },
		end_of_settings
	};

	REQUIRE(mctx != NULL);
	REQUIRE(ldap_dbp != NULL && *ldap_dbp == NULL);

	ldap_db = isc_mem_get(mctx, sizeof(ldap_db_t));
	if (ldap_db == NULL)
		return ISC_R_NOMEMORY;

	ZERO_PTR(ldap_db, ldap_db_t);
	memset(ldap_db, 0, sizeof(ldap_db_t));

	isc_mem_attach(mctx, &ldap_db->mctx);

	INIT_LIST(ldap_db->conn_list);
	ldap_db->auth_method = AUTH_NONE;	/* todo: should be in settings */

	CHECK(str_new(ldap_db->mctx, &ldap_db->host));
	CHECK(str_new(ldap_db->mctx, &ldap_db->base));

	ldap_settings[0].target = ldap_db->host;
	ldap_settings[1].target = &ldap_db->connections;
	ldap_settings[2].target = ldap_db->base;

	CHECK(set_settings(ldap_settings, argv));
	if (ldap_db->connections < 1) {
		log_error("at least one connection is required");
		result = ISC_R_FAILURE;
		goto cleanup;
	}

	CHECK(semaphore_init(&ldap_db->conn_semaphore, ldap_db->connections));

	for (i = 0; i < ldap_db->connections; i++) {
		ldap_inst = NULL;
		CHECK(new_ldap_instance(ldap_db, &ldap_inst));
		ldap_connect(ldap_inst);
		APPEND(ldap_db->conn_list, ldap_inst, link);
	}

	*ldap_dbp = ldap_db;

	return ISC_R_SUCCESS;

cleanup:
	destroy_ldap_db(&ldap_db);

	return result;
}

void
destroy_ldap_db(ldap_db_t **ldap_dbp)
{
	ldap_db_t *ldap_db;
	ldap_instance_t *elem;
	ldap_instance_t *next;

	REQUIRE(ldap_dbp != NULL && *ldap_dbp != NULL);

	ldap_db = *ldap_dbp;

	elem = HEAD(ldap_db->conn_list);
	while (elem != NULL) {
		next = NEXT(elem, link);
		UNLINK(ldap_db->conn_list, elem, link);
		destroy_ldap_instance(&elem);
		elem = next;
	}

	str_destroy(&ldap_db->host);
	str_destroy(&ldap_db->base);

	semaphore_destroy(&ldap_db->conn_semaphore);
	isc_mem_putanddetach(&ldap_db->mctx, ldap_db, sizeof(ldap_db_t));

	*ldap_dbp = NULL;
}

static isc_result_t
new_ldap_instance(ldap_db_t *ldap_db, ldap_instance_t **ldap_instp)
{
	isc_result_t result;
	ldap_instance_t *ldap_inst;

	REQUIRE(ldap_db != NULL);
	REQUIRE(ldap_instp != NULL && *ldap_instp == NULL);

	ldap_inst = isc_mem_get(ldap_db->mctx, sizeof(ldap_instance_t));
	if (ldap_inst == NULL)
		return ISC_R_NOMEMORY;

	ZERO_PTR(ldap_inst, ldap_instance_t);
	memset(ldap_inst, 0, sizeof(ldap_instance_t));

	ldap_inst->database = ldap_db;
	INIT_LINK(ldap_inst, link);
	result = isc_mutex_init(&ldap_inst->lock);
	if (result != ISC_R_SUCCESS) {
		isc_mem_put(ldap_db->mctx, ldap_db, sizeof(ldap_instance_t));
		return result;
	}

	CHECK(str_new(ldap_db->mctx, &ldap_inst->query_string));
	CHECK(str_new(ldap_db->mctx, &ldap_inst->base));

	*ldap_instp = ldap_inst;

	return ISC_R_SUCCESS;

cleanup:
	destroy_ldap_instance(&ldap_inst);

	return result;
}

static void
destroy_ldap_instance(ldap_instance_t **ldap_instp)
{
	ldap_instance_t *ldap_inst;

	REQUIRE(ldap_instp != NULL && *ldap_instp != NULL);

	ldap_inst = *ldap_instp;
	DESTROYLOCK(&ldap_inst->lock);
	if (ldap_inst->ldap_handle != NULL)
		ldap_unbind_ext_s(ldap_inst->ldap_handle, NULL, NULL);

	str_destroy(&ldap_inst->query_string);
	str_destroy(&ldap_inst->base);

	isc_mem_put(ldap_inst->database->mctx, *ldap_instp, sizeof(ldap_instance_t));
	*ldap_instp = NULL;
}

void
get_zone_list(ldap_db_t *ldap_db)
{
	ldap_instance_t *ldap_inst;
	int i;
	char *a;
	LDAPMessage *e;
	BerElement *ber;
	char **vals;
	char *attrs[] = {
		"idnsName", "idnsSOAmName", "idnsSOArName", "idnsSOAserial",
		"idnsSOArefresh", "idnsSOAretry", "idnsSOAexpire",
		"idnsSOAminimum", NULL
	};

	ldap_inst = get_connection(ldap_db);

	ldap_query(ldap_inst, LDAP_SCOPE_SUBTREE, attrs, 0,
		   "(objectClass=idnsZone)");

	log_error("list of ldap values:");
	for (e = ldap_first_entry(ldap_inst->ldap_handle, ldap_inst->result);
	     e != NULL;
	     e = ldap_next_entry(ldap_inst->ldap_handle, e)) {
		for (a = ldap_first_attribute(ldap_inst->ldap_handle, e, &ber);
		     a != NULL;
		     a = ldap_next_attribute(ldap_inst->ldap_handle, e, ber)) {
			vals = ldap_get_values(ldap_inst->ldap_handle, e, a);
			if (vals == NULL)
				continue;
			for (i = 0; vals[i] != NULL; i++) {
				log_error("attribute %s: %s", a, vals[i]);
			}
			ldap_value_free(vals);
		}
		ber_free(ber, 0);
	}
	log_error("end of ldap values");

	put_connection(ldap_inst);
}

static ldap_instance_t *
get_connection(ldap_db_t *ldap_db)
{
	ldap_instance_t *ldap_inst;

	semaphore_wait(&ldap_db->conn_semaphore);
	ldap_inst = HEAD(ldap_db->conn_list);
	while (ldap_inst != NULL) {
		if (isc_mutex_trylock(&ldap_inst->lock) == ISC_R_SUCCESS)
			break;
		ldap_inst = NEXT(ldap_inst, link);
	}

	RUNTIME_CHECK(ldap_inst != NULL);

	/* todo: find a clever way to not really require this */
	str_copy(ldap_inst->base, ldap_db->base);

	return ldap_inst;
}

static void
put_connection(ldap_instance_t *ldap_inst)
{
	if (ldap_inst->result != NULL) {
		ldap_msgfree(ldap_inst->result);
		ldap_inst->result = NULL;
	}

	UNLOCK(&ldap_inst->lock);
	semaphore_signal(&ldap_inst->database->conn_semaphore);
}


static isc_result_t
ldap_query(ldap_instance_t *ldap_inst, int scope, char **attrs,
	   int attrsonly, const char *filter, ...)
{
	va_list ap;
	int ret;

	va_start(ap, filter);
	str_vsprintf(ldap_inst->query_string, filter, ap);
	va_end(ap);

	log_error("Querying '%s' with '%s'", str_buf(ldap_inst->base),
			str_buf(ldap_inst->query_string));

	ret = ldap_search_ext_s(ldap_inst->ldap_handle, str_buf(ldap_inst->base),
				scope, str_buf(ldap_inst->query_string), attrs,
				attrsonly, NULL, NULL, NULL, LDAP_NO_LIMIT,
				&ldap_inst->result);

	log_error("Result: %d", ldap_count_entries(ldap_inst->ldap_handle,
				ldap_inst->result));

	return ISC_R_SUCCESS;
}

/*
 * Static methods local to this unit ABRAKA
 */
static isc_result_t
ldap_connect(ldap_instance_t *ldap_inst)
{
	LDAP *ld;
	int ret;
	ldap_db_t *ldap_db;

	REQUIRE(ldap_inst != NULL);

	ldap_db = ldap_inst->database;

	/* XXX: port should be overridable */
	ret = ldap_initialize(&ld, str_buf(ldap_db->host));
	if (ret != LDAP_SUCCESS) {
		log_error("LDAP initialization failed: %s", ldap_err2string(ret));
		goto cleanup;
	}

	/*
	ret = ldap_set_option(ld, LDAP_OPT_TIMELIMIT, (void *)&ldap_db->timeout);
	if (ret != LDAP_OPT_SUCCESS) {
		log_error("Failed to set timeout: %s", ldap_err2string(ret));
		goto cleanup;
	}
	*/

	log_debug(2, "Trying to make an LDAP connection to %s", str_buf(ldap_db->host));

	switch (ldap_db->auth_method) {
	case AUTH_NONE:
		ret = ldap_simple_bind_s(ld, NULL, NULL);
		break;
	case AUTH_SIMPLE:
		fatal_error("Simple auth not supported yet.");
		break;
	case AUTH_SASL:
		fatal_error("SASL auth not supported yet.");
		break;
	default:
		fatal_error("Bug in ldap_connect(): unsupported authentication mechanism");
		return ISC_R_UNEXPECTED;
	}

	if (ret != LDAP_SUCCESS) {
		log_error("Bind to LDAP server failed: %s", ldap_err2string(ret));
		goto cleanup;
	}

	ldap_inst->ldap_handle = ld;

	return ISC_R_SUCCESS;

cleanup:

	if (ld != NULL)
		ldap_unbind_ext_s(ld, NULL, NULL);

	return ISC_R_FAILURE;
}
