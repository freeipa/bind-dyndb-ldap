/* Authors: Martin Nagy <mnagy@redhat.com>
 *          Adam Tkac <atkac@redhat.com>
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

#include <dns/rdata.h>
#include <dns/rdataclass.h>
#include <dns/rdatalist.h>
#include <dns/rdatatype.h>
#include <dns/result.h>
#include <dns/ttl.h>

#include <isc/buffer.h>
#include <isc/lex.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/region.h>
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
	ld_string_t		*query_string;
	ld_string_t		*base;

	LDAP			*handle;
	LDAPMessage		*result;
	LDAPMessage		*entry;
	BerElement		*ber;
	char			*attribute;
	char			**values;
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

static const LDAPMessage *next_entry(ldap_instance_t *inst);
static const char *next_attribute(ldap_instance_t *inst);
static const char *get_attribute(ldap_instance_t *inst);
static char **get_values(ldap_instance_t *inst);

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

	ZERO_PTR(ldap_db);
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

	ZERO_PTR(ldap_inst);
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
	if (ldap_inst->handle != NULL)
		ldap_unbind_ext_s(ldap_inst->handle, NULL, NULL);

	str_destroy(&ldap_inst->query_string);
	str_destroy(&ldap_inst->base);

	isc_mem_put(ldap_inst->database->mctx, *ldap_instp, sizeof(ldap_instance_t));
	*ldap_instp = NULL;
}

isc_result_t
ldapdb_rdatalist_findrdatatype(ldapdb_rdatalist_t *rdatalist,
			       dns_rdatatype_t rdtype,
			       dns_rdatalist_t **rdlistp)
{
	dns_rdatalist_t *rdlist;

	REQUIRE(rdatalist != NULL);
	REQUIRE(rdlistp != NULL && *rdlistp == NULL);

	rdlist = HEAD(*rdatalist);
	while (rdlist != NULL && rdlist->type != rdtype) {
		rdlist = NEXT(rdlist, link);
	}

	*rdlistp = rdlist;

	return (rdlist == NULL) ? ISC_R_NOTFOUND : ISC_R_SUCCESS;
}

void
ldapdb_rdatalist_destroy(isc_mem_t *mctx, ldapdb_rdatalist_t *rdatalist)
{
	dns_rdata_t *rdata;
	dns_rdatalist_t *rdlist;
	isc_region_t r;

	REQUIRE(rdatalist != NULL);

	while (!EMPTY(*rdatalist)) {
		rdlist = HEAD(*rdatalist);
		while (!EMPTY(rdlist->rdata)) {
			rdata = HEAD(rdlist->rdata);
			UNLINK(rdlist->rdata, rdata, link);
			dns_rdata_toregion(rdata, &r);
			isc_mem_put(mctx, r.base, r.length);
			isc_mem_put(mctx, rdata, sizeof(*rdata));
		}
		UNLINK(*rdatalist, rdlist, link);
		isc_mem_put(mctx, rdlist, sizeof(*rdlist));
	}
}

isc_result_t
ldapdb_rdatalist_get(isc_mem_t *mctx, dns_name_t *name,
		     ldapdb_rdatalist_t *rdatalist)
{

	/* Max type length definitions, from lib/dns/master.c */
	#define MINTSIZ (65535 - 12 - 1 - 2 - 2 - 4 - 2)
	#define TOKENSIZ (8*1024)

	isc_lex_t *lex = NULL;
	isc_result_t result;
	isc_buffer_t target, lexbuffer;
	unsigned char *targetmem;
	isc_region_t rdatamem;
	dns_rdataclass_t rdclass;
	dns_rdatatype_t rdtype;
	isc_textregion_t rdtype_text, rdclass_text, ttl_text, rdata_text;
	dns_ttl_t ttl;
	isc_boolean_t seen_error = ISC_FALSE;
	dns_rdata_t *rdata;
	dns_rdatalist_t *rdlist = NULL;

	REQUIRE(name != NULL);
	REQUIRE(rdatalist != NULL);

	/*
	 * Get info from ldap - name, type, class, TTL + value. Try avoid
	 * ENOMEM as much as possible, if nothing found return ISC_R_NOTFOUND
	 */

	result = isc_lex_create(mctx, TOKENSIZ, &lex);
	if (result != ISC_R_SUCCESS)
		return result;

	targetmem = isc_mem_get(mctx, MINTSIZ);
	if (targetmem == NULL) {
		result = ISC_R_NOMEMORY;
		goto cleanup;
	}

	INIT_LIST(*rdatalist);

	for (;0;) {
		/*
		 * Note: if rdclass_text and rdtype_text are ttl_text are allocated
		 * free() them correctly before break and before next iteration!
		 */
		rdclass_text.base = "in";
		rdclass_text.length = strlen(rdclass_text.base);
		result = dns_rdataclass_fromtext(&rdclass, &rdclass_text);
		if (result != ISC_R_SUCCESS) {
			seen_error = ISC_TRUE;
			/* XXX write nice error message here */
			break;
		}
		/* Everything else than IN class is pretty bad */
		INSIST(rdclass == dns_rdataclass_in);

		rdtype_text.base = "a";
		rdtype_text.length = strlen(rdtype_text.base);
		result = dns_rdatatype_fromtext(&rdtype, &rdtype_text);
		if (result != ISC_R_SUCCESS) {
			seen_error = ISC_TRUE;
			/* XXX write something romantic here as well... */
			break;
		}

		ttl_text.base = "86400";
		ttl_text.length = strlen(ttl_text.base);
		result = dns_ttl_fromtext(&ttl_text, &ttl);
		if (result != ISC_R_SUCCESS) {
			seen_error = ISC_TRUE;
			break;
		}

		/* put record in master file format here */
		rdata_text.base = "192.168.1.1";
		rdata_text.length = strlen(rdata_text.base);

		isc_buffer_init(&lexbuffer, rdata_text.base, rdata_text.length);
		isc_buffer_add(&lexbuffer, rdata_text.length);
		isc_buffer_setactive(&lexbuffer, rdata_text.length);

		result = isc_lex_openbuffer(lex, &lexbuffer);
		if (result != ISC_R_SUCCESS) {
			seen_error = ISC_TRUE;
			break;
		}

		isc_buffer_init(&target, targetmem, MINTSIZ);

		/*
		 * If ldap returns relative domain name then tune it here, via
		 * "origin" parameter.
		 *
		 * We might want to use the last parameter - error callbacks but
		 * use default ones for now.
		 */
		result = dns_rdata_fromtext(NULL, rdclass, rdtype, lex, NULL,
					    0, mctx, &target, NULL);

		if (result != ISC_R_SUCCESS) {
			seen_error = ISC_TRUE;
			break;
		}

		result = isc_lex_close(lex);
		/* Use strong condition here, error is suspicious */
		INSIST(result == ISC_R_SUCCESS);

		/* Don't waste memory, use exact buffers for rdata */
		rdata = isc_mem_get(mctx, sizeof(*rdata));
		if (rdata == NULL)
			goto for_cleanup1;

		rdatamem.length = isc_buffer_usedlength(&target);
		rdatamem.base = isc_mem_get(mctx, rdatamem.length);
		if (rdatamem.base == NULL)
			goto for_cleanup2;

		memcpy(rdatamem.base, isc_buffer_base(&target), rdatamem.length);
		dns_rdata_fromregion(rdata, rdclass, rdtype, &rdatamem);

		result = ldapdb_rdatalist_findrdatatype(rdatalist, rdtype,
							&rdlist);

		/* no rdata with rdtype exist in rdatalist => add it */
		if (result != ISC_R_SUCCESS) {
			rdlist = isc_mem_get(mctx, sizeof(*rdlist));
			if (rdlist == NULL)
				goto for_cleanup3;

			dns_rdatalist_init(rdlist);
			rdlist->rdclass = rdclass;
			rdlist->type = rdtype;
			rdlist->ttl = ttl;
			APPEND(*rdatalist, rdlist, link);
		} else {
			/*
			 * Use strong condition here, we are not allowing
			 * different TTLs for one name.
			 */
			INSIST(rdlist->ttl == ttl);
		}

		APPEND(rdlist->rdata, rdata, link);

		continue;

for_cleanup3:
		isc_mem_put(mctx, rdatamem.base, rdatamem.length);
for_cleanup2:
		isc_mem_put(mctx, rdata, sizeof(*rdata));
for_cleanup1:
		result = ISC_R_NOMEMORY;
		seen_error = ISC_TRUE;
		break;
	}

	if (seen_error == ISC_TRUE)
		ldapdb_rdatalist_destroy(mctx, rdatalist);

cleanup:
	isc_mem_put(mctx, targetmem, MINTSIZ);
	isc_lex_destroy(&lex);

	return result;
}
void
get_zone_list(ldap_db_t *ldap_db)
{
	ldap_instance_t *ldap_inst;
	int i;
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
	while (next_entry(ldap_inst)) {
		while (next_attribute(ldap_inst)) {
			vals = get_values(ldap_inst);
			for (i = 0; vals[i] != NULL; i++) {
				log_error("attribute %s: %s",
					  get_attribute(ldap_inst),
					  vals[i]);
			}
		}
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
	if (ldap_inst->values) {
		ldap_value_free(ldap_inst->values);
		ldap_inst->values = NULL;
	}
	if (ldap_inst->attribute) {
		ldap_memfree(ldap_inst->attribute);
		ldap_inst->attribute = NULL;
	}
	if (ldap_inst->ber) {
		ber_free(ldap_inst->ber, 0);
		ldap_inst->ber = NULL;
	}
	if (ldap_inst->result) {
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

	ret = ldap_search_ext_s(ldap_inst->handle, str_buf(ldap_inst->base),
				scope, str_buf(ldap_inst->query_string), attrs,
				attrsonly, NULL, NULL, NULL, LDAP_NO_LIMIT,
				&ldap_inst->result);

	log_error("Result: %d", ldap_count_entries(ldap_inst->handle,
				ldap_inst->result));

	return ISC_R_SUCCESS;
}

static const LDAPMessage *
next_entry(ldap_instance_t *inst)
{
	if (inst->ber) {
		ber_free(inst->ber, 0);
		inst->ber = NULL;
	}

	if (inst->handle && inst->entry)
		inst->entry = ldap_next_entry(inst->handle, inst->entry);
	else if (inst->handle && inst->result)
		inst->entry = ldap_first_entry(inst->handle, inst->result);
	else
		inst->entry = NULL;

	return inst->entry;
}

static const char *
next_attribute(ldap_instance_t *inst)
{
	if (inst->attribute) {
		ldap_memfree(inst->attribute);
		inst->attribute = NULL;
	}

	if (inst->handle && inst->entry && inst->ber)
		inst->attribute = ldap_next_attribute(inst->handle, inst->entry,
						      inst->ber);
	else if (inst->handle && inst->entry)
		inst->attribute = ldap_first_attribute(inst->handle, inst->entry,
						       &inst->ber);

	return inst->attribute;
}

static const char *
get_attribute(ldap_instance_t *inst)
{
	return inst->attribute;
}

static char **
get_values(ldap_instance_t *inst)
{
	if (inst->values) {
		ldap_value_free(inst->values);
		inst->values = NULL;
	}

	if (inst->handle && inst->entry && inst->attribute)
		inst->values = ldap_get_values(inst->handle, inst->entry,
					       inst->attribute);

	return inst->values;
}

#if 0
static const char *
next_value(ldap_instance_t *inst)
{
	if (inst->values == NULL)
		get_values(inst);

	if (inst->values[inst->value_cnt])
		inst->value_cnt++;

	return inst->values[inst->value_cnt - 1];
}

static const char *
get_value(ldap_instance_t *inst)
{
	if (inst->values)
		return inst->values[inst->value_cnt - 1];
	else
		return NULL;
}
#endif

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

	ldap_inst->handle = ld;

	return ISC_R_SUCCESS;

cleanup:

	if (ld != NULL)
		ldap_unbind_ext_s(ld, NULL, NULL);

	return ISC_R_FAILURE;
}
