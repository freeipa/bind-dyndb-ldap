/*
 * Authors: Martin Nagy <mnagy@redhat.com>
 *          Adam Tkac <atkac@redhat.com>
 *
 * Copyright (C) 2008, 2009  Red Hat
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

#include <dns/dynamic_db.h>
#include <dns/rbt.h>
#include <dns/rdata.h>
#include <dns/rdataclass.h>
#include <dns/rdatalist.h>
#include <dns/rdatatype.h>
#include <dns/result.h>
#include <dns/ttl.h>
#include <dns/view.h>
#include <dns/zone.h>

#include <isc/buffer.h>
#include <isc/lex.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/region.h>
#include <isc/rwlock.h>
#include <isc/task.h>
#include <isc/time.h>
#include <isc/util.h>

#include <alloca.h>
#define LDAP_DEPRECATED 1
#include <ldap.h>
#include <limits.h>
#include <sasl/sasl.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "acl.h"
#include "krb5_helper.h"
#include "ldap_convert.h"
#include "ldap_entry.h"
#include "ldap_helper.h"
#include "log.h"
#include "semaphore.h"
#include "settings.h"
#include "str.h"
#include "util.h"
#include "zone_register.h"


/* Max type length definitions, from lib/dns/master.c */
#define MINTSIZ (65535 - 12 - 1 - 2 - 2 - 4 - 2)
#define TOKENSIZ (8*1024)

#define LDAP_OPT_CHECK(r, ...)						\
	do {								\
		if ((r) != LDAP_OPT_SUCCESS) {				\
			log_error(__VA_ARGS__);				\
			goto cleanup;					\
		}							\
	} while (0)

/*
 * LDAP related typedefs and structs.
 */

/*
 * Note about locking in this source.
 *
 * ldap_instance_t structure is equal to dynamic-db {}; statement in named.conf.
 * Attributes in ldap_instance_t can be modified only in new_ldap_instance
 * function, which means server is started or reloaded.
 *
 * ldap_connection_t structure represents connection to the LDAP database and
 * per-connection specific data. Access is controlled via
 * ldap_connection_t->lock and ldap_pool_t->conn_semaphore. Each read
 * or write access to ldap_connection_t structure (except create/destroy)
 * must acquire the semaphore and the lock.
 */

typedef struct ldap_connection  ldap_connection_t;
typedef struct ldap_pool	ldap_pool_t;
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
struct ldap_instance {
	isc_mem_t		*mctx;

	/* These are needed for zone creation. */
	const char *		db_name;
	dns_view_t		*view;
	dns_zonemgr_t		*zmgr;

	/* Pool of LDAP connections */
	ldap_pool_t		*pool;

	/* RRs cache */
	ldap_cache_t		*cache;

	/* Our own list of zones. */
	zone_register_t		*zone_register;

	/* krb5 kinit mutex */
	isc_mutex_t		kinit_lock;

	/* Settings. */
	ld_string_t		*uri;
	ld_string_t		*base;
	unsigned int		connections;
	unsigned int		reconnect_interval;
	unsigned int		timeout;
	ldap_auth_t		auth_method;
	ld_string_t		*bind_dn;
	ld_string_t		*password;
	ld_string_t		*krb5_principal;
	ld_string_t		*sasl_mech;
	ld_string_t		*sasl_user;
	ld_string_t		*sasl_auth_name;
	ld_string_t		*sasl_realm;
	ld_string_t		*sasl_password;
	ld_string_t		*krb5_keytab;
	ld_string_t		*fake_mname;
};

struct ldap_pool {
	isc_mem_t		*mctx;
	/* List of LDAP connections. */
	unsigned int		connections; /* number of connections */
	semaphore_t		conn_semaphore;
	ldap_connection_t	**conns;

};

struct ldap_connection {
	isc_mem_t		*mctx;
	isc_mutex_t		lock;
	ld_string_t		*query_string;

	LDAP			*handle;
	LDAPMessage		*result;
	LDAPControl		*serverctrls[2]; /* psearch/NULL or NULL/NULL */

	/* Parsing. */
	isc_lex_t		*lex;
	isc_buffer_t		rdata_target;
	unsigned char		*rdata_target_mem;

	/* Cache. */
	ldap_entrylist_t	ldap_entries;

	/* For reconnection logic. */
	isc_time_t		next_reconnect;
	unsigned int		tries;

	/* Temporary stuff. */
	LDAPMessage		*entry;
	BerElement		*ber;
	char			*attribute;
	char			**values;
	char			*dn;
};

/*
 * Constants.
 */

extern const char *ldapdb_impname;

/* Supported authentication types. */
const ldap_auth_pair_t supported_ldap_auth[] = {
	{ AUTH_NONE,	"none"		},
	{ AUTH_SIMPLE,	"simple"	},
	{ AUTH_SASL,	"sasl"		},
	{ AUTH_INVALID, NULL		},
};

/*
 * Forward declarations.
 */

/* TODO: reorganize this stuff & clean it up. */
static isc_result_t new_ldap_connection(ldap_pool_t *pool,
		ldap_connection_t **ldap_connp);
static void destroy_ldap_connection(ldap_pool_t *pool,
		ldap_connection_t **ldap_connp);

static isc_result_t findrdatatype_or_create(isc_mem_t *mctx,
		ldapdb_rdatalist_t *rdatalist, dns_rdataclass_t rdclass,
		dns_rdatatype_t rdtype, dns_ttl_t ttl, dns_rdatalist_t **rdlistp);
static isc_result_t add_soa_record(isc_mem_t *mctx, ldap_connection_t *ldap_conn,
		dns_name_t *origin, ldap_entry_t *entry,
		ldapdb_rdatalist_t *rdatalist, const ld_string_t *fake_mname);
static isc_result_t parse_rdata(isc_mem_t *mctx, ldap_connection_t *ldap_conn,
		dns_rdataclass_t rdclass, dns_rdatatype_t rdtype,
		dns_name_t *origin, const char *rdata_text,
		dns_rdata_t **rdatap);

static const char * get_dn(ldap_connection_t *ldap_conn, ldap_entry_t *entry);

#if 0
static const LDAPMessage *next_entry(ldap_connection_t *inst);
static const char *get_dn(ldap_connection_t *inst);
#endif

static isc_result_t ldap_connect(ldap_instance_t *ldap_inst,
		ldap_connection_t *ldap_conn);
static isc_result_t ldap_reconnect(ldap_instance_t *ldap_inst,
		ldap_connection_t *ldap_conn);
static int handle_connection_error(ldap_instance_t *ldap_inst,
		ldap_connection_t *ldap_conn, isc_result_t *result);
static isc_result_t ldap_query(ldap_instance_t *ldap_inst, ldap_connection_t *ldap_conn,
		const char *base,
		int scope, char **attrs, int attrsonly, const char *filter, ...);

/* Functions for writing to LDAP. */
static isc_result_t ldap_modify_do(ldap_connection_t *ldap_conn, const char *dn,
		LDAPMod **mods, isc_boolean_t delete_node);
static isc_result_t ldap_rdttl_to_ldapmod(isc_mem_t *mctx,
		dns_rdatalist_t *rdlist, LDAPMod **changep);
static isc_result_t ldap_rdatalist_to_ldapmod(isc_mem_t *mctx,
		dns_rdatalist_t *rdlist, LDAPMod **changep, int mod_op);
static void free_ldapmod(isc_mem_t *mctx, LDAPMod **changep);
static isc_result_t ldap_rdata_to_char_array(isc_mem_t *mctx,
		dns_rdata_t *rdata_head, char ***valsp);
static void free_char_array(isc_mem_t *mctx, char ***valsp);
static isc_result_t modify_ldap_common(dns_name_t *owner, ldap_instance_t *ldap_inst,
		dns_rdatalist_t *rdlist, int mod_op, isc_boolean_t delete_node);

/* Functions for maintaining pool of LDAP connections */
static isc_result_t ldap_pool_create(isc_mem_t *mctx, unsigned int connections,
		ldap_pool_t **poolp);
static void ldap_pool_destroy(ldap_pool_t **poolp);
static ldap_connection_t * ldap_pool_getconnection(ldap_pool_t *pool);
static void ldap_pool_putconnection(ldap_pool_t *pool,
		ldap_connection_t *ldap_conn);
static isc_result_t ldap_pool_connect(ldap_pool_t *pool,
		ldap_instance_t *ldap_inst);

/* Functions for manipulating LDAP persistent search control */
static isc_result_t ldap_pscontrol_create(isc_mem_t *mctx, LDAPControl **ctrlp);
static void ldap_pscontrol_destroy(isc_mem_t *mctx, LDAPControl **ctrlp);

isc_result_t
new_ldap_instance(isc_mem_t *mctx, const char *db_name,
		  const char * const *argv, dns_dyndb_arguments_t *dyndb_args,
		  ldap_instance_t **ldap_instp)
{
	unsigned int i;
	isc_result_t result;
	ldap_instance_t *ldap_inst;
	ld_string_t *auth_method_str = NULL;
	setting_t ldap_settings[] = {
		{ "uri",	 no_default_string		},
		{ "connections", default_uint(2)		},
		{ "reconnect_interval", default_uint(60)	},
		{ "timeout",	 default_uint(10)		},
		{ "base",	 no_default_string		},
		{ "auth_method", default_string("none")		},
		{ "bind_dn",	 default_string("")		},
		{ "password",	 default_string("")		},
		{ "krb5_principal", default_string("")		},
		{ "sasl_mech",	 default_string("GSSAPI")	},
		{ "sasl_user",	 default_string("")		},
		{ "sasl_auth_name", default_string("")		},
		{ "sasl_realm",	 default_string("")		},
		{ "sasl_password", default_string("")		},
		{ "krb5_keytab", default_string("")		},
		{ "fake_mname",	 default_string("")		},
		end_of_settings
	};

	REQUIRE(mctx != NULL);
	REQUIRE(ldap_instp != NULL && *ldap_instp == NULL);

	ldap_inst = isc_mem_get(mctx, sizeof(ldap_instance_t));
	if (ldap_inst == NULL)
		return ISC_R_NOMEMORY;

	ZERO_PTR(ldap_inst);

	isc_mem_attach(mctx, &ldap_inst->mctx);
	ldap_inst->db_name = db_name;
	ldap_inst->view = dns_dyndb_get_view(dyndb_args);
	ldap_inst->zmgr = dns_dyndb_get_zonemgr(dyndb_args);
	/* commented out for now, cause named to hang */
	//dns_view_attach(view, &ldap_inst->view);

	CHECK(zr_create(mctx, &ldap_inst->zone_register));

	CHECK(isc_mutex_init(&ldap_inst->kinit_lock));

	CHECK(str_new(mctx, &auth_method_str));
	CHECK(str_new(mctx, &ldap_inst->uri));
	CHECK(str_new(mctx, &ldap_inst->base));
	CHECK(str_new(mctx, &ldap_inst->bind_dn));
	CHECK(str_new(mctx, &ldap_inst->password));
	CHECK(str_new(mctx, &ldap_inst->krb5_principal));
	CHECK(str_new(mctx, &ldap_inst->sasl_mech));
	CHECK(str_new(mctx, &ldap_inst->sasl_user));
	CHECK(str_new(mctx, &ldap_inst->sasl_auth_name));
	CHECK(str_new(mctx, &ldap_inst->sasl_realm));
	CHECK(str_new(mctx, &ldap_inst->sasl_password));
	CHECK(str_new(mctx, &ldap_inst->krb5_keytab));
	CHECK(str_new(mctx, &ldap_inst->fake_mname));

	i = 0;
	ldap_settings[i++].target = ldap_inst->uri;
	ldap_settings[i++].target = &ldap_inst->connections;
	ldap_settings[i++].target = &ldap_inst->reconnect_interval;
	ldap_settings[i++].target = &ldap_inst->timeout;
	ldap_settings[i++].target = ldap_inst->base;
	ldap_settings[i++].target = auth_method_str;
	ldap_settings[i++].target = ldap_inst->bind_dn;
	ldap_settings[i++].target = ldap_inst->password;
	ldap_settings[i++].target = ldap_inst->krb5_principal;
	ldap_settings[i++].target = ldap_inst->sasl_mech;
	ldap_settings[i++].target = ldap_inst->sasl_user;
	ldap_settings[i++].target = ldap_inst->sasl_auth_name;
	ldap_settings[i++].target = ldap_inst->sasl_realm;
	ldap_settings[i++].target = ldap_inst->sasl_password;
	ldap_settings[i++].target = ldap_inst->krb5_keytab;
	ldap_settings[i++].target = ldap_inst->fake_mname;

	CHECK(set_settings(ldap_settings, argv));

	/* Validate and check settings. */
	str_toupper(ldap_inst->sasl_mech);
	if (ldap_inst->connections < 1) {
		log_error("at least one connection is required");
		result = ISC_R_FAILURE;
		goto cleanup;
	}
	/* Select authentication method. */
	ldap_inst->auth_method = AUTH_INVALID;
	for (i = 0; supported_ldap_auth[i].name != NULL; i++) {
		if (!str_casecmp_char(auth_method_str,
				      supported_ldap_auth[i].name)) {
			ldap_inst->auth_method = supported_ldap_auth[i].value;
			break;
		}
	}
	if (ldap_inst->auth_method == AUTH_INVALID) {
		log_error("unknown authentication method '%s'",
			  str_buf(auth_method_str));
		result = ISC_R_FAILURE;
		goto cleanup;
	}

	/* check we have the right data when SASL/GSSAPI is selected */
	if ((ldap_inst->auth_method == AUTH_SASL) &&
	     (str_casecmp_char(ldap_inst->sasl_mech, "GSSAPI") == 0)) {
		if ((ldap_inst->krb5_principal == NULL) ||
		    (str_len(ldap_inst->krb5_principal) == 0)) {
			if ((ldap_inst->sasl_user == NULL) ||
			    (str_len(ldap_inst->sasl_user) == 0)) {
				char hostname[255];
				if (gethostname(hostname, 255) != 0) {
					log_error("SASL mech GSSAPI defined but krb5_principal"
						"and sasl_user are empty. Could not get hostname");
					result = ISC_R_FAILURE;
					goto cleanup;
				} else {
					str_sprintf(ldap_inst->krb5_principal, "DNS/%s", hostname);
					log_debug(2, "SASL mech GSSAPI defined but krb5_principal"
						"and sasl_user are empty, using default %s",
						str_buf(ldap_inst->krb5_principal));
				}
			} else {
				str_copy(ldap_inst->krb5_principal, ldap_inst->sasl_user);
			}
		}
	}

	CHECK(new_ldap_cache(mctx, argv, &ldap_inst->cache));
	CHECK(ldap_pool_create(mctx, ldap_inst->connections, &ldap_inst->pool));
	CHECK(ldap_pool_connect(ldap_inst->pool, ldap_inst));

cleanup:
	if (result != ISC_R_SUCCESS)
		destroy_ldap_instance(&ldap_inst);
	else
		*ldap_instp = ldap_inst;

	str_destroy(&auth_method_str);

	return result;
}

void
destroy_ldap_instance(ldap_instance_t **ldap_instp)
{
	ldap_instance_t *ldap_inst;

	REQUIRE(ldap_instp != NULL && *ldap_instp != NULL);

	ldap_inst = *ldap_instp;

	ldap_pool_destroy(&ldap_inst->pool);

	str_destroy(&ldap_inst->uri);
	str_destroy(&ldap_inst->base);
	str_destroy(&ldap_inst->bind_dn);
	str_destroy(&ldap_inst->password);
	str_destroy(&ldap_inst->krb5_principal);
	str_destroy(&ldap_inst->sasl_mech);
	str_destroy(&ldap_inst->sasl_user);
	str_destroy(&ldap_inst->sasl_auth_name);
	str_destroy(&ldap_inst->sasl_realm);
	str_destroy(&ldap_inst->sasl_password);
	str_destroy(&ldap_inst->krb5_keytab);
	str_destroy(&ldap_inst->fake_mname);

	/* commented out for now, causes named to hang */
	//dns_view_detach(&ldap_inst->view);

	DESTROYLOCK(&ldap_inst->kinit_lock);

	if (ldap_inst->cache != NULL)
		destroy_ldap_cache(&ldap_inst->cache);

	zr_destroy(&ldap_inst->zone_register);

	isc_mem_putanddetach(&ldap_inst->mctx, ldap_inst, sizeof(ldap_instance_t));

	*ldap_instp = NULL;
}

static isc_result_t
new_ldap_connection(ldap_pool_t *pool, ldap_connection_t **ldap_connp)
{
	isc_result_t result;
	ldap_connection_t *ldap_conn;

	REQUIRE(pool != NULL);
	REQUIRE(ldap_connp != NULL && *ldap_connp == NULL);

	ldap_conn = isc_mem_get(pool->mctx, sizeof(ldap_connection_t));
	if (ldap_conn == NULL)
		return ISC_R_NOMEMORY;

	ZERO_PTR(ldap_conn);

	result = isc_mutex_init(&ldap_conn->lock);
	if (result != ISC_R_SUCCESS) {
		isc_mem_put(pool->mctx, ldap_conn, sizeof(ldap_connection_t));
		return result;
	}

	isc_mem_attach(pool->mctx, &ldap_conn->mctx);

	CHECK(str_new(ldap_conn->mctx, &ldap_conn->query_string));

	CHECK(isc_lex_create(ldap_conn->mctx, TOKENSIZ, &ldap_conn->lex));
	CHECKED_MEM_GET(ldap_conn->mctx, ldap_conn->rdata_target_mem, MINTSIZ);
	CHECK(ldap_pscontrol_create(ldap_conn->mctx,
				    &ldap_conn->serverctrls[0]));

	*ldap_connp = ldap_conn;

	return ISC_R_SUCCESS;

cleanup:
	destroy_ldap_connection(pool, &ldap_conn);

	return result;
}

static void
destroy_ldap_connection(ldap_pool_t *pool, ldap_connection_t **ldap_connp)
{
	ldap_connection_t *ldap_conn;

	REQUIRE(ldap_connp != NULL && *ldap_connp != NULL);

	ldap_conn = *ldap_connp;
	DESTROYLOCK(&ldap_conn->lock);
	if (ldap_conn->handle != NULL)
		ldap_unbind_ext_s(ldap_conn->handle, NULL, NULL);

	str_destroy(&ldap_conn->query_string);

	if (ldap_conn->lex != NULL)
		isc_lex_destroy(&ldap_conn->lex);
	if (ldap_conn->rdata_target_mem != NULL) {
		isc_mem_put(ldap_conn->mctx,
			    ldap_conn->rdata_target_mem, MINTSIZ);
	}
	if (ldap_conn->serverctrls[0] != NULL) {
		ldap_pscontrol_destroy(ldap_conn->mctx,
				       &ldap_conn->serverctrls[0]);
	}

	isc_mem_detach(&ldap_conn->mctx);

	isc_mem_put(pool->mctx, *ldap_connp, sizeof(ldap_connection_t));
	*ldap_connp = NULL;
}

/*
 * Create a new zone with origin 'name'. The zone will be added to the
 * ldap_inst->view.
 */
static isc_result_t
create_zone(ldap_instance_t *ldap_inst, dns_name_t *name, dns_zone_t **zonep)
{
	isc_result_t result;
	dns_zone_t *zone = NULL;
	const char *argv[2];

	REQUIRE(ldap_inst != NULL);
	REQUIRE(name != NULL);
	REQUIRE(zonep != NULL && *zonep == NULL);

	argv[0] = ldapdb_impname;
	argv[1] = ldap_inst->db_name;

	result = dns_view_findzone(ldap_inst->view, name, &zone);
	if (result == ISC_R_SUCCESS) {
		result = ISC_R_EXISTS;
		log_error_r("failed to create new zone");
		goto cleanup;
	} else if (result != ISC_R_NOTFOUND) {
		log_error_r("dns_view_findzone() failed");
		goto cleanup;
	}

	CHECK(dns_zone_create(&zone, ldap_inst->mctx));
	dns_zone_setview(zone, ldap_inst->view);
	CHECK(dns_zone_setorigin(zone, name));
	dns_zone_setclass(zone, dns_rdataclass_in);
	dns_zone_settype(zone, dns_zone_master);
	CHECK(dns_zone_setdbtype(zone, 2, argv));

	*zonep = zone;
	return ISC_R_SUCCESS;

cleanup:
	if (zone != NULL)
		dns_zone_detach(&zone);

	return result;
}

static isc_result_t
publish_zone(ldap_instance_t *ldap_inst, dns_zone_t *zone)
{
	isc_result_t result;

	REQUIRE(ldap_inst != NULL);
	REQUIRE(zone != NULL);

	result = dns_zonemgr_managezone(ldap_inst->zmgr, zone);
	if (result != ISC_R_SUCCESS)
		return result;
	CHECK(dns_view_addzone(ldap_inst->view, zone));

	return ISC_R_SUCCESS;

cleanup:
	dns_zonemgr_releasezone(ldap_inst->zmgr, zone);

	return result;
}

/* In BIND9 terminology "ssu" means "Simple Secure Update" */
static isc_result_t
configure_zone_ssutable(dns_zone_t *zone, const char *update_str)
{
	REQUIRE(zone != NULL);

	/*
	 * This is meant only for debugging.
	 * DANGEROUS: Do not leave uncommented!
	 */
#if 0
	{
		dns_acl_t *any;
		dns_acl_any(dns_zone_getmctx(zone), &any);
		dns_zone_setupdateacl(zone, any);
		dns_acl_detach(&any);
	}

	return ISC_R_SUCCESS;
#endif

	/* Set simple update table. */
	return acl_configure_zone_ssutable(update_str, zone);
}

/* Parse the zone entry */
static isc_result_t
ldap_parse_zoneentry(isc_task_t *task, ldap_entry_t *entry,
		     ldap_instance_t *inst, ldap_connection_t *conn,
		     isc_boolean_t create)
{
	const char *dn;
	ldap_valuelist_t values;
	dns_name_t name;
	dns_zone_t *zone;
	isc_result_t result;
	isc_boolean_t runtime_add = ISC_FALSE;

	zone = NULL;
	dns_name_init(&name, NULL);

	/* Derive the dns name of the zone from the DN. */
	dn = get_dn(conn, entry);
	CHECK_NEXT(dn_to_dnsname(conn->mctx, dn, &name));

	/* If we are in the configuration phase, create the zone,
	 * otherwise we will just search for it in our zone register
	 * and modify the zone we found. */
	if (create) {
		/* Configuration phase, make sure we are running exclusively */
		RUNTIME_CHECK(isc_task_beginexclusive(task) == ISC_R_LOCKBUSY);
newzone:
		CHECK_NEXT(create_zone(inst, &name, &zone));
		CHECK_NEXT(zr_add_zone(inst->zone_register, zone, dn));
		log_debug(2, "created zone %p: %s", zone, dn);
	} else {
		/* Run exclusively */
		RUNTIME_CHECK(isc_task_beginexclusive(task) == ISC_R_SUCCESS);

		result = zr_get_zone_ptr(inst->zone_register,
					 &name, &zone);
		if (result != ISC_R_SUCCESS) {
			dns_view_thaw(inst->view);
			runtime_add = ISC_TRUE;
			goto newzone;
		}
	}

	log_debug(2, "Setting SSU table for %p: %s", zone, dn);
	/* Get the update policy and update the zone with it. */
	result = ldap_entry_getvalues(entry, "idnsUpdatePolicy", &values);
	if (result == ISC_R_SUCCESS)
		CHECK_NEXT(configure_zone_ssutable(zone, HEAD(values)->value));
	else
		CHECK_NEXT(configure_zone_ssutable(zone, NULL));

	/* Fetch allow-query and allow-transfer ACLs */
	log_debug(2, "Setting allow-query for %p: %s", zone, dn);
	result = ldap_entry_getvalues(entry, "idnsAllowQuery", &values);
	if (result == ISC_R_SUCCESS) {
		dns_acl_t *queryacl = NULL;
		CHECK_NEXT(acl_from_ldap(inst->mctx, &values, &queryacl));
		dns_zone_setqueryacl(zone, queryacl);
		dns_acl_detach(&queryacl);
	} else
		log_debug(2, "allow-query not set");

	log_debug(2, "Setting allow-transfer for %p: %s", zone, dn);
	result = ldap_entry_getvalues(entry, "idnsAllowTransfer", &values);
	if (result == ISC_R_SUCCESS) {
		dns_acl_t *transferacl = NULL;
		CHECK_NEXT(acl_from_ldap(inst->mctx, &values, &transferacl));
		dns_zone_setxfracl(zone, transferacl);
		dns_acl_detach(&transferacl);
	} else
		log_debug(2, "allow-transfer not set");

	if (create || runtime_add) {
		/* Everything is set correctly, publish zone */
		CHECK_NEXT(publish_zone(inst, zone));
	}

next:
	if (runtime_add) {
		/*
		 * Don't bother if load fails, server will return
		 * SERVFAIL for queries beneath this zone. This is
		 * admin's problem.
		 */
		(void) dns_zone_load(zone);
		dns_view_freeze(inst->view);
		runtime_add = ISC_FALSE;
	}
	if (!create)
		isc_task_endexclusive(task);
	if (dns_name_dynamic(&name))
		dns_name_free(&name, conn->mctx);
	if (zone != NULL)
		dns_zone_detach(&zone);

	return ISC_R_SUCCESS;
}

/*
 * Search in LDAP for zones. If 'create' is true, create the zones. Otherwise,
 * we assume that we are past the configuration phase and no new zones can be
 * added. In that case, only modify the zone's properties, like the update
 * policy.
 *
 * Returns ISC_R_SUCCESS if we found and successfully added at least one zone.
 * Returns ISC_R_FAILURE otherwise.
 */
isc_result_t
refresh_zones_from_ldap(isc_task_t *task, ldap_instance_t *ldap_inst,
			isc_boolean_t create)
{
	isc_result_t result = ISC_R_SUCCESS;
	ldap_connection_t *ldap_conn;
	int zone_count = 0;
	ldap_entry_t *entry;
	char *attrs[] = {
		"idnsName", "idnsUpdatePolicy", "idnsAllowQuery",
		"idnsAllowTransfer", NULL
	};

	REQUIRE(ldap_inst != NULL);

	log_debug(2, "refreshing list of zones for %s", ldap_inst->db_name);

	ldap_conn = ldap_pool_getconnection(ldap_inst->pool);

	CHECK(ldap_query(ldap_inst, ldap_conn, str_buf(ldap_inst->base),
			 LDAP_SCOPE_SUBTREE, attrs, 0,
			 "(&(objectClass=idnsZone)(idnsZoneActive=TRUE))"));

	for (entry = HEAD(ldap_conn->ldap_entries);
	     entry != NULL;
	     entry = NEXT(entry, link)) {
		CHECK(ldap_parse_zoneentry(task, entry, ldap_inst, ldap_conn,
					   create));
		zone_count++;
	}

cleanup:
	ldap_pool_putconnection(ldap_inst->pool, ldap_conn);

	log_debug(2, "finished refreshing list of zones");

	if (zone_count > 0)
		return ISC_R_SUCCESS;
	else
		return ISC_R_FAILURE;
}

static const char *
get_dn(ldap_connection_t *ldap_conn, ldap_entry_t *entry)
{
	if (entry->dn) {
		ldap_memfree(entry->dn);
		entry->dn = NULL;
	}
	if (ldap_conn->handle)
		entry->dn = ldap_get_dn(ldap_conn->handle, entry->ldap_entry);

	return entry->dn;
}

#if 0
static const char *
get_dn(ldap_connection_t *inst)
{
	if (inst->dn) {
		ldap_memfree(inst->dn);
		inst->dn = NULL;
	}

	if (inst->handle && inst->entry)
		inst->dn = ldap_get_dn(inst->handle, inst->entry);

	return inst->dn;

}
#endif

static isc_result_t
findrdatatype_or_create(isc_mem_t *mctx, ldapdb_rdatalist_t *rdatalist,
			dns_rdataclass_t rdclass, dns_rdatatype_t rdtype,
			dns_ttl_t ttl, dns_rdatalist_t **rdlistp)
{
	isc_result_t result;
	dns_rdatalist_t *rdlist = NULL;

	REQUIRE(rdatalist != NULL);
	REQUIRE(rdlistp != NULL);

	*rdlistp = NULL;

	result = ldapdb_rdatalist_findrdatatype(rdatalist, rdtype, &rdlist);
	if (result != ISC_R_SUCCESS) {
		CHECKED_MEM_GET_PTR(mctx, rdlist);

		dns_rdatalist_init(rdlist);
		rdlist->rdclass = rdclass;
		rdlist->type = rdtype;
		rdlist->ttl = ttl;
		APPEND(*rdatalist, rdlist, link);
		result = ISC_R_SUCCESS;
	} else {
		/*
		 * No support for different TTLs yet.
		 */
		if (rdlist->ttl != ttl)
			result = ISC_R_FAILURE;
	}

	*rdlistp = rdlist;
	return ISC_R_SUCCESS;

cleanup:
	SAFE_MEM_PUT_PTR(mctx, rdlist);

	return result;
}

/*
 * ldapdb_rdatalist_t related functions.
 */
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
	dns_rdatalist_t *rdlist;

	REQUIRE(rdatalist != NULL);

	while (!EMPTY(*rdatalist)) {
		rdlist = HEAD(*rdatalist);
		free_rdatalist(mctx, rdlist);
		UNLINK(*rdatalist, rdlist, link);
		isc_mem_put(mctx, rdlist, sizeof(*rdlist));
	}
}

void
free_rdatalist(isc_mem_t *mctx, dns_rdatalist_t *rdlist)
{
	dns_rdata_t *rdata;
	isc_region_t r;

	REQUIRE(rdlist != NULL);

	while (!EMPTY(rdlist->rdata)) {
		rdata = HEAD(rdlist->rdata);
		UNLINK(rdlist->rdata, rdata, link);
		dns_rdata_toregion(rdata, &r);
		isc_mem_put(mctx, r.base, r.length);
		isc_mem_put(mctx, rdata, sizeof(*rdata));
	}
}

static isc_result_t
ldap_parse_rrentry(isc_mem_t *mctx, ldap_entry_t *entry,
		   ldap_connection_t *conn, dns_name_t *origin,
		   const ld_string_t *fake_mname, ld_string_t *buf,
		   ldapdb_rdatalist_t *rdatalist)
{
	isc_result_t result;
	dns_rdataclass_t rdclass;
	dns_ttl_t ttl;
	dns_rdatatype_t rdtype;
	dns_rdata_t *rdata = NULL;
	dns_rdatalist_t *rdlist = NULL;
	ldap_attribute_t *attr;

	result = add_soa_record(mctx, conn, origin, entry,
				rdatalist, fake_mname);
	if (result != ISC_R_SUCCESS && result != ISC_R_NOTFOUND)
		goto cleanup;

	rdclass = ldap_entry_getrdclass(entry);
	ttl = ldap_entry_getttl(entry);

	for (result = ldap_entry_nextrdtype(entry, &attr, &rdtype);
	     result == ISC_R_SUCCESS;
	     result = ldap_entry_nextrdtype(entry, &attr, &rdtype)) {

		CHECK(findrdatatype_or_create(mctx, rdatalist, rdclass,
					      rdtype, ttl, &rdlist));
		while (ldap_attr_nextvalue(attr, buf) != NULL) {
			CHECK(parse_rdata(mctx, conn, rdclass,
					  rdtype, origin,
					  str_buf(buf), &rdata));
			APPEND(rdlist->rdata, rdata, link);
			rdata = NULL;
		}
		rdlist = NULL;
	}

	return ISC_R_SUCCESS;

cleanup:
	return result;
}

isc_result_t
ldapdb_rdatalist_get(isc_mem_t *mctx, ldap_instance_t *ldap_inst, dns_name_t *name,
		     dns_name_t *origin, ldapdb_rdatalist_t *rdatalist)
{
	isc_result_t result;
	ldap_connection_t *ldap_conn;
	ldap_entry_t *entry;
	ld_string_t *string = NULL;
	ldap_cache_t *cache;

	REQUIRE(mctx != NULL);
	REQUIRE(ldap_inst != NULL);
	REQUIRE(name != NULL);
	REQUIRE(rdatalist != NULL);

	/* Check if RRs are in the cache */
	cache = ldap_instance_getcache(ldap_inst);
	result = ldap_cache_getrdatalist(mctx, cache, name, rdatalist);
	if (result == ISC_R_SUCCESS)
		return ISC_R_SUCCESS;
	else if (result != ISC_R_NOTFOUND)
		return result;

	/* RRs aren't in the cache, perform ordinary LDAP query */
	ldap_conn = ldap_pool_getconnection(ldap_inst->pool);

	INIT_LIST(*rdatalist);
	CHECK(str_new(mctx, &string));
	CHECK(dnsname_to_dn(ldap_inst->zone_register, name, string));

	CHECK(ldap_query(ldap_inst, ldap_conn, str_buf(string), LDAP_SCOPE_BASE,
			 NULL, 0, "(objectClass=idnsRecord)"));

	if (EMPTY(ldap_conn->ldap_entries)) {
		result = ISC_R_NOTFOUND;
		goto cleanup;
	}

	for (entry = HEAD(ldap_conn->ldap_entries);
	     entry != NULL;
	     entry = NEXT(entry, link)) {
		CHECK(ldap_parse_rrentry(mctx, entry, ldap_conn,
					 origin, ldap_inst->fake_mname,
					 string, rdatalist));
	}

	/* Cache RRs */
	CHECK(ldap_cache_addrdatalist(cache, name, rdatalist));
	/* result = ISC_R_SUCCESS; - Performed by ldap_cache_addrdatalist call above */

cleanup:
	ldap_pool_putconnection(ldap_inst->pool, ldap_conn);
	str_destroy(&string);

	if (result != ISC_R_SUCCESS)
		ldapdb_rdatalist_destroy(mctx, rdatalist);

	return result;
}

static isc_result_t
add_soa_record(isc_mem_t *mctx, ldap_connection_t *ldap_conn, dns_name_t *origin,
	       ldap_entry_t *entry, ldapdb_rdatalist_t *rdatalist,
	       const ld_string_t *fake_mname)
{
	isc_result_t result;
	ld_string_t *string = NULL;
	dns_rdataclass_t rdclass;
	dns_rdata_t *rdata = NULL;
	dns_rdatalist_t *rdlist = NULL;

	CHECK(str_new(mctx, &string));

	CHECK(ldap_entry_getfakesoa(entry, fake_mname, string));
	rdclass = ldap_entry_getrdclass(entry);
	CHECK(parse_rdata(mctx, ldap_conn, rdclass, dns_rdatatype_soa, origin,
			  str_buf(string), &rdata));

	CHECK(findrdatatype_or_create(mctx, rdatalist, rdclass, dns_rdatatype_soa,
				      ldap_entry_getttl(entry), &rdlist));

	APPEND(rdlist->rdata, rdata, link);

cleanup:
	str_destroy(&string);
	if (result != ISC_R_SUCCESS)
		SAFE_MEM_PUT_PTR(mctx, rdata);

	return result;
}

static isc_result_t
parse_rdata(isc_mem_t *mctx, ldap_connection_t *ldap_conn,
	    dns_rdataclass_t rdclass, dns_rdatatype_t rdtype,
	    dns_name_t *origin, const char *rdata_text, dns_rdata_t **rdatap)
{
	isc_result_t result;
	isc_consttextregion_t text;
	isc_buffer_t lex_buffer;
	isc_region_t rdatamem;
	dns_rdata_t *rdata;

	REQUIRE(mctx != NULL);
	REQUIRE(ldap_conn != NULL);
	REQUIRE(rdata_text != NULL);
	REQUIRE(rdatap != NULL);

	rdata = NULL;
	rdatamem.base = NULL;

	text.base = rdata_text;
	text.length = strlen(text.base);

	isc_buffer_init(&lex_buffer, text.base, text.length);
	isc_buffer_add(&lex_buffer, text.length);
	isc_buffer_setactive(&lex_buffer, text.length);

	CHECK(isc_lex_openbuffer(ldap_conn->lex, &lex_buffer));

	isc_buffer_init(&ldap_conn->rdata_target, ldap_conn->rdata_target_mem,
			MINTSIZ);
	CHECK(dns_rdata_fromtext(NULL, rdclass, rdtype, ldap_conn->lex, origin,
				 0, mctx, &ldap_conn->rdata_target, NULL));

	CHECKED_MEM_GET_PTR(mctx, rdata);
	dns_rdata_init(rdata);

	rdatamem.length = isc_buffer_usedlength(&ldap_conn->rdata_target);
	CHECKED_MEM_GET(mctx, rdatamem.base, rdatamem.length);

	memcpy(rdatamem.base, isc_buffer_base(&ldap_conn->rdata_target),
	       rdatamem.length);
	dns_rdata_fromregion(rdata, rdclass, rdtype, &rdatamem);

	isc_lex_close(ldap_conn->lex);

	*rdatap = rdata;
	return ISC_R_SUCCESS;

cleanup:
	isc_lex_close(ldap_conn->lex);
	if (rdata != NULL)
		isc_mem_put(mctx, rdata, sizeof(*rdata));
	if (rdatamem.base != NULL)
		isc_mem_put(mctx, rdatamem.base, rdatamem.length);

	return result;
}

static isc_result_t
ldap_query(ldap_instance_t *ldap_inst, ldap_connection_t *ldap_conn,
	   const char *base, int scope, char **attrs,
	   int attrsonly, const char *filter, ...)
{
	va_list ap;
	isc_result_t result;

	REQUIRE(ldap_conn != NULL);

	va_start(ap, filter);
	str_vsprintf(ldap_conn->query_string, filter, ap);
	va_end(ap);

	log_debug(2, "querying '%s' with '%s'", base,
		  str_buf(ldap_conn->query_string));

	if (ldap_conn->handle == NULL) {
		log_bug("ldap_conn->handle is NULL");
		return ISC_R_FAILURE;
	}

	do {
		int ret;

		ret = ldap_search_ext_s(ldap_conn->handle, base, scope,
					str_buf(ldap_conn->query_string),
					attrs, attrsonly, NULL, NULL, NULL,
					LDAP_NO_LIMIT, &ldap_conn->result);

		if (ret == 0) {
			int cnt;

			ldap_conn->tries = 0;
			cnt = ldap_count_entries(ldap_conn->handle, ldap_conn->result);
			log_debug(2, "entry count: %d", cnt);

			result = ldap_entrylist_create(ldap_conn->mctx,
						       ldap_conn->handle,
						       ldap_conn->result,
						       &ldap_conn->ldap_entries);
			if (result != ISC_R_SUCCESS) {
				log_error("failed to save LDAP query results");
				return result;
			}

			return ISC_R_SUCCESS;
		}
	} while (handle_connection_error(ldap_inst, ldap_conn, &result));

	return result;
}

#if 0
/* FIXME: this function is obsolete, remove. */
static const LDAPMessage *
next_entry(ldap_connection_t *inst)
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
#endif

/* FIXME: Tested with SASL/GSSAPI/KRB5 only */
static int
ldap_sasl_interact(LDAP *ld, unsigned flags, void *defaults, void *sin)
{
	sasl_interact_t *in;
	ldap_instance_t *ldap_inst = defaults;
	int ret = LDAP_OTHER;

	REQUIRE(ldap_inst != NULL);
	UNUSED(flags);

	if (ld == NULL || sin == NULL)
		return LDAP_PARAM_ERROR;

	log_debug(4, "doing interactive bind");
	for (in = sin; in != NULL && in->id != SASL_CB_LIST_END; in++) {
		switch (in->id) {
		case SASL_CB_USER:
			log_debug(4, "got request for SASL_CB_USER");
			in->result = str_buf(ldap_inst->sasl_user);
			in->len = str_len(ldap_inst->sasl_user);
			ret = LDAP_SUCCESS;
			break;
		case SASL_CB_GETREALM:
			log_debug(4, "got request for SASL_CB_GETREALM");
			in->result = str_buf(ldap_inst->sasl_realm);
			in->len = str_len(ldap_inst->sasl_realm);
			ret = LDAP_SUCCESS;
			break;
		case SASL_CB_AUTHNAME:
			log_debug(4, "got request for SASL_CB_AUTHNAME");
			in->result = str_buf(ldap_inst->sasl_auth_name);
			in->len = str_len(ldap_inst->sasl_auth_name);
			ret = LDAP_SUCCESS;
			break;
		case SASL_CB_PASS:
			log_debug(4, "got request for SASL_CB_PASS");
			in->result = str_buf(ldap_inst->sasl_password);
			in->len = str_len(ldap_inst->sasl_password);
			ret = LDAP_SUCCESS;
			break;
		default:
			in->result = NULL;
			in->len = 0;
			ret = LDAP_OTHER;
		}
	}

	return ret;
}

/*
 * Initialize the LDAP handle and bind to the server. Needed authentication
 * credentials and settings are available from the ldap_inst.
 */
static isc_result_t
ldap_connect(ldap_instance_t *ldap_inst, ldap_connection_t *ldap_conn)
{
	LDAP *ld;
	int ret;
	int version;
	struct timeval timeout;

	REQUIRE(ldap_conn != NULL);

	ret = ldap_initialize(&ld, str_buf(ldap_inst->uri));
	if (ret != LDAP_SUCCESS) {
		log_error("LDAP initialization failed: %s",
			  ldap_err2string(ret));
		goto cleanup;
	}

	version = LDAP_VERSION3;
	ret = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
	LDAP_OPT_CHECK(ret, "failed to set LDAP version");

	timeout.tv_sec = ldap_inst->timeout;
	timeout.tv_usec = 0;

	ret = ldap_set_option(ld, LDAP_OPT_TIMEOUT, &timeout);
	LDAP_OPT_CHECK(ret, "failed to set timeout");

	if (ldap_conn->handle != NULL)
		ldap_unbind_ext_s(ldap_conn->handle, NULL, NULL);
	ldap_conn->handle = ld;

	return ldap_reconnect(ldap_inst, ldap_conn);

cleanup:

	if (ld != NULL)
		ldap_unbind_ext_s(ld, NULL, NULL);

	return ISC_R_FAILURE;
}

static isc_result_t
ldap_reconnect(ldap_instance_t *ldap_inst, ldap_connection_t *ldap_conn)
{
	int ret = 0;
	const char *bind_dn = NULL;
	const char *password = NULL;

	if (ldap_conn->tries > 0) {
		isc_time_t now;
		int time_cmp;
		isc_result_t result;

		result = isc_time_now(&now);
		time_cmp = isc_time_compare(&now, &ldap_conn->next_reconnect);
		if (result == ISC_R_SUCCESS && time_cmp < 0)
			return ISC_R_FAILURE;
	}

	/* If either bind_dn or the password is not set, we will use
	 * password-less bind. */
	if (str_len(ldap_inst->bind_dn) > 0 && str_len(ldap_inst->password) > 0) {
		bind_dn = str_buf(ldap_inst->bind_dn);
		password = str_buf(ldap_inst->password);
	}

	/* Set the next possible reconnect time. */
	{
		isc_interval_t delay;
		unsigned int i;
		unsigned int seconds;
		const unsigned int intervals[] = { 2, 5, 20, UINT_MAX };
		const size_t ntimes = sizeof(intervals) / sizeof(intervals[0]);

		i = ISC_MIN(ntimes - 1, ldap_conn->tries);
		seconds = ISC_MIN(intervals[i], ldap_inst->reconnect_interval);
		isc_interval_set(&delay, seconds, 0);
		isc_time_nowplusinterval(&ldap_conn->next_reconnect, &delay);
	}

	ldap_conn->tries++;
	log_debug(2, "trying to establish LDAP connection to %s",
		  str_buf(ldap_inst->uri));

	switch (ldap_inst->auth_method) {
	case AUTH_NONE:
		ret = ldap_simple_bind_s(ldap_conn->handle, NULL, NULL);
		break;
	case AUTH_SIMPLE:
		ret = ldap_simple_bind_s(ldap_conn->handle, bind_dn, password);
		break;
	case AUTH_SASL:
		if (strcmp(str_buf(ldap_inst->sasl_mech), "GSSAPI") == 0) {
			isc_result_t result;
			LOCK(&ldap_inst->kinit_lock);
			result = get_krb5_tgt(ldap_inst->mctx,
					      str_buf(ldap_inst->krb5_principal),
					      str_buf(ldap_inst->krb5_keytab));
			UNLOCK(&ldap_inst->kinit_lock);
			if (result != ISC_R_SUCCESS)
				return result;
		}

		log_debug(4, "trying interactive bind using %s mechanism",
			  str_buf(ldap_inst->sasl_mech));
		ret = ldap_sasl_interactive_bind_s(ldap_conn->handle, NULL,
						   str_buf(ldap_inst->sasl_mech),
						   NULL, NULL, LDAP_SASL_QUIET,
						   ldap_sasl_interact,
						   ldap_inst);
		break;
	default:
		log_bug("unsupported authentication mechanism");
		ret = LDAP_OTHER;
		break;
	}

	if (ret != LDAP_SUCCESS) {
		log_error("bind to LDAP server failed: %s",
			  ldap_err2string(ret));

		switch (ret) {
		case LDAP_INVALID_CREDENTIALS:
			return ISC_R_NOPERM;
		case LDAP_SERVER_DOWN:
			return ISC_R_NOTCONNECTED;
		default:
			return ISC_R_FAILURE;
		}
	} else
		log_debug(2, "bind to LDAP server successful");

	ldap_conn->tries = 0;

	return ISC_R_SUCCESS;
}

static int
handle_connection_error(ldap_instance_t *ldap_inst, ldap_connection_t *ldap_conn,
			isc_result_t *result)
{
	int ret;
	int err_code;
	const char *err_string = NULL;

	*result = ISC_R_FAILURE;

	ret = ldap_get_option(ldap_conn->handle, LDAP_OPT_RESULT_CODE,
			      (void *)&err_code);

	if (ret != LDAP_OPT_SUCCESS) {
		err_string = "failed to get error code";
	} else if (err_code == LDAP_NO_SUCH_OBJECT) {
		*result = ISC_R_SUCCESS;
		ldap_conn->tries = 0;
		return 0;
	} else if (err_code == LDAP_SERVER_DOWN || err_code == LDAP_CONNECT_ERROR) {
		if (ldap_conn->tries == 0)
			log_error("connection to the LDAP server was lost");
		if (ldap_connect(ldap_inst, ldap_conn) == ISC_R_SUCCESS)
			return 1;
	} else if (err_code == LDAP_TIMEOUT) {
		log_error("LDAP query timed out. Try to adjust \"timeout\" parameter");
	} else {
		err_string = ldap_err2string(err_code);
	}

	if (err_string != NULL)
		log_error("LDAP error: %s", err_string);

	return 0;
}

/* FIXME: Handle the case where the LDAP handle is NULL -> try to reconnect. */
static isc_result_t
ldap_modify_do(ldap_connection_t *ldap_conn, const char *dn, LDAPMod **mods,
	       isc_boolean_t delete_node)
{
	int ret;
	int err_code;
	const char *operation_str;

	REQUIRE(ldap_conn != NULL);
	REQUIRE(dn != NULL);
	REQUIRE(mods != NULL);

	if (delete_node) {
		log_debug(2, "deleting whole node: '%s'", dn);
		ret = ldap_delete_ext_s(ldap_conn->handle, dn, NULL, NULL);
	} else {
		log_debug(2, "writing to '%s'", dn);
		ret = ldap_modify_ext_s(ldap_conn->handle, dn, mods, NULL, NULL);
	}

	if (ret == LDAP_SUCCESS)
		return ISC_R_SUCCESS;

	ldap_get_option(ldap_conn->handle, LDAP_OPT_RESULT_CODE, &err_code);
	if (mods[0]->mod_op == LDAP_MOD_ADD)
		operation_str = "modifying(add)";
	else
		operation_str = "modifying(del)";

	/* If there is no object yet, create it with an ldap add operation. */
	if (mods[0]->mod_op == LDAP_MOD_ADD && err_code == LDAP_NO_SUCH_OBJECT) {
		int i;
		LDAPMod **new_mods;
		char *obj_str[] = { "idnsRecord", NULL };
		LDAPMod obj_class = {
			0, "objectClass", { .modv_strvals = obj_str },
		};

		/*
		 * Create a new array of LDAPMod structures. We will change
		 * the mod_op member of each one to 0 (but preserve
		 * LDAP_MOD_BVALUES. Additionally, we also need to specify
		 * the objectClass attribute.
		 */
		for (i = 0; mods[i]; i++)
			mods[i]->mod_op &= LDAP_MOD_BVALUES;
		new_mods = alloca((i + 2) * sizeof(LDAPMod *));
		memcpy(new_mods, mods, i * sizeof(LDAPMod *));
		new_mods[i] = &obj_class;
		new_mods[i + 1] = NULL;

		ret = ldap_add_ext_s(ldap_conn->handle, dn, new_mods, NULL, NULL);
		if (ret == LDAP_SUCCESS)
			return ISC_R_SUCCESS;
		ldap_get_option(ldap_conn->handle, LDAP_OPT_RESULT_CODE,
				&err_code);
		operation_str = "adding";
	}

	log_debug(2, "error(%s) %s entry %s", ldap_err2string(err_code),
		  operation_str, dn);

	/* do not error out if we are trying to delete an
	 * unexisting attribute */
	if (mods[0]->mod_op != LDAP_MOD_DELETE ||
	    err_code != LDAP_NO_SUCH_ATTRIBUTE) {

		return ISC_R_FAILURE;
	}

	return ISC_R_SUCCESS;
}

static isc_result_t
ldap_rdatalist_to_ldapmod(isc_mem_t *mctx, dns_rdatalist_t *rdlist,
			  LDAPMod **changep, int mod_op)
{
	isc_result_t result;
	LDAPMod *change = NULL;
	char **vals = NULL;
	const char *attr_name_c;
	char *attr_name;


	REQUIRE(changep != NULL && *changep == NULL);

	CHECKED_MEM_GET_PTR(mctx, change);
	ZERO_PTR(change);

	result = rdatatype_to_ldap_attribute(rdlist->type, &attr_name_c);
	if (result != ISC_R_SUCCESS) {
		result = ISC_R_FAILURE;
		goto cleanup;
	}
	DE_CONST(attr_name_c, attr_name);
	CHECK(ldap_rdata_to_char_array(mctx, HEAD(rdlist->rdata), &vals));

	change->mod_op = mod_op;
	change->mod_type = attr_name;
	change->mod_values = vals;

	*changep = change;
	return ISC_R_SUCCESS;

cleanup:
	free_ldapmod(mctx, &change);

	return result;
}

static void
free_ldapmod(isc_mem_t *mctx, LDAPMod **changep)
{
	LDAPMod *change;

	REQUIRE(changep != NULL);

	change = *changep;
	if (change == NULL)
		return;

	free_char_array(mctx, &change->mod_values);
	SAFE_MEM_PUT_PTR(mctx, change);

	*changep = NULL;
}

static isc_result_t
ldap_rdata_to_char_array(isc_mem_t *mctx, dns_rdata_t *rdata_head,
			 char ***valsp)
{
	isc_result_t result;
	char **vals;
	unsigned int i;
	unsigned int rdata_count = 0;
	size_t vals_size;
	dns_rdata_t *rdata;

	REQUIRE(rdata_head != NULL);
	REQUIRE(valsp != NULL && *valsp == NULL);

	for (rdata = rdata_head; rdata != NULL; rdata = NEXT(rdata, link))
		rdata_count++;

	vals_size = (rdata_count + 1) * sizeof(char *);

	CHECKED_MEM_ALLOCATE(mctx, vals, vals_size);
	memset(vals, 0, vals_size);

	rdata = rdata_head;
	for (i = 0; i < rdata_count && rdata != NULL; i++) {
		DECLARE_BUFFER(buffer, MINTSIZ);
		isc_region_t region;

		/* Convert rdata to text. */
		INIT_BUFFER(buffer);
		CHECK(dns_rdata_totext(rdata, NULL, &buffer));
		isc_buffer_usedregion(&buffer, &region);

		/* Now allocate the string with the right size. */
		CHECKED_MEM_ALLOCATE(mctx, vals[i], region.length + 1);
		memcpy(vals[i], region.base, region.length);
		vals[i][region.length] = '\0';

		rdata = NEXT(rdata, link);
	}

	*valsp = vals;
	return ISC_R_SUCCESS;

cleanup:
	free_char_array(mctx, &vals);
	return result;
}

static void
free_char_array(isc_mem_t *mctx, char ***valsp)
{
	char **vals;
	unsigned int i;

	REQUIRE(valsp != NULL);

	vals = *valsp;
	if (vals == NULL)
		return;

	for (i = 0; vals[i] != NULL; i++)
		isc_mem_free(mctx, vals[i]);

	isc_mem_free(mctx, vals);
	*valsp = NULL;
}

static isc_result_t
ldap_rdttl_to_ldapmod(isc_mem_t *mctx, dns_rdatalist_t *rdlist,
		      LDAPMod **changep)
{
	LDAPMod *change = NULL;
	ld_string_t *ttlval = NULL;
	char **vals = NULL;
	isc_result_t result;

	REQUIRE(changep != NULL && *changep == NULL);

	CHECK(str_new(mctx, &ttlval));
	CHECK(str_sprintf(ttlval, "%d", rdlist->ttl));

	CHECKED_MEM_GET_PTR(mctx, change);
	ZERO_PTR(change);

	change->mod_op = LDAP_MOD_REPLACE;
	change->mod_type = "dnsTTL";

	CHECKED_MEM_ALLOCATE(mctx, vals, 2 * sizeof(char *));
	memset(vals, 0, 2 * sizeof(char *));
	change->mod_values = vals;

	CHECKED_MEM_ALLOCATE(mctx, vals[0], str_len(ttlval) + 1);
	memcpy(vals[0], str_buf(ttlval), str_len(ttlval) + 1);

	*changep = change;

cleanup:
	if (ttlval) str_destroy(&ttlval);
	if (change && result != ISC_R_SUCCESS) free_ldapmod(mctx, &change);

	return result;
}

/*
 * Modify the SOA record of a zone, where DN of the zone is 'zone_dn'.
 * The SOA record is a special case because we need to update serial,
 * refresh, retry, expire and minimum attributes for each SOA record.
 */
static isc_result_t
modify_soa_record(ldap_connection_t *ldap_conn, const char *zone_dn,
		  dns_rdata_t *rdata)
{
	isc_mem_t *mctx = ldap_conn->mctx;
	dns_rdata_soa_t soa;
	LDAPMod change[5];
	LDAPMod *changep[6] = {
		&change[0], &change[1], &change[2], &change[3], &change[4],
		NULL
	};

#define SET_LDAP_MOD(index, name) \
	change[index].mod_op = LDAP_MOD_REPLACE; \
	change[index].mod_type = "idnsSOA" #name; \
	change[index].mod_values = alloca(2 * sizeof(char *)); \
	change[index].mod_values[0] = alloca(sizeof(soa.name) + 1); \
	change[index].mod_values[1] = NULL; \
	snprintf(change[index].mod_values[0], sizeof(soa.name) + 1, "%d", soa.name)

	dns_rdata_tostruct(rdata, (void *)&soa, mctx);

	SET_LDAP_MOD(0, serial);
	SET_LDAP_MOD(1, refresh);
	SET_LDAP_MOD(2, retry);
	SET_LDAP_MOD(3, expire);
	SET_LDAP_MOD(4, minimum);

	dns_rdata_freestruct((void *)&soa);

	return ldap_modify_do(ldap_conn, zone_dn, changep, ISC_FALSE);

#undef SET_LDAP_MOD
}

static isc_result_t
modify_ldap_common(dns_name_t *owner, ldap_instance_t *ldap_inst,
		   dns_rdatalist_t *rdlist, int mod_op, isc_boolean_t delete_node)
{
	isc_result_t result;
	isc_mem_t *mctx = ldap_inst->mctx;
	ldap_connection_t *ldap_conn = NULL;
	ld_string_t *owner_dn = NULL;
	LDAPMod *change[3] = { NULL };
	ldap_cache_t *cache;

	/* Flush modified record from the cache */
	cache = ldap_instance_getcache(ldap_inst);
	CHECK(discard_from_cache(cache, owner));

	if (rdlist->type == dns_rdatatype_soa && mod_op == LDAP_MOD_DELETE)
		return ISC_R_SUCCESS;

	ldap_conn = ldap_pool_getconnection(ldap_inst->pool);

	CHECK(str_new(mctx, &owner_dn));
	CHECK(dnsname_to_dn(ldap_inst->zone_register, owner, owner_dn));

	if (rdlist->type == dns_rdatatype_soa) {
		result = modify_soa_record(ldap_conn, str_buf(owner_dn),
					   HEAD(rdlist->rdata));
		goto cleanup;
	}

	CHECK(ldap_rdatalist_to_ldapmod(mctx, rdlist, &change[0], mod_op));
	if (mod_op == LDAP_MOD_ADD) {
		/* for now always replace the ttl on add */
		CHECK(ldap_rdttl_to_ldapmod(mctx, rdlist, &change[1]));
	}

	CHECK(ldap_modify_do(ldap_conn, str_buf(owner_dn), change, delete_node));

cleanup:
	ldap_pool_putconnection(ldap_inst->pool, ldap_conn);
	str_destroy(&owner_dn);
	free_ldapmod(mctx, &change[0]);
	free_ldapmod(mctx, &change[1]);

	return result;
}

isc_result_t
write_to_ldap(dns_name_t *owner, ldap_instance_t *ldap_inst, dns_rdatalist_t *rdlist)
{
	return modify_ldap_common(owner, ldap_inst, rdlist, LDAP_MOD_ADD, ISC_FALSE);
}

isc_result_t
remove_from_ldap(dns_name_t *owner, ldap_instance_t *ldap_inst,
		 dns_rdatalist_t *rdlist, isc_boolean_t delete_node)
{
	return modify_ldap_common(owner, ldap_inst, rdlist, LDAP_MOD_DELETE,
				  delete_node);
}

ldap_cache_t *
ldap_instance_getcache(ldap_instance_t *ldap_inst)
{
	return ldap_inst->cache;
}

static isc_result_t
ldap_pool_create(isc_mem_t *mctx, unsigned int connections, ldap_pool_t **poolp)
{
	ldap_pool_t *pool;
	isc_result_t result;

	REQUIRE(poolp != NULL && *poolp == NULL);

	CHECKED_MEM_GET(mctx, pool, sizeof(*pool));
	ZERO_PTR(pool);
	isc_mem_attach(mctx, &pool->mctx);
	
	CHECK(semaphore_init(&pool->conn_semaphore, connections));
	CHECKED_MEM_GET(mctx, pool->conns,
			connections * sizeof(ldap_connection_t *));
	memset(pool->conns, 0, connections * sizeof(ldap_connection_t *));
	pool->connections = connections;

	*poolp = pool;

	return ISC_R_SUCCESS;

cleanup:
	if (pool != NULL)
		ldap_pool_destroy(&pool);
	return result;
}
static void
ldap_pool_destroy(ldap_pool_t **poolp)
{
	ldap_pool_t *pool;
	ldap_connection_t *ldap_conn;
	unsigned int i;

	REQUIRE(poolp != NULL && *poolp != NULL);

	pool = *poolp;

	for (i = 0; i < pool->connections; i++) {
		ldap_conn = pool->conns[i];
		if (ldap_conn != NULL)
			destroy_ldap_connection(pool, &ldap_conn);
	}

	SAFE_MEM_PUT(pool->mctx, pool->conns,
		     pool->connections * sizeof(ldap_connection_t *));

	semaphore_destroy(&pool->conn_semaphore);

	MEM_PUT_AND_DETACH(pool);
}

static ldap_connection_t *
ldap_pool_getconnection(ldap_pool_t *pool)
{
	ldap_connection_t *ldap_conn;
	unsigned int i;

	REQUIRE(pool != NULL);

	semaphore_wait(&pool->conn_semaphore);
	for (i = 0; i < pool->connections; i++) {
		ldap_conn = pool->conns[i];
		if (isc_mutex_trylock(&ldap_conn->lock) == ISC_R_SUCCESS)
			break;
	}

	RUNTIME_CHECK(ldap_conn != NULL);

	INIT_LIST(ldap_conn->ldap_entries);

	return ldap_conn;
}

static void
ldap_pool_putconnection(ldap_pool_t *pool, ldap_connection_t *ldap_conn)
{
	if (ldap_conn == NULL)
		return;

	if (ldap_conn->dn) {
		ldap_memfree(ldap_conn->dn);
		ldap_conn->dn = NULL;
	}
	if (ldap_conn->values) {
		ldap_value_free(ldap_conn->values);
		ldap_conn->values = NULL;
	}
	if (ldap_conn->attribute) {
		ldap_memfree(ldap_conn->attribute);
		ldap_conn->attribute = NULL;
	}
	if (ldap_conn->ber) {
		ber_free(ldap_conn->ber, 0);
		ldap_conn->ber = NULL;
	}
	if (ldap_conn->result) {
		ldap_msgfree(ldap_conn->result);
		ldap_conn->result = NULL;
	}

	ldap_entrylist_destroy(ldap_conn->mctx, &ldap_conn->ldap_entries);

	UNLOCK(&ldap_conn->lock);
	semaphore_signal(&pool->conn_semaphore);
}

static isc_result_t
ldap_pool_connect(ldap_pool_t *pool, ldap_instance_t *ldap_inst)
{
	isc_result_t result;
	ldap_connection_t *ldap_conn;
	unsigned int i;

retry:
	for (i = 0; i < pool->connections; i++) {
		ldap_conn = NULL;
		CHECK(new_ldap_connection(pool, &ldap_conn));
		result = ldap_connect(ldap_inst, ldap_conn);
		/* If the credentials are invalid, try passwordless login. */
		if (result == ISC_R_NOPERM
		    && ldap_inst->auth_method != AUTH_NONE) {
			destroy_ldap_connection(pool, &ldap_conn);
			/* It's safe to reuse "i" here */
			for (i = 0; i < pool->connections; i++) {
				ldap_conn = pool->conns[i];
				if (ldap_conn != NULL)
					destroy_ldap_connection(pool, &ldap_conn);
			}
			ldap_inst->auth_method = AUTH_NONE;
			log_debug(2, "falling back to password-less login");
			goto retry;
		} else if (result == ISC_R_NOTCONNECTED) {
			/* LDAP server is down which can happen, continue */
			result = ISC_R_SUCCESS;
		} else if (result != ISC_R_SUCCESS) {
			goto cleanup;
		}
		pool->conns[i] = ldap_conn;
	}

	return ISC_R_SUCCESS;

cleanup:
	for (i = 0; i < pool->connections; i++) {
		ldap_conn = pool->conns[i];
		if (ldap_conn != NULL)
			destroy_ldap_connection(pool, &ldap_conn);
	}
	return result;
}

#define LDAP_CONTROL_PERSISTENTSEARCH "2.16.840.1.113730.3.4.3"
/*
 * Creates persistent search (aka psearch,
 * http://tools.ietf.org/id/draft-ietf-ldapext-psearch-03.txt) control.
 */
static isc_result_t
ldap_pscontrol_create(isc_mem_t *mctx, LDAPControl **ctrlp)
{
	BerElement *ber;
	LDAPControl *ctrl = NULL;
	isc_result_t result = ISC_R_FAILURE;

	REQUIRE(ctrlp != NULL && *ctrlp == NULL);

	ber = ber_alloc_t(LBER_USE_DER);
	if (ber == NULL)
		return ISC_R_NOMEMORY;

	/*
	 * Check the draft above, section 4 to get info about PS control
	 * format.
	 *
	 * We are interested in all changes in DNS related DNs and we
	 * want to get initial state of the "watched" LDAP subtree.
	 */
	if (ber_printf(ber, "{ibb}", 1 | 2 | 4 | 8, 0, 1) == -1)
		goto cleanup;

	CHECKED_MEM_GET(mctx, ctrl, sizeof(*ctrl));
	ZERO_PTR(ctrl);
	ctrl->ldctl_iscritical = 1;
	ctrl->ldctl_oid = strdup(LDAP_CONTROL_PERSISTENTSEARCH);
	if (ctrl->ldctl_oid == NULL)
		goto cleanup;

	if (ber_flatten2(ber, &ctrl->ldctl_value, 1) < 0)
		goto cleanup;

	ber_free(ber, 1);
	*ctrlp = ctrl;

	return ISC_R_SUCCESS;

cleanup:
	ber_free(ber, 1);
	ldap_pscontrol_destroy(mctx, &ctrl);

	return result;
}

static void
ldap_pscontrol_destroy(isc_mem_t *mctx, LDAPControl **ctrlp)
{
	LDAPControl *ctrl;

	REQUIRE(ctrlp != NULL);

	if (*ctrlp == NULL)
		return;

	ctrl = *ctrlp;
	if (ctrl->ldctl_oid != NULL)
		free(ctrl->ldctl_oid);
	SAFE_MEM_PUT(mctx, ctrl, sizeof(*ctrl));
	*ctrlp = NULL;
}
