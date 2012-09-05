/*
 * Authors: Martin Nagy <mnagy@redhat.com>
 *          Adam Tkac <atkac@redhat.com>
 *          Jiri Kuncar <jkuncar@redhat.com>
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
#include <dns/db.h>
#include <dns/zt.h>
#include <dns/byaddr.h>
#include <dns/forward.h>
#include <dns/soa.h>
#include <isc/serial.h>

#include <isc/buffer.h>
#include <isc/lex.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/region.h>
#include <isc/rwlock.h>
#include <isc/task.h>
#include <isc/thread.h>
#include <isc/time.h>
#include <isc/util.h>
#include <isc/netaddr.h>
#include <isc/parseint.h>
#include <isc/timer.h>
#include <isc/string.h>

#include <alloca.h>
#define LDAP_DEPRECATED 1
#include <ldap.h>
#include <limits.h>
#include <sasl/sasl.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <netdb.h>

#include "acl.h"
#include "krb5_helper.h"
#include "ldap_convert.h"
#include "ldap_entry.h"
#include "ldap_helper.h"
#include "log.h"
#include "rdlist.h"
#include "semaphore.h"
#include "settings.h"
#include "str.h"
#include "util.h"
#include "zone_manager.h"
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
 * Attributes in ldap_instance_t are be modified in new_ldap_instance function,
 * which means server is started or reloaded (running single-thread).
 * Before modifying at other places, switch to single-thread mode via
 * isc_task_beginexclusive() and then return back via isc_task_endexclusive()!
 *
 * ldap_connection_t structure represents connection to the LDAP database and
 * per-connection specific data. Access is controlled via
 * ldap_connection_t->lock and ldap_pool_t->conn_semaphore. Each read
 * or write access to ldap_connection_t structure (except create/destroy)
 * must acquire the semaphore and the lock.
 */

typedef struct ldap_qresult	ldap_qresult_t;
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
	isc_boolean_t		psearch;
	ld_string_t		*ldap_hostname;
	isc_task_t		*task;
	isc_thread_t		watcher;
	isc_boolean_t		exiting;
	isc_boolean_t		sync_ptr;
	isc_boolean_t		dyn_update;
	isc_boolean_t		serial_autoincrement;
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

	LDAP			*handle;
	LDAPControl		*serverctrls[2]; /* psearch/NULL or NULL/NULL */
	int			msgid;

	/* For reconnection logic. */
	isc_time_t		next_reconnect;
	unsigned int		tries;
};

/**
 * Result from single LDAP query.
 */
struct ldap_qresult {
	isc_mem_t		*mctx;
	ld_string_t		*query_string;
	LDAPMessage		*result;
	ldap_entrylist_t	ldap_entries;

	/* Parsing. */
	isc_lex_t		*lex;
	isc_buffer_t		rdata_target;
	unsigned char		*rdata_target_mem;
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

#define LDAPDB_EVENTCLASS 	ISC_EVENTCLASS(0xDDDD)
#define LDAPDB_EVENT_PSEARCH	(LDAPDB_EVENTCLASS + 0)

typedef struct ldap_psearchevent ldap_psearchevent_t;
struct ldap_psearchevent {
	ISC_EVENT_COMMON(ldap_psearchevent_t);
	isc_mem_t *mctx;
	char *dbname;
	char *dn;
	char *prevdn;
	int chgtype;
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
static isc_result_t add_soa_record(isc_mem_t *mctx, ldap_qresult_t *qresult,
		dns_name_t *origin, ldap_entry_t *entry,
		ldapdb_rdatalist_t *rdatalist, const ld_string_t *fake_mname);
static isc_result_t parse_rdata(isc_mem_t *mctx, ldap_qresult_t *qresult,
		dns_rdataclass_t rdclass, dns_rdatatype_t rdtype,
		dns_name_t *origin, const char *rdata_text,
		dns_rdata_t **rdatap);
static isc_result_t ldap_parse_rrentry(isc_mem_t *mctx, ldap_entry_t *entry,
		ldap_qresult_t *qresult, dns_name_t *origin,
		const ld_string_t *fake_mname, ld_string_t *buf,
		ldapdb_rdatalist_t *rdatalist);
static inline isc_result_t ldap_get_zone_serial(ldap_instance_t *inst,
		dns_name_t *zone_name, isc_uint32_t *serial);

static isc_result_t ldap_connect(ldap_instance_t *ldap_inst,
		ldap_connection_t *ldap_conn, isc_boolean_t force);
static isc_result_t ldap_reconnect(ldap_instance_t *ldap_inst,
		ldap_connection_t *ldap_conn, isc_boolean_t force);
static isc_result_t handle_connection_error(ldap_instance_t *ldap_inst,
		ldap_connection_t *ldap_conn, isc_boolean_t force);
static isc_result_t ldap_query(ldap_instance_t *ldap_inst, ldap_connection_t *ldap_conn,
		   ldap_qresult_t **ldap_qresultp, const char *base, int scope, char **attrs,
		   int attrsonly, const char *filter, ...);
static isc_result_t ldap_query_create(isc_mem_t *mctx, ldap_qresult_t **ldap_qresultp);
static void ldap_query_free(isc_boolean_t prepare_reuse, ldap_qresult_t **ldap_qresultp);

/* Functions for writing to LDAP. */
static isc_result_t ldap_modify_do(ldap_instance_t *ldap_inst,
		ldap_connection_t *ldap_conn, const char *dn, LDAPMod **mods,
		isc_boolean_t delete_node);
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
static isc_result_t soa_serial_increment(isc_mem_t *mctx, ldap_instance_t *inst,
		dns_name_t *zone_name);

static isc_result_t
ldap_delete_zone2(ldap_instance_t *inst, dns_name_t *name, isc_boolean_t lock);

/* Functions for maintaining pool of LDAP connections */
static isc_result_t ldap_pool_create(isc_mem_t *mctx, unsigned int connections,
		ldap_pool_t **poolp);
static void ldap_pool_destroy(ldap_pool_t **poolp);
static isc_result_t ldap_pool_getconnection(ldap_pool_t *pool,
		ldap_connection_t ** conn);
static void ldap_pool_putconnection(ldap_pool_t *pool,
		ldap_connection_t ** conn);
static isc_result_t ldap_pool_connect(ldap_pool_t *pool,
		ldap_instance_t *ldap_inst);

/* Functions for manipulating LDAP persistent search control */
static isc_result_t ldap_pscontrol_create(LDAPControl **ctrlp);

static isc_threadresult_t ldap_psearch_watcher(isc_threadarg_t arg);
static void psearch_update(ldap_instance_t *inst, ldap_entry_t *entry,
		LDAPControl **ctrls);


/* Persistent updates watcher */
static isc_threadresult_t
ldap_psearch_watcher(isc_threadarg_t arg);

isc_result_t
new_ldap_instance(isc_mem_t *mctx, const char *db_name,
		  const char * const *argv, dns_dyndb_arguments_t *dyndb_args,
		  isc_task_t *task, ldap_instance_t **ldap_instp)
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
		{ "psearch",	 default_boolean(ISC_FALSE)	},
		{ "ldap_hostname", default_string("")		},
		{ "sync_ptr",	 default_boolean(ISC_FALSE) },
		{ "dyn_update",	 default_boolean(ISC_FALSE) },
		{ "serial_autoincrement",	 default_boolean(ISC_FALSE) },
		end_of_settings
	};

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
	CHECK(str_new(mctx, &ldap_inst->ldap_hostname));

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
	ldap_settings[i++].target = &ldap_inst->psearch; 
	ldap_settings[i++].target = ldap_inst->ldap_hostname;
	ldap_settings[i++].target = &ldap_inst->sync_ptr;
	ldap_settings[i++].target = &ldap_inst->dyn_update;
	ldap_settings[i++].target = &ldap_inst->serial_autoincrement;
	CHECK(set_settings(ldap_settings, argv));

	/* Set timer for deadlock detection inside semaphore_wait_timed . */
	if (semaphore_wait_timeout.seconds < ldap_inst->timeout*SEM_WAIT_TIMEOUT_MUL)
		semaphore_wait_timeout.seconds = ldap_inst->timeout*SEM_WAIT_TIMEOUT_MUL;

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
					CHECK(str_sprintf(ldap_inst->krb5_principal,
							"DNS/%s", hostname));
					log_debug(2, "SASL mech GSSAPI defined but krb5_principal"
						"and sasl_user are empty, using default %s",
						str_buf(ldap_inst->krb5_principal));
				}
			} else {
				str_copy(ldap_inst->krb5_principal, ldap_inst->sasl_user);
			}
		}
	}

	ldap_inst->task = task;

	if (ldap_inst->psearch && ldap_inst->connections < 2) {
		/* watcher needs one and update_*() will request second */
		log_error("psearch needs at least 2 connections, "
			  "increasing limit");
		ldap_inst->connections = 2;
	}
	if (ldap_inst->serial_autoincrement == ISC_TRUE
		&& ldap_inst->psearch != ISC_TRUE) {
		log_error("SOA serial number auto-increment feature requires "
				"persistent search");
		result = ISC_R_FAILURE;
		goto cleanup;
	}

	CHECK(new_ldap_cache(mctx, argv, &ldap_inst->cache, ldap_inst->psearch));
	CHECK(ldap_pool_create(mctx, ldap_inst->connections, &ldap_inst->pool));
	CHECK(ldap_pool_connect(ldap_inst->pool, ldap_inst));

	if (ldap_inst->psearch) {
		/* Start the watcher thread */
		result = isc_thread_create(ldap_psearch_watcher, ldap_inst,
					   &ldap_inst->watcher);
		if (result != ISC_R_SUCCESS) {
			log_error("Failed to create psearch watcher thread");
			goto cleanup;
		}
	}

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
	dns_rbtnodechain_t chain;
	dns_rbt_t *rbt;
	isc_result_t result;

	REQUIRE(ldap_instp != NULL && *ldap_instp != NULL);

	ldap_inst = *ldap_instp;

	/*
	 * Unregister all zones already registered in BIND.
	 *
	 * NOTE: This should be probably done in zone_register.c
	 */
	dns_rbtnodechain_init(&chain, ldap_inst->mctx);
	rbt = zr_get_rbt(ldap_inst->zone_register);

	/* Potentially ISC_R_NOSPACE can occur. Destroy codepath has no way to
	 * return errors, so kill BIND.
	 * DNS_R_NAMETOOLONG should never happen, because all names were checked
	 * while loading. */
	result = dns_rbtnodechain_first(&chain, rbt, NULL, NULL);
	RUNTIME_CHECK(result == ISC_R_SUCCESS || result == DNS_R_NEWORIGIN
			|| result == ISC_R_NOTFOUND);

	while (result != ISC_R_NOMORE && result != ISC_R_NOTFOUND) {
		dns_fixedname_t name;
		dns_fixedname_init(&name);
		result = dns_rbtnodechain_current(&chain, NULL,
						  dns_fixedname_name(&name),
						  NULL);
                RUNTIME_CHECK(result == ISC_R_SUCCESS);

		result = ldap_delete_zone2(ldap_inst,
					   dns_fixedname_name(&name),
					   ISC_TRUE);
                RUNTIME_CHECK(result == ISC_R_SUCCESS);

		result = dns_rbtnodechain_next(&chain, NULL, NULL);
		RUNTIME_CHECK(result == ISC_R_SUCCESS ||
			      result == DNS_R_NEWORIGIN ||
			      result == ISC_R_NOMORE);
	}

	dns_rbtnodechain_invalidate(&chain);

	/* TODO: Terminate psearch watcher sooner? */
	if (ldap_inst->psearch && ldap_inst->watcher != 0) {
		ldap_inst->exiting = ISC_TRUE;
		/*
		 * Wake up the watcher thread. This might look like a hack
		 * but isc_thread_t is actually pthread_t and libisc don't
		 * have any isc_thread_kill() func.
		 *
		 * We use SIGUSR1 to not to interfere with any signal
		 * used by BIND itself.
		 */
		REQUIRE(pthread_kill(ldap_inst->watcher, SIGUSR1) == 0);
		RUNTIME_CHECK(isc_thread_join(ldap_inst->watcher, NULL)
			      == ISC_R_SUCCESS);
		ldap_inst->watcher = 0;
	}

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
	str_destroy(&ldap_inst->ldap_hostname);

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

	CHECK(ldap_pscontrol_create(&ldap_conn->serverctrls[0]));

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

	REQUIRE(ldap_connp != NULL);

	ldap_conn = *ldap_connp;
	if (ldap_conn == NULL)
		return;

	DESTROYLOCK(&ldap_conn->lock);
	if (ldap_conn->handle != NULL)
		ldap_unbind_ext_s(ldap_conn->handle, NULL, NULL);

	if (ldap_conn->serverctrls[0] != NULL) {
		ldap_control_free(ldap_conn->serverctrls[0]);
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
publish_zone(ldap_instance_t *inst, dns_zone_t *zone)
{
	isc_result_t result;
	isc_boolean_t freeze = ISC_FALSE;

	REQUIRE(inst != NULL);
	REQUIRE(zone != NULL);

	if (inst->view->frozen) {
		freeze = ISC_TRUE;
		dns_view_thaw(inst->view);
	}

	dns_zone_setview(zone, inst->view);
	result = dns_zonemgr_managezone(inst->zmgr, zone);
	if (result != ISC_R_SUCCESS)
		return result;
	CHECK(dns_view_addzone(inst->view, zone));

cleanup:
	if (result != ISC_R_SUCCESS)
		dns_zonemgr_releasezone(inst->zmgr, zone);

	if (freeze)
		dns_view_freeze(inst->view);

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

/* Delete zone by dns zone name */
static isc_result_t
ldap_delete_zone2(ldap_instance_t *inst, dns_name_t *name, isc_boolean_t lock)
{
	isc_result_t result;
	isc_boolean_t unlock = ISC_FALSE;
	isc_boolean_t freeze = ISC_FALSE;
	dns_zone_t *zone = NULL;
	dns_zone_t *foundzone = NULL;

	if (lock) {
		result = isc_task_beginexclusive(inst->task);
		RUNTIME_CHECK(result == ISC_R_SUCCESS ||
			      result == ISC_R_LOCKBUSY);
		if (result == ISC_R_SUCCESS)
			unlock = ISC_TRUE;

		/* TODO: flush cache records belonging to deleted zone */
		CHECK(discard_from_cache(inst->cache, name));
	}

	result = zr_get_zone_ptr(inst->zone_register, name, &zone);
	if (result == ISC_R_NOTFOUND) {
		result = ISC_R_SUCCESS;
		goto cleanup;
	} else if (result != ISC_R_SUCCESS)
		goto cleanup;

	CHECK(dns_view_findzone(inst->view, name, &foundzone));
	/* foundzone != zone indicates a bug */
	RUNTIME_CHECK(foundzone == zone);
	dns_zone_detach(&foundzone);

	if (lock) {
		dns_view_thaw(inst->view);
		freeze = ISC_TRUE;
	}

	/* Do not unload partially loaded zones, they have incomplete structures. */
	dns_db_t *dbp = NULL;
	if (dns_zone_getdb(zone, &dbp) == ISC_R_SUCCESS) {
		dns_db_detach(&dbp); /* dns_zone_getdb() attaches DB implicitly */
		dns_zone_unload(zone);
	}
	CHECK(dns_zt_unmount(inst->view->zonetable, zone));
	CHECK(zr_del_zone(inst->zone_register, name));
	dns_zonemgr_releasezone(inst->zmgr, zone);
	dns_zone_detach(&zone);

cleanup:
	if (freeze)
		dns_view_freeze(inst->view);
	if (unlock)
		isc_task_endexclusive(inst->task);

	return result;
}

/* Delete zone */
static isc_result_t
ldap_delete_zone(ldap_instance_t *inst, const char *dn, isc_boolean_t lock)
{
	isc_result_t result;
	dns_name_t name;
	dns_name_init(&name, NULL);
	
	CHECK(dn_to_dnsname(inst->mctx, dn, &name, NULL));

	result = ldap_delete_zone2(inst, &name, lock);

cleanup:
	if (dns_name_dynamic(&name))
		dns_name_free(&name, inst->mctx);

	return result;
}



static isc_result_t
configure_zone_forwarders(ldap_entry_t *entry, ldap_instance_t *inst, 
                          dns_name_t *name, ldap_valuelist_t *values)
{
	const char *dn = entry->dn;
	isc_result_t result;
	ldap_value_t *value;
	isc_sockaddrlist_t addrs;

	REQUIRE(entry != NULL && inst != NULL && name != NULL && values != NULL);

	/* Clean old fwdtable. */
	result = dns_fwdtable_delete(inst->view->fwdtable, name);
	if (result != ISC_R_SUCCESS && result != ISC_R_NOTFOUND) {
		log_error("Failed to update forwarders");
		return ISC_R_FAILURE;
	}

	if (EMPTY(*values)) {
		log_debug(1, "Forwarders are empty for '%s'", dn);
		return ISC_R_SUCCESS;
	}

	ISC_LIST_INIT(addrs);
	for (value = HEAD(*values); value != NULL; value = NEXT(value, link)) {
		isc_sockaddr_t *addr = NULL;
		char forwarder_txt[ISC_SOCKADDR_FORMATSIZE];

		if( acl_parse_forwarder(value->value, inst->mctx, &addr)
				!= ISC_R_SUCCESS) {
			log_error("Could not parse forwarder '%s'", value->value);
			continue;
		}

		ISC_LINK_INIT(addr, link);
		ISC_LIST_APPEND(addrs, addr, link);
		isc_sockaddr_format(addr, forwarder_txt, ISC_SOCKADDR_FORMATSIZE);
		log_debug(5, "Adding forwarder %s for %s", forwarder_txt, dn);
	}

	/*
	 * Fetch forward policy.
	 */
	dns_fwdpolicy_t fwdpolicy = dns_fwdpolicy_first; /* "first" is default option. */
	result = ldap_entry_getvalues(entry, "idnsForwardPolicy", values);
	if (result == ISC_R_SUCCESS) {
		value = HEAD(*values);
		/*
		 * fwdpolicy: "only" or "first" (default)
		 */
		if (value != NULL && value->value != NULL &&
		    strcmp(value->value, "only") == 0)
			fwdpolicy = dns_fwdpolicy_only;
	}

	if (ISC_LIST_EMPTY(addrs)) {
		log_debug(5, "No forwarders seen; disabling forwarding");
		fwdpolicy = dns_fwdpolicy_none;
	}

	log_debug(5, "Forward policy: %d", fwdpolicy);
		
	/* Set forward table up. */
	result = dns_fwdtable_add(inst->view->fwdtable, name, &addrs, fwdpolicy);

	while (!ISC_LIST_EMPTY(addrs)) {
		isc_sockaddr_t *addr = NULL;
		addr = ISC_LIST_HEAD(addrs);
		ISC_LIST_UNLINK(addrs, addr, link);
		isc_mem_put(inst->mctx, addr, sizeof(*addr));
	}

	return result;
}

/* Parse the config object entry */
static isc_result_t
ldap_parse_configentry(ldap_entry_t *entry, ldap_instance_t *inst)
{
	isc_result_t result;
	ldap_valuelist_t values;
	isc_boolean_t sync_ptr_new;
	isc_timer_t *timer_inst;
	isc_interval_t timer_interval;
	isc_uint32_t interval_sec;
	isc_timertype_t timer_type;

	/* BIND functions are thread safe, lock only ldap instance 'inst'. */

	log_debug(3, "Parsing configuration object");

	/* idnsForwardPolicy change is handled by configure_zone_forwarders() */
	result = ldap_entry_getvalues(entry, "idnsForwarders", &values);
	if (result == ISC_R_SUCCESS) {
		log_debug(2, "Setting global forwarders");
		result = configure_zone_forwarders(entry, inst, dns_rootname, &values);
		if (result != ISC_R_SUCCESS) {
			log_error("Global forwarder could not be set up.");
		}
	}

	result = ldap_entry_getvalues(entry, "idnsAllowSyncPTR", &values);
	if (result == ISC_R_SUCCESS) {
		log_debug(2, "Setting global AllowSyncPTR = %s", HEAD(values)->value);
		sync_ptr_new = (strcmp(HEAD(values)->value, "TRUE") == 0)
						? ISC_TRUE : ISC_FALSE;

		if (inst->sync_ptr != sync_ptr_new) { /* lock BIND only if necessary */
			result = isc_task_beginexclusive(inst->task);
			RUNTIME_CHECK(result == ISC_R_SUCCESS ||
							result == ISC_R_LOCKBUSY);
			inst->sync_ptr = sync_ptr_new;
			if (result == ISC_R_SUCCESS) {
				isc_task_endexclusive(inst->task);
			}
		}
	}

	result = ldap_entry_getvalues(entry, "idnsZoneRefresh", &values);
	if (result == ISC_R_SUCCESS) {
		log_debug(2, "Setting global ZoneRefresh timer = %s", HEAD(values)->value);
		RUNTIME_CHECK(manager_get_db_timer(inst->db_name, &timer_inst) == ISC_R_SUCCESS);

		result = isc_parse_uint32(&interval_sec, HEAD(values)->value, 10);
		if (result != ISC_R_SUCCESS) {
			log_error("Could not parse ZoneRefresh interval");
			goto cleanup;
		}
		isc_interval_set(&timer_interval, interval_sec, 0);
		/* update interval only, not timer type */
		timer_type = isc_timer_gettype(timer_inst);
		result = isc_timer_reset(timer_inst, timer_type, NULL,
				&timer_interval, ISC_TRUE);
		if (result != ISC_R_SUCCESS) {
			log_error("Could not adjust ZoneRefresh timer");
			goto cleanup;
		}
	}

cleanup:
	/* Configuration errors are not fatal. */
	return ISC_R_SUCCESS;   
}

/* Parse the zone entry */
static isc_result_t
ldap_parse_zoneentry(ldap_entry_t *entry, ldap_instance_t *inst)
{
	const char *dn;
	ldap_valuelist_t values;
	dns_name_t name;
	dns_zone_t *zone = NULL;
	isc_result_t result;
	isc_boolean_t unlock = ISC_FALSE;
	isc_boolean_t publish = ISC_FALSE;
	isc_task_t *task = inst->task;
	isc_uint32_t ldap_serial;
	isc_uint32_t zr_serial;	/* SOA serial value from in-memory zone register */
	unsigned char ldap_digest[RDLIST_DIGESTLENGTH];
	unsigned char *zr_digest = NULL;
	ldapdb_rdatalist_t rdatalist;

	REQUIRE(entry != NULL);
	REQUIRE(inst != NULL);

	dns_name_init(&name, NULL);
	INIT_LIST(rdatalist);

	/* Derive the dns name of the zone from the DN. */
	dn = entry->dn;
	CHECK(dn_to_dnsname(inst->mctx, dn, &name, NULL));

	result = isc_task_beginexclusive(task);
	RUNTIME_CHECK(result == ISC_R_SUCCESS || result == ISC_R_LOCKBUSY);
	if (result == ISC_R_SUCCESS)
		unlock = ISC_TRUE;

	CHECK(discard_from_cache(inst->cache, &name));

	/* 
	 * Fetch forwarders. 
	 * Forwarding has top priority hence when the forwarders are properly
	 * set up all others attributes are ignored.
	 */
	result = ldap_entry_getvalues(entry, "idnsForwarders", &values);
	if (result == ISC_R_SUCCESS) {
		log_debug(2, "Setting forwarders for %s", dn);
		CHECK(configure_zone_forwarders(entry, inst, &name, &values));
		/* DO NOT CHANGE ANYTHING ELSE after forwarders are set up! */
		goto cleanup;
	} else {
		/* No forwarders are used. Remove zone from fwdtable. */
		CHECK(configure_zone_forwarders(entry, inst, &name, &values));
	}

	/* Check if we are already serving given zone */
	result = zr_get_zone_ptr(inst->zone_register, &name, &zone);
	if (result != ISC_R_SUCCESS) { /* TODO: What about other errors? */
		CHECK(create_zone(inst, &name, &zone));
		CHECK(zr_add_zone(inst->zone_register, zone, dn));
		publish = ISC_TRUE;
		log_debug(2, "created zone %p: %s", zone, dn);
	}

	log_debug(2, "Setting SSU table for %p: %s", zone, dn);
	/* Get the update policy and update the zone with it. */
	result = ldap_entry_getvalues(entry, "idnsUpdatePolicy", &values);
	if (result == ISC_R_SUCCESS)
		CHECK(configure_zone_ssutable(zone, HEAD(values)->value));
	else
		CHECK(configure_zone_ssutable(zone, NULL));

	/* Fetch allow-query and allow-transfer ACLs */
	log_debug(2, "Setting allow-query for %p: %s", zone, dn);
	result = ldap_entry_getvalues(entry, "idnsAllowQuery", &values);
	if (result == ISC_R_SUCCESS) {
		dns_acl_t *queryacl = NULL;
		CHECK(acl_from_ldap(inst->mctx, HEAD(values)->value,
		      acl_type_query, &queryacl));
		dns_zone_setqueryacl(zone, queryacl);
		dns_acl_detach(&queryacl);
	} else {
		log_debug(2, "allow-query not set");
		dns_zone_clearqueryacl(zone);
	}

	log_debug(2, "Setting allow-transfer for %p: %s", zone, dn);
	result = ldap_entry_getvalues(entry, "idnsAllowTransfer", &values);
	if (result == ISC_R_SUCCESS) {
		dns_acl_t *transferacl = NULL;
		CHECK(acl_from_ldap(inst->mctx, HEAD(values)->value,
		      acl_type_transfer, &transferacl));
		dns_zone_setxfracl(zone, transferacl);
		dns_acl_detach(&transferacl);
	} else {
		log_debug(2, "allow-transfer not set");
		dns_zone_clearxfracl(zone);
	}

	if (publish) {
		/* Everything is set correctly, publish zone */
		CHECK(publish_zone(inst, zone));
	}

	/*
	 * Don't bother if load fails, server will return
	 * SERVFAIL for queries beneath this zone. This is
	 * admin's problem.
	 */
	result = dns_zone_load(zone);
	if (result != ISC_R_SUCCESS && result != DNS_R_UPTODATE
		&& result != DNS_R_DYNAMIC && result != DNS_R_CONTINUE)
		goto cleanup;

	result = ISC_R_SUCCESS;

	/* initialize serial in zone register and always increment serial
	 * for a new zone (typically after BIND start)
	 * - the zone was possibly changed in meanwhile */
	if (publish) {
		memset(ldap_digest, 0, RDLIST_DIGESTLENGTH);
		CHECK(ldap_get_zone_serial(inst, &name, &ldap_serial));
		CHECK(zr_set_zone_serial_digest(inst->zone_register, &name, ldap_serial,
				ldap_digest));
	}

	/* SOA serial autoincrement feature for SOA record:
	 * 1) Remember old (already processed) SOA serial and digest computed from
	 *    zone root records in zone register.
	 * 2) After each change notification compare the old and new SOA serials
	 *    and recomputed digests. If:
	 * 3a) Nothing was changed (false change notification received) - do nothing
	 * 3b) Serial was changed - remember the new serial and recompute digest,
	 *     do not autoincrement (respect external change).
	 * 3c) The old and new serials are same: autoincrement only if something
	 *     else was changed.
	 */
	if (inst->serial_autoincrement) {
		CHECK(ldap_get_zone_serial(inst, &name, &ldap_serial));
		CHECK(ldapdb_rdatalist_get(inst->mctx, inst, &name,
				&name, &rdatalist));
		CHECK(rdatalist_digest(inst->mctx, &rdatalist, ldap_digest));

		CHECK(zr_get_zone_serial_digest(inst->zone_register, &name, &zr_serial,
				&zr_digest));
		if (ldap_serial == zr_serial) {
			/* serials are same - increment only if something was changed */
			if (memcmp(zr_digest, ldap_digest, RDLIST_DIGESTLENGTH) != 0)
				CHECK(soa_serial_increment(inst->mctx, inst, &name));
		} else { /* serial in LDAP was changed - update zone register */
			CHECK(zr_set_zone_serial_digest(inst->zone_register, &name,
					ldap_serial, ldap_digest));
		}
	}

cleanup:
	if (unlock)
		isc_task_endexclusive(task);
	if (dns_name_dynamic(&name))
		dns_name_free(&name, inst->mctx);
	if (zone != NULL)
		dns_zone_detach(&zone);
	ldapdb_rdatalist_destroy(inst->mctx, &rdatalist);

	return result;
}

/*
 * Search in LDAP for zones. If 'create' is true, create the zones. Otherwise,
 * we assume that we are past the configuration phase and no new zones can be
 * added. In that case, only modify the zone's properties, like the update
 * policy.
 *
 * @param delete_only Do LDAP vs. zone register cross-check and delete zones
 *                    which aren't in LDAP, but do not load new zones.
 *
 * Returns ISC_R_SUCCESS if we found and successfully added at least one zone.
 * Returns ISC_R_FAILURE otherwise.
 */
isc_result_t
refresh_zones_from_ldap(ldap_instance_t *ldap_inst, isc_boolean_t delete_only)
{
	isc_result_t result = ISC_R_SUCCESS;
	ldap_connection_t *ldap_conn = NULL;
	ldap_qresult_t *ldap_config_qresult = NULL;
	ldap_qresult_t *ldap_zones_qresult = NULL;
	int zone_count = 0;
	ldap_entry_t *entry;
	dns_rbt_t *rbt = NULL;
	isc_boolean_t invalidate_nodechain = ISC_FALSE;
	char *config_attrs[] = {
		"idnsForwardPolicy", "idnsForwarders", 
		"idnsAllowSyncPTR", "idnsZoneRefresh",
		"idnsPersistentSearch", NULL
	};
	char *zone_attrs[] = {
		"idnsName", "idnsUpdatePolicy", "idnsAllowQuery",
		"idnsAllowTransfer", "idnsForwardPolicy", 
		"idnsForwarders", NULL
	};

	REQUIRE(ldap_inst != NULL);

	if (ldap_inst->psearch && !delete_only) {
		/* Watcher does the work for us, but deletion is allowed. */
		return ISC_R_SUCCESS;
	}

	log_debug(2, "refreshing list of zones for %s", ldap_inst->db_name);

	/* Query for configuration and zones from LDAP and release LDAP connection
	 * before processing them. It prevents deadlock in situations where
	 * ldap_parse_zoneentry() requests another connection. */
	CHECK(ldap_pool_getconnection(ldap_inst->pool, &ldap_conn));
	CHECK(ldap_query(ldap_inst, ldap_conn, &ldap_config_qresult, str_buf(ldap_inst->base),
			 LDAP_SCOPE_SUBTREE, config_attrs, 0,
			 "(objectClass=idnsConfigObject)"));
	CHECK(ldap_query(ldap_inst, ldap_conn, &ldap_zones_qresult, str_buf(ldap_inst->base),
			 LDAP_SCOPE_SUBTREE, zone_attrs, 0,
			 "(&(objectClass=idnsZone)(idnsZoneActive=TRUE))"));
	ldap_pool_putconnection(ldap_inst->pool, &ldap_conn);

	for (entry = HEAD(ldap_config_qresult->ldap_entries);
	     entry != NULL;
	     entry = NEXT(entry, link)) {
		CHECK(ldap_parse_configentry(entry, ldap_inst));
	}

	/*
	 * Create RB-tree with all zones stored in LDAP for cross check
	 * with registered zones in plugin.
	 */
	CHECK(dns_rbt_create(ldap_inst->mctx, NULL, NULL, &rbt));
	
	for (entry = HEAD(ldap_zones_qresult->ldap_entries);
	     entry != NULL;
	     entry = NEXT(entry, link)) {

		/* Derive the dns name of the zone from the DN. */
		dns_name_t name;
		dns_name_init(&name, NULL);
		result = dn_to_dnsname(ldap_inst->mctx, entry->dn, &name, NULL);
		if (result == ISC_R_SUCCESS) {
			log_debug(5, "Refresh %s", entry->dn);
			/* Add found zone to RB-tree for later check. */
			result = dns_rbt_addname(rbt, &name, NULL);
		}
		if (dns_name_dynamic(&name))
			dns_name_free(&name, ldap_inst->mctx);
		
		if (result != ISC_R_SUCCESS) {
			log_error("Could not parse zone %s", entry->dn);
			continue;
		}

		if (!delete_only)
			CHECK(ldap_parse_zoneentry(entry, ldap_inst));
		zone_count++;
	}

	dns_rbtnode_t *node;
	dns_rbtnodechain_t chain;
	isc_boolean_t delete = ISC_FALSE;	
	
	DECLARE_BUFFERED_NAME(fname);
	DECLARE_BUFFERED_NAME(forig);
	DECLARE_BUFFERED_NAME(aname);
	
	INIT_BUFFERED_NAME(fname);
	INIT_BUFFERED_NAME(forig);
	INIT_BUFFERED_NAME(aname);
	
	dns_rbtnodechain_init(&chain, ldap_inst->mctx);
	invalidate_nodechain = ISC_TRUE;
	result = dns_rbtnodechain_first(&chain, zr_get_rbt(ldap_inst->zone_register), NULL, NULL);
	
	while (result == DNS_R_NEWORIGIN || result == ISC_R_SUCCESS) {
		
		delete = ISC_FALSE;	
		node = NULL;
		
		result = dns_rbtnodechain_current(&chain, &fname, &forig, &node);
		if (result != ISC_R_SUCCESS) {
			if (result != ISC_R_NOTFOUND)
				log_error_r(
					"unable to walk through RB-tree during zone_refresh");
			goto next;
		}

		if (dns_name_concatenate(&fname, &forig, &aname, aname.buffer)
				!= ISC_R_SUCCESS) {
			log_error_r("unable to concatenate DNS names during zone_refresh");
			goto next;	
		}

		/* Do not remove auxiliary (= non-zone) nodes. */
		char buf[DNS_NAME_FORMATSIZE];
		dns_name_format(&aname, buf, DNS_NAME_FORMATSIZE);
		if (!node->data) {
			log_debug(11,"auxiliary zone/node '%s' will not be removed", buf);
			goto next;
		}

		DECLARE_BUFFERED_NAME(foundname);
		INIT_BUFFERED_NAME(foundname);
		
		void *data = NULL;
		if (dns_rbt_findname(rbt, &aname, DNS_RBTFIND_EMPTYDATA,
		                     &foundname, &data) == ISC_R_SUCCESS) {
			goto next;		
		}
		/* Log zone removing. */
		log_debug(1, "Zone '%s' has been removed from database.", buf);
		
		delete = ISC_TRUE;
next:	
		result = dns_rbtnodechain_next(&chain, NULL, NULL);
	
		if (delete == ISC_TRUE)
			ldap_delete_zone2(ldap_inst, &aname, ISC_FALSE);
	}


cleanup:
	if (rbt != NULL)
		dns_rbt_destroy(&rbt); 

	if (invalidate_nodechain)
		dns_rbtnodechain_invalidate(&chain);

	ldap_query_free(ISC_FALSE, &ldap_config_qresult);
	ldap_query_free(ISC_FALSE, &ldap_zones_qresult);
	ldap_pool_putconnection(ldap_inst->pool, &ldap_conn);

	log_debug(2, "finished refreshing list of zones");

	if (zone_count > 0)
		return ISC_R_SUCCESS;
	else
		return ISC_R_FAILURE;
}

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
		   ldap_qresult_t *qresult, dns_name_t *origin,
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

	result = add_soa_record(mctx, qresult, origin, entry,
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
			CHECK(parse_rdata(mctx, qresult, rdclass,
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
ldapdb_nodelist_get(isc_mem_t *mctx, ldap_instance_t *ldap_inst, dns_name_t *name,
		     dns_name_t *origin, ldapdb_nodelist_t *nodelist)
{
	isc_result_t result;
	ldap_qresult_t *ldap_qresult = NULL;
	ldap_entry_t *entry;
	ld_string_t *string = NULL;
	ldapdb_node_t *node;
	dns_name_t node_name;

	REQUIRE(ldap_inst != NULL);
	REQUIRE(name != NULL);
	REQUIRE(nodelist != NULL);

	/* RRs aren't in the cache, perform ordinary LDAP query */
	INIT_LIST(*nodelist);
	CHECK(str_new(mctx, &string));
	CHECK(dnsname_to_dn(ldap_inst->zone_register, name, string));

	CHECK(ldap_query(ldap_inst, NULL, &ldap_qresult, str_buf(string),
			 LDAP_SCOPE_SUBTREE, NULL, 0, "(objectClass=idnsRecord)"));

	if (EMPTY(ldap_qresult->ldap_entries)) {
		result = ISC_R_NOTFOUND;
		goto cleanup;
	}

	for (entry = HEAD(ldap_qresult->ldap_entries);
		entry != NULL;
		entry = NEXT(entry, link)) {
		node = NULL;	
		dns_name_init(&node_name, NULL);
		if (dn_to_dnsname(mctx, entry->dn,  &node_name, NULL)
		    != ISC_R_SUCCESS) {
			log_error("Failed to parse dn %s", entry->dn);
			continue;
		}

		result = ldapdbnode_create(mctx, &node_name, &node);
		dns_name_free(&node_name, mctx);
		if (result == ISC_R_SUCCESS) {
			result = ldap_parse_rrentry(mctx, entry, ldap_qresult,
		                       origin, ldap_inst->fake_mname,
		                       string, &node->rdatalist);
		}
		if (result != ISC_R_SUCCESS) {
			log_error("Failed to parse RR entry (%s)", str_buf(string));
			/* node cleaning */	
			dns_name_reset(&node->owner);
			ldapdb_rdatalist_destroy(mctx, &node->rdatalist);
			SAFE_MEM_PUT_PTR(mctx, node);
			continue;
		}
		INIT_LINK(node, link);
		APPEND(*nodelist, node, link);
	}

	result = ISC_R_SUCCESS;

cleanup:
	ldap_query_free(ISC_FALSE, &ldap_qresult);
	str_destroy(&string);

	return result;
}

isc_result_t
ldapdb_rdatalist_get(isc_mem_t *mctx, ldap_instance_t *ldap_inst, dns_name_t *name,
		     dns_name_t *origin, ldapdb_rdatalist_t *rdatalist)
{
	isc_result_t result;
	ldap_qresult_t *ldap_qresult = NULL;
	ldap_entry_t *entry;
	ld_string_t *string = NULL;
	ldap_cache_t *cache;

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
	INIT_LIST(*rdatalist);
	CHECK(str_new(mctx, &string));
	CHECK(dnsname_to_dn(ldap_inst->zone_register, name, string));

	CHECK(ldap_query(ldap_inst, NULL, &ldap_qresult, str_buf(string),
			 LDAP_SCOPE_BASE, NULL, 0, "(objectClass=idnsRecord)"));

	if (EMPTY(ldap_qresult->ldap_entries)) {
		result = ISC_R_NOTFOUND;
		goto cleanup;
	}

	for (entry = HEAD(ldap_qresult->ldap_entries);
		entry != NULL;
		entry = NEXT(entry, link)) {
		if (ldap_parse_rrentry(mctx, entry, ldap_qresult,
		                       origin, ldap_inst->fake_mname,
		                       string, rdatalist) != ISC_R_SUCCESS ) {
			log_error("Failed to parse RR entry (%s)", str_buf(string));
		}
	}

	if (!EMPTY(*rdatalist)) {
		/* Cache RRs */
		CHECK(ldap_cache_addrdatalist(cache, name, rdatalist));
		/* result = ISC_R_SUCCESS; - Performed by above call */
	} else
		result = ISC_R_NOTFOUND;

cleanup:
	ldap_query_free(ISC_FALSE, &ldap_qresult);
	str_destroy(&string);

	if (result != ISC_R_SUCCESS)
		ldapdb_rdatalist_destroy(mctx, rdatalist);

	return result;
}

static isc_result_t
add_soa_record(isc_mem_t *mctx, ldap_qresult_t *qresult, dns_name_t *origin,
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
	CHECK(parse_rdata(mctx, qresult, rdclass, dns_rdatatype_soa, origin,
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
parse_rdata(isc_mem_t *mctx, ldap_qresult_t *qresult,
	    dns_rdataclass_t rdclass, dns_rdatatype_t rdtype,
	    dns_name_t *origin, const char *rdata_text, dns_rdata_t **rdatap)
{
	isc_result_t result;
	isc_consttextregion_t text;
	isc_buffer_t lex_buffer;
	isc_region_t rdatamem;
	dns_rdata_t *rdata;

	REQUIRE(qresult != NULL);
	REQUIRE(rdata_text != NULL);
	REQUIRE(rdatap != NULL);

	rdata = NULL;
	rdatamem.base = NULL;

	text.base = rdata_text;
	text.length = strlen(text.base);

	isc_buffer_init(&lex_buffer, text.base, text.length);
	isc_buffer_add(&lex_buffer, text.length);
	isc_buffer_setactive(&lex_buffer, text.length);

	CHECK(isc_lex_openbuffer(qresult->lex, &lex_buffer));

	isc_buffer_init(&qresult->rdata_target, qresult->rdata_target_mem,
			MINTSIZ);
	CHECK(dns_rdata_fromtext(NULL, rdclass, rdtype, qresult->lex, origin,
				 0, mctx, &qresult->rdata_target, NULL));

	CHECKED_MEM_GET_PTR(mctx, rdata);
	dns_rdata_init(rdata);

	rdatamem.length = isc_buffer_usedlength(&qresult->rdata_target);
	CHECKED_MEM_GET(mctx, rdatamem.base, rdatamem.length);

	memcpy(rdatamem.base, isc_buffer_base(&qresult->rdata_target),
	       rdatamem.length);
	dns_rdata_fromregion(rdata, rdclass, rdtype, &rdatamem);

	isc_lex_close(qresult->lex);

	*rdatap = rdata;
	return ISC_R_SUCCESS;

cleanup:
	isc_lex_close(qresult->lex);
	if (rdata != NULL)
		isc_mem_put(mctx, rdata, sizeof(*rdata));
	if (rdatamem.base != NULL)
		isc_mem_put(mctx, rdatamem.base, rdatamem.length);

	return result;
}

/**
 * @param ldap_conn    A LDAP connection structure obtained via ldap_get_connection().
 * @param ldap_qresult New ldap_qresult structure will be allocated and pointer
 *                     to it will be returned through this parameter. The result
 *                     has to be freed by caller via ldap_query_free().
 */
static isc_result_t
ldap_query(ldap_instance_t *ldap_inst, ldap_connection_t *ldap_conn,
	   ldap_qresult_t **ldap_qresultp, const char *base, int scope, char **attrs,
	   int attrsonly, const char *filter, ...)
{
	va_list ap;
	isc_result_t result;
	ldap_qresult_t *ldap_qresult = NULL;
	int cnt;
	int ret;
	int ldap_err_code;
	int once = 0;
	isc_boolean_t autoconn = (ldap_conn == NULL);

	REQUIRE(ldap_inst != NULL);
	REQUIRE(base != NULL);
	REQUIRE(ldap_qresultp != NULL && *ldap_qresultp == NULL);

	CHECK(ldap_query_create(ldap_inst->mctx, &ldap_qresult));
	if (autoconn)
		CHECK(ldap_pool_getconnection(ldap_inst->pool, &ldap_conn));

	va_start(ap, filter);
	str_vsprintf(ldap_qresult->query_string, filter, ap);
	va_end(ap);

	log_debug(2, "querying '%s' with '%s'", base,
		  str_buf(ldap_qresult->query_string));

	if (ldap_conn->handle == NULL) {
		/*
		 * handle can be NULL when the first connection to LDAP wasn't
		 * successful
		 * TODO: handle this case inside ldap_pool_getconnection()?
		 */
		CHECK(ldap_connect(ldap_inst, ldap_conn, ISC_FALSE));
	}

retry:
	ret = ldap_search_ext_s(ldap_conn->handle, base, scope,
				str_buf(ldap_qresult->query_string),
				attrs, attrsonly, NULL, NULL, NULL,
				LDAP_NO_LIMIT, &ldap_qresult->result);
	if (ret == 0) {
		ldap_conn->tries = 0;
		cnt = ldap_count_entries(ldap_conn->handle, ldap_qresult->result);
		log_debug(2, "entry count: %d", cnt);

		result = ldap_entrylist_create(ldap_conn->mctx,
					       ldap_conn->handle,
					       ldap_qresult->result,
					       &ldap_qresult->ldap_entries);
		if (result != ISC_R_SUCCESS) {
			log_error("failed to save LDAP query results");
			goto cleanup;
		}
		/* LDAP call suceeded, errors from ldap_entrylist_create() will be
		 * handled in cleanup section */

	} else { /* LDAP error - continue with error handler */
		result = ISC_R_FAILURE;
		ret = ldap_get_option(ldap_conn->handle, LDAP_OPT_RESULT_CODE,
					  (void *)&ldap_err_code);
		if (ret == LDAP_OPT_SUCCESS && ldap_err_code == LDAP_NO_SUCH_OBJECT) {
			result = ISC_R_NOTFOUND;
		} else if (!once) {
			/* some error happened during ldap_search, try to recover */
			once++;
			result = handle_connection_error(ldap_inst, ldap_conn,
							 ISC_FALSE);
			if (result == ISC_R_SUCCESS)
				goto retry;
		}
	}

cleanup:
	if (autoconn)
		ldap_pool_putconnection(ldap_inst->pool, &ldap_conn);
	if (result != ISC_R_SUCCESS) {
		ldap_query_free(ISC_FALSE, &ldap_qresult);
	} else {
		*ldap_qresultp = ldap_qresult;
	}
	return result;
}

/**
 * Allocate and initialize new ldap_qresult structure.
 * @param[out] ldap_qresultp Newly allocated ldap_qresult structure.
 * @return ISC_R_SUCCESS or ISC_R_NOMEMORY (from CHECKED_MEM_GET_PTR)
 */
static isc_result_t
ldap_query_create(isc_mem_t *mctx, ldap_qresult_t **ldap_qresultp) {
	ldap_qresult_t *ldap_qresult = NULL;
	isc_result_t result;

	CHECKED_MEM_GET_PTR(mctx, ldap_qresult);
	ZERO_PTR(ldap_qresult);
	ldap_qresult->mctx = mctx;
	INIT_LIST(ldap_qresult->ldap_entries);
	CHECK(str_new(mctx, &ldap_qresult->query_string));

	CHECKED_MEM_GET(ldap_qresult->mctx, ldap_qresult->rdata_target_mem, MINTSIZ);
	CHECK(isc_lex_create(ldap_qresult->mctx, TOKENSIZ, &ldap_qresult->lex));

	*ldap_qresultp = ldap_qresult;
	return ISC_R_SUCCESS;

cleanup:
	if (ldap_qresult != NULL) {
		str_destroy(&ldap_qresult->query_string);
		SAFE_MEM_PUT(ldap_qresult->mctx, ldap_qresult->rdata_target_mem, MINTSIZ);
		if (ldap_qresult->lex != NULL)
			isc_lex_destroy(&ldap_qresult->lex);
		SAFE_MEM_PUT_PTR(mctx, ldap_qresult);
	}

	return result;
}

/**
 * Free LDAP query result. Can free the whole structure or internal parts only.
 * Freeing internal parts is suitable before reusing the structure.
 * @param[in] prepare_reuse ISC_TRUE implies freeing internal parts,
 *                          but not the whole structure.
 * @param[in,out] ldap_qresultp Pointer to freed query. Will be set to NULL
 *                              if prepare_reuse == ISC_FALSE.
 */
static void
ldap_query_free(isc_boolean_t prepare_reuse, ldap_qresult_t **ldap_qresultp)
{
	ldap_qresult_t *qresult;
	REQUIRE(ldap_qresultp != NULL);

	qresult = *ldap_qresultp;

	if (qresult == NULL)
		return;

	if (qresult->result) {
		ldap_msgfree(qresult->result);
		qresult->result = NULL;
	}

	ldap_entrylist_destroy(qresult->mctx, &qresult->ldap_entries);

	if (prepare_reuse) {
		str_clear(qresult->query_string);
		INIT_LIST(qresult->ldap_entries);
		isc_lex_close(qresult->lex);
	} else { /* free the whole structure */
		str_destroy(&qresult->query_string);
		if (qresult->lex != NULL)
			isc_lex_destroy(&qresult->lex);
		if (qresult->rdata_target_mem != NULL)
			isc_mem_put(qresult->mctx, qresult->rdata_target_mem, MINTSIZ);
		SAFE_MEM_PUT_PTR(qresult->mctx, qresult);
		*ldap_qresultp = NULL;
	}
}

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
ldap_connect(ldap_instance_t *ldap_inst, ldap_connection_t *ldap_conn,
	     isc_boolean_t force)
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

	if (str_len(ldap_inst->ldap_hostname) > 0) {
		ret = ldap_set_option(ld, LDAP_OPT_HOST_NAME,
				      str_buf(ldap_inst->ldap_hostname));
		LDAP_OPT_CHECK(ret, "failed to set LDAP_OPT_HOST_NAME");
	}

	if (ldap_conn->handle != NULL)
		ldap_unbind_ext_s(ldap_conn->handle, NULL, NULL);
	ldap_conn->handle = ld;

	return ldap_reconnect(ldap_inst, ldap_conn, force);

cleanup:

	if (ld != NULL)
		ldap_unbind_ext_s(ld, NULL, NULL);
	
	/* Make sure handle is NULL. */
	if (ldap_conn->handle != NULL) {
		ldap_unbind_ext_s(ldap_conn->handle, NULL, NULL);
		ldap_conn->handle = NULL;
	}

	return ISC_R_FAILURE;
}

static isc_result_t
ldap_reconnect(ldap_instance_t *ldap_inst, ldap_connection_t *ldap_conn,
	       isc_boolean_t force)
{
	int ret = 0;
	const char *bind_dn = NULL;
	const char *password = NULL;

	if (force)
		goto force_reconnect;

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
force_reconnect:
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

		/*
		 * Clean the connection handle.
		 */
		if (ldap_conn->handle != NULL) {
			ldap_unbind_ext_s(ldap_conn->handle, NULL, NULL);
			ldap_conn->handle = NULL;
		}

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

static isc_result_t
handle_connection_error(ldap_instance_t *ldap_inst, ldap_connection_t *ldap_conn,
			isc_boolean_t force)
{
	int ret;
	int err_code;

	ret = ldap_get_option(ldap_conn->handle, LDAP_OPT_RESULT_CODE,
			      (void *)&err_code);

	if (ret != LDAP_OPT_SUCCESS) {
		log_error("handle_connection_error failed to obtain ldap error code");
		goto reconnect;
	}

	switch (err_code) {
	case LDAP_NO_SUCH_OBJECT:
		ldap_conn->tries = 0;
		return ISC_R_SUCCESS;
	case LDAP_TIMEOUT:
		log_error("LDAP query timed out. Try to adjust \"timeout\" parameter");
		break;
	case LDAP_INVALID_DN_SYNTAX:
	case LDAP_INVALID_SYNTAX:
		log_bug("Invalid syntax in handle_connection_error indicates a bug");
		break;
	default:
		/* Try to reconnect on other errors. */
		log_error("LDAP error: %s", ldap_err2string(err_code));
reconnect:
		if (ldap_conn->tries == 0)
			log_error("connection to the LDAP server was lost");
		return ldap_connect(ldap_inst, ldap_conn, force);
		
	}

	return ISC_R_FAILURE;
}

static isc_result_t
ldap_modify_do(ldap_instance_t *ldap_inst, ldap_connection_t *ldap_conn,
		const char *dn, LDAPMod **mods, isc_boolean_t delete_node)
{
	int ret;
	int err_code;
	const char *operation_str;
	isc_result_t result;
	isc_boolean_t autoconn = (ldap_conn == NULL);

	REQUIRE(dn != NULL);
	REQUIRE(mods != NULL);
	REQUIRE(ldap_inst != NULL);

	if (autoconn)
		CHECK(ldap_pool_getconnection(ldap_inst->pool, &ldap_conn));

	if (ldap_conn->handle == NULL) {
		/*
		 * handle can be NULL when the first connection to LDAP wasn't
		 * successful
		 * TODO: handle this case inside ldap_pool_getconnection()?
		 */
		CHECK(ldap_connect(ldap_inst, ldap_conn, ISC_FALSE));
	}

	if (delete_node) {
		log_debug(2, "deleting whole node: '%s'", dn);
		ret = ldap_delete_ext_s(ldap_conn->handle, dn, NULL, NULL);
	} else {
		log_debug(2, "writing to '%s'", dn);
		ret = ldap_modify_ext_s(ldap_conn->handle, dn, mods, NULL, NULL);
	}

	result = (ret == LDAP_SUCCESS) ? ISC_R_SUCCESS : ISC_R_FAILURE;
	if (ret == LDAP_SUCCESS)
		goto cleanup;

	if (mods[0]->mod_op == LDAP_MOD_ADD)
		operation_str = "modifying(add)";
	else if (mods[0]->mod_op == LDAP_MOD_DELETE)
		operation_str = "modifying(del)";
	else {
		operation_str = "modifying(unknown operation)";
		CHECK(ISC_R_NOTIMPLEMENTED);
	}

	LDAP_OPT_CHECK(ldap_get_option(ldap_conn->handle, LDAP_OPT_RESULT_CODE,
			&err_code), "ldap_modify_do(%s) failed to obtain ldap error code",
			operation_str);

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
		result = (ret == LDAP_SUCCESS) ? ISC_R_SUCCESS : ISC_R_FAILURE;
		if (ret == LDAP_SUCCESS)
			goto cleanup;
		LDAP_OPT_CHECK(ldap_get_option(ldap_conn->handle, LDAP_OPT_RESULT_CODE,
				&err_code),
				"ldap_modify_do(add) failed to obtain ldap error code");
		operation_str = "adding";
	}

	log_debug(2, "error(%s) %s entry %s", ldap_err2string(err_code),
		  operation_str, dn);

	/* do not error out if we are trying to delete an
	 * unexisting attribute */
	if (mods[0]->mod_op != LDAP_MOD_DELETE ||
	    err_code != LDAP_NO_SUCH_ATTRIBUTE) {
		result = ISC_R_FAILURE;
	}
cleanup:
	if (autoconn)
		ldap_pool_putconnection(ldap_inst->pool, &ldap_conn);

	return result;
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
modify_soa_record(ldap_instance_t *ldap_inst, ldap_connection_t *ldap_conn,
		const char *zone_dn, dns_rdata_t *rdata)
{
	isc_result_t result;
	dns_rdata_soa_t soa;
	LDAPMod change[5];
	LDAPMod *changep[6] = {
		&change[0], &change[1], &change[2], &change[3], &change[4],
		NULL
	};

	REQUIRE(ldap_inst != NULL);

/* all values in SOA record are isc_uint32_t, i.e. max. 2^32-1 */
#define MAX_SOANUM_LENGTH (10 + 1)
#define SET_LDAP_MOD(index, name) \
	change[index].mod_op = LDAP_MOD_REPLACE; \
	change[index].mod_type = "idnsSOA" #name; \
	change[index].mod_values = alloca(2 * sizeof(char *)); \
	change[index].mod_values[0] = alloca(MAX_SOANUM_LENGTH); \
	change[index].mod_values[1] = NULL; \
	CHECK(isc_string_printf(change[index].mod_values[0], \
		MAX_SOANUM_LENGTH, "%u", soa.name));

	dns_rdata_tostruct(rdata, (void *)&soa, ldap_inst->mctx);

	SET_LDAP_MOD(0, serial);
	SET_LDAP_MOD(1, refresh);
	SET_LDAP_MOD(2, retry);
	SET_LDAP_MOD(3, expire);
	SET_LDAP_MOD(4, minimum);

	dns_rdata_freestruct((void *)&soa);

	result = ldap_modify_do(ldap_inst, ldap_conn, zone_dn, changep, ISC_FALSE);

cleanup:
	return result;

#undef MAX_SOANUM_LENGTH
#undef SET_LDAP_MOD
}

static isc_result_t
modify_ldap_common(dns_name_t *owner, ldap_instance_t *ldap_inst,
		   dns_rdatalist_t *rdlist, int mod_op, isc_boolean_t delete_node)
{
	isc_result_t result;
	isc_mem_t *mctx = ldap_inst->mctx;
	ldap_connection_t *ldap_conn = NULL;
	ldap_qresult_t *ldap_qresult = NULL;
	ld_string_t *owner_dn = NULL;
	LDAPMod *change[3] = { NULL };
	LDAPMod *change_ptr = NULL;
	ldap_cache_t *cache;
	ldap_entry_t *entry;
	ldap_valuelist_t values;
	isc_boolean_t zone_dyn_update = ldap_inst->dyn_update;
	isc_boolean_t zone_sync_ptr = ldap_inst->sync_ptr;
	ld_string_t *owner_dn_ptr = NULL;
	char *attrs[] = {"idnsAllowSyncPTR", "idnsAllowDynUpdate", NULL};

	/*
	 * Find parent zone entry and check if Dynamic Update is allowed.
	 * @todo Try the cache first and improve split: SOA records are problematic.
	 */
	CHECK(str_new(mctx, &owner_dn));
	CHECK(dnsname_to_dn(ldap_inst->zone_register, owner, owner_dn));
	char *zone_dn = strstr(str_buf(owner_dn),", ");

	if (zone_dn == NULL) { /* SOA record; owner = zone => owner_dn = zone_dn */
		zone_dn = (char *)str_buf(owner_dn);
	} else {
		zone_dn += 1; /* skip whitespace */
	}

	CHECK(ldap_pool_getconnection(ldap_inst->pool, &ldap_conn));
	CHECK(ldap_query(ldap_inst, ldap_conn, &ldap_qresult, zone_dn,
					 LDAP_SCOPE_BASE, attrs, 0,
					 "(&(objectClass=idnsZone)(idnsZoneActive=TRUE))"));

	/* only 0 or 1 active zone can be returned from query */
	entry = HEAD(ldap_qresult->ldap_entries);
	if (entry == NULL) {
		log_debug(3, "Active zone %s not found", zone_dn);
		result = ISC_R_NOTFOUND;
		goto cleanup;
	}

	result = ldap_entry_getvalues(entry, "idnsAllowDynUpdate", &values);
	if (result == ISC_R_SUCCESS) { /* zone specific setting found */
		zone_dyn_update = (strcmp(HEAD(values)->value, "TRUE") == 0 )
			? ISC_TRUE : ISC_FALSE;
	}

	if (!zone_dyn_update) {
		log_debug(3, "Dynamic Update is not allowed in zone %s", zone_dn);
		result = ISC_R_NOPERM;
		goto cleanup;
	}

	if (rdlist->type == dns_rdatatype_soa && mod_op == LDAP_MOD_DELETE) {
		result = ISC_R_SUCCESS;
		goto cleanup;
	}
	/* Flush modified record from the cache */
	cache = ldap_instance_getcache(ldap_inst);
	CHECK(discard_from_cache(cache, owner));

	if (rdlist->type == dns_rdatatype_soa) {
		result = modify_soa_record(ldap_inst, ldap_conn, str_buf(owner_dn),
					   HEAD(rdlist->rdata));
		goto cleanup;
	}

	CHECK(ldap_rdatalist_to_ldapmod(mctx, rdlist, &change[0], mod_op));
	if (mod_op == LDAP_MOD_ADD) {
		/* for now always replace the ttl on add */
		CHECK(ldap_rdttl_to_ldapmod(mctx, rdlist, &change[1]));
	}
	
	CHECK(ldap_modify_do(ldap_inst, ldap_conn, str_buf(owner_dn), change, delete_node));

	/* Keep the PTR of corresponding A/AAAA record synchronized. */
	if (rdlist->type == dns_rdatatype_a || rdlist->type == dns_rdatatype_aaaa) {
		/*
		 * Look for zone "idnsAllowSyncPTR" attribute. If attribute do not exist,
		 * use global plugin configuration: option "sync_ptr"
		 */

		result = ldap_entry_getvalues(entry, "idnsAllowSyncPTR", &values);
		if (result == ISC_R_SUCCESS) { /* zone specific setting found */
			zone_sync_ptr = (strcmp(HEAD(values)->value, "TRUE") == 0)
				? ISC_TRUE : ISC_FALSE;
		}

		if (!zone_sync_ptr) {
			log_debug(3, "Sync PTR is not allowed in zone %s", zone_dn);
			result = ISC_R_SUCCESS;
			goto cleanup;
		}
		log_debug(3, "Sync PTR is allowed for zone %s", zone_dn);

		/* Get string with IP address from change request
		 * and convert it to in_addr structure. */
		in_addr_t ip;
		if ((ip = inet_addr(change[0]->mod_values[0])) == 0) {
			log_bug("Could not convert IP address from string '%s'.",
			        change[0]->mod_values[0]);
			result = ISC_R_FAILURE;
			goto cleanup;
		}
		
		/* Use internal net address representation. */
		isc_netaddr_t isc_ip;
		/* Only copy data to isc_ip stucture. */
		isc_netaddr_fromin(&isc_ip,(struct in_addr *) &ip);
		
		/*
		 * Convert IP address to PTR record.
		 *
		 * @example
		 * 192.168.0.1 -> 1.0.168.192.in-addr.arpa
		 *
		 * @todo Check if it works for IPv6 correctly.
		 */ 
		struct dns_fixedname name;
		dns_fixedname_init(&name);
		CHECK(dns_byaddr_createptrname2(&isc_ip, 0, dns_fixedname_name(&name)));
	   
		/* Find PTR entry in LDAP. */
		ldapdb_rdatalist_t rdlist_search;
		dns_rdatalist_t *rdlist_ptr = NULL;
		result = ldapdb_rdatalist_get(mctx, ldap_inst, dns_fixedname_name(&name), 
									  NULL, &rdlist_search); 
	
		/* Check the value of PTR entry. */	
		if (mod_op == LDAP_MOD_DELETE && result == ISC_R_SUCCESS) {
			result = ldapdb_rdatalist_findrdatatype(&rdlist_search, 
			                                        dns_rdatatype_ptr, &rdlist_ptr);
		}

		if (result != ISC_R_SUCCESS && result != ISC_R_NOTFOUND) {
			log_error("Can not synchronize PTR record, ldapdb_rdatalist_get = %d", 
			          result);
			result = ISC_R_FAILURE; /* Synchronization required: report error. */
			goto cleanup;
		}

		/* 
		 * Do not overwrite old record and delete only existing record. 
		 */
		if ((result == ISC_R_SUCCESS && mod_op == LDAP_MOD_ADD) ||
			(result == ISC_R_NOTFOUND && mod_op == LDAP_MOD_DELETE)) {
			log_debug(2,"Can not synchronize PTR record for A/AAAA one (%s) - record %s.",
			        str_buf(owner_dn), 
			        ((mod_op == LDAP_MOD_ADD)?"already exists":"not found"));
			result = ISC_R_SUCCESS; /* @todo: More checks for ADD operation. */
			goto cleanup;
		}

		/* Get LDAP entry indentifier. */ 
		CHECK(str_new(mctx, &owner_dn_ptr));   
		CHECK(dnsname_to_dn(ldap_inst->zone_register, dns_fixedname_name(&name),
		      owner_dn_ptr));
	
		/*
		 * @example 
		 * owner_dn_ptr = "idnsName=100.0.168, idnsname=192.in-addr.arpa,cn=dns,$SUFFIX"
		 * owner_zone_dn_ptr = "idnsname=192.in-addr.arpa,cn=dns,$SUFFIX"
		 */
		char *owner_zone_dn_ptr = strstr(str_buf(owner_dn_ptr),", ") + 1;
		
		/* Get attribute "idnsAllowDynUpdate" for reverse zone or use default. */
		ldap_query_free(ISC_FALSE, &ldap_qresult);
		zone_dyn_update = ldap_inst->dyn_update;
		CHECK(ldap_query(ldap_inst, ldap_conn, &ldap_qresult, owner_zone_dn_ptr,
						 LDAP_SCOPE_BASE, attrs, 0,
						 "(&(objectClass=idnsZone)(idnsZoneActive=TRUE))"));

		/* Only 0 or 1 active zone can be returned from query. */
		entry = HEAD(ldap_qresult->ldap_entries);
		if (entry == NULL) {
			log_debug(3, "Active zone %s not found", zone_dn);
			result = ISC_R_NOTFOUND;
			goto cleanup;
		}

		result = ldap_entry_getvalues(entry, "idnsAllowDynUpdate", &values);
		if (result == ISC_R_SUCCESS) { /* zone specific setting found */
			zone_dyn_update = (strcmp(HEAD(values)->value, "TRUE") == 0)
				? ISC_TRUE : ISC_FALSE;
		}

		if (!zone_dyn_update) {
			log_debug(3, "Dynamic Update is not allowed in zone %s", owner_zone_dn_ptr);
			result = ISC_R_NOPERM;
			goto cleanup;
		}

		log_debug(3, "Dynamic Update is allowed for zone %s", owner_zone_dn_ptr);
		
		/* 
		 * Get string representation of PTR record value.
		 * 
		 * @example str_ptr = "host.example.com." 
		 */
		ld_string_t *str_ptr = NULL;
		CHECK(str_new(mctx, &str_ptr));
		CHECK(dn_to_text(str_buf(owner_dn), str_ptr, NULL));
		 
		/*
		 * Delete only when PTR record's value == A/AAAA record's key.
		 *
		 * @example
		 *
		 * www.example.com. 			A 		192.168.0.100
		 * ; PTR record can be synchronized.
		 * 100.0.168.192.in-addr.arpa. 	PTR		www.example.com.
		 * ; PTR record can NOT be synchronized.
		 * 100.0.168.192.in-addr.arpa.	PTR		not.valid.com.
		 *
		 */ 
		if (mod_op == LDAP_MOD_DELETE) {
			char **vals = NULL;
			CHECK(ldap_rdata_to_char_array(mctx, HEAD(rdlist_ptr->rdata), &vals));
			if (vals != NULL && vals[0] != NULL && strcmp(vals[0], str_buf(str_ptr)) != 0) {
				log_debug(3,"Cannot delete PTR record, unexpected value found "
					"(expected \"%s\")\n", str_buf(str_ptr));
				result = ISC_R_FAILURE;
				goto cleanup;
			}
		}
		
		/* Fill the LDAPMod change structure up. */
		char **vals = NULL;
		CHECKED_MEM_GET_PTR(mctx, change_ptr);
		ZERO_PTR(change_ptr);

		/* Do the same action what has been done with A/AAAA record. */	
		change_ptr->mod_op = mod_op;
		char *attr_name;
		const char *attr_name_c;
		CHECK(rdatatype_to_ldap_attribute(dns_rdatatype_ptr, &attr_name_c));
		
		DE_CONST(attr_name_c, attr_name);
		change_ptr->mod_type = attr_name;  

		CHECKED_MEM_ALLOCATE(mctx, vals, 2 * sizeof(char *));
		memset(vals, 0, 2 * sizeof(char *));
		change_ptr->mod_values = vals;

		CHECKED_MEM_ALLOCATE(mctx, vals[0], str_len(str_ptr) + 1);
		memcpy(vals[0], str_buf(str_ptr), str_len(str_ptr) + 1);
	   
		/* Switch pointers and free the old memory. */ 
		free_ldapmod(mctx, &change[0]);
		change[0] = change_ptr;
		change_ptr = NULL;

		/* Modify PTR record. */
		CHECK(ldap_modify_do(ldap_inst, ldap_conn, str_buf(owner_dn_ptr), change, delete_node));
		(void) discard_from_cache(ldap_instance_getcache(ldap_inst),
					  dns_fixedname_name(&name)); 
	}
	
cleanup:
	ldap_query_free(ISC_FALSE, &ldap_qresult);
	ldap_pool_putconnection(ldap_inst->pool, &ldap_conn);
	str_destroy(&owner_dn_ptr);
	str_destroy(&owner_dn);
	free_ldapmod(mctx, &change[0]);
	free_ldapmod(mctx, &change[1]);
	if (change_ptr != NULL) free_ldapmod(mctx, &change_ptr);

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
	ldap_pool_destroy(&pool);
	return result;
}
static void
ldap_pool_destroy(ldap_pool_t **poolp)
{
	ldap_pool_t *pool;
	ldap_connection_t *ldap_conn;
	unsigned int i;

	REQUIRE(poolp != NULL);

	pool = *poolp;
	if (pool == NULL)
		return;

	for (i = 0; i < pool->connections; i++) {
		ldap_conn = pool->conns[i];
		if (ldap_conn != NULL)
			destroy_ldap_connection(pool, &ldap_conn);
	}

	SAFE_MEM_PUT(pool->mctx, pool->conns,
		     pool->connections * sizeof(ldap_connection_t *));

	semaphore_destroy(&pool->conn_semaphore);

	MEM_PUT_AND_DETACH(pool);
	*poolp = NULL;
}

static isc_result_t
ldap_pool_getconnection(ldap_pool_t *pool, ldap_connection_t ** conn)
{
	ldap_connection_t *ldap_conn = NULL;
	unsigned int i;
	isc_result_t result;

	REQUIRE(pool != NULL);
	REQUIRE(conn != NULL && *conn == NULL);
	ldap_conn = *conn;

	CHECK(semaphore_wait_timed(&pool->conn_semaphore));
	for (i = 0; i < pool->connections; i++) {
		ldap_conn = pool->conns[i];
		if (isc_mutex_trylock(&ldap_conn->lock) == ISC_R_SUCCESS)
			break;
	}

	RUNTIME_CHECK(ldap_conn != NULL);

	*conn = ldap_conn;

cleanup:
	if (result != ISC_R_SUCCESS) {
		log_error("timeout in ldap_pool_getconnection(): try to raise "
				"'connections' parameter; potential deadlock?");
	}
	return result;
}

static void
ldap_pool_putconnection(ldap_pool_t *pool, ldap_connection_t **conn)
{
	REQUIRE(conn != NULL);
	ldap_connection_t *ldap_conn = *conn;

	if (ldap_conn == NULL)
		return;

	UNLOCK(&ldap_conn->lock);
	semaphore_signal(&pool->conn_semaphore);

	*conn = NULL;
}

static isc_result_t
ldap_pool_connect(ldap_pool_t *pool, ldap_instance_t *ldap_inst)
{
	isc_result_t result;
	ldap_connection_t *ldap_conn;
	unsigned int i;

	for (i = 0; i < pool->connections; i++) {
		ldap_conn = NULL;
		CHECK(new_ldap_connection(pool, &ldap_conn));
		result = ldap_connect(ldap_inst, ldap_conn, ISC_FALSE);
		if (result == ISC_R_NOTCONNECTED) {
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
		destroy_ldap_connection(pool, &pool->conns[i]);
	}
	return result;
}

#define LDAP_CONTROL_PERSISTENTSEARCH "2.16.840.1.113730.3.4.3"
#define LDAP_CONTROL_ENTRYCHANGE "2.16.840.1.113730.3.4.7"

#define LDAP_ENTRYCHANGE_NONE	0 /* entry change control is not present */
#define LDAP_ENTRYCHANGE_ADD	1
#define LDAP_ENTRYCHANGE_DEL	2
#define LDAP_ENTRYCHANGE_MOD	4
#define LDAP_ENTRYCHANGE_MODDN	8
#define LDAP_ENTRYCHANGE_ALL	(1 | 2 | 4 | 8)

#define PSEARCH_ADD(chgtype) ((chgtype & LDAP_ENTRYCHANGE_ADD) != 0)
#define PSEARCH_DEL(chgtype) ((chgtype & LDAP_ENTRYCHANGE_DEL) != 0)
#define PSEARCH_MOD(chgtype) ((chgtype & LDAP_ENTRYCHANGE_MOD) != 0)
#define PSEARCH_MODDN(chgtype) ((chgtype & LDAP_ENTRYCHANGE_MODDN) != 0)
#define PSEARCH_ANY(chgtype) ((chgtype & LDAP_ENTRYCHANGE_ALL) != 0)
/*
 * Creates persistent search (aka psearch,
 * http://tools.ietf.org/id/draft-ietf-ldapext-psearch-03.txt) control.
 */
static isc_result_t
ldap_pscontrol_create(LDAPControl **ctrlp)
{
	BerElement *ber;
	struct berval *berval;
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
	if (ber_printf(ber, "{ibb}", LDAP_ENTRYCHANGE_ALL, 0, 1) == -1)
		goto cleanup;

	if (ber_flatten(ber, &berval) < 0)
		goto cleanup;

	if (ldap_control_create(LDAP_CONTROL_PERSISTENTSEARCH, 1, berval, 1, ctrlp)
			!= LDAP_SUCCESS)
		goto cleanup;

	ber_free(ber, 1);
	ber_bvfree(berval);

	return ISC_R_SUCCESS;

cleanup:
	ber_free(ber, 1);
	ber_bvfree(berval);

	return result;
}

static inline isc_result_t
ldap_get_zone_serial(ldap_instance_t *inst, dns_name_t *zone_name,
				isc_uint32_t *serial) {
	isc_result_t result;
	dns_zone_t *zone = NULL;

	CHECK(zr_get_zone_ptr(inst->zone_register, zone_name, &zone));
	CHECK(dns_zone_getserial2(zone, serial));
	dns_zone_detach(&zone);

cleanup:
	return result;
}

static isc_result_t
soa_serial_increment(isc_mem_t *mctx, ldap_instance_t *inst,
		dns_name_t *zone_name) {
	isc_result_t result = ISC_R_FAILURE;
	ld_string_t *zone_dn = NULL;
	ldapdb_rdatalist_t rdatalist;
	dns_rdatalist_t *rdlist = NULL;
	dns_rdata_t *soa_rdata = NULL;
	isc_uint32_t old_serial;
	isc_uint32_t new_serial;
	isc_time_t curr_time;

	REQUIRE(inst != NULL);
	REQUIRE(zone_name != NULL);

	INIT_LIST(rdatalist);
	CHECK(str_new(mctx, &zone_dn));
	CHECK(dnsname_to_dn(inst->zone_register, zone_name, zone_dn));
	log_debug(5, "incrementing SOA serial number in zone '%s'",
				str_buf(zone_dn));

	/* get original SOA rdata and serial value */
	CHECK(ldapdb_rdatalist_get(mctx, inst, zone_name, zone_name, &rdatalist));
	CHECK(ldapdb_rdatalist_findrdatatype(&rdatalist, dns_rdatatype_soa, &rdlist));
	soa_rdata = ISC_LIST_HEAD(rdlist->rdata);
	CHECK(ldap_get_zone_serial(inst, zone_name, &old_serial));

	/* Compute the new SOA serial - use actual timestamp.
	 * If timestamp <= oldSOAserial then increment old serial by one. */
	isc_time_now(&curr_time);
	new_serial = isc_time_seconds(&curr_time) & 0xFFFFFFFF;
	if (!isc_serial_gt(new_serial, old_serial)) {
		/* increment by one, RFC1982, from bind-9.8.2/bin/named/update.c */
		new_serial = (old_serial + 1) & 0xFFFFFFFF;
	}
	if (new_serial == 0)
		new_serial = 1;
	log_debug(5,"zone '%s': old serial %u, new serial %u",
				str_buf(zone_dn), old_serial, new_serial);
	dns_soa_setserial(new_serial, soa_rdata);

	/* write the new serial back to DB */
	CHECK(modify_soa_record(inst, NULL, str_buf(zone_dn), soa_rdata));
	CHECK(discard_from_cache(ldap_instance_getcache(inst), zone_name));

	/* put the new SOA to inst->cache and compare old and new serials */
	CHECK(ldap_get_zone_serial(inst, zone_name, &new_serial));
	INSIST(isc_serial_gt(new_serial, old_serial) == ISC_TRUE);

cleanup:
	if (result != ISC_R_SUCCESS)
		log_error("SOA serial number incrementation failed in zone '%s'",
					str_buf(zone_dn));

	str_destroy(&zone_dn);
	ldapdb_rdatalist_destroy(mctx, &rdatalist);
	return result;
}

/*
 * update_action routine is processed asynchronously so it cannot assume
 * anything about state of ldap_inst from where it was sent. The ldap_inst
 * could have been already destroyed due server reload. The safest
 * way how to handle zone update is to refetch ldap_inst,
 * perform query to LDAP and delete&add the zone. This is expensive
 * operation but zones don't change often.
 */
static void
update_zone(isc_task_t *task, isc_event_t *event)
{
	ldap_psearchevent_t *pevent = (ldap_psearchevent_t *)event;
	isc_result_t result ;
	ldap_instance_t *inst = NULL;
	ldap_qresult_t *ldap_qresult_zone = NULL;
	ldap_qresult_t *ldap_qresult_record = NULL;
	ldap_entry_t *entry_zone = NULL;
	ldap_entry_t *entry_record = NULL;
	isc_boolean_t delete = ISC_TRUE;
	isc_mem_t *mctx;
	dns_name_t prevname;
	char *attrs_zone[] = {
		"idnsName", "idnsUpdatePolicy", "idnsAllowQuery",
		"idnsAllowTransfer", "idnsForwardPolicy", "idnsForwarders", NULL
	};
	char *attrs_record[] = {
			"objectClass", "dn", NULL
	};

	UNUSED(task);

	mctx = pevent->mctx;
	dns_name_init(&prevname, NULL);

	CHECK(manager_get_ldap_instance(pevent->dbname, &inst));
	CHECK(ldap_query(inst, NULL, &ldap_qresult_zone, pevent->dn,
			 LDAP_SCOPE_BASE, attrs_zone, 0,
			 "(&(objectClass=idnsZone)(idnsZoneActive=TRUE))"));

	for (entry_zone = HEAD(ldap_qresult_zone->ldap_entries);
			entry_zone != NULL;
			entry_zone = NEXT(entry_zone, link)) {
		delete = ISC_FALSE;
		CHECK(ldap_parse_zoneentry(entry_zone, inst));

		if (PSEARCH_MODDN(pevent->chgtype)) {
			if (dn_to_dnsname(inst->mctx, pevent->prevdn, &prevname, NULL)
					== ISC_R_SUCCESS) {
				CHECK(ldap_delete_zone(inst, pevent->prevdn, ISC_TRUE));
			} else {
				log_debug(5, "update_action: old zone wasn't managed "
						"by plugin, dn '%s'", pevent->prevdn);
			}

			/* fill the cache with records from renamed zone */
			CHECK(ldap_query(inst, NULL, &ldap_qresult_record, pevent->dn,
					LDAP_SCOPE_ONELEVEL, attrs_record, 0,
					"(objectClass=idnsRecord)"));

			/* LDAP schema requires SOA record (at least) */
			INSIST(HEAD(ldap_qresult_record->ldap_entries) != NULL);
			for (entry_record = HEAD(ldap_qresult_record->ldap_entries);
					entry_record != NULL;
					entry_record = NEXT(entry_record, link)) {

				psearch_update(inst, entry_record, NULL);
			}
		}

		INSIST(NEXT(entry_zone, link) == NULL); /* no multiple zones with same DN */
	}

	if (delete)
		CHECK(ldap_delete_zone(inst, pevent->dn, ISC_TRUE));

cleanup:
	if (result != ISC_R_SUCCESS)
		log_error("update_action (psearch) failed for '%s': %s. "
			  "Zones can be outdated, run `rndc reload`",
			  pevent->dn, isc_result_totext(result));

	ldap_query_free(ISC_FALSE, &ldap_qresult_zone);
	ldap_query_free(ISC_FALSE, &ldap_qresult_record);
	if (dns_name_dynamic(&prevname))
		dns_name_free(&prevname, inst->mctx);
	isc_mem_free(mctx, pevent->dbname);
	if (pevent->prevdn != NULL)
		isc_mem_free(mctx, pevent->prevdn);
	isc_mem_free(mctx, pevent->dn);
	isc_mem_detach(&mctx);
	isc_event_free(&event);
}

static void
update_config(isc_task_t *task, isc_event_t *event)
{
	ldap_psearchevent_t *pevent = (ldap_psearchevent_t *)event;
	isc_result_t result ;
	ldap_instance_t *inst = NULL;
	ldap_qresult_t *ldap_qresult = NULL;
	ldap_entry_t *entry;
	isc_mem_t *mctx;
	char *attrs[] = {
		"idnsAllowSyncPTR", "idnsForwardPolicy", "idnsForwarders",
		"idnsZoneRefresh", "idnsPersistentSearch", NULL
	};

	UNUSED(task);

	mctx = pevent->mctx;

	result = manager_get_ldap_instance(pevent->dbname, &inst);
	if (result != ISC_R_SUCCESS)
		goto cleanup;

	CHECK(ldap_query(inst, NULL, &ldap_qresult, pevent->dn,
			 LDAP_SCOPE_BASE, attrs, 0,
			 "(objectClass=idnsConfigObject)"));

	if (EMPTY(ldap_qresult->ldap_entries))
		log_error("Config object can not be empty"); /* TODO: WHY? */

	for (entry = HEAD(ldap_qresult->ldap_entries);
	     entry != NULL;
	     entry = NEXT(entry, link)) {
		result = ldap_parse_configentry(entry, inst);
		if (result != ISC_R_SUCCESS)
			goto cleanup;
	}


cleanup:
	if (result != ISC_R_SUCCESS)
		log_error("update_config (psearch) failed for %s. "
			  "Configuration can be outdated, run `rndc reload`",
			  pevent->dn);

	ldap_query_free(ISC_FALSE, &ldap_qresult);
	isc_mem_free(mctx, pevent->dbname);
	isc_mem_free(mctx, pevent->dn);
	isc_mem_detach(&mctx);
	isc_event_free(&event);
}

/**
 * @brief Update record in cache.
 *
 * If it exists it is replaced with newer version.
 *
 * @param task Task indentifier.
 * @param event Internal data of type ldap_psearchevent_t.
 */
static void
update_record(isc_task_t *task, isc_event_t *event)
{
	/* Psearch event */
	ldap_psearchevent_t *pevent = (ldap_psearchevent_t *)event;
	isc_result_t result;
	ldap_instance_t *inst = NULL;
	ldap_cache_t *cache;
	isc_mem_t *mctx;
	mctx = pevent->mctx;

	UNUSED(task);
	CHECK(manager_get_ldap_instance(pevent->dbname, &inst));
	
	/* Structure to be stored in the cache. */
	ldapdb_rdatalist_t rdatalist;

	/* Convert domain name from text to struct dns_name_t. */
	dns_name_t name;
	dns_name_t origin;
	dns_name_t prevname;
	dns_name_t prevorigin;
	dns_name_init(&name, NULL);
	dns_name_init(&origin, NULL);
	dns_name_init(&prevname, NULL);
	dns_name_init(&prevorigin, NULL);
	CHECK(dn_to_dnsname(mctx, pevent->dn, &name, &origin));

	if (PSEARCH_DEL(pevent->chgtype) || PSEARCH_MODDN(pevent->chgtype)) {
		log_debug(5, "psearch_update: removing name from cache, dn: '%s'",
		          pevent->dn);
	}

	/* Get cache instance & clean old record */
	cache = ldap_instance_getcache(inst);
	CHECK(discard_from_cache(cache, &name));

	if (PSEARCH_MODDN(pevent->chgtype)) {
		/* remove previous name only if it was inside DNS subtree */
		if(dn_to_dnsname(mctx, pevent->prevdn, &prevname, &prevorigin)
				== ISC_R_SUCCESS) {
			log_debug(5, "psearch_update: removing name from cache, dn: '%s'",
					  pevent->prevdn);
			CHECK(discard_from_cache(cache, &prevname));
		} else {
			log_debug(5, "psearch_update: old name wasn't managed "
					"by plugin, dn '%s'", pevent->prevdn);
		}
	}

	if (PSEARCH_ADD(pevent->chgtype) || PSEARCH_MOD(pevent->chgtype) ||
			PSEARCH_MODDN(pevent->chgtype) || !PSEARCH_ANY(pevent->chgtype)) {
		/* 
		 * Find new data in LDAP. !PSEARCH_ANY indicates unchanged entry
		 * found during initial lookup (i.e. database dump).
		 *
		 * @todo Change this to convert ldap_entry_t to ldapdb_rdatalist_t.
		 */
		log_debug(5, "psearch_update: updating name in cache, dn: '%s'",
		          pevent->dn);
		CHECK(ldapdb_rdatalist_get(mctx, inst, &name, &origin, &rdatalist));
	
		/* 
		 * The cache is updated in ldapdb_rdatalist_get(...):
		 * CHECK(ldap_cache_addrdatalist(cache, &name, &rdatalist);
		 */

		/* Destroy rdatalist, it is now in the cache. */
		ldapdb_rdatalist_destroy(mctx, &rdatalist);
	}

	/* Do not bump serial during initial database dump. */
	if (inst->serial_autoincrement && PSEARCH_ANY(pevent->chgtype)) {
		CHECK(soa_serial_increment(mctx, inst, &origin));
	}
cleanup:
	if (result != ISC_R_SUCCESS)
		log_error("update_record (psearch) failed, dn '%s'. "
			  "Records can be outdated, run `rndc reload`",
			  pevent->dn);

	if (dns_name_dynamic(&name))
		dns_name_free(&name, inst->mctx);
	if (dns_name_dynamic(&prevname))
		dns_name_free(&prevname, inst->mctx);
	if (dns_name_dynamic(&origin))
		dns_name_free(&origin, inst->mctx);
	if (dns_name_dynamic(&prevorigin))
		dns_name_free(&prevorigin, inst->mctx);
	isc_mem_free(mctx, pevent->dbname);
	if (pevent->prevdn != NULL)
		isc_mem_free(mctx, pevent->prevdn);
	isc_mem_free(mctx, pevent->dn);
	isc_mem_detach(&mctx);
	isc_event_free(&event);
}

/*
 * Parses persistent search entrychange control.
 *
 * This entry says if particular entry was added/modified/deleted.
 * Details are in http://tools.ietf.org/id/draft-ietf-ldapext-psearch-03.txt
 */
static isc_result_t
ldap_parse_entrychangectrl(LDAPControl **ctrls, int *chgtypep, char **prevdnp)
{
	int i;
	isc_result_t result = ISC_R_SUCCESS;
	BerElement *ber = NULL;
	ber_int_t chgtype;
	ber_tag_t berret;
	char *prevdn = NULL;

	REQUIRE(ctrls != NULL);
	REQUIRE(chgtypep != NULL);
	REQUIRE(prevdnp != NULL && *prevdnp == NULL);

	/* Find entrycontrol OID */
	for (i = 0; ctrls[i] != NULL; i++) {
		if (strcmp(ctrls[i]->ldctl_oid,
		    LDAP_CONTROL_ENTRYCHANGE) == 0)
			break;
	}

	if (ctrls[i] == NULL)
		return ISC_R_NOTFOUND;

	ber = ber_init(&(ctrls[i]->ldctl_value));
	if (ber == NULL)
		return ISC_R_NOMEMORY;

	berret = ber_scanf(ber, "{e", &chgtype);
	if (berret == LBER_ERROR) {
		result = ISC_R_FAILURE;
		goto cleanup;
	}

	if (chgtype == LDAP_ENTRYCHANGE_MODDN) {
		berret = ber_scanf(ber, "a", &prevdn);
		if (berret == LBER_ERROR) {
			result = ISC_R_FAILURE;
			goto cleanup;
		}
	}

	*chgtypep = chgtype;
	*prevdnp = prevdn;

cleanup:
	if (ber != NULL)
		ber_free(ber, 1);

	return result;
}

static void
psearch_update(ldap_instance_t *inst, ldap_entry_t *entry, LDAPControl **ctrls)
{
	ldap_entryclass_t class;
	isc_result_t result = ISC_R_SUCCESS;
	ldap_psearchevent_t *pevent = NULL;
	int chgtype = LDAP_ENTRYCHANGE_NONE;
	char *dn = NULL;
	char *prevdn_ldap = NULL;
	char *prevdn = NULL;
	char *dbname = NULL;
	isc_mem_t *mctx = NULL;
	isc_taskaction_t action = NULL;

	class = ldap_entry_getclass(entry);
	if (class == LDAP_ENTRYCLASS_NONE) {
		log_error("psearch_update: ignoring entry with unknown class, dn '%s'",
			  entry->dn);
		return; /* ignore it, it's OK */
	}

	if (ctrls != NULL)
		CHECK(ldap_parse_entrychangectrl(ctrls, &chgtype, &prevdn_ldap));


	log_debug(20,"psearch change type: none%d, add%d, del%d, mod%d, moddn%d",
				!PSEARCH_ANY(chgtype), PSEARCH_ADD(chgtype),
				PSEARCH_DEL(chgtype), PSEARCH_MOD(chgtype),
				PSEARCH_MODDN(chgtype));

	isc_mem_attach(inst->mctx, &mctx);

	dn = isc_mem_strdup(mctx, entry->dn);
	if (dn == NULL) {
		result = ISC_R_NOMEMORY;
		goto cleanup;
	}
	dbname = isc_mem_strdup(mctx, inst->db_name);
	if (dbname == NULL) {
		result = ISC_R_NOMEMORY;
		goto cleanup;
	}

	if (PSEARCH_MODDN(chgtype)) {
		prevdn = isc_mem_strdup(mctx, prevdn_ldap);
		if (prevdn == NULL) {
			result = ISC_R_NOMEMORY;
			goto cleanup;
		}
	}

	/*
	 * We are very simple. Every update (add/mod/del) means that
	 * we remove the zone/record, fetch it's entry from LDAP
	 * and then add it again. This is definitely place for improvement
	 * but it should be enough for now.
	 */

	if ((class & LDAP_ENTRYCLASS_CONFIG) != 0)
		action = update_config;
	else if ((class & LDAP_ENTRYCLASS_ZONE) != 0)
		action = update_zone;
	else if ((class & LDAP_ENTRYCLASS_RR) != 0)
		action = update_record;
	else {
		result = ISC_R_FAILURE;
		goto cleanup;
	}

	pevent = (ldap_psearchevent_t *)isc_event_allocate(inst->mctx,
				inst, LDAPDB_EVENT_PSEARCH,
				action, NULL,
				sizeof(ldap_psearchevent_t));

	if (pevent == NULL) {
		result = ISC_R_NOMEMORY;
		goto cleanup;
	}

	pevent->mctx = mctx;
	pevent->dbname = dbname;
	pevent->dn = dn;
	pevent->prevdn = prevdn;
	pevent->chgtype = chgtype;
	isc_task_send(inst->task, (isc_event_t **)&pevent);

cleanup:
	if (ctrls != NULL)
		ldap_controls_free(ctrls);
	if (result != ISC_R_SUCCESS) {
		if (dbname != NULL)
			isc_mem_free(mctx, dbname);
		if (dn != NULL)
			isc_mem_free(mctx, dn);
		if (prevdn != NULL)
			isc_mem_free(mctx, prevdn);
		if (mctx != NULL)
			isc_mem_detach(&mctx);
		if (prevdn_ldap != NULL)
			ldap_memfree(prevdn);

		log_error("psearch_update failed for %s zone. "
			  "Zone can be outdated, run `rndc reload`",
			  entry->dn);
	}
}

#define CHECK_EXIT \
	do { \
		if (inst->exiting) \
			goto cleanup; \
	} while (0)

/*
 * This "sane" sleep allows us to end if signal set the "exiting" variable.
 *
 * Returns ISC_FALSE if we should terminate, ISC_TRUE otherwise.
 */
static inline isc_boolean_t
sane_sleep(const ldap_instance_t *inst, unsigned int timeout)
{
	unsigned int remains = timeout;

	while (remains && !inst->exiting)
		remains = sleep(remains);

	if (remains)
		log_debug(99, "sane_sleep: interrupted");

	return inst->exiting ? ISC_FALSE : ISC_TRUE;
}

/* No-op signal handler for SIGUSR1 */
static void
noop_handler(int signal)
{
	UNUSED(signal);
}

static inline void
install_usr1handler(void)
{
	struct sigaction sa;
	struct sigaction oldsa;
	int ret;
	static isc_boolean_t once = ISC_FALSE;

	if (once)
		return;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = &noop_handler;

	ret = sigaction(SIGUSR1, &sa, &oldsa);
	RUNTIME_CHECK(ret == 0); /* If sigaction fails, it's a bug */

	/* Don't attempt to replace already existing handler */
	RUNTIME_CHECK(oldsa.sa_handler == NULL);

	once = ISC_TRUE;
}

/*
 * NOTE:
 * Every blocking call in psearch_watcher thread must be preemptible.
 */
static isc_threadresult_t
ldap_psearch_watcher(isc_threadarg_t arg)
{
	ldap_instance_t *inst = (ldap_instance_t *)arg;
	ldap_connection_t *conn = NULL;
	ldap_qresult_t *ldap_qresult = NULL;
	struct timeval tv;
	int ret, cnt;
	isc_result_t result;
	sigset_t sigset;
	isc_boolean_t flush_required;

	log_debug(1, "Entering ldap_psearch_watcher");

	install_usr1handler();

	/*
	 * By default, BIND sets threads to accept signals only via
	 * sigwait(). However we need to use SIGUSR1 to interrupt
	 * watcher from waiting inside ldap_result so enable
	 * asynchronous delivering of SIGUSR1.
	 */
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGUSR1);
	ret = pthread_sigmask(SIG_UNBLOCK, &sigset, NULL);
	/* pthread_sigmask fails only due invalid args */
	RUNTIME_CHECK(ret == 0);

	/* Wait indefinitely */
	tv.tv_sec = -1;
	tv.tv_usec = 0;

	/* Pick connection, one is reserved purely for this thread */
	CHECK(ldap_pool_getconnection(inst->pool, &conn));

	/* Try to connect. */
	while (conn->handle == NULL) {
		CHECK_EXIT;

		log_error("ldap_psearch_watcher handle is NULL. "
		          "Next try in %ds", inst->reconnect_interval);
		if (!sane_sleep(inst, inst->reconnect_interval))
			goto cleanup;
		ldap_connect(inst, conn, ISC_TRUE);
	}

	CHECK(ldap_query_create(conn->mctx, &ldap_qresult));

restart:
	/* Perform initial lookup */
	flush_required = ISC_TRUE;
	if (inst->psearch) {
		log_debug(1, "Sending initial psearch lookup");
		ret = ldap_search_ext(conn->handle,
				      str_buf(inst->base),
				      LDAP_SCOPE_SUBTREE,
					  /*
					   * (objectClass==idnsZone AND idnsZoneActive==TRUE) 
					   * OR (objectClass == idnsRecord)
					   * OR (objectClass == idnsConfigObject)
					   */
				      "(|(&(objectClass=idnsZone)(idnsZoneActive=TRUE))"
					  "(objectClass=idnsRecord)"
					  "(objectClass=idnsConfigObject))",
				      NULL, 0, conn->serverctrls, NULL, NULL,
				      LDAP_NO_LIMIT, &conn->msgid);
		if (ret != LDAP_SUCCESS) {
			log_error("failed to send initial psearch request");
			ldap_unbind_ext_s(conn->handle, NULL, NULL);
			goto cleanup;
		}
	}

	while (!inst->exiting) {
		ret = ldap_result(conn->handle, conn->msgid, 0, &tv,
				  &ldap_qresult->result);
		if (ret <= 0) {
			/* Don't reconnect if signaled to exit */
			CHECK_EXIT;
			while (handle_connection_error(inst, conn, ISC_TRUE)
			       != ISC_R_SUCCESS) {
				log_error("ldap_psearch_watcher failed to handle "
					  "LDAP connection error. Reconnection "
					  "in %ds", inst->reconnect_interval);
				if (!sane_sleep(inst, inst->reconnect_interval))
					goto cleanup;
			}
			ldap_query_free(ISC_TRUE, &ldap_qresult);
			goto restart;
		} else if (flush_required == ISC_TRUE) {
			/* First LDAP result after (re)start was received successfully:
			 * Unload old zones and flush record cache.
			 * We want to save cache in case of search timeout during restart.
			 */
			CHECK(refresh_zones_from_ldap(inst, ISC_TRUE));
			CHECK(flush_ldap_cache(inst->cache));
			flush_required = ISC_FALSE;
		}

		switch (ret) {
		case LDAP_RES_SEARCH_ENTRY:
			break;
		default:
			log_debug(3, "Ignoring psearch msg with retcode %x",
				  ret);
		}

		conn->tries = 0;
		cnt = ldap_count_entries(conn->handle, ldap_qresult->result);

		if (cnt > 0) {
			log_debug(3, "Got psearch updates (%d)", cnt);
			result = ldap_entrylist_append(conn->mctx,
						       conn->handle,
						       ldap_qresult->result,
						       &ldap_qresult->ldap_entries);
			if (result != ISC_R_SUCCESS) {
				/*
				 * Error means inconsistency of our zones
				 * data.
				 */
				log_error("ldap_psearch_watcher failed, zones "
					  "might be outdated. Run `rndc reload`");
				goto soft_err;
			}

			ldap_entry_t *entry;
			for (entry = HEAD(ldap_qresult->ldap_entries);
			     entry != NULL;
			     entry = NEXT(entry, link)) {
				LDAPControl **ctrls = NULL;
				ret = ldap_get_entry_controls(conn->handle,
							      entry->ldap_entry,
							      &ctrls);
				if (ret != LDAP_SUCCESS) {
					log_error("failed to extract controls "
						  "from psearch update. Zones "
						  "might be outdated, run "
						  "`rndc reload");
					goto soft_err;
				}

				psearch_update(inst, entry, ctrls);
			}
soft_err:
			ldap_query_free(ISC_TRUE, &ldap_qresult);
		}
	}

	log_debug(1, "Ending ldap_psearch_watcher");

cleanup:
	ldap_query_free(ISC_FALSE, &ldap_qresult);
	ldap_pool_putconnection(inst->pool, &conn);

	return (isc_threadresult_t)0;
}

