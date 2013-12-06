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
#include "cache.h"
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
#include "rbt_helper.h"
#include "fwd_register.h"


/* Max type length definitions, from lib/dns/master.c */
#define MINTSIZ (65535 - 12 - 1 - 2 - 2 - 4 - 2)
#define TOKENSIZ (8*1024)

const enum_txt_assoc_t forwarder_policy_txts[] = {
	{ dns_fwdpolicy_none,	"none"	},
	{ dns_fwdpolicy_first,	"first"	},
	{ dns_fwdpolicy_only,	"only"	},
	{ -1,			NULL	} /* end marker */
};

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

	/* Our own list of zones. */
	zone_register_t		*zone_register;
	fwd_register_t		*fwd_register;

	/* krb5 kinit mutex */
	isc_mutex_t		kinit_lock;

	isc_task_t		*task;
	isc_thread_t		watcher;
	isc_boolean_t		exiting;

	/* Settings. */
	settings_set_t		*local_settings;
	settings_set_t		*global_settings;
	dns_forwarders_t	orig_global_forwarders; /* from named.conf */
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

extern const settings_set_t const settings_default_set;

/** Local configuration file */
static const setting_t settings_local_default[] = {
	{ "uri",			no_default_string	},
	{ "connections",		no_default_uint		},
	{ "reconnect_interval",		no_default_uint		},
	{ "timeout",			no_default_uint		},
	{ "cache_ttl",			no_default_uint		},
	{ "base",			no_default_string	},
	{ "auth_method",		no_default_string	},
	{ "auth_method_enum",		no_default_uint		},
	{ "bind_dn",			no_default_string	},
	{ "password",			no_default_string	},
	{ "krb5_principal",		no_default_string	},
	{ "sasl_mech",			no_default_string	},
	{ "sasl_user",			no_default_string	},
	{ "sasl_auth_name",		no_default_string	},
	{ "sasl_realm",			no_default_string	},
	{ "sasl_password",		no_default_string	},
	{ "krb5_keytab",		no_default_string	},
	{ "fake_mname",			no_default_string	},
	{ "zone_refresh",		no_default_uint		},
	{ "psearch",			no_default_boolean	},
	{ "ldap_hostname",		no_default_string	},
	{ "sync_ptr",			no_default_boolean	},
	{ "dyn_update",			no_default_boolean	},
	{ "serial_autoincrement",	no_default_boolean	},
	{ "verbose_checks",		no_default_boolean	},
	end_of_settings
};

/** Global settings from idnsConfig object. */
static setting_t settings_global_default[] = {
	{ "dyn_update",		no_default_boolean	},
	{ "sync_ptr",		no_default_boolean	},
	{ "zone_refresh",	no_default_uint		},
/*	{ "psearch",		no_default_boolean	}, unsupported */
	end_of_settings
};

/*
 * Forward declarations.
 */

/* TODO: reorganize this stuff & clean it up. */
static isc_result_t new_ldap_connection(ldap_pool_t *pool,
					ldap_connection_t **ldap_connp) ATTR_NONNULLS;
static void destroy_ldap_connection(ldap_connection_t **ldap_connp) ATTR_NONNULLS;

static isc_result_t findrdatatype_or_create(isc_mem_t *mctx,
		ldapdb_rdatalist_t *rdatalist, dns_rdataclass_t rdclass,
		dns_rdatatype_t rdtype, dns_ttl_t ttl, dns_rdatalist_t **rdlistp) ATTR_NONNULLS;
static isc_result_t add_soa_record(isc_mem_t *mctx, ldap_qresult_t *qresult,
		dns_name_t *origin, ldap_entry_t *entry,
		ldapdb_rdatalist_t *rdatalist, const char *fake_mname) ATTR_NONNULLS;
static isc_result_t parse_rdata(isc_mem_t *mctx, ldap_qresult_t *qresult,
		dns_rdataclass_t rdclass, dns_rdatatype_t rdtype,
		dns_name_t *origin, const char *rdata_text,
		dns_rdata_t **rdatap) ATTR_NONNULLS;
static isc_result_t ldap_parse_rrentry(isc_mem_t *mctx, ldap_entry_t *entry,
		ldap_qresult_t *qresult, dns_name_t *origin,
		const char *fake_mname, ld_string_t *buf,
		ldapdb_rdatalist_t *rdatalist) ATTR_NONNULLS;
static inline isc_result_t ldap_get_zone_serial(ldap_instance_t *inst,
		dns_name_t *zone_name, isc_uint32_t *serial) ATTR_NONNULLS;

static isc_result_t ldap_connect(ldap_instance_t *ldap_inst,
		ldap_connection_t *ldap_conn, isc_boolean_t force) ATTR_NONNULLS;
static isc_result_t ldap_reconnect(ldap_instance_t *ldap_inst,
		ldap_connection_t *ldap_conn, isc_boolean_t force) ATTR_NONNULLS;
static isc_result_t handle_connection_error(ldap_instance_t *ldap_inst,
		ldap_connection_t *ldap_conn, isc_boolean_t force) ATTR_NONNULLS;
static isc_result_t ldap_query(ldap_instance_t *ldap_inst, ldap_connection_t *ldap_conn,
		   ldap_qresult_t **ldap_qresultp, const char *base, int scope, char **attrs,
		   int attrsonly, const char *filter, ...) ATTR_NONNULL(1, 3, 4, 8);
static isc_result_t ldap_query_create(isc_mem_t *mctx, ldap_qresult_t **ldap_qresultp) ATTR_NONNULLS;
static void ldap_query_free(isc_boolean_t prepare_reuse, ldap_qresult_t **ldap_qresultp) ATTR_NONNULLS;

/* Functions for writing to LDAP. */
static isc_result_t ldap_modify_do(ldap_instance_t *ldap_inst,
		const char *dn, LDAPMod **mods, isc_boolean_t delete_node) ATTR_NONNULLS;
static isc_result_t ldap_rdttl_to_ldapmod(isc_mem_t *mctx,
		dns_rdatalist_t *rdlist, LDAPMod **changep) ATTR_NONNULLS;
static isc_result_t ldap_rdatalist_to_ldapmod(isc_mem_t *mctx,
		dns_rdatalist_t *rdlist, LDAPMod **changep, int mod_op) ATTR_NONNULLS;

static isc_result_t ldap_rdata_to_char_array(isc_mem_t *mctx,
		dns_rdata_t *rdata_head, char ***valsp) ATTR_NONNULLS;
static void free_char_array(isc_mem_t *mctx, char ***valsp) ATTR_NONNULLS;
static isc_result_t modify_ldap_common(dns_name_t *owner, ldap_instance_t *ldap_inst,
		dns_rdatalist_t *rdlist, int mod_op, isc_boolean_t delete_node) ATTR_NONNULLS;
static isc_result_t soa_serial_increment(isc_mem_t *mctx, ldap_instance_t *inst,
		dns_name_t *zone_name) ATTR_NONNULLS;

/* Functions for maintaining pool of LDAP connections */
static isc_result_t ldap_pool_create(isc_mem_t *mctx, unsigned int connections,
		ldap_pool_t **poolp) ATTR_NONNULLS;
static void ldap_pool_destroy(ldap_pool_t **poolp);
static isc_result_t ldap_pool_getconnection(ldap_pool_t *pool,
		ldap_connection_t ** conn) ATTR_NONNULLS;
static void ldap_pool_putconnection(ldap_pool_t *pool,
		ldap_connection_t ** conn) ATTR_NONNULLS;
static isc_result_t ldap_pool_connect(ldap_pool_t *pool,
		ldap_instance_t *ldap_inst) ATTR_NONNULLS;

/* Functions for manipulating LDAP persistent search control */
static isc_result_t ldap_pscontrol_create(LDAPControl **ctrlp) ATTR_NONNULLS;

static isc_threadresult_t ldap_psearch_watcher(isc_threadarg_t arg) ATTR_NONNULLS;
static void psearch_update(ldap_instance_t *inst, ldap_entry_t *entry,
		LDAPControl **ctrls) ATTR_NONNULL(1, 2);


/* Persistent updates watcher */
static isc_threadresult_t
ldap_psearch_watcher(isc_threadarg_t arg);

#define PRINT_BUFF_SIZE 10 /* for unsigned int 2^32 */
isc_result_t
validate_local_instance_settings(ldap_instance_t *inst, settings_set_t *set) {
	isc_result_t result;

	isc_boolean_t psearch;
	isc_boolean_t serial_autoincrement;
	isc_uint32_t uint;
	const char *sasl_mech = NULL;
	const char *sasl_user = NULL;
	const char *sasl_realm = NULL;
	const char *sasl_password = NULL;
	const char *krb5_principal = NULL;
	const char *bind_dn = NULL;
	const char *password = NULL;
	ld_string_t *buff = NULL;

	char print_buff[PRINT_BUFF_SIZE];
	const char *auth_method_str = NULL;
	ldap_auth_t auth_method_enum = AUTH_INVALID;

	/* Set timer for deadlock detection inside semaphore_wait_timed . */
	CHECK(setting_get_uint("timeout", set, &uint));
	if (semaphore_wait_timeout.seconds < uint*SEM_WAIT_TIMEOUT_MUL)
		semaphore_wait_timeout.seconds = uint*SEM_WAIT_TIMEOUT_MUL;

	CHECK(setting_get_bool("psearch", set, &psearch));
	CHECK(setting_get_uint("connections", set, &uint));
	if (!psearch && uint < 1) {
		log_error("zone refresh mode requires one connection at least");
		CLEANUP_WITH(ISC_R_RANGE);
	}
	else if (psearch && uint < 2) {
		log_error("persistent search mode requires two connections "
			  "at least");
		/* watcher needs one and update_*() requests second connection */
		CLEANUP_WITH(ISC_R_RANGE);
	}
	if (!psearch)
		log_info("configuration without persistent search is deprecated "
			 "and the support for zone_refresh will be removed "
			 "in the future");
	else
		log_info("persistent search will be replaced with RFC 4533 "
			 "and options cache_ttl, psearch and zone_refresh will "
			 "be removed in the future; please prepare your LDAP "
			 "server");

	CHECK(setting_get_bool("serial_autoincrement", set, &serial_autoincrement));
	if (serial_autoincrement && !psearch) {
		log_error("SOA serial number auto-increment feature requires "
			  "persistent search");
		CLEANUP_WITH(ISC_R_FAILURE);
	}

	CHECK(setting_get_uint("zone_refresh", set, &uint));
	if (uint != 0 && psearch) {
		log_error("zone refresh and persistent search "
			  "cannot be enabled at same time");
		CLEANUP_WITH(ISC_R_FAILURE);
	}

	/* Select authentication method. */
	CHECK(setting_get_str("auth_method", set, &auth_method_str));
	auth_method_enum = AUTH_INVALID;
	for (int i = 0; supported_ldap_auth[i].name != NULL; i++) {
		if (!strcasecmp(auth_method_str, supported_ldap_auth[i].name)) {
			auth_method_enum = supported_ldap_auth[i].value;
			break;
		}
	}
	if (auth_method_enum == AUTH_INVALID) {
		log_error("unknown authentication method '%s'",
			  auth_method_str);
		CLEANUP_WITH(ISC_R_FAILURE);
	}
	CHECK(isc_string_printf(print_buff, PRINT_BUFF_SIZE, "%u", auth_method_enum));
	CHECK(setting_set("auth_method_enum", inst->local_settings, print_buff,
			  inst->task));

	/* check we have the right data when SASL/GSSAPI is selected */
	CHECK(setting_get_str("sasl_mech", set, &sasl_mech));
	CHECK(setting_get_str("krb5_principal", set, &krb5_principal));
	CHECK(setting_get_str("sasl_user", set, &sasl_user));
	CHECK(setting_get_str("sasl_realm", set, &sasl_realm));
	CHECK(setting_get_str("sasl_password", set, &sasl_password));
	CHECK(setting_get_str("bind_dn", set, &bind_dn));
	CHECK(setting_get_str("password", set, &password));

	if (auth_method_enum != AUTH_SIMPLE &&
	   (strlen(bind_dn) != 0 || strlen(password) != 0)) {
		log_error("options 'bind_dn' and 'password' are allowed only "
			  "for auth_method 'simple'");
		CLEANUP_WITH(ISC_R_FAILURE);
	}

	if (auth_method_enum == AUTH_SIMPLE &&
	    (strlen(bind_dn) == 0 || strlen(password) == 0)) {
		log_error("auth_method 'simple' requires 'bind_dn' and 'password'");
		log_info("for anonymous bind please use auth_method 'none'");
		CLEANUP_WITH(ISC_R_FAILURE);
	}

	if (auth_method_enum != AUTH_SASL &&
	   (strlen(sasl_realm) != 0 || strlen(sasl_user) != 0 ||
	    strlen(sasl_password) != 0 || strlen(krb5_principal) != 0)) {
		log_error("options 'sasl_realm', 'sasl_user', 'sasl_password' "
			  "and 'krb5_principal' are effective only with "
			  "auth_method 'sasl'");
		CLEANUP_WITH(ISC_R_FAILURE);
	}

	if ((auth_method_enum == AUTH_SASL) &&
	    (strcasecmp(sasl_mech, "GSSAPI") == 0)) {
		if ((krb5_principal == NULL) || (strlen(krb5_principal) == 0)) {
			if ((sasl_user == NULL) || (strlen(sasl_user) == 0)) {
				char hostname[HOST_NAME_MAX];
				if (gethostname(hostname, HOST_NAME_MAX) != 0) {
					log_error("SASL mech GSSAPI defined "
						  "but krb5_principal and "
						  "sasl_user are empty and"
						  "gethostname() failed");
					CLEANUP_WITH(ISC_R_FAILURE);
				} else {
					CHECK(str_new(inst->mctx, &buff));
					CHECK(str_sprintf(buff,
							  "DNS/%s", hostname));
					log_debug(2, "SASL mech GSSAPI defined "
						  "but krb5_principal and "
						  "sasl_user are empty, using "
						  "default '%s'",
						  str_buf(buff));
					CHECK(setting_set("krb5_principal", set,
							  str_buf(buff),
							  inst->task));
				}
			} else {
				CHECK(setting_set("krb5_principal", set,
						  sasl_user,
						  inst->task));
			}
		}
	} else if (auth_method_enum == AUTH_SASL) {
		log_info("SASL mechanisms other than GSSAPI+Kerberos "
			 "are untested; expect problems");
	}

	if (settings_set_isfilled(set) != ISC_TRUE)
		result = ISC_R_FAILURE;

cleanup:
	str_destroy(&buff);
	if (result != ISC_R_SUCCESS)
		log_error_r("LDAP config validation failed for database '%s'",
			    inst->db_name);
	return result;
}
#undef PRINT_BUFF_SIZE

#define PRINT_BUFF_SIZE 255
isc_result_t
new_ldap_instance(isc_mem_t *mctx, const char *db_name,
		  const char * const *argv, dns_dyndb_arguments_t *dyndb_args,
		  isc_task_t *task, ldap_instance_t **ldap_instp)
{
	isc_result_t result;
	ldap_instance_t *ldap_inst;
	dns_view_t *view = NULL;
	dns_forwarders_t *orig_global_forwarders = NULL;
	isc_boolean_t psearch;
	isc_uint32_t connections;
	char settings_name[PRINT_BUFF_SIZE];

	REQUIRE(ldap_instp != NULL && *ldap_instp == NULL);

	CHECKED_MEM_GET_PTR(mctx, ldap_inst);
	ZERO_PTR(ldap_inst);
	isc_mem_attach(mctx, &ldap_inst->mctx);

	ldap_inst->db_name = db_name;
	view = dns_dyndb_get_view(dyndb_args);
	dns_view_attach(view, &ldap_inst->view);
	ldap_inst->zmgr = dns_dyndb_get_zonemgr(dyndb_args);
	ISC_LIST_INIT(ldap_inst->orig_global_forwarders.addrs);
	ldap_inst->task = task;
	ldap_inst->watcher = 0;

	isc_string_printf_truncate(settings_name, PRINT_BUFF_SIZE,
				   SETTING_SET_NAME_LOCAL " for database %s",
				   db_name);
	CHECK(settings_set_create(mctx, settings_local_default,
	      sizeof(settings_local_default), settings_name,
	      &settings_default_set, &ldap_inst->local_settings));

	isc_string_printf_truncate(settings_name, PRINT_BUFF_SIZE,
				   SETTING_SET_NAME_GLOBAL " for database %s",
				   db_name);
	CHECK(settings_set_create(mctx, settings_global_default,
	      sizeof(settings_global_default), settings_name,
	      ldap_inst->local_settings, &ldap_inst->global_settings));

	CHECK(settings_set_fill(ldap_inst->local_settings, argv, task));
	CHECK(validate_local_instance_settings(ldap_inst, ldap_inst->local_settings));
	if (settings_set_isfilled(ldap_inst->global_settings) != ISC_TRUE)
		CLEANUP_WITH(ISC_R_FAILURE);

	CHECK(setting_get_bool("psearch", ldap_inst->local_settings, &psearch));
	CHECK(setting_get_uint("connections", ldap_inst->local_settings, &connections));

	CHECK(zr_create(mctx, ldap_inst, ldap_inst->global_settings,
			&ldap_inst->zone_register));
	CHECK(fwdr_create(ldap_inst->mctx, &ldap_inst->fwd_register));

	CHECK(isc_mutex_init(&ldap_inst->kinit_lock));

	/* copy global forwarders setting for configuration roll back in
	 * configure_zone_forwarders() */
	result = dns_fwdtable_find(ldap_inst->view->fwdtable, dns_rootname,
				   &orig_global_forwarders);
	if (result == ISC_R_SUCCESS) {
		isc_sockaddr_t *addr;
		isc_sockaddr_t *new_addr;
		for (addr = ISC_LIST_HEAD(orig_global_forwarders->addrs);
		     addr != NULL;
		     addr = ISC_LIST_NEXT(addr, link)) {
			CHECKED_MEM_GET_PTR(mctx, new_addr);
			*new_addr = *addr;
			ISC_LINK_INIT(new_addr, link);
			ISC_LIST_APPEND(ldap_inst->orig_global_forwarders.addrs,
					new_addr, link);
		}
		ldap_inst->orig_global_forwarders.fwdpolicy =
				orig_global_forwarders->fwdpolicy;

	} else if (result == ISC_R_NOTFOUND) {
		/* global forwarders are not configured */
		ldap_inst->orig_global_forwarders.fwdpolicy = dns_fwdpolicy_none;
	} else {
		goto cleanup;
	}

	CHECK(ldap_pool_create(mctx, connections, &ldap_inst->pool));
	CHECK(ldap_pool_connect(ldap_inst->pool, ldap_inst));

	if (psearch) {
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

	return result;
}
#undef PRINT_BUFF_SIZE

void
destroy_ldap_instance(ldap_instance_t **ldap_instp)
{
	ldap_instance_t *ldap_inst;
	const char *db_name;
	isc_sockaddr_t *addr;

	REQUIRE(ldap_instp != NULL);

	ldap_inst = *ldap_instp;
	if (ldap_inst == NULL)
		return;

	db_name = ldap_inst->db_name; /* points to DB instance: outside ldap_inst */

	if (ldap_inst->watcher != 0) {
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

	/* Unregister all zones already registered in BIND. */
	zr_destroy(&ldap_inst->zone_register);
	fwdr_destroy(&ldap_inst->fwd_register);

	ldap_pool_destroy(&ldap_inst->pool);
	dns_view_detach(&ldap_inst->view);

	DESTROYLOCK(&ldap_inst->kinit_lock);

	while (!ISC_LIST_EMPTY(ldap_inst->orig_global_forwarders.addrs)) {
		addr = ISC_LIST_HEAD(ldap_inst->orig_global_forwarders.addrs);
		ISC_LIST_UNLINK(ldap_inst->orig_global_forwarders.addrs, addr, link);
		SAFE_MEM_PUT_PTR(ldap_inst->mctx, addr);
	}

	settings_set_free(&ldap_inst->global_settings);
	settings_set_free(&ldap_inst->local_settings);

	MEM_PUT_AND_DETACH(ldap_inst);

	*ldap_instp = NULL;
	log_debug(1, "LDAP instance '%s' destroyed", db_name);
}

static isc_result_t ATTR_NONNULLS
new_ldap_connection(ldap_pool_t *pool, ldap_connection_t **ldap_connp)
{
	isc_result_t result;
	ldap_connection_t *ldap_conn;

	REQUIRE(pool != NULL);
	REQUIRE(ldap_connp != NULL && *ldap_connp == NULL);

	CHECKED_MEM_GET_PTR(pool->mctx, ldap_conn);
	ZERO_PTR(ldap_conn);

	result = isc_mutex_init(&ldap_conn->lock);
	if (result != ISC_R_SUCCESS) {
		SAFE_MEM_PUT_PTR(pool->mctx, ldap_conn);
		return result;
	}

	isc_mem_attach(pool->mctx, &ldap_conn->mctx);

	CHECK(ldap_pscontrol_create(&ldap_conn->serverctrls[0]));

	*ldap_connp = ldap_conn;

	return ISC_R_SUCCESS;

cleanup:
	destroy_ldap_connection(&ldap_conn);

	return result;
}

static void
destroy_ldap_connection(ldap_connection_t **ldap_connp)
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

	MEM_PUT_AND_DETACH(*ldap_connp);
}

/* Test if the existing zone is 'empty zone' per RFC 6303. */
static isc_boolean_t ATTR_NONNULLS
zone_isempty(isc_mem_t *mctx, dns_zone_t *zone) {
	char **argv = NULL;
	isc_boolean_t result = ISC_FALSE;

	if (dns_zone_getdbtype(zone, &argv, mctx) != ISC_R_SUCCESS)
		CLEANUP_WITH(ISC_FALSE);

	if (argv[0] != NULL && strcmp("_builtin", argv[0]) == 0 &&
	    argv[1] != NULL && strcmp("empty", argv[1]) == 0) {
		result = ISC_TRUE;
	} else {
		result = ISC_FALSE;
	}
	isc_mem_free(mctx, argv);

cleanup:
	return result;
}

/**
 * Delete a zone from plain BIND. LDAP zones require further steps for complete
 * removal, like deletion from zone register etc.
 *
 * @pre A zone pointer has to be attached to *zonep.
 *
 * @returns Values returned by dns_zt_unmount().
 */
static isc_result_t ATTR_NONNULLS
delete_bind_zone(dns_zt_t *zt, dns_zone_t **zonep) {
	dns_zone_t *zone;
	dns_db_t *dbp = NULL;
	dns_zonemgr_t *zmgr;
	isc_result_t result;

	REQUIRE (zonep != NULL && *zonep != NULL);

	zone = *zonep;

	/* Do not unload partially loaded zones, they have uninitialized
	 * structures. */
	if (dns_zone_getdb(zone, &dbp) == ISC_R_SUCCESS) {
		dns_db_detach(&dbp); /* dns_zone_getdb() attaches DB implicitly */
		dns_zone_unload(zone);
		dns_zone_log(zone, ISC_LOG_INFO, "shutting down");
	} else {
		dns_zone_log(zone, ISC_LOG_DEBUG(1), "not loaded - unload skipped");
	}

	result = dns_zt_unmount(zt, zone);
	zmgr = dns_zone_getmgr(zone);
	if (zmgr != NULL)
		dns_zonemgr_releasezone(zmgr, zone);
	dns_zone_detach(zonep);

	return result;
}

/*
 * Create a new zone with origin 'name'. The zone will be added to the
 * ldap_inst->view.
 */
static isc_result_t ATTR_NONNULLS
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
	if (result != ISC_R_NOTFOUND) {
		char zone_name[DNS_NAME_FORMATSIZE];
		dns_name_format(name, zone_name, DNS_NAME_FORMATSIZE);

		if (result != ISC_R_SUCCESS) {
			log_error_r("dns_view_findzone() failed while "
				    "searching for zone '%s'", zone_name);
		} else { /* zone already exists */
			if (zone_isempty(ldap_inst->mctx, zone) == ISC_TRUE) {
				result = delete_bind_zone(ldap_inst->view->zonetable,
							  &zone);
				if (result != ISC_R_SUCCESS)
					log_error_r("failed to create new zone "
						    "'%s': unable to unload "
						    "automatic empty zone",
						    zone_name);
				else
					log_info("automatic empty zone %s "
						 "unloaded", zone_name);

			} else {
				result = ISC_R_EXISTS;
				log_error_r("failed to create new zone '%s'",
					    zone_name);
			}
		}
		if (result != ISC_R_SUCCESS)
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

static isc_result_t ATTR_NONNULLS
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

static isc_result_t ATTR_NONNULLS
configure_zone_acl(isc_mem_t *mctx, dns_zone_t *zone,
		void (acl_setter)(dns_zone_t *zone, dns_acl_t *acl),
		const char *aclstr, acl_type_t type) {
	isc_result_t result;
	isc_result_t result2;
	dns_acl_t *acl = NULL;
	const char *type_txt = NULL;

	result = acl_from_ldap(mctx, aclstr, type, &acl);
	if (result != ISC_R_SUCCESS) {
		result2 = get_enum_description(acl_type_txts, type, &type_txt);
		if (result2 != ISC_R_SUCCESS) {
			log_bug("invalid acl type %u", type);
			type_txt = "<unknown>";
		}

		dns_zone_logc(zone, DNS_LOGCATEGORY_SECURITY, ISC_LOG_ERROR,
			      "%s policy is invalid: %s; configuring most "
			      "restrictive %s policy as possible",
			      type_txt, isc_result_totext(result), type_txt);
		result2 = acl_from_ldap(mctx, "", type, &acl);
		if (result2 != ISC_R_SUCCESS) {
			dns_zone_logc(zone, DNS_LOGCATEGORY_SECURITY, ISC_LOG_CRITICAL,
				      "cannot configure restrictive %s policy: %s",
				      type_txt, isc_result_totext(result2));
			FATAL_ERROR(__FILE__, __LINE__,
				    "insecure state detected");
		}
	}
	acl_setter(zone, acl);

	if (acl != NULL)
		dns_acl_detach(&acl);

	return result;
}

/* In BIND9 terminology "ssu" means "Simple Secure Update" */
static isc_result_t ATTR_NONNULLS
configure_zone_ssutable(dns_zone_t *zone, const char *update_str)
{
	isc_result_t result;
	isc_result_t result2;

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
	result = acl_configure_zone_ssutable(update_str, zone);
	if (result != ISC_R_SUCCESS) {
		dns_zone_logc(zone, DNS_LOGCATEGORY_SECURITY, ISC_LOG_ERROR,
			      "disabling all updates because of error in "
			      "update policy configuration: %s",
			      isc_result_totext(result));
		result2 = acl_configure_zone_ssutable("", zone);
		if (result2 != ISC_R_SUCCESS) {
			dns_zone_logc(zone, DNS_LOGCATEGORY_SECURITY, ISC_LOG_CRITICAL,
				      "cannot disable all updates: %s",
				      isc_result_totext(result2));
			FATAL_ERROR(__FILE__, __LINE__,
				    "insecure state detected");
		}
	}

	return result;
}

static isc_result_t ATTR_NONNULLS
delete_forwarding_table(ldap_instance_t *inst, dns_name_t *name,
			const char *msg_obj_type, const char *dn) {
	isc_result_t result;

	result = dns_fwdtable_delete(inst->view->fwdtable, name);
	if (result != ISC_R_SUCCESS && result != ISC_R_NOTFOUND) {
		log_error_r("%s '%s': failed to delete forwarders",
			    msg_obj_type, dn);
		return result;
	} else {
		return ISC_R_SUCCESS; /* ISC_R_NOTFOUND = nothing to delete */
	}
}

/* Delete zone by dns zone name */
isc_result_t
ldap_delete_zone2(ldap_instance_t *inst, dns_name_t *name, isc_boolean_t lock,
		  isc_boolean_t preserve_forwarding)
{
	isc_result_t result;
	isc_result_t isforward = ISC_R_NOTFOUND;
	isc_boolean_t unlock = ISC_FALSE;
	isc_boolean_t freeze = ISC_FALSE;
	dns_zone_t *zone = NULL;
	dns_zone_t *foundzone = NULL;
	char zone_name_char[DNS_NAME_FORMATSIZE];

	dns_name_format(name, zone_name_char, DNS_NAME_FORMATSIZE);
	log_debug(1, "deleting zone '%s'", zone_name_char);
	if (lock) {
		result = isc_task_beginexclusive(inst->task);
		RUNTIME_CHECK(result == ISC_R_SUCCESS ||
			      result == ISC_R_LOCKBUSY);
		if (result == ISC_R_SUCCESS)
			unlock = ISC_TRUE;
	}

	if (!preserve_forwarding) {
		CHECK(delete_forwarding_table(inst, name, "zone",
					      zone_name_char));
		isforward = fwdr_zone_ispresent(inst->fwd_register, name);
		if (isforward == ISC_R_SUCCESS)
			CHECK(fwdr_del_zone(inst->fwd_register, name));
	}

	result = zr_get_zone_ptr(inst->zone_register, name, &zone);
	if (result == ISC_R_NOTFOUND || result == DNS_R_PARTIALMATCH) {
		if (isforward == ISC_R_SUCCESS)
			log_info("forward zone '%s': shutting down", zone_name_char);
		log_debug(1, "zone '%s' not found in zone register", zone_name_char);
		result = dns_view_flushcache(inst->view);
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

	CHECK(delete_bind_zone(inst->view->zonetable, &zone));
	CHECK(zr_del_zone(inst->zone_register, name));

cleanup:
	if (freeze)
		dns_view_freeze(inst->view);
	if (unlock)
		isc_task_endexclusive(inst->task);

	return result;
}

/* Delete zone */
static isc_result_t ATTR_NONNULLS
ldap_delete_zone(ldap_instance_t *inst, const char *dn, isc_boolean_t lock,
		 isc_boolean_t preserve_forwarding)
{
	isc_result_t result;
	dns_name_t name;
	dns_name_init(&name, NULL);
	
	CHECK(dn_to_dnsname(inst->mctx, dn, &name, NULL));

	result = ldap_delete_zone2(inst, &name, lock, preserve_forwarding);

cleanup:
	if (dns_name_dynamic(&name))
		dns_name_free(&name, inst->mctx);

	return result;
}

/**
 * Read forwarding policy (from idnsForwardingPolicy attribute) and
 * list of forwarders (from idnsForwarders multi-value attribute)
 * and update forwarding settings for given zone.
 *
 * Enable forwarding if forwarders are specified and policy is not 'none'.
 * Disable forwarding if forwarding policy is 'none' or list of forwarders
 * is empty.
 *
 * Invalid forwarders are skipped, forwarding will be enabled if at least
 * one valid forwarder is defined. Global forwarders will be used if all
 * defined forwarders are invalid or list of forwarders is not present at all.
 *
 * @retval ISC_R_SUCCESS  Forwarding was enabled.
 * @retval ISC_R_DISABLED Forwarding was disabled.
 * @retval ISC_R_UNEXPECTEDTOKEN Forwarding policy is invalid
 *                               or all specified forwarders are invalid.
 * @retval ISC_R_NOMEMORY
 * @retval others	  Some RBT manipulation errors including ISC_R_FAILURE.
 */
static isc_result_t ATTR_NONNULLS
configure_zone_forwarders(ldap_entry_t *entry, ldap_instance_t *inst, 
                          dns_name_t *name)
{
	const char *dn = entry->dn;
	isc_result_t result;
	isc_result_t orig_result;
	ldap_valuelist_t values;
	ldap_value_t *value;
	isc_sockaddrlist_t addrs;
	isc_boolean_t is_global_config;
	isc_boolean_t fwdtbl_deletion_requested = ISC_TRUE;
	isc_boolean_t fwdtbl_update_requested = ISC_FALSE;
	dns_forwarders_t *old_setting = NULL;
	dns_fixedname_t foundname;
	dns_zone_t *zone = NULL;
	const char *msg_use_global_fwds;
	const char *msg_obj_type;
	const char *msg_forwarders_not_def;
	const char *msg_forward_policy = NULL;
	/**
	 * BIND forward policies are "first" (default) or "only".
	 * We invented option "none" which disables forwarding for zone
	 * regardless idnsForwarders attribute and global forwarders.
	 */
	dns_fwdpolicy_t fwdpolicy = dns_fwdpolicy_first;

	REQUIRE(entry != NULL && inst != NULL && name != NULL);
	ISC_LIST_INIT(addrs);
	dns_fixedname_init(&foundname);
	if (dns_name_equal(name, dns_rootname)) {
		is_global_config = ISC_TRUE;
		msg_obj_type = "global configuration";
		msg_use_global_fwds = "; global forwarders will be disabled";
		msg_forwarders_not_def = "; global forwarders from "
					 "configuration file will be used";
	} else {
		is_global_config = ISC_FALSE;
		msg_obj_type = "zone";
		msg_use_global_fwds = "; global forwarders will be used "
				      "(if they are configured)";
		msg_forwarders_not_def = msg_use_global_fwds;
	}

	/*
	 * Fetch forward policy.
	 */
	result = ldap_entry_getvalues(entry, "idnsForwardPolicy", &values);
	if (result == ISC_R_SUCCESS) {
		value = HEAD(values);
		if (value != NULL && value->value != NULL) {
			if (strcasecmp(value->value, "only") == 0)
				fwdpolicy = dns_fwdpolicy_only;
			else if (strcasecmp(value->value, "first") == 0)
				fwdpolicy = dns_fwdpolicy_first;
			else if (strcasecmp(value->value, "none") == 0)
				fwdpolicy = dns_fwdpolicy_none;
			else {
				log_error("%s '%s': invalid value '%s' in "
					  "idnsForwardPolicy attribute; "
					  "valid values: first, only, none"
					  "%s",
					  msg_obj_type, dn, value->value,
					  msg_use_global_fwds);
				CLEANUP_WITH(ISC_R_UNEXPECTEDTOKEN);
			}
		}
	}

	if (fwdpolicy == dns_fwdpolicy_none) {
		ISC_LIST_INIT(values); /* ignore idnsForwarders in LDAP */
	} else {
		result = ldap_entry_getvalues(entry, "idnsForwarders", &values);
		if (result == ISC_R_NOTFOUND || EMPTY(values)) {
			log_debug(5, "%s '%s': idnsForwarders attribute is "
				  "not present%s", msg_obj_type, dn,
				  msg_forwarders_not_def);
			if (is_global_config) {
				ISC_LIST_INIT(values);
				addrs = inst->orig_global_forwarders.addrs;
				fwdpolicy = inst->orig_global_forwarders.fwdpolicy;
			} else {
				CLEANUP_WITH(ISC_R_DISABLED);
			}
		}
	}

	CHECK(get_enum_description(forwarder_policy_txts, fwdpolicy,
				   &msg_forward_policy));
	log_debug(5, "%s '%s': forward policy is '%s'", msg_obj_type, dn,
		  msg_forward_policy);

	for (value = HEAD(values); value != NULL; value = NEXT(value, link)) {
		isc_sockaddr_t *addr = NULL;
		char forwarder_txt[ISC_SOCKADDR_FORMATSIZE];

		if (acl_parse_forwarder(value->value, inst->mctx, &addr)
				!= ISC_R_SUCCESS) {
			log_error("%s '%s': could not parse forwarder '%s'",
					msg_obj_type, dn, value->value);
			continue;
		}

		ISC_LINK_INIT(addr, link);
		ISC_LIST_APPEND(addrs, addr, link);
		isc_sockaddr_format(addr, forwarder_txt, ISC_SOCKADDR_FORMATSIZE);
		log_debug(5, "%s '%s': adding forwarder '%s'", msg_obj_type,
			  dn, forwarder_txt);
	}

	if (fwdpolicy != dns_fwdpolicy_none && ISC_LIST_EMPTY(addrs)) {
		log_debug(5, "%s '%s': all idnsForwarders are invalid%s",
			  msg_obj_type, dn, msg_use_global_fwds);
		CLEANUP_WITH(ISC_R_UNEXPECTEDTOKEN);
	} else if (fwdpolicy == dns_fwdpolicy_none) {
		log_debug(5, "%s '%s': forwarding explicitly disabled "
			  "(policy 'none', ignoring global forwarders)",
			  msg_obj_type, dn);
	}

	/* Check for old and new forwarding settings equality. */
	result = dns_fwdtable_find2(inst->view->fwdtable, name,
				    dns_fixedname_name(&foundname),
				    &old_setting);
	if (result == ISC_R_SUCCESS &&
	   (dns_name_equal(name, dns_fixedname_name(&foundname)) == ISC_TRUE)) {
		isc_sockaddr_t *s1, *s2;

		if (fwdpolicy != old_setting->fwdpolicy)
			fwdtbl_update_requested = ISC_TRUE;

		/* Check address lists item by item. */
		for (s1 = ISC_LIST_HEAD(addrs), s2 = ISC_LIST_HEAD(old_setting->addrs);
		     s1 != NULL && s2 != NULL && !fwdtbl_update_requested;
		     s1 = ISC_LIST_NEXT(s1, link), s2 = ISC_LIST_NEXT(s2, link))
			if (!isc_sockaddr_equal(s1, s2))
				fwdtbl_update_requested = ISC_TRUE;

		if (!fwdtbl_update_requested && ((s1 != NULL) || (s2 != NULL)))
			fwdtbl_update_requested = ISC_TRUE;
	} else {
		fwdtbl_update_requested = ISC_TRUE;
		if (result != ISC_R_SUCCESS && result != ISC_R_NOTFOUND)
			log_error_r("%s '%s': can't obtain old forwarding "
				    "settings", msg_obj_type, dn);
	}

	if (fwdtbl_update_requested) {
		/* Shutdown automatic empty zone if it is present. */
		result = dns_zt_find(inst->view->zonetable, name, 0, NULL,
				     &zone);
		if (result == ISC_R_SUCCESS || result == DNS_R_PARTIALMATCH) {
			if (zone_isempty(inst->mctx, zone)) {
				dns_zone_log(zone, ISC_LOG_INFO, "automatic "
					     "empty zone will be shut down "
					     "to enable forwarding");
				result = delete_bind_zone(inst->view->zonetable,
							  &zone);
			} else {
				dns_zone_detach(&zone);
				result = ISC_R_SUCCESS;
			}
		}
		if (result != ISC_R_SUCCESS && result != ISC_R_NOTFOUND)
			goto cleanup;

		/* Something was changed - set forward table up. */
		CHECK(delete_forwarding_table(inst, name, msg_obj_type, dn));
		result = dns_fwdtable_add(inst->view->fwdtable, name, &addrs, fwdpolicy);
		if (result != ISC_R_SUCCESS)
			log_error_r("%s '%s': forwarding table update failed",
				    msg_obj_type, dn);
	} else {
		result = ISC_R_SUCCESS;
		log_debug(5, "%s '%s': forwarding table unmodified",
			  msg_obj_type, dn);
	}
	if (result == ISC_R_SUCCESS) {
		fwdtbl_deletion_requested = ISC_FALSE;
		if (fwdpolicy == dns_fwdpolicy_none)
			result = ISC_R_DISABLED;
	}

cleanup:
	if (ISC_LIST_HEAD(addrs) !=
	    ISC_LIST_HEAD(inst->orig_global_forwarders.addrs)) {
		while(!ISC_LIST_EMPTY(addrs)) {
			isc_sockaddr_t *addr = NULL;
			addr = ISC_LIST_HEAD(addrs);
			ISC_LIST_UNLINK(addrs, addr, link);
			SAFE_MEM_PUT_PTR(inst->mctx, addr);
		}
	}
	if (fwdtbl_deletion_requested) {
		orig_result = result;
		result = delete_forwarding_table(inst, name, msg_obj_type, dn);
		if (result == ISC_R_SUCCESS)
			result = orig_result;
	}
	if (fwdtbl_deletion_requested || fwdtbl_update_requested) {
		log_debug(5, "%s '%s': forwarder table was updated: %s",
			  msg_obj_type, dn, dns_result_totext(result));
		orig_result = result;
		result = dns_view_flushcache(inst->view);
		if (result == ISC_R_SUCCESS)
			result = orig_result;
	}
	return result;
}

/* Parse the config object entry */
static isc_result_t ATTR_NONNULLS
ldap_parse_configentry(ldap_entry_t *entry, ldap_instance_t *inst)
{
	isc_result_t result;
	isc_timer_t *timer_inst;
	isc_interval_t timer_interval;
	isc_uint32_t interval_sec;
	isc_timertype_t timer_type;

	/* BIND functions are thread safe, ldap instance 'inst' is locked
	 * inside setting* functions. */

	log_debug(3, "Parsing configuration object");

	/* idnsForwardPolicy change is handled by configure_zone_forwarders() */
	result = configure_zone_forwarders(entry, inst, dns_rootname);
	if (result != ISC_R_SUCCESS && result != ISC_R_DISABLED) {
		log_error_r("global forwarder could not be set up");
	}

	result = setting_update_from_ldap_entry("dyn_update",
						inst->global_settings,
						"idnsAllowDynUpdate",
						entry, inst->task);
	if (result != ISC_R_SUCCESS && result != ISC_R_IGNORE)
		goto cleanup;

	result = setting_update_from_ldap_entry("sync_ptr",
						inst->global_settings,
						"idnsAllowSyncPTR",
						entry, inst->task);
	if (result != ISC_R_SUCCESS && result != ISC_R_IGNORE)
		goto cleanup;

	result = setting_update_from_ldap_entry("zone_refresh",
						inst->global_settings,
						"idnsZoneRefresh",
						entry, inst->task);
	if (result == ISC_R_SUCCESS) {
		RUNTIME_CHECK(manager_get_db_timer(inst->db_name, &timer_inst)
			      == ISC_R_SUCCESS);
		CHECK(setting_get_uint("zone_refresh", inst->global_settings,
				       &interval_sec));
		isc_interval_set(&timer_interval, interval_sec, 0);
		/* update interval only, not timer type */
		timer_type = isc_timer_gettype(timer_inst);
		result = isc_timer_reset(timer_inst, timer_type, NULL,
				&timer_interval, ISC_TRUE);
		if (result != ISC_R_SUCCESS) {
			log_error_r("could not adjust ZoneRefresh timer");
			goto cleanup;
		}
	} else if (result != ISC_R_IGNORE) {
		goto cleanup;
	}

cleanup:
	/* Configuration errors are not fatal. */
	/* TODO: log something? */
	return ISC_R_SUCCESS;
}

/* Parse the forward zone entry */
static isc_result_t ATTR_NONNULLS
ldap_parse_fwd_zoneentry(ldap_entry_t *entry, ldap_instance_t *inst)
{
	const char *dn;
	dns_name_t name;
	char name_txt[DNS_NAME_FORMATSIZE];
	isc_result_t result;

	REQUIRE(entry != NULL);
	REQUIRE(inst != NULL);

	dns_name_init(&name, NULL);

	/* Derive the DNS name of the zone from the DN. */
	dn = entry->dn;
	CHECK(dn_to_dnsname(inst->mctx, dn, &name, NULL));

	result = configure_zone_forwarders(entry, inst, &name);
	if (result != ISC_R_DISABLED && result != ISC_R_SUCCESS) {
		log_error_r("forward zone '%s': could not configure forwarding", dn);
		goto cleanup;
	}

	result = fwdr_zone_ispresent(inst->fwd_register, &name);
	if (result == ISC_R_NOTFOUND) {
		CHECK(fwdr_add_zone(inst->fwd_register, &name));
		dns_name_format(&name, name_txt, DNS_NAME_FORMATSIZE);
		log_info("forward zone '%s': loaded", name_txt);
	}
	else if (result != ISC_R_SUCCESS)
		log_error_r("forward zone '%s': could not read forwarding register", dn);

cleanup:
	if (dns_name_dynamic(&name))
		dns_name_free(&name, inst->mctx);

	return result;
}

/* Parse the master zone entry */
static isc_result_t ATTR_NONNULLS
ldap_parse_master_zoneentry(ldap_entry_t *entry, ldap_instance_t *inst)
{
	const char *dn;
	ldap_valuelist_t values;
	dns_name_t name;
	dns_zone_t *zone = NULL;
	isc_result_t result;
	isc_boolean_t unlock = ISC_FALSE;
	isc_boolean_t publish = ISC_FALSE;
	isc_boolean_t published = ISC_FALSE;
	isc_boolean_t ssu_changed;
	isc_task_t *task = inst->task;
	isc_uint32_t ldap_serial;
	isc_uint32_t zr_serial;	/* SOA serial value from in-memory zone register */
	unsigned char ldap_digest[RDLIST_DIGESTLENGTH] = {0};
	unsigned char *zr_digest = NULL;
	ldapdb_rdatalist_t rdatalist;
	isc_boolean_t zone_dynamic = ISC_FALSE;
	ldap_cache_t *cache = NULL;
	settings_set_t *zone_settings = NULL;
	isc_boolean_t serial_autoincrement;

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

	/* cache will not exist before zone load */
	result = zr_get_zone_cache(inst->zone_register, &name, &cache);
	if (result == ISC_R_SUCCESS)
		CHECK(discard_from_cache(cache, &name));
	else if (result != ISC_R_NOTFOUND)
		goto cleanup;

	/*
	 * TODO: Remove this hack, most probably before Fedora 20.
	 * Forwarding has top priority hence when the forwarders are properly
	 * set up all others attributes are ignored.
	 */
	result = configure_zone_forwarders(entry, inst, &name);
	if (result != ISC_R_DISABLED) {
		if (result == ISC_R_SUCCESS) {
			/* forwarding was enabled for the zone
			 * => zone type was changed to "forward"
			 * => delete "master" zone */
			CHECK(ldap_delete_zone2(inst, &name, ISC_FALSE,
						ISC_TRUE));
		}
		/* DO NOT CHANGE ANYTHING ELSE after forwarders are set up! */
		goto cleanup;
	}
	/* No forwarders are used. Zone was removed from fwdtable.
	 * Load the zone. */

	/* Check if we are already serving given zone */
	result = zr_get_zone_ptr(inst->zone_register, &name, &zone);
	if (result == ISC_R_NOTFOUND || result == DNS_R_PARTIALMATCH) {
		CHECK(create_zone(inst, &name, &zone));
		CHECK(zr_add_zone(inst->zone_register, zone, dn));
		publish = ISC_TRUE;
		log_debug(2, "created zone %p: %s", zone, dn);
	} else if (result != ISC_R_SUCCESS)
		goto cleanup;

	CHECK(zr_get_zone_settings(inst->zone_register, &name, &zone_settings));

	result = setting_update_from_ldap_entry("dyn_update", zone_settings,
				       "idnsAllowDynUpdate", entry, inst->task);
	if (result != ISC_R_SUCCESS && result != ISC_R_IGNORE)
		goto cleanup;
	ssu_changed = (result == ISC_R_SUCCESS);

	result = setting_update_from_ldap_entry("sync_ptr", zone_settings,
				       "idnsAllowSyncPTR", entry, inst->task);
	if (result != ISC_R_SUCCESS && result != ISC_R_IGNORE)
		goto cleanup;

	result = setting_update_from_ldap_entry("update_policy", zone_settings,
				       "idnsUpdatePolicy", entry, inst->task);
	if (result != ISC_R_SUCCESS && result != ISC_R_IGNORE)
		goto cleanup;

	if (result == ISC_R_SUCCESS || ssu_changed) {
		isc_boolean_t ssu_enabled;
		const char *ssu_policy = NULL;

		log_debug(2, "Setting SSU table for %p: %s", zone, dn);
		CHECK(setting_get_bool("dyn_update", zone_settings, &ssu_enabled));
		if (ssu_enabled) {
			/* Get the update policy and update the zone with it. */
			CHECK(setting_get_str("update_policy", zone_settings,
					      &ssu_policy));
			CHECK(configure_zone_ssutable(zone, ssu_policy));
		} else {
			/* Empty policy will prevent the update from reaching
			 * LDAP driver and error will be logged. */
			CHECK(configure_zone_ssutable(zone, ""));
		}
	}

	/* Fetch allow-query and allow-transfer ACLs */
	log_debug(2, "Setting allow-query for %p: %s", zone, dn);
	result = ldap_entry_getvalues(entry, "idnsAllowQuery", &values);
	if (result == ISC_R_SUCCESS) {
		CHECK(configure_zone_acl(inst->mctx, zone, &dns_zone_setqueryacl,
					 HEAD(values)->value, acl_type_query));
	} else {
		log_debug(2, "allow-query not set");
		dns_zone_clearqueryacl(zone);
	}

	log_debug(2, "Setting allow-transfer for %p: %s", zone, dn);
	result = ldap_entry_getvalues(entry, "idnsAllowTransfer", &values);
	if (result == ISC_R_SUCCESS) {
		CHECK(configure_zone_acl(inst->mctx, zone, &dns_zone_setxfracl,
					 HEAD(values)->value, acl_type_transfer));
	} else {
		log_debug(2, "allow-transfer not set");
		dns_zone_clearxfracl(zone);
	}

	if (publish) {
		/* Everything is set correctly, publish zone */
		CHECK(publish_zone(inst, zone));
		published = ISC_TRUE;
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

	zone_dynamic = (result == DNS_R_DYNAMIC);

	/* initialize serial in zone register and always increment serial
	 * for a new zone (typically after BIND start)
	 * - the zone was possibly changed in meanwhile */
	if (publish) {
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
	CHECK(ldap_get_zone_serial(inst, &name, &ldap_serial));
	CHECK(zr_get_zone_serial_digest(inst->zone_register, &name, &zr_serial,
			&zr_digest));
	CHECK(setting_get_bool("serial_autoincrement", zone_settings,
			       &serial_autoincrement));
	if (serial_autoincrement) {
		CHECK(ldapdb_rdatalist_get(inst->mctx, inst, &name,
				&name, &rdatalist));
		CHECK(rdatalist_digest(inst->mctx, &rdatalist, ldap_digest));

		if (ldap_serial == zr_serial) {
			/* serials are same - increment only if something was changed */
			if (memcmp(zr_digest, ldap_digest, RDLIST_DIGESTLENGTH) != 0)
				CHECK(soa_serial_increment(inst->mctx, inst, &name));
		}
	}
	if (ldap_serial != zr_serial) {
		/* serial in LDAP was changed - update zone register */
		CHECK(zr_set_zone_serial_digest(inst->zone_register, &name,
				ldap_serial, ldap_digest));

		if (zone_dynamic)
			dns_zone_notify(zone);
	}
	if (publish)
		dns_zone_log(zone, ISC_LOG_INFO, "loaded serial %u", ldap_serial);

cleanup:
	if (publish && !published) { /* Failure in ACL parsing or so. */
		log_error_r("zone '%s': publishing failed, rolling back due to",
			    entry->dn);
		result = delete_forwarding_table(inst, &name, "zone", entry->dn);
		if (result != ISC_R_SUCCESS)
			log_error_r("zone '%s': rollback failed: forwarding",
				    entry->dn);
		result = zr_del_zone(inst->zone_register, &name);
		if (result != ISC_R_SUCCESS)
			log_error_r("zone '%s': rollback failed: zone register",
				    entry->dn);
	}
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
 * Search in LDAP for zones.
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
	ldap_entryclass_t zone_class;
	ldap_entry_t *entry;
	dns_rbt_t *master_rbt = NULL;  /** < Master zones only */
	dns_rbt_t *forward_rbt = NULL; /** < Forward zones only */
	isc_boolean_t psearch;
	const char *base = NULL;
	rbt_iterator_t *iter = NULL;
	char *config_attrs[] = {
		"idnsForwardPolicy", "idnsForwarders", 
		"idnsAllowSyncPTR", "idnsZoneRefresh",
		"idnsPersistentSearch", NULL
	};
	char *zone_attrs[] = {
		"idnsName", "idnsUpdatePolicy", "idnsAllowQuery",
		"idnsAllowTransfer", "idnsForwardPolicy", "idnsForwarders",
		"idnsAllowDynUpdate", "idnsAllowSyncPTR", "objectClass", NULL
	};

	REQUIRE(ldap_inst != NULL);

	CHECK(setting_get_bool("psearch", ldap_inst->global_settings,
			       &psearch));
	if (psearch && !delete_only) {
		/* Watcher does the work for us, but deletion is allowed. */
		return ISC_R_SUCCESS;
	}

	log_debug(2, "refreshing list of zones for %s", ldap_inst->db_name);

	/* Query for configuration and zones from LDAP and release LDAP connection
	 * before processing them. It prevents deadlock in situations where
	 * ldap_parse_zoneentry() requests another connection. */
	CHECK(setting_get_str("base", ldap_inst->global_settings, &base));
	CHECK(ldap_pool_getconnection(ldap_inst->pool, &ldap_conn));
	CHECK(ldap_query(ldap_inst, ldap_conn, &ldap_zones_qresult, base,
			 LDAP_SCOPE_SUBTREE, zone_attrs, 0,
			 "(&(idnsZoneActive=TRUE)"
			 "(|(objectClass=idnsZone)(objectClass=idnsForwardZone)))"));

	/* Do not touch configuration from psearch watcher thread, otherwise
	 * BIND will crash. The problem is that isc_task_beginexclusive()
	 * is called before task associated with psearch watcher thread
	 * is fully initialized. */
	if (!delete_only)
		CHECK(ldap_query(ldap_inst, ldap_conn, &ldap_config_qresult,
				base, LDAP_SCOPE_SUBTREE,
				config_attrs, 0, "(objectClass=idnsConfigObject)"));

	ldap_pool_putconnection(ldap_inst->pool, &ldap_conn);

	if (!delete_only) {
		for (entry = HEAD(ldap_config_qresult->ldap_entries);
		     entry != NULL;
		     entry = NEXT(entry, link))
			CHECK(ldap_parse_configentry(entry, ldap_inst));
	}

	/*
	 * Create RB-trees with all master and forward zones stored in LDAP
	 * for cross check with zones registered in plugin.
	 */
	CHECK(dns_rbt_create(ldap_inst->mctx, NULL, NULL, &master_rbt));
	CHECK(dns_rbt_create(ldap_inst->mctx, NULL, NULL, &forward_rbt));

	for (entry = HEAD(ldap_zones_qresult->ldap_entries);
	     entry != NULL;
	     entry = NEXT(entry, link)) {
		if (ldap_entry_getclass(entry, &zone_class) != ISC_R_SUCCESS)
			continue;

		/* Derive the dns name of the zone from the DN. */
		dns_name_t name;
		dns_name_init(&name, NULL);
		result = dn_to_dnsname(ldap_inst->mctx, entry->dn, &name, NULL);
		if (result == ISC_R_SUCCESS) {
			log_debug(5, "Refresh %s", entry->dn);
			/* Add found zone to RB-tree for later check. */
			if (zone_class & LDAP_ENTRYCLASS_MASTER)
				result = dns_rbt_addname(master_rbt, &name, NULL);
			else if (zone_class & LDAP_ENTRYCLASS_FORWARD)
				result = dns_rbt_addname(forward_rbt, &name, NULL);
		}
		if (dns_name_dynamic(&name))
			dns_name_free(&name, ldap_inst->mctx);

		if (result != ISC_R_SUCCESS) {
			log_error("Could not parse zone %s", entry->dn);
			continue;
		}

		if (!delete_only) {
			if (zone_class & LDAP_ENTRYCLASS_MASTER)
				result = ldap_parse_master_zoneentry(entry, ldap_inst);
			else if (zone_class & LDAP_ENTRYCLASS_FORWARD)
				result = ldap_parse_fwd_zoneentry(entry, ldap_inst);
		}
		if (result == ISC_R_SUCCESS)
			zone_count++;
		else
			log_error_r("error parsing zone '%s'", entry->dn);
	}

	/* Walk through master zone register and remove all zones which
	 * disappeared from LDAP. */
	char name_txt[DNS_NAME_FORMATSIZE];
	DECLARE_BUFFERED_NAME(registered_name);
	DECLARE_BUFFERED_NAME(ldap_name);

	INIT_BUFFERED_NAME(registered_name);
	result = zr_rbt_iter_init(ldap_inst->zone_register, &iter, &registered_name);
	while (result == ISC_R_SUCCESS) {
		void *data = NULL;
		INIT_BUFFERED_NAME(ldap_name);

		result = dns_rbt_findname(master_rbt, &registered_name,
					  DNS_RBTFIND_EMPTYDATA,
					  &ldap_name, &data);
		if (result == ISC_R_NOTFOUND || result == DNS_R_PARTIALMATCH) {
			rbt_iter_stop(&iter);
			dns_name_format(&registered_name, name_txt, DNS_NAME_FORMATSIZE);
			log_debug(1, "master zone '%s' is being removed", name_txt);
			result = ldap_delete_zone2(ldap_inst, &registered_name,
						   ISC_FALSE, ISC_FALSE);
			if (result != ISC_R_SUCCESS) {
				log_error_r("unable to delete master zone '%s'", name_txt);
			} else {
				/* Deletion invalidated the chain, restart iteration. */
				result = zr_rbt_iter_init(ldap_inst->zone_register,
							  &iter, &registered_name);
				continue;
			}
		} else if (result != ISC_R_SUCCESS) {
			break;
		}
		result = rbt_iter_next(&iter, &registered_name);
	}
	if (result != ISC_R_NOTFOUND && result != ISC_R_NOMORE)
		goto cleanup;

	/* Walk through forward zone register and remove all zones which
	 * disappeared from LDAP. */
	INIT_BUFFERED_NAME(registered_name);
	iter = NULL;
	result = fwdr_rbt_iter_init(ldap_inst->fwd_register, &iter, &registered_name);
	while (result == ISC_R_SUCCESS) {
		void *data = NULL;
		INIT_BUFFERED_NAME(ldap_name);

		result = dns_rbt_findname(forward_rbt, &registered_name,
					  DNS_RBTFIND_EMPTYDATA,
					  &ldap_name, &data);
		if (result == ISC_R_NOTFOUND || result == DNS_R_PARTIALMATCH) {
			rbt_iter_stop(&iter);
			dns_name_format(&registered_name, name_txt, DNS_NAME_FORMATSIZE);
			log_debug(1, "forward zone '%s' is being removed", name_txt);
			result = delete_forwarding_table(ldap_inst, &registered_name,
							 "forward zone", name_txt);
			if (result != ISC_R_SUCCESS) {
				log_error_r("could not remove forwarding for zone '%s': "
					    "forward register mismatch", name_txt);
			}
			result = fwdr_del_zone(ldap_inst->fwd_register, &registered_name);
			if (result == ISC_R_SUCCESS) {
				/* Deletion invalidated the chain, restart iteration. */
				result = fwdr_rbt_iter_init(ldap_inst->fwd_register,
							    &iter, &registered_name);
				continue;
			} else {
				log_error_r("unable to delete forward zone '%s' "
					    "from forwarding register", name_txt);
			}
		} else if (result != ISC_R_SUCCESS) {
			break;
		}
		result = rbt_iter_next(&iter, &registered_name);
	}
	if (result == ISC_R_NOTFOUND || result == ISC_R_NOMORE)
		goto cleanup;

cleanup:
	rbt_iter_stop(&iter);
	if (master_rbt != NULL)
		dns_rbt_destroy(&master_rbt);
	if (forward_rbt != NULL)
		dns_rbt_destroy(&forward_rbt);

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
	} else {
		/*
		 * No support for different TTLs yet.
		 */
		if (rdlist->ttl != ttl) {
			log_error("different TTLs in single rdata list "
				  "are not supported");
			CLEANUP_WITH(ISC_R_NOTIMPLEMENTED);
		}
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
		SAFE_MEM_PUT_PTR(mctx, rdlist);
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
		SAFE_MEM_PUT_PTR(mctx, rdata);
	}
}

static isc_result_t
ldap_parse_rrentry(isc_mem_t *mctx, ldap_entry_t *entry,
		   ldap_qresult_t *qresult, dns_name_t *origin,
		   const char *fake_mname, ld_string_t *buf,
		   ldapdb_rdatalist_t *rdatalist)
{
	isc_result_t result;
	dns_rdataclass_t rdclass;
	ldap_entryclass_t objclass;
	dns_ttl_t ttl;
	dns_rdatatype_t rdtype;
	dns_rdata_t *rdata = NULL;
	dns_rdatalist_t *rdlist = NULL;
	ldap_attribute_t *attr;
	const char *dn = "<NULL entry>";
	const char *data = "<NULL data>";

	CHECK(ldap_entry_getclass(entry, &objclass));
	if ((objclass & LDAP_ENTRYCLASS_MASTER) != 0)
		CHECK(add_soa_record(mctx, qresult, origin, entry,
				     rdatalist, fake_mname));

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
	if (entry != NULL)
		dn = entry->dn;
	if (buf != NULL && str_buf(buf) != NULL)
		data = str_buf(buf);
	log_error_r("failed to parse RR entry: dn '%s': data '%s'", dn, data);
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
	const char *fake_mname = NULL;

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

	CHECK(setting_get_str("fake_mname", ldap_inst->local_settings,
			      &fake_mname));
	for (entry = HEAD(ldap_qresult->ldap_entries);
		entry != NULL;
		entry = NEXT(entry, link)) {
		node = NULL;	
		dns_name_init(&node_name, NULL);
		if (dn_to_dnsname(mctx, entry->dn,  &node_name, NULL)
		    != ISC_R_SUCCESS) {
			continue;
		}

		result = ldapdbnode_create(mctx, &node_name, &node);
		dns_name_free(&node_name, mctx);
		if (result == ISC_R_SUCCESS) {
			result = ldap_parse_rrentry(mctx, entry, ldap_qresult,
		                       origin, fake_mname,
		                       string, &node->rdatalist);
		}
		if (result != ISC_R_SUCCESS) {
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
	ldap_cache_t *cache = NULL;
	const char *fake_mname = NULL;

	REQUIRE(ldap_inst != NULL);
	REQUIRE(name != NULL);
	REQUIRE(rdatalist != NULL);

	/* Check if RRs are in the cache */
	CHECK(zr_get_zone_cache(ldap_inst->zone_register, name, &cache));
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

	CHECK(setting_get_str("fake_mname", ldap_inst->local_settings,
			      &fake_mname));
	for (entry = HEAD(ldap_qresult->ldap_entries);
		entry != NULL;
		entry = NEXT(entry, link)) {
		CHECK(ldap_parse_rrentry(mctx, entry, ldap_qresult,
				   origin, fake_mname,
				   string, rdatalist));
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
	       const char *fake_mname)
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

	isc_buffer_init(&lex_buffer, (char *)text.base, text.length);
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
	SAFE_MEM_PUT_PTR(mctx, rdata);
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
		CHECK(handle_connection_error(ldap_inst, ldap_conn, ISC_FALSE));
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
static int ATTR_NONNULL(3)
ldap_sasl_interact(LDAP *ld, unsigned flags, void *defaults, void *sin)
{
	sasl_interact_t *in;
	ldap_instance_t *ldap_inst = defaults;
	int ret = LDAP_OTHER;
	isc_result_t result;

	REQUIRE(ldap_inst != NULL);
	UNUSED(flags);

	if (ld == NULL || sin == NULL)
		return LDAP_PARAM_ERROR;

	log_debug(4, "doing interactive bind");
	for (in = sin; in != NULL && in->id != SASL_CB_LIST_END; in++) {
		switch (in->id) {
		case SASL_CB_USER:
			log_debug(4, "got request for SASL_CB_USER");
			CHECK(setting_get_str("sasl_user",
					      ldap_inst->global_settings,
					      (const char **)&in->result));
			in->len = strlen(in->result);
			ret = LDAP_SUCCESS;
			break;
		case SASL_CB_GETREALM:
			log_debug(4, "got request for SASL_CB_GETREALM");
			CHECK(setting_get_str("sasl_realm",
					      ldap_inst->global_settings,
					      (const char **)&in->result));
			in->len = strlen(in->result);
			ret = LDAP_SUCCESS;
			break;
		case SASL_CB_AUTHNAME:
			log_debug(4, "got request for SASL_CB_AUTHNAME");
			CHECK(setting_get_str("sasl_auth_name",
					      ldap_inst->global_settings,
					      (const char **)&in->result));
			in->len = strlen(in->result);
			ret = LDAP_SUCCESS;
			break;
		case SASL_CB_PASS:
			log_debug(4, "got request for SASL_CB_PASS");
			CHECK(setting_get_str("sasl_password",
					      ldap_inst->global_settings,
					      (const char **)&in->result));
			in->len = strlen(in->result);
			ret = LDAP_SUCCESS;
			break;
		default:
			goto cleanup;
		}
	}

	return ret;

cleanup:
	in->result = NULL;
	in->len = 0;
	return LDAP_OTHER;
}

/*
 * Initialize the LDAP handle and bind to the server. Needed authentication
 * credentials and settings are available from the ldap_inst.
 */
static isc_result_t
ldap_connect(ldap_instance_t *ldap_inst, ldap_connection_t *ldap_conn,
	     isc_boolean_t force)
{
	LDAP *ld = NULL;
	int ret;
	int version;
	struct timeval timeout;
	isc_result_t result = ISC_R_FAILURE;
	const char *uri = NULL;
	const char *ldap_hostname = NULL;
	isc_uint32_t timeout_sec;

	REQUIRE(ldap_inst != NULL);
	REQUIRE(ldap_conn != NULL);

	CHECK(setting_get_str("uri", ldap_inst->local_settings, &uri));
	ret = ldap_initialize(&ld, uri);
	if (ret != LDAP_SUCCESS) {
		log_error("LDAP initialization failed: %s",
			  ldap_err2string(ret));
		CLEANUP_WITH(ISC_R_FAILURE);
	}

	version = LDAP_VERSION3;
	ret = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
	LDAP_OPT_CHECK(ret, "failed to set LDAP version");

	CHECK(setting_get_uint("timeout", ldap_inst->global_settings,
			       &timeout_sec));
	timeout.tv_sec = timeout_sec;
	timeout.tv_usec = 0;

	ret = ldap_set_option(ld, LDAP_OPT_TIMEOUT, &timeout);
	LDAP_OPT_CHECK(ret, "failed to set timeout");

	CHECK(setting_get_str("ldap_hostname", ldap_inst->local_settings,
			      &ldap_hostname));
	if (strlen(ldap_hostname) > 0) {
		ret = ldap_set_option(ld, LDAP_OPT_HOST_NAME, ldap_hostname);
		LDAP_OPT_CHECK(ret, "failed to set LDAP_OPT_HOST_NAME");
	}

	if (ldap_conn->handle != NULL)
		ldap_unbind_ext_s(ldap_conn->handle, NULL, NULL);
	ldap_conn->handle = ld;
	ld = NULL; /* prevent double-unbind from ldap_reconnect() and cleanup: */

	CHECK(ldap_reconnect(ldap_inst, ldap_conn, force));
	return result;

cleanup:
	if (ld != NULL)
		ldap_unbind_ext_s(ld, NULL, NULL);
	
	/* Make sure handle is NULL. */
	if (ldap_conn->handle != NULL) {
		ldap_unbind_ext_s(ldap_conn->handle, NULL, NULL);
		ldap_conn->handle = NULL;
	}

	return result;
}

static isc_result_t
ldap_reconnect(ldap_instance_t *ldap_inst, ldap_connection_t *ldap_conn,
	       isc_boolean_t force)
{
	isc_result_t result;
	int ret = 0;
	const char *bind_dn = NULL;
	const char *password = NULL;
	const char *uri = NULL;
	const char *sasl_mech = NULL;
	const char *krb5_principal = NULL;
	const char *krb5_keytab = NULL;
	ldap_auth_t auth_method_enum = AUTH_INVALID;
	isc_uint32_t reconnect_interval;

	if (force)
		goto force_reconnect;

	if (ldap_conn->tries > 0) {
		isc_time_t now;
		int time_cmp;

		result = isc_time_now(&now);
		time_cmp = isc_time_compare(&now, &ldap_conn->next_reconnect);
		if (result == ISC_R_SUCCESS && time_cmp < 0)
			return ISC_R_SOFTQUOTA;
	}

	/* Set the next possible reconnect time. */
	{
		isc_interval_t delay;
		unsigned int i;
		unsigned int seconds;
		const unsigned int intervals[] = { 2, 5, 20, UINT_MAX };
		const size_t ntimes = sizeof(intervals) / sizeof(intervals[0]);

		i = ISC_MIN(ntimes - 1, ldap_conn->tries);
		CHECK(setting_get_uint("reconnect_interval",
				       ldap_inst->global_settings,
				       &reconnect_interval));
		seconds = ISC_MIN(intervals[i], reconnect_interval);
		isc_interval_set(&delay, seconds, 0);
		isc_time_nowplusinterval(&ldap_conn->next_reconnect, &delay);
	}

	ldap_conn->tries++;
force_reconnect:
	CHECK(setting_get_str("uri", ldap_inst->local_settings, &uri));
	log_debug(2, "trying to establish LDAP connection to %s", uri);

	CHECK(setting_get_uint("auth_method_enum", ldap_inst->local_settings,
			       &auth_method_enum));
	switch (auth_method_enum) {
	case AUTH_NONE:
		ret = ldap_simple_bind_s(ldap_conn->handle, NULL, NULL);
		break;
	case AUTH_SIMPLE:
		CHECK(setting_get_str("bind_dn", ldap_inst->global_settings, &bind_dn));
		CHECK(setting_get_str("password", ldap_inst->global_settings, &password));
		ret = ldap_simple_bind_s(ldap_conn->handle, bind_dn, password);
		break;
	case AUTH_SASL:
		CHECK(setting_get_str("sasl_mech", ldap_inst->local_settings,
				      &sasl_mech));
		if (strcmp(sasl_mech, "GSSAPI") == 0) {
			CHECK(setting_get_str("krb5_principal",
					      ldap_inst->local_settings,
					      &krb5_principal));
			CHECK(setting_get_str("krb5_keytab",
					      ldap_inst->local_settings,
					      &krb5_keytab));
			LOCK(&ldap_inst->kinit_lock);
			result = get_krb5_tgt(ldap_inst->mctx,
					      krb5_principal,
					      krb5_keytab);
			UNLOCK(&ldap_inst->kinit_lock);
			if (result != ISC_R_SUCCESS)
				return ISC_R_NOTCONNECTED;
		}

		log_debug(4, "trying interactive bind using '%s' mechanism",
			  sasl_mech);
		ret = ldap_sasl_interactive_bind_s(ldap_conn->handle, NULL,
						   sasl_mech,
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
		log_ldap_error(ldap_conn->handle, "bind to LDAP server failed");

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
		case LDAP_TIMEOUT:
			return ISC_R_TIMEDOUT;
		default:
			return ISC_R_FAILURE;
		}
	} else
		log_debug(2, "bind to LDAP server successful");

	ldap_conn->tries = 0;

	return ISC_R_SUCCESS;

cleanup:
	return result;
}

static isc_result_t
handle_connection_error(ldap_instance_t *ldap_inst, ldap_connection_t *ldap_conn,
			isc_boolean_t force)
{
	int ret;
	int err_code;
	isc_result_t result = ISC_R_FAILURE;

	REQUIRE(ldap_conn != NULL);

	if (ldap_conn->handle == NULL)
		goto reconnect;

	ret = ldap_get_option(ldap_conn->handle, LDAP_OPT_RESULT_CODE,
				(void *)&err_code);
	if (ret != LDAP_OPT_SUCCESS) {
		log_error("handle_connection_error failed to obtain ldap error code");
		goto reconnect;
	}

	switch (err_code) {
	case LDAP_NO_SUCH_OBJECT:
		ldap_conn->tries = 0;
		result = ISC_R_SUCCESS;
		break;
	case LDAP_TIMEOUT:
		log_error("LDAP query timed out. Try to adjust \"timeout\" parameter");
		result = ISC_R_TIMEDOUT;
		break;
	case LDAP_INVALID_DN_SYNTAX:
	case LDAP_INVALID_SYNTAX:
	case LDAP_FILTER_ERROR:
		log_ldap_error(ldap_conn->handle, "invalid syntax in "
			       "handle_connection_error indicates a bug");
		result = ISC_R_UNEXPECTEDTOKEN;
		break;
	default:
		/* Try to reconnect on other errors. */
		log_ldap_error(ldap_conn->handle, "connection error");
reconnect:
		if (ldap_conn->tries == 0)
			log_error("connection to the LDAP server was lost");
		result = ldap_connect(ldap_inst, ldap_conn, force);
		if (result == ISC_R_SUCCESS)
			log_info("successfully reconnected to LDAP server");
		break;
	}

	return result;
}

static isc_result_t
ldap_modify_do(ldap_instance_t *ldap_inst, const char *dn, LDAPMod **mods,
		isc_boolean_t delete_node)
{
	int ret;
	int err_code;
	const char *operation_str;
	isc_result_t result;
	ldap_connection_t *ldap_conn = NULL;

	REQUIRE(dn != NULL);
	REQUIRE(mods != NULL);
	REQUIRE(ldap_inst != NULL);

	/* Any mod_op can be ORed with LDAP_MOD_BVALUES. */
	if ((mods[0]->mod_op & ~LDAP_MOD_BVALUES) == LDAP_MOD_ADD)
		operation_str = "modifying(add)";
	else if ((mods[0]->mod_op & ~LDAP_MOD_BVALUES) == LDAP_MOD_DELETE)
		operation_str = "modifying(del)";
	else if ((mods[0]->mod_op & ~LDAP_MOD_BVALUES) == LDAP_MOD_REPLACE)
		operation_str = "modifying(replace)";
	else {
		operation_str = "modifying(unknown operation)";
		log_bug("%s: 0x%x", operation_str, mods[0]->mod_op);
		CLEANUP_WITH(ISC_R_NOTIMPLEMENTED);
	}

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
		log_debug(2, "writing to '%s': %s", dn, operation_str);
		ret = ldap_modify_ext_s(ldap_conn->handle, dn, mods, NULL, NULL);
	}

	result = (ret == LDAP_SUCCESS) ? ISC_R_SUCCESS : ISC_R_FAILURE;
	if (ret == LDAP_SUCCESS)
		goto cleanup;

	LDAP_OPT_CHECK(ldap_get_option(ldap_conn->handle, LDAP_OPT_RESULT_CODE,
			&err_code), "ldap_modify_do(%s) failed to obtain ldap error code",
			operation_str);

	/* If there is no object yet, create it with an ldap add operation. */
	if ((mods[0]->mod_op & ~LDAP_MOD_BVALUES) == LDAP_MOD_ADD &&
	     err_code == LDAP_NO_SUCH_OBJECT) {
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

	log_ldap_error(ldap_conn->handle, "while %s entry '%s'", operation_str, dn);

	/* do not error out if we are trying to delete an
	 * unexisting attribute */
	if ((mods[0]->mod_op & ~LDAP_MOD_BVALUES) != LDAP_MOD_DELETE ||
	    err_code != LDAP_NO_SUCH_ATTRIBUTE) {
		result = ISC_R_FAILURE;
	}
cleanup:
	ldap_pool_putconnection(ldap_inst->pool, &ldap_conn);

	return result;
}

static void ATTR_NONNULLS
ldap_mod_free(isc_mem_t *mctx, LDAPMod **changep)
{
	LDAPMod *change;

	REQUIRE(changep != NULL);

	change = *changep;
	if (change == NULL)
		return;

	free_char_array(mctx, &change->mod_values);
	if (change->mod_type != NULL)
		SAFE_MEM_PUT(mctx, change->mod_type, LDAP_ATTR_FORMATSIZE);
	SAFE_MEM_PUT_PTR(mctx, change);

	*changep = NULL;
}

static isc_result_t ATTR_NONNULLS
ldap_mod_create(isc_mem_t *mctx, LDAPMod **changep)
{
	LDAPMod *change = NULL;
	isc_result_t result;

	REQUIRE(changep != NULL && *changep == NULL);

	CHECKED_MEM_GET_PTR(mctx, change);
	ZERO_PTR(change);
	CHECKED_MEM_GET(mctx, change->mod_type, LDAP_ATTR_FORMATSIZE);

	*changep = change;
	return ISC_R_SUCCESS;

cleanup:
	if (change != NULL)
		SAFE_MEM_PUT_PTR(mctx, change);

	return result;
}

static isc_result_t
ldap_rdatalist_to_ldapmod(isc_mem_t *mctx, dns_rdatalist_t *rdlist,
			  LDAPMod **changep, int mod_op)
{
	isc_result_t result;
	LDAPMod *change = NULL;
	char **vals = NULL;

	CHECK(ldap_mod_create(mctx, &change));
	CHECK(rdatatype_to_ldap_attribute(rdlist->type, change->mod_type,
					  LDAP_ATTR_FORMATSIZE));
	CHECK(ldap_rdata_to_char_array(mctx, HEAD(rdlist->rdata), &vals));

	change->mod_op = mod_op;
	change->mod_values = vals;

	*changep = change;
	return ISC_R_SUCCESS;

cleanup:
	ldap_mod_free(mctx, &change);

	return result;
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

	CHECK(ldap_mod_create(mctx, &change));
	change->mod_op = LDAP_MOD_REPLACE;
	CHECK(isc_string_copy(change->mod_type, LDAP_ATTR_FORMATSIZE, "dnsTTL"));

	CHECKED_MEM_ALLOCATE(mctx, vals, 2 * sizeof(char *));
	memset(vals, 0, 2 * sizeof(char *));
	change->mod_values = vals;

	CHECKED_MEM_ALLOCATE(mctx, vals[0], str_len(ttlval) + 1);
	memcpy(vals[0], str_buf(ttlval), str_len(ttlval) + 1);

	*changep = change;

cleanup:
	if (ttlval) str_destroy(&ttlval);
	if (change && result != ISC_R_SUCCESS) ldap_mod_free(mctx, &change);

	return result;
}

/*
 * Modify the SOA record of a zone, where DN of the zone is 'zone_dn'.
 * The SOA record is a special case because we need to update serial,
 * refresh, retry, expire and minimum attributes for each SOA record.
 */
static isc_result_t ATTR_NONNULLS
modify_soa_record(ldap_instance_t *ldap_inst, const char *zone_dn,
		  dns_rdata_t *rdata)
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

	result = ldap_modify_do(ldap_inst, zone_dn, changep, ISC_FALSE);

cleanup:
	return result;

#undef MAX_SOANUM_LENGTH
#undef SET_LDAP_MOD
}


#define SYNCPTR_PREF    "PTR record synchronization "
#define SYNCPTR_FMTPRE  SYNCPTR_PREF "(%s) for A/AAAA '%s' "
#define SYNCPTR_FMTPOST ldap_modop_str(mod_op), a_name_str

static const char *
ldap_modop_str(unsigned int mod_op) {
	static const char *add = "addition";
	static const char *del = "deletion";

	switch (mod_op) {
	case LDAP_MOD_ADD:
		return add;

	case LDAP_MOD_DELETE:
		return del;

	default:
		INSIST("unsupported LDAP mod_op" == NULL);
		return NULL;
	}
}

static void
append_trailing_dot(char *str, unsigned int size) {
	unsigned int length = strlen(str);
	if (str[length] != '.') {
		REQUIRE(length + 1 < size);
		str[length] = '.';
		str[length+1] = '\0';
	}
}

static isc_result_t
ldap_find_ptr(ldap_instance_t *ldap_inst, const int af, const char *ip_str,
	      dns_name_t *ptr_name, ld_string_t *ptr_dn,
	      dns_name_t *zone_name) {
	isc_result_t result;
	const char *owner_zone_dn_ptr;
	isc_mem_t *mctx = ldap_inst->mctx;

	union {
		struct in_addr v4;
		struct in6_addr v6;
	} ip;
	isc_netaddr_t isc_ip; /* internal net address representation */

	/* Get string with IP address from change request
	 * and convert it to in_addr structure. */
	if (inet_pton(af, ip_str, &ip) != 1) {
		log_bug(SYNCPTR_PREF "could not convert IP address "
			"from string '%s'", ip_str);
		CLEANUP_WITH(ISC_R_UNEXPECTED);
	}

	/* Only copy data to isc_ip stucture. */
	switch (af) {
	case AF_INET:
		isc_netaddr_fromin(&isc_ip, &ip.v4);
		break;
	case AF_INET6:
		isc_netaddr_fromin6(&isc_ip, &ip.v6);
		break;
	default:
		log_bug("unsupported address family 0x%x", af);
		CLEANUP_WITH(ISC_R_NOTIMPLEMENTED);
		break;
	}

	/*
	 * Convert IP address to PTR record.
	 *
	 * @example
	 * 192.168.0.1 -> 1.0.168.192.in-addr.arpa
	 *
	 * @todo Check if it works for IPv6 correctly.
	 */
	CHECK(dns_byaddr_createptrname2(&isc_ip, 0, ptr_name));

	/* Get LDAP entry indentifier. */
	CHECK(dnsname_to_dn(ldap_inst->zone_register, ptr_name, ptr_dn));

	/*
	 * @example
	 * owner_dn_ptr = "idnsName=100.0.168, idnsname=192.in-addr.arpa,cn=dns,$SUFFIX"
	 * owner_zone_dn_ptr = "idnsname=192.in-addr.arpa,cn=dns,$SUFFIX"
	 */
	owner_zone_dn_ptr = strstr(str_buf(ptr_dn),", ") + 1;

	/* Get attribute "idnsAllowDynUpdate" for reverse zone or use default. */
	CHECK(dn_to_dnsname(mctx, owner_zone_dn_ptr, zone_name, NULL));

cleanup:
	return result;
}

/**
 * Check if PTR record's value in LDAP == name of the modified A/AAAA record.
 * Update will be refused if the PTR name contains multiple PTR records or
 * if the value in LDAP != expected name.
 *
 * @param[in] a_name     Name of modified A/AAAA record.
 * @param[in] a_name_str Name of modified A/AAAA record as NUL terminated string.
 * @param[in] ptr_name   Name of PTR record generated from IP address in A/AAAA.
 * @param[in] mod_op     LDAP_MOD_DELETE if A/AAAA record is being deleted
 *                       or LDAP_MOD_ADD if A/AAAA record is being added.
 * @param[out] delete_node Will be set to ISC_TRUE if the database node
 *                         is empty after PTR record deletion.
 *
 * @retval ISC_R_IGNORE  A and PTR records match, no change is required.
 * @retval ISC_R_SUCCESS Prerequisites fulfilled, update is allowed.
 * @retval other         Errors
 *
 * @code
 * ** A record deletion **
 * ; nsupdate command:
 * update delete www.example.com. IN A	192.0.2.1
 *
 * ; PTR update will be allowed if the zone contains following data:
 * www.example.com.		A	192.0.2.1
 * 1.2.0.192.in-addr.arpa.	PTR	www.example.com.
 *
 * ; PTR update will not be allowed if the zone contains following data:
 * www.example.com.		A	192.0.2.1
 * 1.2.0.192.in-addr.arpa.	PTR	mail.example.com.
 * @endcode
 *
 * @code
 * ** A record addition **
 * ; nsupdate command:
 * update add www.example.com. 3600 IN A 192.0.2.1
 *
 * ; PTR update will be allowed if the zone does not contain A and PTR record.
 *
 * ; PTR update will not be allowed if the zone contains following data:
 * 1.2.0.192.in-addr.arpa. 	PTR	mail.example.com.
 * @endcode
 */
static isc_result_t
ldap_sync_ptr_validate(ldap_instance_t *ldap_inst, dns_name_t *a_name,
		       const char *a_name_str, dns_name_t *ptr_name,
		       int mod_op, isc_boolean_t *delete_node) {
	isc_result_t result;
	isc_mem_t *mctx = ldap_inst->mctx;

	char ptr_name_str[DNS_NAME_FORMATSIZE+1];
	isc_boolean_t ptr_found;
	dns_rdata_ptr_t ptr_rdata;
	char ptr_rdata_str[DNS_NAME_FORMATSIZE+1];
	isc_boolean_t ptr_a_equal = ISC_FALSE; /* GCC requires initialization */

	ldapdb_rdatalist_t ldap_rdlist;
	dns_rdatalist_t *ptr_rdlist = NULL;

	ISC_LIST_INIT(ldap_rdlist);

	REQUIRE(mod_op == LDAP_MOD_DELETE || mod_op == LDAP_MOD_ADD);
	REQUIRE(a_name_str != NULL);

	/* Find PTR entry in LDAP. */
	ptr_found = ISC_FALSE;
	result = ldapdb_rdatalist_get(mctx, ldap_inst, ptr_name,
				      NULL, &ldap_rdlist);

	*delete_node = ISC_FALSE;
	if (result != ISC_R_SUCCESS && result != ISC_R_NOTFOUND) {
		log_error_r(SYNCPTR_FMTPRE "failed in ldapdb_rdatalist_get()",
			    SYNCPTR_FMTPOST);
		goto cleanup;
	}

	/* Find the value of PTR entry. */
	if (result == ISC_R_SUCCESS) {
		result = ldapdb_rdatalist_findrdatatype(&ldap_rdlist,
							dns_rdatatype_ptr,
							&ptr_rdlist);
		if (result == ISC_R_SUCCESS && HEAD(ptr_rdlist->rdata) != NULL) {
			if (HEAD(ptr_rdlist->rdata) != TAIL(ptr_rdlist->rdata)) {
				dns_name_format(ptr_name, ptr_name_str,
						DNS_NAME_FORMATSIZE);
				append_trailing_dot(ptr_name_str,
						    sizeof(ptr_name_str));
				log_error(SYNCPTR_FMTPRE
					  "failed: multiple PTR records under "
					  "name '%s' are not supported",
					  SYNCPTR_FMTPOST, ptr_name_str);
				CLEANUP_WITH(ISC_R_NOTIMPLEMENTED);
			}
			dns_rdata_tostruct(HEAD(ptr_rdlist->rdata), &ptr_rdata,
					   NULL);

			ptr_found = ISC_TRUE;

			/* Compare PTR value with name of the A/AAAA record. */
			if (dns_name_isabsolute(a_name) &&
			    dns_name_isabsolute(&ptr_rdata.ptr) &&
			    dns_name_equal(&ptr_rdata.ptr, a_name)) {
				ptr_a_equal = ISC_TRUE;
			} else {
				ptr_a_equal = ISC_FALSE;
				dns_name_format(ptr_name, ptr_name_str,
						DNS_NAME_FORMATSIZE);
				append_trailing_dot(ptr_name_str,
						    sizeof(ptr_name_str));
				dns_name_format(&ptr_rdata.ptr, ptr_rdata_str,
						DNS_NAME_FORMATSIZE);
				append_trailing_dot(ptr_rdata_str,
						    sizeof(ptr_rdata_str));
			}
		}
	}

	if (mod_op == LDAP_MOD_DELETE) {
		if (ptr_found == ISC_FALSE) {
			log_debug(3, SYNCPTR_FMTPRE "skipped: no PTR records "
				  "found", SYNCPTR_FMTPOST);
			CLEANUP_WITH(ISC_R_IGNORE);

		} else if (ptr_a_equal == ISC_FALSE) {
			log_error(SYNCPTR_FMTPRE "failed: "
				  "existing PTR record '%s' contains unexpected "
				  "value '%s' (value '%s' expected)",
				  SYNCPTR_FMTPOST, ptr_name_str, ptr_rdata_str,
				  a_name_str);
			CLEANUP_WITH(ISC_R_UNEXPECTEDTOKEN);

		} else if (HEAD(ldap_rdlist) == TAIL(ldap_rdlist)) {
			/* Exactly one PTR record was found and rdlist contains
			 * exactly one RRset, so the deleted PTR record
			 * is the only RR in the node. */
			REQUIRE(HEAD(ldap_rdlist)->type == dns_rdatatype_ptr);
			*delete_node = ISC_TRUE;
		}

	} else if (mod_op == LDAP_MOD_ADD && ptr_found == ISC_TRUE) {
		if (ptr_a_equal == ISC_TRUE) {
			log_debug(3, SYNCPTR_FMTPRE "skipped: PTR record with"
				  "desired value is already present",
				  SYNCPTR_FMTPOST);
			CLEANUP_WITH(ISC_R_IGNORE);

		} else {
			log_error(SYNCPTR_FMTPRE "failed: "
				  "existing PTR record '%s' contains unexpected "
				  "value '%s' (value '%s' or no value expected)",
				  SYNCPTR_FMTPOST, ptr_name_str, ptr_rdata_str,
				  a_name_str);
			CLEANUP_WITH(DNS_R_SINGLETON);
		}
	}

	result = ISC_R_SUCCESS;

cleanup:
	ldapdb_rdatalist_destroy(mctx, &ldap_rdlist);

	return result;
}

static isc_result_t
ldap_sync_ptr(ldap_instance_t *ldap_inst, dns_name_t *a_name,
		const int af, const char *ip_str, const int mod_op) {
	isc_result_t result;
	isc_mem_t *mctx = ldap_inst->mctx;

	char **vals = NULL;

	char a_name_str[DNS_NAME_FORMATSIZE+1];

	ld_string_t *ptr_dn = NULL;
	struct dns_fixedname ptr_name;
	LDAPMod *change[2] = { NULL };

	dns_name_t zone_name;
	ldap_cache_t *zone_cache = NULL;
	settings_set_t *zone_settings = NULL;
	isc_boolean_t zone_dyn_update;

	isc_boolean_t delete_node;

	dns_name_init(&zone_name, NULL);
	dns_fixedname_init(&ptr_name);
	CHECK(str_new(mctx, &ptr_dn));

	/**
	 * Get string representation of PTR record value.
	 * @code
	 * a_name_str = "host.example.com."
	 * @endcode
	 */
	dns_name_format(a_name, a_name_str, DNS_NAME_FORMATSIZE);
	append_trailing_dot(a_name_str, sizeof(a_name_str));

	result = ldap_find_ptr(ldap_inst, af, ip_str,
			       dns_fixedname_name(&ptr_name), ptr_dn, &zone_name);
	if (result != ISC_R_SUCCESS) {
		log_error_r(SYNCPTR_FMTPRE "refused: "
			    "unable to find active reverse zone "
			    "for IP address '%s'", SYNCPTR_FMTPOST, ip_str);
		CLEANUP_WITH(ISC_R_NOTFOUND);
	}

	CHECK(zr_get_zone_settings(ldap_inst->zone_register, &zone_name,
				   &zone_settings));
	CHECK(setting_get_bool("dyn_update", zone_settings, &zone_dyn_update));
	if (!zone_dyn_update) {
		char zone_name_str[DNS_NAME_FORMATSIZE];
		dns_name_format(&zone_name, zone_name_str, DNS_NAME_FORMATSIZE);
		log_error(SYNCPTR_FMTPRE "refused: "
			  "IP address '%s' belongs to reverse zone '%s' "
			  "and dynamic updates are not allowed for that zone",
			  SYNCPTR_FMTPOST, ip_str, zone_name_str);
		CLEANUP_WITH(ISC_R_NOPERM);
	}

	result = ldap_sync_ptr_validate(ldap_inst, a_name, a_name_str,
					dns_fixedname_name(&ptr_name), mod_op,
					&delete_node);
	if (result == ISC_R_IGNORE)
		CLEANUP_WITH(ISC_R_SUCCESS);
	else if (result != ISC_R_SUCCESS)
		CLEANUP_WITH(DNS_R_SERVFAIL);

	/* Fill the LDAPMod change structure up. */
	CHECK(ldap_mod_create(mctx, &change[0]));

	/* Do the same action what has been done with A/AAAA record. */
	change[0]->mod_op = mod_op;
	CHECK(rdatatype_to_ldap_attribute(dns_rdatatype_ptr, change[0]->mod_type,
					  LDAP_ATTR_FORMATSIZE));

	CHECKED_MEM_ALLOCATE(mctx, vals, 2 * sizeof(char *));
	memset(vals, 0, 2 * sizeof(char *));
	change[0]->mod_values = vals;

	CHECKED_MEM_ALLOCATE(mctx, vals[0], strlen(a_name_str) + 1);
	memcpy(vals[0], a_name_str, strlen(a_name_str) + 1);

	/* Modify PTR record. */
	CHECK(ldap_modify_do(ldap_inst, str_buf(ptr_dn),
			     change, delete_node));
	CHECK(zr_get_zone_cache(ldap_inst->zone_register,
				dns_fixedname_name(&ptr_name), &zone_cache));
	CHECK(discard_from_cache(zone_cache, dns_fixedname_name(&ptr_name)));

cleanup:
	if (dns_name_dynamic(&zone_name))
		dns_name_free(&zone_name, mctx);
	str_destroy(&ptr_dn);
	ldap_mod_free(mctx, &change[0]);

	return result;
}
#undef SYNCPTR_PREF
#undef SYNCPTR_FMTPRE
#undef SYNCPTR_FMTPOST

static isc_result_t
modify_ldap_common(dns_name_t *owner, ldap_instance_t *ldap_inst,
		   dns_rdatalist_t *rdlist, int mod_op, isc_boolean_t delete_node)
{
	isc_result_t result;
	isc_mem_t *mctx = ldap_inst->mctx;
	ld_string_t *owner_dn = NULL;
	LDAPMod *change[3] = { NULL };
	ldap_cache_t *cache = NULL;
	isc_boolean_t zone_sync_ptr;
	char **vals = NULL;
	dns_name_t zone_name;
	char *zone_dn = NULL;
	settings_set_t *zone_settings = NULL;
	int af; /* address family */

	/*
	 * Find parent zone entry and check if Dynamic Update is allowed.
	 * @todo Try the cache first and improve split: SOA records are problematic.
	 */
	dns_name_init(&zone_name, NULL);
	CHECK(str_new(mctx, &owner_dn));

	CHECK(dnsname_to_dn(ldap_inst->zone_register, owner, owner_dn));
	zone_dn = strstr(str_buf(owner_dn),", ");

	if (zone_dn == NULL) { /* SOA record; owner = zone => owner_dn = zone_dn */
		zone_dn = (char *)str_buf(owner_dn);
	} else {
		zone_dn += 1; /* skip whitespace */
	}

	CHECK(dn_to_dnsname(mctx, zone_dn, &zone_name, NULL));

	result = zr_get_zone_settings(ldap_inst->zone_register, &zone_name,
				      &zone_settings);
	if (result != ISC_R_SUCCESS) {
		if (result == ISC_R_NOTFOUND)
			log_debug(3, "update refused: "
				  "active zone '%s' not found", zone_dn);
		CLEANUP_WITH(DNS_R_NOTAUTH);
	}

	if (rdlist->type == dns_rdatatype_soa && mod_op == LDAP_MOD_DELETE)
		CLEANUP_WITH(ISC_R_SUCCESS);

	/* Flush modified record from the cache */
	CHECK(zr_get_zone_cache(ldap_inst->zone_register, owner, &cache));
	CHECK(discard_from_cache(cache, owner));

	if (rdlist->type == dns_rdatatype_soa) {
		result = modify_soa_record(ldap_inst, str_buf(owner_dn),
					   HEAD(rdlist->rdata));
		goto cleanup;
	}

	CHECK(ldap_rdatalist_to_ldapmod(mctx, rdlist, &change[0], mod_op));
	if (mod_op == LDAP_MOD_ADD) {
		/* for now always replace the ttl on add */
		CHECK(ldap_rdttl_to_ldapmod(mctx, rdlist, &change[1]));
	}

	CHECK(ldap_modify_do(ldap_inst, str_buf(owner_dn), change, delete_node));

	/* Keep the PTR of corresponding A/AAAA record synchronized. */
	if (rdlist->type == dns_rdatatype_a || rdlist->type == dns_rdatatype_aaaa) {
		/*
		 * Look for zone "idnsAllowSyncPTR" attribute. If attribute do not exist,
		 * use global plugin configuration: option "sync_ptr"
		 */

		CHECK(setting_get_bool("sync_ptr", zone_settings, &zone_sync_ptr));
		if (!zone_sync_ptr) {
			log_debug(3, "sync PTR is disabled for zone '%s'", zone_dn);
			CLEANUP_WITH(ISC_R_SUCCESS);
		}
		log_debug(3, "sync PTR is enabled for zone '%s'", zone_dn);

		af = (rdlist->type == dns_rdatatype_a) ? AF_INET : AF_INET6;
		result = ldap_sync_ptr(ldap_inst, owner, af,
				       change[0]->mod_values[0], mod_op);
	}

cleanup:
	str_destroy(&owner_dn);
	ldap_mod_free(mctx, &change[0]);
	ldap_mod_free(mctx, &change[1]);
	free_char_array(mctx, &vals);
	dns_name_free(&zone_name, mctx);

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

	if (pool->conns != NULL) {
		for (i = 0; i < pool->connections; i++) {
			ldap_conn = pool->conns[i];
			if (ldap_conn != NULL)
				destroy_ldap_connection(&ldap_conn);
		}

		SAFE_MEM_PUT(pool->mctx, pool->conns,
			     pool->connections * sizeof(ldap_connection_t *));
	}

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
	/* Following assertion is necessary to convince clang static analyzer
	 * that the loop is always entered. */
	REQUIRE(pool->connections > 0);
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
		/* Continue even if LDAP server is down */
		if (result != ISC_R_NOTCONNECTED && result != ISC_R_TIMEDOUT &&
		    result != ISC_R_SUCCESS) {
			goto cleanup;
		}
		pool->conns[i] = ldap_conn;
	}

	return ISC_R_SUCCESS;

cleanup:
	log_error_r("couldn't establish connection in LDAP connection pool");
	for (i = 0; i < pool->connections; i++) {
		destroy_ldap_connection(&pool->conns[i]);
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
	BerElement *ber = NULL;
	struct berval *berval = NULL;
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

	result = ISC_R_SUCCESS;

cleanup:
	if (ber != NULL)
		ber_free(ber, 1);
	if (berval != NULL)
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

cleanup:
	if (zone != NULL)
		dns_zone_detach(&zone);
	return result;
}

static isc_result_t
soa_serial_increment(isc_mem_t *mctx, ldap_instance_t *inst,
		dns_name_t *zone_name) {
	isc_result_t result = ISC_R_FAILURE;
	ld_string_t *zone_dn = NULL;
	const char *zone_dn_char = "INACTIVE/UNKNOWN";
	ldapdb_rdatalist_t rdatalist;
	dns_rdatalist_t *rdlist = NULL;
	dns_rdata_t *soa_rdata = NULL;
	isc_uint32_t old_serial;
	isc_uint32_t new_serial;
	isc_time_t curr_time;
	ldap_cache_t *cache = NULL;

	REQUIRE(inst != NULL);
	REQUIRE(zone_name != NULL);

	INIT_LIST(rdatalist);
	CHECK(str_new(mctx, &zone_dn));
	CHECK(dnsname_to_dn(inst->zone_register, zone_name, zone_dn));
	zone_dn_char = str_buf(zone_dn);
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
	CHECK(modify_soa_record(inst, str_buf(zone_dn), soa_rdata));
	CHECK(zr_get_zone_cache(inst->zone_register, zone_name, &cache));
	CHECK(discard_from_cache(cache, zone_name));

	/* put the new SOA to inst->cache and compare old and new serials */
	CHECK(ldap_get_zone_serial(inst, zone_name, &new_serial));

cleanup:
	if (result == ISC_R_SUCCESS &&
	    isc_serial_gt(new_serial, old_serial) == ISC_FALSE)
		result = DNS_R_UNCHANGED;
	if (result != ISC_R_SUCCESS)
		log_error_r("SOA serial number incrementation failed in zone "
			    "'%s'", zone_dn_char);

	str_destroy(&zone_dn);
	ldapdb_rdatalist_destroy(mctx, &rdatalist);
	return result;
}

/*
 * update_zone routine is processed asynchronously so it cannot assume
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
	ldap_entryclass_t objclass;
	ldap_entry_t *entry_zone = NULL;
	ldap_entry_t *entry_record = NULL;
	isc_mem_t *mctx;
	dns_name_t prevname;
	dns_name_t currname;
	char *attrs_zone[] = {
		"idnsName", "idnsUpdatePolicy", "idnsAllowQuery",
		"idnsAllowTransfer", "idnsForwardPolicy", "idnsForwarders",
		"idnsAllowDynUpdate", "idnsAllowSyncPTR", "objectClass", NULL
	};
	char *attrs_record[] = {
			"objectClass", "dn", NULL
	};

	UNUSED(task);

	mctx = pevent->mctx;
	dns_name_init(&currname, NULL);
	dns_name_init(&prevname, NULL);

	CHECK(manager_get_ldap_instance(pevent->dbname, &inst));

	result = ldap_query(inst, NULL, &ldap_qresult_zone, pevent->dn,
			 LDAP_SCOPE_BASE, attrs_zone, 0,
			 "(&(|(objectClass=idnsZone)"
			 "(objectClass=idnsForwardZone))"
			 "(idnsZoneActive=TRUE))");
	if (result != ISC_R_SUCCESS && result != ISC_R_NOTFOUND)
		goto cleanup;

	CHECK(dn_to_dnsname(inst->mctx, pevent->dn, &currname, NULL));

	if (ldap_qresult_zone != NULL &&
	    HEAD(ldap_qresult_zone->ldap_entries) != NULL) {
		entry_zone = HEAD(ldap_qresult_zone->ldap_entries);
		CHECK(ldap_entry_getclass(entry_zone, &objclass));
		if (objclass & LDAP_ENTRYCLASS_MASTER)
			CHECK(ldap_parse_master_zoneentry(entry_zone, inst));
		else if (objclass & LDAP_ENTRYCLASS_FORWARD)
			CHECK(ldap_parse_fwd_zoneentry(entry_zone, inst));

		if (PSEARCH_MODDN(pevent->chgtype)) {
			if (dn_to_dnsname(inst->mctx, pevent->prevdn, &prevname, NULL)
					== ISC_R_SUCCESS) {
				CHECK(ldap_delete_zone(inst, pevent->prevdn,
				      ISC_TRUE, ISC_FALSE));
			} else {
				log_debug(5, "update_zone: old zone wasn't managed "
					     "by plugin, dn '%s'", pevent->prevdn);
			}

			/* fill the cache with records from renamed zone */
			if (objclass & LDAP_ENTRYCLASS_MASTER) {
				CHECK(ldap_query(inst, NULL, &ldap_qresult_record, pevent->dn,
						LDAP_SCOPE_ONELEVEL, attrs_record, 0,
						"(objectClass=idnsRecord)"));

				for (entry_record = HEAD(ldap_qresult_record->ldap_entries);
						entry_record != NULL;
						entry_record = NEXT(entry_record, link)) {

					psearch_update(inst, entry_record, NULL);
				}
			}
		}

		INSIST(NEXT(entry_zone, link) == NULL); /* no multiple zones with same DN */
	} else {
		CHECK(ldap_delete_zone(inst, pevent->dn, ISC_TRUE, ISC_FALSE));
	}

cleanup:
	if (result != ISC_R_SUCCESS)
		log_error_r("update_zone (psearch) failed for '%s'. "
			  "Zones can be outdated, run `rndc reload`",
			  pevent->dn);

	ldap_query_free(ISC_FALSE, &ldap_qresult_zone);
	ldap_query_free(ISC_FALSE, &ldap_qresult_record);
	if (dns_name_dynamic(&currname))
		dns_name_free(&currname, inst->mctx);
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

	CHECK(manager_get_ldap_instance(pevent->dbname, &inst));
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
		log_error_r("update_config (psearch) failed for '%s'. "
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
	ldap_cache_t *cache = NULL;
	isc_boolean_t serial_autoincrement;
	isc_mem_t *mctx;
	dns_zone_t *zone_ptr = NULL;
	isc_boolean_t zone_found = ISC_FALSE;
	isc_boolean_t zone_reloaded = ISC_FALSE;
	isc_uint32_t serial;
	mctx = pevent->mctx;

	UNUSED(task);

	/* Structure to be stored in the cache. */
	ldapdb_rdatalist_t rdatalist;

	/* Convert domain name from text to struct dns_name_t. */
	settings_set_t *zone_settings;
	dns_name_t name;
	dns_name_t origin;
	dns_name_t prevname;
	dns_name_t prevorigin;
	dns_name_init(&name, NULL);
	dns_name_init(&origin, NULL);
	dns_name_init(&prevname, NULL);
	dns_name_init(&prevorigin, NULL);
	CHECK(manager_get_ldap_instance(pevent->dbname, &inst));
	CHECK(dn_to_dnsname(mctx, pevent->dn, &name, &origin));
	zone_found = ISC_TRUE;

update_restart:
	if (PSEARCH_DEL(pevent->chgtype) || PSEARCH_MODDN(pevent->chgtype)) {
		log_debug(5, "psearch_update: removing name from cache, dn: '%s'",
		          pevent->dn);
	}

	/* Get cache instance & clean old record */
	cache = NULL;
	CHECK(zr_get_zone_cache(inst->zone_register, &name, &cache));
	CHECK(discard_from_cache(cache, &name));

	/* TODO: double check correctness before replacing ldap_query() with
	 *       data from *event */
	if (PSEARCH_MODDN(pevent->chgtype)) {
		/* remove previous name only if it was inside DNS subtree */
		if (dn_to_dnsname(mctx, pevent->prevdn, &prevname, &prevorigin)
				== ISC_R_SUCCESS) {
			log_debug(5, "psearch_update: removing name from cache, dn: '%s'",
					  pevent->prevdn);
			cache = NULL;
			result = zr_get_zone_cache(inst->zone_register, &prevname, &cache);
			if (result == ISC_R_SUCCESS)
				CHECK(discard_from_cache(cache, &prevname));
			else if (result != ISC_R_NOTFOUND)
				goto cleanup;
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
	if (PSEARCH_ANY(pevent->chgtype)) {
		zone_settings = NULL;
		CHECK(zr_get_zone_settings(inst->zone_register, &origin, &zone_settings));
		CHECK(setting_get_bool("serial_autoincrement", zone_settings,
				       &serial_autoincrement));

		/* Serial autoincrement does zone state check implicitly.
		 * Ldap_get_zone_serial() is required for other cases, because
		 * no function above returns DNS_R_NOTLOADED for invalid zone. */
		if (serial_autoincrement)
			CHECK(soa_serial_increment(mctx, inst, &origin));
		else {
			CHECK(ldap_get_zone_serial(inst, &origin, &serial));
		}
	}

cleanup:
	if (result != ISC_R_SUCCESS && zone_found && !zone_reloaded &&
	   (result == DNS_R_NOTLOADED || result == DNS_R_BADZONE)) {
		log_debug(1, "reloading invalid zone after a change; "
			     "reload triggered by change in '%s'",
			     pevent->dn);

		result = zr_get_zone_ptr(inst->zone_register, &origin, &zone_ptr);
		if (result == ISC_R_SUCCESS)
			result = dns_zone_load(zone_ptr);

		if (result == ISC_R_SUCCESS || result == DNS_R_UPTODATE ||
		    result == DNS_R_DYNAMIC || result == DNS_R_CONTINUE) {
			/* zone reload succeeded, fire current event again */
			log_debug(1, "restarting update_record after zone reload "
				     "caused by change in '%s'", pevent->dn);
			zone_reloaded = ISC_TRUE;
			result = dns_zone_getserial2(zone_ptr, &serial);
			if (result == ISC_R_SUCCESS) {
				dns_zone_log(zone_ptr, ISC_LOG_INFO,
					     "reloaded serial %u", serial);
				goto update_restart;
			} else {
				dns_zone_log(zone_ptr, ISC_LOG_ERROR,
					     "could not get serial after "
					     "reload");
			}
		} else {
			log_error_r("unable to reload invalid zone; "
				    "reload triggered by change in '%s'",
				    pevent->dn);
		}

	} else if (result != ISC_R_SUCCESS) {
		/* error other than invalid zone */
		log_error_r("update_record (psearch) failed, dn '%s' change type 0x%x. "
			  "Records can be outdated, run `rndc reload`",
			  pevent->dn, pevent->chgtype);
	}

	if (zone_ptr != NULL)
		dns_zone_detach(&zone_ptr);
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

	CHECK(ldap_entry_getclass(entry, &class));

	if (ctrls != NULL)
		CHECK(ldap_parse_entrychangectrl(ctrls, &chgtype, &prevdn_ldap));


	log_debug(20,"psearch change type: none%d, add%d, del%d, mod%d, moddn%d",
				!PSEARCH_ANY(chgtype), PSEARCH_ADD(chgtype),
				PSEARCH_DEL(chgtype), PSEARCH_MOD(chgtype),
				PSEARCH_MODDN(chgtype));

	isc_mem_attach(inst->mctx, &mctx);

	CHECKED_MEM_STRDUP(mctx, entry->dn, dn);
	CHECKED_MEM_STRDUP(mctx, inst->db_name, dbname);

	if (PSEARCH_MODDN(chgtype)) {
		CHECKED_MEM_STRDUP(mctx, prevdn_ldap, prevdn);
	}

	/*
	 * We are very simple. Every update (add/mod/del) means that
	 * we remove the zone/record, fetch it's entry from LDAP
	 * and then add it again. This is definitely place for improvement
	 * but it should be enough for now.
	 */

	if ((class & LDAP_ENTRYCLASS_CONFIG) != 0)
		action = update_config;
	else if ((class & LDAP_ENTRYCLASS_MASTER) != 0)
		action = update_zone;
	else if ((class & LDAP_ENTRYCLASS_FORWARD) != 0)
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

		log_error_r("psearch_update failed for '%s' zone. "
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
	isc_boolean_t psearch;
	isc_uint32_t reconnect_interval;
	const char *base = NULL;

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
		CHECK(setting_get_uint("reconnect_interval", inst->global_settings,
				       &reconnect_interval));

		log_error("ldap_psearch_watcher handle is NULL. "
		          "Next try in %ds", reconnect_interval);
		if (!sane_sleep(inst, reconnect_interval))
			goto cleanup;
		handle_connection_error(inst, conn, ISC_TRUE);
	}

	CHECK(ldap_query_create(conn->mctx, &ldap_qresult));

restart:
	/* Perform initial lookup */
	ldap_query_free(ISC_TRUE, &ldap_qresult);
	flush_required = ISC_TRUE;
	CHECK(setting_get_str("base", inst->global_settings, &base));
	CHECK(setting_get_bool("psearch", inst->global_settings, &psearch));
	if (psearch) {
		log_debug(1, "Sending initial psearch lookup");
		ret = ldap_search_ext(conn->handle,
				      base,
				      LDAP_SCOPE_SUBTREE,
				      /*    class = record
				       * OR class = config
				       * OR class = zone
				       * OR class = forward
				       *
				       * Inactive zones are handled
				       * in update_zone. */
				      "(|"
				      "(objectClass=idnsRecord)"
				      "(objectClass=idnsConfigObject)"
				      "(objectClass=idnsZone)"
				      "(objectClass=idnsForwardZone))",
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
				CHECK(setting_get_uint("reconnect_interval",
						       inst->global_settings,
						       &reconnect_interval));
				log_error("ldap_psearch_watcher failed to "
					  "handle LDAP connection error. "
					  "Reconnection in %ds",
					  reconnect_interval);
				if (!sane_sleep(inst, reconnect_interval))
					goto cleanup;
			}
			goto restart;
		} else if (flush_required == ISC_TRUE) {
			isc_boolean_t restart_needed = ISC_FALSE;
			/* First LDAP result after (re)start was received successfully:
			 * Unload old zones and flush record cache.
			 * We want to save cache in case of search timeout during restart.
			 */
			if ((result = refresh_zones_from_ldap(inst, ISC_TRUE))
			     != ISC_R_SUCCESS) {
				log_error_r("zone refresh after initial psearch lookup failed");
				restart_needed = ISC_TRUE;
			} else if ((result = zr_flush_all_caches(inst->zone_register))
				    != ISC_R_SUCCESS) {
				log_error_r("cache flush after initial psearch lookup failed");
				restart_needed = ISC_TRUE;
			}

			if (restart_needed) {
				CHECK(setting_get_uint("reconnect_interval",
						       inst->global_settings,
						       &reconnect_interval));
				if (!sane_sleep(inst, reconnect_interval))
					goto cleanup;

				goto restart;
			}

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
				log_error_r("ldap_psearch_watcher failed, zones "
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

settings_set_t *
ldap_instance_getsettings_local(ldap_instance_t *ldap_inst)
{
	return ldap_inst->local_settings;
}
