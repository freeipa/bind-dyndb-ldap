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

#include "config.h"

#include <dns/dynamic_db.h>
#include <dns/diff.h>
#include <dns/journal.h>
#include <dns/rbt.h>
#include <dns/rdata.h>
#include <dns/rdataclass.h>
#include <dns/rdatalist.h>
#include <dns/rdatasetiter.h>
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
#include <dns/update.h>

#include <isc/buffer.h>
#include <isc/dir.h>
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
#include <isc/serial.h>
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
#include "fs.h"
#include "krb5_helper.h"
#include "ldap_convert.h"
#include "ldap_driver.h"
#include "ldap_entry.h"
#include "ldap_helper.h"
#include "lock.h"
#include "log.h"
#include "metadb.h"
#include "mldap.h"
#include "semaphore.h"
#include "settings.h"
#include "str.h"
#include "syncptr.h"
#include "syncrepl.h"
#include "util.h"
#include "zone.h"
#include "zone_manager.h"
#include "zone_register.h"
#include "rbt_helper.h"
#include "fwd_register.h"

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

/* BIND 9.10 changed forwarder representation in struct dns_forwarders */
#if LIBDNS_VERSION_MAJOR < 140
	#define inst_fwdlist(inst) ((inst)->orig_global_forwarders.addrs)
#else /* LIBDNS_VERSION_MAJOR >= 140 */
	#define inst_fwdlist(inst) ((inst)->orig_global_forwarders.fwdrs)
#endif

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

	sync_ctx_t		*sctx;
	mldapdb_t		*mldapdb;
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
	int			msgid;

	/* For reconnection logic. */
	isc_time_t		next_reconnect;
	unsigned int		tries;
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

#define LDAPDB_EVENT_SYNCREPL_UPDATE	(LDAPDB_EVENTCLASS + 1)

typedef struct ldap_syncreplevent ldap_syncreplevent_t;
struct ldap_syncreplevent {
	ISC_EVENT_COMMON(ldap_syncreplevent_t);
	isc_mem_t *mctx;
	char *dbname;
	char *dn;
	char *prevdn;
	int chgtype;
	ldap_entry_t *entry;
};

extern const settings_set_t settings_default_set;

/** Local configuration file */
static const setting_t settings_local_default[] = {
	{ "uri",			no_default_string	},
	{ "connections",		no_default_uint		},
	{ "reconnect_interval",		no_default_uint		},
	{ "timeout",			no_default_uint		},
	{ "cache_ttl",			no_default_string	}, /* No longer supported */
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
	{ "zone_refresh",		no_default_string	}, /* No longer supported */
	{ "psearch",			no_default_string	}, /* No longer supported */
	{ "ldap_hostname",		no_default_string	},
	{ "sync_ptr",			no_default_boolean	},
	{ "dyn_update",			no_default_boolean	},
	{ "serial_autoincrement",	no_default_string	}, /* No longer supported */
	{ "verbose_checks",		no_default_boolean	},
	{ "directory",			no_default_string	},
	{ "nsec3param",			default_string("0 0 0 00")	}, /* NSEC only */
	end_of_settings
};

/** Global settings from idnsConfig object. */
static setting_t settings_global_default[] = {
	{ "dyn_update",		no_default_boolean	},
	{ "sync_ptr",		no_default_boolean	},
	end_of_settings
};

/*
 * Forward declarations.
 */

/* TODO: reorganize this stuff & clean it up. */
static isc_result_t new_ldap_connection(ldap_pool_t *pool,
					ldap_connection_t **ldap_connp) ATTR_NONNULLS ATTR_CHECKRESULT;
static void destroy_ldap_connection(ldap_connection_t **ldap_connp) ATTR_NONNULLS;

static isc_result_t findrdatatype_or_create(isc_mem_t *mctx,
		ldapdb_rdatalist_t *rdatalist, dns_rdataclass_t rdclass,
		dns_rdatatype_t rdtype, dns_ttl_t ttl, dns_rdatalist_t **rdlistp) ATTR_NONNULLS ATTR_CHECKRESULT;
static isc_result_t add_soa_record(isc_mem_t *mctx, dns_name_t *origin,
		ldap_entry_t *entry, ldapdb_rdatalist_t *rdatalist,
		const char *fake_mname) ATTR_NONNULLS ATTR_CHECKRESULT;
static isc_result_t parse_rdata(isc_mem_t *mctx, ldap_entry_t *entry,
		dns_rdataclass_t rdclass, dns_rdatatype_t rdtype,
		dns_name_t *origin, const char *rdata_text,
		dns_rdata_t **rdatap) ATTR_NONNULLS ATTR_CHECKRESULT;
static isc_result_t
ldap_parse_master_zoneentry(ldap_entry_t * const entry, dns_db_t * const olddb,
			    ldap_instance_t *const inst,
			    isc_task_t *const task)
			    ATTR_NONNULL(1,3,4) ATTR_CHECKRESULT;
static isc_result_t
ldap_parse_rrentry(isc_mem_t *mctx, ldap_entry_t *entry, dns_name_t *origin,
		   const char *fake_mname, ldapdb_rdatalist_t *rdatalist) ATTR_NONNULLS ATTR_CHECKRESULT;

static isc_result_t ldap_connect(ldap_instance_t *ldap_inst,
		ldap_connection_t *ldap_conn, isc_boolean_t force) ATTR_NONNULLS ATTR_CHECKRESULT;
static isc_result_t ldap_reconnect(ldap_instance_t *ldap_inst,
		ldap_connection_t *ldap_conn, isc_boolean_t force) ATTR_NONNULLS ATTR_CHECKRESULT;
static isc_result_t handle_connection_error(ldap_instance_t *ldap_inst,
		ldap_connection_t *ldap_conn, isc_boolean_t force) ATTR_NONNULLS;

/* Functions for writing to LDAP. */
static isc_result_t ldap_rdttl_to_ldapmod(isc_mem_t *mctx,
		dns_rdatalist_t *rdlist, LDAPMod **changep) ATTR_NONNULLS ATTR_CHECKRESULT;
static isc_result_t ldap_rdatalist_to_ldapmod(isc_mem_t *mctx,
		dns_rdatalist_t *rdlist, LDAPMod **changep, int mod_op) ATTR_NONNULLS ATTR_CHECKRESULT;

static isc_result_t ldap_rdata_to_char_array(isc_mem_t *mctx,
		dns_rdata_t *rdata_head, char ***valsp) ATTR_NONNULLS ATTR_CHECKRESULT;
static void free_char_array(isc_mem_t *mctx, char ***valsp) ATTR_NONNULLS;
static isc_result_t modify_ldap_common(dns_name_t *owner, dns_name_t *zone, ldap_instance_t *ldap_inst,
		dns_rdatalist_t *rdlist, int mod_op, isc_boolean_t delete_node) ATTR_NONNULLS ATTR_CHECKRESULT;

/* Functions for maintaining pool of LDAP connections */
static isc_result_t ldap_pool_create(isc_mem_t *mctx, unsigned int connections,
		ldap_pool_t **poolp) ATTR_NONNULLS ATTR_CHECKRESULT;
static void ldap_pool_destroy(ldap_pool_t **poolp);
static isc_result_t ldap_pool_getconnection(ldap_pool_t *pool,
		ldap_connection_t ** conn) ATTR_NONNULLS ATTR_CHECKRESULT;
static void ldap_pool_putconnection(ldap_pool_t *pool,
		ldap_connection_t ** conn) ATTR_NONNULLS;
static isc_result_t ldap_pool_connect(ldap_pool_t *pool,
		ldap_instance_t *ldap_inst) ATTR_NONNULLS ATTR_CHECKRESULT;

/* Persistent updates watcher */
static isc_threadresult_t
ldap_syncrepl_watcher(isc_threadarg_t arg) ATTR_NONNULLS ATTR_CHECKRESULT;

static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
zone_master_reconfigure_nsec3param(settings_set_t *zone_settings,
				   dns_zone_t *secure);

#define PRINT_BUFF_SIZE 10 /* for unsigned int 2^32 */
isc_result_t
validate_local_instance_settings(ldap_instance_t *inst, settings_set_t *set) {
	isc_result_t result;

	isc_uint32_t uint;
	const char *sasl_mech = NULL;
	const char *sasl_user = NULL;
	const char *sasl_realm = NULL;
	const char *sasl_password = NULL;
	const char *krb5_principal = NULL;
	const char *bind_dn = NULL;
	const char *password = NULL;
	const char *dir_name = NULL;
	isc_boolean_t dir_default;
	ld_string_t *buff = NULL;

	/* handle cache_ttl, psearch, serial_autoincrement, and zone_refresh
	 * in special way */
	const char *obsolete_value = NULL;
	char *obsolete_options[] = {"cache_ttl", "psearch",
				    "serial_autoincrement", "zone_refresh",
				    NULL};

	char print_buff[PRINT_BUFF_SIZE];
	const char *auth_method_str = NULL;
	ldap_auth_t auth_method_enum = AUTH_INVALID;

	if (strlen(inst->db_name) <= 0) {
		log_error("LDAP instance name cannot be empty");
		CLEANUP_WITH(ISC_R_UNEXPECTEDEND);
	}

	/* Use instance name as default working directory */
	CHECK(str_new(inst->mctx, &buff));
	CHECK(setting_get_str("directory", inst->local_settings, &dir_name));
	dir_default = (strcmp(dir_name, "") == 0);
	if (dir_default == ISC_TRUE) {
		CHECK(str_cat_char(buff, "dyndb-ldap/"));
		CHECK(str_cat_char(buff, inst->db_name));
	} else
		CHECK(str_cat_char(buff, dir_name));

	if (str_buf(buff)[str_len(buff) - 1] != '/')
		CHECK(str_cat_char(buff, "/"));

	if (strcmp(dir_name, str_buf(buff)) != 0)
		CHECK(setting_set("directory", inst->local_settings,
				  str_buf(buff)));
	str_destroy(&buff);
	dir_name = NULL;
	CHECK(setting_get_str("directory", inst->local_settings, &dir_name));

	/* Make sure that working directory exists */
	CHECK(fs_dirs_create(dir_name));

	/* Set timer for deadlock detection inside semaphore_wait_timed . */
	CHECK(setting_get_uint("timeout", set, &uint));
	if (conn_wait_timeout.seconds < uint*SEM_WAIT_TIMEOUT_MUL)
		conn_wait_timeout.seconds = uint*SEM_WAIT_TIMEOUT_MUL;

	CHECK(setting_get_uint("connections", set, &uint));
	if (uint < 2) {
		log_error("at least two connections are required");
		/* watcher needs one and update_*() requests second connection */
		CLEANUP_WITH(ISC_R_RANGE);
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
	CHECK(setting_set("auth_method_enum", inst->local_settings, print_buff));

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
							  str_buf(buff)));
				}
			} else {
				CHECK(setting_set("krb5_principal", set,
						  sasl_user));
			}
		}
	} else if (auth_method_enum == AUTH_SASL) {
		log_info("SASL mechanisms other than GSSAPI+Kerberos "
			 "are untested; expect problems");
	}

	for (char **option = obsolete_options; *option != NULL; option++) {
		CHECK(setting_get_str(*option, set, &obsolete_value));
		if (memcmp("", obsolete_value, 1) != 0)
			log_error("option '%s' is not supported, ignoring", *option);
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
	ISC_LIST_INIT(inst_fwdlist(ldap_inst));
	ldap_inst->task = task;
	ldap_inst->watcher = 0;
	CHECK(sync_ctx_init(ldap_inst->mctx, ldap_inst, &ldap_inst->sctx));

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

	CHECK(settings_set_fill(ldap_inst->local_settings, argv));
	CHECK(validate_local_instance_settings(ldap_inst, ldap_inst->local_settings));
	if (settings_set_isfilled(ldap_inst->global_settings) != ISC_TRUE)
		CLEANUP_WITH(ISC_R_FAILURE);

	CHECK(setting_get_uint("connections", ldap_inst->local_settings, &connections));

	CHECK(zr_create(mctx, ldap_inst, ldap_inst->global_settings,
			&ldap_inst->zone_register));
	CHECK(fwdr_create(ldap_inst->mctx, &ldap_inst->fwd_register));
	CHECK(mldap_new(mctx, &ldap_inst->mldapdb));

	CHECK(isc_mutex_init(&ldap_inst->kinit_lock));

	/* copy global forwarders setting for configuration roll back in
	 * configure_zone_forwarders() */
	result = dns_fwdtable_find(ldap_inst->view->fwdtable, dns_rootname,
				   &orig_global_forwarders);
	if (result == ISC_R_SUCCESS) {
#if LIBDNS_VERSION_MAJOR < 140
		isc_sockaddr_t *fwdr;
		isc_sockaddr_t *new_fwdr;
		for (fwdr = ISC_LIST_HEAD(orig_global_forwarders->addrs);
#else /* LIBDNS_VERSION_MAJOR >= 140 */
		dns_forwarder_t *fwdr;
		dns_forwarder_t *new_fwdr;
		for (fwdr = ISC_LIST_HEAD(orig_global_forwarders->fwdrs);
#endif
		     fwdr != NULL;
		     fwdr = ISC_LIST_NEXT(fwdr, link)) {
			CHECKED_MEM_GET_PTR(mctx, new_fwdr);
			*new_fwdr = *fwdr;
			ISC_LINK_INIT(new_fwdr, link);
			ISC_LIST_APPEND(inst_fwdlist(ldap_inst), new_fwdr, link);
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

	/* Start the watcher thread */
	result = isc_thread_create(ldap_syncrepl_watcher, ldap_inst,
				   &ldap_inst->watcher);
	if (result != ISC_R_SUCCESS) {
		log_error("Failed to create syncrepl watcher thread");
		goto cleanup;
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
#if LIBDNS_VERSION_MAJOR < 140
	isc_sockaddr_t *fwdr;
#else /* LIBDNS_VERSION_MAJOR >= 140 */
	dns_forwarder_t *fwdr;
#endif

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
	mldap_destroy(&ldap_inst->mldapdb);

	ldap_pool_destroy(&ldap_inst->pool);
	dns_view_detach(&ldap_inst->view);

	DESTROYLOCK(&ldap_inst->kinit_lock);

	while (!ISC_LIST_EMPTY(inst_fwdlist(ldap_inst))) {
		fwdr = ISC_LIST_HEAD(inst_fwdlist(ldap_inst));
		ISC_LIST_UNLINK(inst_fwdlist(ldap_inst), fwdr, link);
		SAFE_MEM_PUT_PTR(ldap_inst->mctx, fwdr);
	}

	settings_set_free(&ldap_inst->global_settings);
	settings_set_free(&ldap_inst->local_settings);

	sync_ctx_free(&ldap_inst->sctx);

	MEM_PUT_AND_DETACH(ldap_inst);

	*ldap_instp = NULL;
	log_debug(1, "LDAP instance '%s' destroyed", db_name);
}

static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
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

	MEM_PUT_AND_DETACH(*ldap_connp);
}

/* Test if the existing zone is 'empty zone' per RFC 6303. */
static isc_boolean_t ATTR_NONNULLS ATTR_CHECKRESULT
zone_isempty(dns_zone_t *zone) {
	char **argv = NULL;
	isc_mem_t *mctx = NULL;
	isc_boolean_t result = ISC_FALSE;

	mctx = dns_zone_getmctx(zone);
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
static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
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
	if (result == ISC_R_NOTFOUND) /* zone wasn't part of a view */
		result = ISC_R_SUCCESS;
	zmgr = dns_zone_getmgr(zone);
	if (zmgr != NULL)
		dns_zonemgr_releasezone(zmgr, zone);
	dns_zone_detach(zonep);

	return result;
}

static isc_result_t ATTR_NONNULLS
cleanup_zone_files(dns_zone_t *zone) {
	isc_result_t result;
	isc_boolean_t failure = ISC_FALSE;
	const char *filename = NULL;
	dns_zone_t *raw = NULL;
	int namelen;
	char bck_filename[PATH_MAX];

	dns_zone_getraw(zone, &raw);
	if (raw != NULL) {
		result = cleanup_zone_files(raw);
		dns_zone_detach(&raw);
		failure = (result != ISC_R_SUCCESS);
	}

	filename = dns_zone_getfile(zone);
	result = fs_file_remove(filename);
	failure = failure || (result != ISC_R_SUCCESS);

	filename = dns_zone_getjournal(zone);
	result = fs_file_remove(filename);
	failure = failure || (result != ISC_R_SUCCESS);

	/* Taken from dns_journal_open() from bind-9.9.4-P2:
	 * Journal backup file name ends with ".jbk" instead of ".jnl". */
	namelen = strlen(filename);
	if (namelen > 4 && strcmp(filename + namelen - 4, ".jnl") == 0)
		namelen -= 4;
	CHECK(isc_string_printf(bck_filename, sizeof(bck_filename),
				"%.*s.jbk", namelen, filename));
	CHECK(fs_file_remove(bck_filename));

cleanup:
	failure = failure || (result != ISC_R_SUCCESS);
	if (failure == ISC_TRUE)
		dns_zone_log(zone, ISC_LOG_ERROR,
			     "unable to remove files, expect problems");

	if (failure == ISC_TRUE && result == ISC_R_SUCCESS)
		result = ISC_R_FAILURE;

	return result;
}

/**
 * Remove zone files and journal files associated with all zones in ZR.
 */
static isc_result_t ATTR_CHECKRESULT
cleanup_files(ldap_instance_t *inst) {
	isc_result_t result;
	rbt_iterator_t *iter = NULL;
	dns_zone_t *raw = NULL;
	dns_zone_t *secure = NULL;
	DECLARE_BUFFERED_NAME(name);

	INIT_BUFFERED_NAME(name);
	CHECK(zr_rbt_iter_init(inst->zone_register, &iter, &name));
	do {
		CHECK(zr_get_zone_ptr(inst->zone_register, &name, &raw, &secure));
		cleanup_zone_files(raw);
		dns_zone_detach(&raw);
		if (secure != NULL) {
			cleanup_zone_files(secure);
			dns_zone_detach(&secure);
		}

		INIT_BUFFERED_NAME(name);
		CHECK(rbt_iter_next(&iter, &name));
	} while (result == ISC_R_SUCCESS);

cleanup:
	if (result == ISC_R_NOTFOUND || result == ISC_R_NOMORE)
		result = ISC_R_SUCCESS;
	return result;
}

/**
 * Unload empty zone from given view.
 *
 * @retval ISC_R_EXISTS   if a zone with given name is not an empty zone
 * @retval ISC_R_SUCCESS  if name was an empty zone
 *                        and it was unloaded successfully
 * @retval ISC_R_NOTFOUND if name does not match any zone in given view
 * @retval other errors
 */
static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
zone_unload_ifempty(dns_view_t *view, dns_name_t *name) {
	isc_result_t result;
	dns_zone_t *zone = NULL;
	char zone_name[DNS_NAME_FORMATSIZE];

	CHECK(dns_view_findzone(view, name, &zone));

	if (zone_isempty(zone) == ISC_TRUE) {
		dns_name_format(name, zone_name, DNS_NAME_FORMATSIZE);
		result = delete_bind_zone(view->zonetable, &zone);
		if (result != ISC_R_SUCCESS)
			log_error_r("unable to unload automatic empty zone "
				    "%s", zone_name);
		else
			log_info("automatic empty zone %s unloaded",
				 zone_name);
	} else {
		result = ISC_R_EXISTS;
	}

cleanup:
	if (zone != NULL)
		dns_zone_detach(&zone);
	return result;
}

static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
configure_paths(isc_mem_t *mctx, ldap_instance_t *inst, dns_zone_t *zone,
		isc_boolean_t issecure) {
	isc_result_t result;
	ld_string_t *file_name = NULL;
	ld_string_t *key_dir = NULL;

	CHECK(zr_get_zone_path(mctx, ldap_instance_getsettings_local(inst),
			       dns_zone_getorigin(zone),
			       (issecure ? "signed" : "raw"), &file_name));
	CHECK(dns_zone_setfile(zone, str_buf(file_name)));
	if (issecure == ISC_TRUE) {
		CHECK(zr_get_zone_path(mctx,
				       ldap_instance_getsettings_local(inst),
				       dns_zone_getorigin(zone), "keys/",
				       &key_dir));
		dns_zone_setkeydirectory(zone, str_buf(key_dir));
	}
	CHECK(fs_file_remove(dns_zone_getfile(zone)));
	CHECK(fs_file_remove(dns_zone_getjournal(zone)));

cleanup:
	str_destroy(&file_name);
	str_destroy(&key_dir);
	return result;
}

/*
 * Create a new zone with origin 'name'. The zone will be added to the
 * ldap_inst->view.
 */
static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
create_zone(ldap_instance_t * const inst, const char * const dn,
	    dns_name_t * const name, dns_db_t * const ldapdb,
	    const isc_boolean_t want_secure, dns_zone_t ** const rawp,
	    dns_zone_t ** const securep)
{
	isc_result_t result;
	dns_zone_t *raw = NULL;
	dns_zone_t *secure = NULL;
	const char *ldap_argv[2];
	const char *rbt_argv[1] = { "rbt" };
	sync_state_t sync_state;
	isc_task_t *task = NULL;
	char zone_name[DNS_NAME_FORMATSIZE];

	REQUIRE(inst != NULL);
	REQUIRE(name != NULL);
	REQUIRE(rawp != NULL && *rawp == NULL);

	ldap_argv[0] = ldapdb_impname;
	ldap_argv[1] = inst->db_name;

	result = zone_unload_ifempty(inst->view, name);
	if (result != ISC_R_SUCCESS && result != ISC_R_NOTFOUND)
		goto cleanup;

	CHECK(dns_zone_create(&raw, inst->mctx));
	CHECK(dns_zone_setorigin(raw, name));
	dns_zone_setclass(raw, dns_rdataclass_in);
	dns_zone_settype(raw, dns_zone_master);
	/* dns_zone_setview(raw, view); */
	CHECK(dns_zone_setdbtype(raw, 2, ldap_argv));
	CHECK(configure_paths(inst->mctx, inst, raw, ISC_FALSE));

	if (want_secure == ISC_FALSE) {
		CHECK(dns_zonemgr_managezone(inst->zmgr, raw));
		CHECK(cleanup_zone_files(raw));
	} else {
		CHECK(dns_zone_create(&secure, inst->mctx));
		CHECK(dns_zone_setorigin(secure, name));
		dns_zone_setclass(secure, dns_rdataclass_in);
		dns_zone_settype(secure, dns_zone_master);
		/* dns_zone_setview(secure, view); */
		CHECK(dns_zone_setdbtype(secure, 1, rbt_argv));
		CHECK(dns_zonemgr_managezone(inst->zmgr, secure));
		CHECK(dns_zone_link(secure, raw));
		dns_zone_rekey(secure, ISC_TRUE);
		CHECK(configure_paths(inst->mctx, inst, secure, ISC_TRUE));
		CHECK(cleanup_zone_files(secure));
	}

	sync_state_get(inst->sctx, &sync_state);
	if (sync_state == sync_init) {
		dns_zone_gettask(raw, &task);
		CHECK(sync_task_add(inst->sctx, task));
		isc_task_detach(&task);

		if (secure != NULL) {
			dns_zone_gettask(secure, &task);
			CHECK(sync_task_add(inst->sctx, task));
			isc_task_detach(&task);
		}
	}

	CHECK(zr_add_zone(inst->zone_register, ldapdb, raw, secure, dn));

	*rawp = raw;
	*securep = secure;
	return ISC_R_SUCCESS;

cleanup:
	dns_name_format(name, zone_name, DNS_NAME_FORMATSIZE);
	log_error_r("failed to create new zone '%s'", zone_name);

	if (raw != NULL) {
		if (dns_zone_getmgr(raw) != NULL)
			dns_zonemgr_releasezone(inst->zmgr, raw);
		dns_zone_detach(&raw);
	}
	if (task != NULL)
		isc_task_detach(&task);

	return result;
}

/**
 * @warning Never call this on raw part of in-line secure zone.
 */
static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
load_zone(dns_zone_t *zone, isc_boolean_t log) {
	isc_result_t result;
	isc_boolean_t zone_dynamic;
	isc_uint32_t serial;
	dns_zone_t *raw = NULL;

	result = dns_zone_load(zone);
	if (result != ISC_R_SUCCESS && result != DNS_R_UPTODATE
	    && result != DNS_R_DYNAMIC && result != DNS_R_CONTINUE)
		goto cleanup;
	zone_dynamic = (result == DNS_R_DYNAMIC);

	dns_zone_getraw(zone, &raw);
	if (raw == NULL) {
		dns_zone_attach(zone, &raw);
		zone = NULL;
	}

	CHECK(dns_zone_getserial2(raw, &serial));
	if (log == ISC_TRUE)
		dns_zone_log(raw, ISC_LOG_INFO, "loaded serial %u", serial);
	if (zone != NULL) {
		result = dns_zone_getserial2(zone, &serial);
		if (result == ISC_R_SUCCESS && log == ISC_TRUE)
			dns_zone_log(zone, ISC_LOG_INFO, "loaded serial %u",
				     serial);
		/* in-line secure zone is loaded asynchonously in background */
		else if (result == DNS_R_NOTLOADED) {
			if (log == ISC_TRUE)
				dns_zone_log(zone, ISC_LOG_INFO,
					     "signing in progress");
			result = ISC_R_SUCCESS;
		} else
			goto cleanup;
	}

	if (zone_dynamic)
		dns_zone_notify((zone != NULL) ? zone : raw);

cleanup:
	if (raw != NULL)
		dns_zone_detach(&raw);
	return result;
}

/**
 * Add zone to the view defined in inst->view.
 */
static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
publish_zone(isc_task_t *task, ldap_instance_t *inst, dns_zone_t *zone)
{
	isc_result_t result;
	isc_boolean_t freeze = ISC_FALSE;
	dns_zone_t *zone_in_view = NULL;
	dns_view_t *view_in_zone = NULL;
	isc_result_t lock_state = ISC_R_IGNORE;

	REQUIRE(ISCAPI_TASK_VALID(task));
	REQUIRE(inst != NULL);
	REQUIRE(zone != NULL);

	/* Return success if the zone is already in the view as expected. */
	result = dns_view_findzone(inst->view, dns_zone_getorigin(zone),
				   &zone_in_view);
	if (result != ISC_R_SUCCESS && result != ISC_R_NOTFOUND)
		goto cleanup;

	view_in_zone = dns_zone_getview(zone);
	if (view_in_zone != NULL) {
		/* Zone has a view set -> view should contain the same zone. */
		if (zone_in_view == zone) {
			/* Zone is already published in the right view. */
			CLEANUP_WITH(ISC_R_SUCCESS);
		} else if (view_in_zone != inst->view) {
			/* Un-published inactive zone will have
			 * inst->view in zone but will not be present
			 * in the view itself. */
			dns_zone_log(zone, ISC_LOG_ERROR, "zone->view doesn't "
				     "match data in the view");
			CLEANUP_WITH(ISC_R_UNEXPECTED);
		}
	}
	if (zone_in_view != NULL) {
		dns_zone_log(zone, ISC_LOG_ERROR, "cannot publish zone: view "
			     "already contains another zone with this name");
		CLEANUP_WITH(ISC_R_UNEXPECTED);
	} /* else if (zone_in_view == NULL &&
		      (view_in_zone == NULL || view_in_zone == inst->view))
	     Publish the zone. */

	run_exclusive_enter(inst, &lock_state);
	if (inst->view->frozen) {
		freeze = ISC_TRUE;
		dns_view_thaw(inst->view);
	}

	dns_zone_setview(zone, inst->view);
	CHECK(dns_view_addzone(inst->view, zone));

cleanup:
	if (zone_in_view != NULL)
		dns_zone_detach(&zone_in_view);
	if (freeze)
		dns_view_freeze(inst->view);
	run_exclusive_exit(inst, lock_state);

	return result;
}

/**
 * Add zone to view and call dns_zone_load().
 */
static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
activate_zone(isc_task_t *task, ldap_instance_t *inst, dns_name_t *name) {
	isc_result_t result;
	dns_zone_t *raw = NULL;
	dns_zone_t *secure = NULL;
	dns_zone_t *toview = NULL;
	settings_set_t *zone_settings = NULL;

	CHECK(zr_get_zone_ptr(inst->zone_register, name, &raw, &secure));

	/* Load only "secure" zone if inline-signing is active.
	 * It will not work if raw zone is loaded explicitly
	 * - dns_zone_load() will fail magically. */
	toview = (secure != NULL) ? secure : raw;

	/*
	 * Zone has to be published *before* zone load
	 * otherwise it will race with zone->view != NULL check
	 * in zone_maintenance() in zone.c.
	 */
	result = publish_zone(task, inst, toview);
	if (result != ISC_R_SUCCESS) {
		dns_zone_log(toview, ISC_LOG_ERROR,
			     "cannot add zone to view: %s",
			     dns_result_totext(result));
		goto cleanup;
	}

	CHECK(load_zone(toview, ISC_TRUE));
	if (secure != NULL) {
		CHECK(zr_get_zone_settings(inst->zone_register, name,
					   &zone_settings));
		CHECK(zone_master_reconfigure_nsec3param(zone_settings,
							 secure));
	}

cleanup:
	if (raw != NULL)
		dns_zone_detach(&raw);
	if (secure != NULL)
		dns_zone_detach(&secure);
	return result;
}

/**
 * Add all active zones in zone register to DNS view specified in inst->view
 * and load zones.
 */
isc_result_t
activate_zones(isc_task_t *task, ldap_instance_t *inst) {
	isc_result_t result;
	rbt_iterator_t *iter = NULL;
	DECLARE_BUFFERED_NAME(name);
	unsigned int published_cnt = 0;
	unsigned int total_cnt = 0;
	unsigned int active_cnt = 0;
	settings_set_t *settings;
	isc_boolean_t active;

	INIT_BUFFERED_NAME(name);
	for(result = zr_rbt_iter_init(inst->zone_register, &iter, &name);
	    result == ISC_R_SUCCESS;
	    dns_name_reset(&name), result = rbt_iter_next(&iter, &name)) {
		settings = NULL;
		result = zr_get_zone_settings(inst->zone_register, &name, &settings);
		INSIST(result == ISC_R_SUCCESS);
		result = setting_get_bool("active", settings, &active);
		INSIST(result == ISC_R_SUCCESS);

		++total_cnt;
		if (active == ISC_TRUE) {
			++active_cnt;
			result = activate_zone(task, inst, &name);
			if (result == ISC_R_SUCCESS)
				++published_cnt;
		}
	};

	log_info("%u master zones from LDAP instance '%s' loaded (%u zones "
		 "defined, %u inactive, %u failed to load)", published_cnt,
		 inst->db_name, total_cnt, total_cnt - active_cnt,
		 active_cnt - published_cnt);
	if (total_cnt < 1)
		log_info("0 master zones is suspicious number, please check "
			 "access control instructions on LDAP server");
	return result;
}


static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
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
static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
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

static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
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
	isc_result_t lock_state = ISC_R_IGNORE;
	isc_boolean_t freeze = ISC_FALSE;
	dns_zone_t *raw = NULL;
	dns_zone_t *secure = NULL;
	dns_zone_t *foundzone = NULL;
	char zone_name_char[DNS_NAME_FORMATSIZE];

	dns_name_format(name, zone_name_char, DNS_NAME_FORMATSIZE);
	log_debug(1, "deleting zone '%s'", zone_name_char);
	if (lock)
		run_exclusive_enter(inst, &lock_state);

	if (!preserve_forwarding) {
		CHECK(delete_forwarding_table(inst, name, "zone",
					      zone_name_char));
		isforward = fwdr_zone_ispresent(inst->fwd_register, name);
		if (isforward == ISC_R_SUCCESS)
			CHECK(fwdr_del_zone(inst->fwd_register, name));
	}

	result = zr_get_zone_ptr(inst->zone_register, name, &raw, &secure);
	if (result == ISC_R_NOTFOUND || result == DNS_R_PARTIALMATCH) {
		if (isforward == ISC_R_SUCCESS)
			log_info("forward zone '%s': shutting down", zone_name_char);
		log_debug(1, "zone '%s' not found in zone register", zone_name_char);
		result = dns_view_flushcache(inst->view);
		goto cleanup;
	} else if (result != ISC_R_SUCCESS)
		goto cleanup;

	result = dns_view_findzone(inst->view, name, &foundzone);
	if (result == ISC_R_SUCCESS) {
		/* foundzone != zone indicates a bug */
		if (secure != NULL)
			RUNTIME_CHECK(foundzone == secure);
		else
			RUNTIME_CHECK(foundzone == raw);
		dns_zone_detach(&foundzone);

		if (lock) {
			dns_view_thaw(inst->view);
			freeze = ISC_TRUE;
		}
	} /* else: zone wasn't in a view */

	if (secure != NULL)
		CHECK(delete_bind_zone(inst->view->zonetable, &secure));
	CHECK(delete_bind_zone(inst->view->zonetable, &raw));
	CHECK(zr_del_zone(inst->zone_register, name));

cleanup:
	if (freeze)
		dns_view_freeze(inst->view);
	run_exclusive_exit(inst, lock_state);

	return result;
}

/**
 * Remove zone from view but let the zone object intact. The same zone object
 * can be re-published later using publish_zone().
 *
 * @warning
 * This function removes zone from view but the zone->view pointer will stay
 * unchanged and will reference the old view.
 * It works like that because dns_zone_setview() doesn't work with NULL view.
 * I hope it will not break something...
 */
static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
unpublish_zone(ldap_instance_t *inst, dns_name_t *name, const char *dn) {
	isc_result_t result;
	isc_result_t lock_state = ISC_R_IGNORE;
	dns_zone_t *raw = NULL;
	dns_zone_t *secure = NULL;
	dns_zone_t *zone_in_view = NULL;
	isc_boolean_t freeze = ISC_FALSE;

	CHECK(zr_get_zone_ptr(inst->zone_register, name, &raw, &secure));

	run_exclusive_enter(inst, &lock_state);
	if (inst->view->frozen) {
		freeze = ISC_TRUE;
		dns_view_thaw(inst->view);
	}
	CHECK(dns_view_findzone(inst->view, name, &zone_in_view));
	INSIST(zone_in_view == raw || zone_in_view == secure);
	CHECK(delete_forwarding_table(inst, name, "zone", dn));
	CHECK(dns_zt_unmount(inst->view->zonetable, zone_in_view));

cleanup:
	if (freeze)
		dns_view_freeze(inst->view);
	run_exclusive_exit(inst, lock_state);
	if (result != ISC_R_SUCCESS)
		log_error_r("zone '%s' un-publication failed", dn);
	if (raw != NULL)
		dns_zone_detach(&raw);
	if (secure != NULL)
		dns_zone_detach(&secure);
	if (zone_in_view != NULL)
		dns_zone_detach(&zone_in_view);

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
static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
configure_zone_forwarders(ldap_entry_t *entry, ldap_instance_t *inst,
			  dns_name_t *name)
{
	const char *dn = entry->dn;
	isc_result_t result;
	isc_result_t orig_result;
	isc_result_t lock_state = ISC_R_IGNORE;
	ldap_valuelist_t values;
	ldap_value_t *value;
#if LIBDNS_VERSION_MAJOR < 140
	isc_sockaddrlist_t fwdrs;
#else /* LIBDNS_VERSION_MAJOR >= 140 */
	dns_forwarderlist_t fwdrs;
#endif
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
	ISC_LIST_INIT(fwdrs);
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
				fwdrs = inst_fwdlist(inst);
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
#if LIBDNS_VERSION_MAJOR < 140
		isc_sockaddr_t *fwdr = NULL;
#else /* LIBDNS_VERSION_MAJOR >= 140 */
		dns_forwarder_t *fwdr = NULL;
#endif
		char forwarder_txt[ISC_SOCKADDR_FORMATSIZE];

		if (acl_parse_forwarder(value->value, inst->mctx, &fwdr)
				!= ISC_R_SUCCESS) {
			log_error("%s '%s': could not parse forwarder '%s'",
					msg_obj_type, dn, value->value);
			continue;
		}

		ISC_LINK_INIT(fwdr, link);
		ISC_LIST_APPEND(fwdrs, fwdr, link);
		isc_sockaddr_format(
#if LIBDNS_VERSION_MAJOR < 140
				fwdr,
#else /* LIBDNS_VERSION_MAJOR >= 140 */
				&fwdr->addr,
#endif
				forwarder_txt, ISC_SOCKADDR_FORMATSIZE);
		log_debug(5, "%s '%s': adding forwarder '%s'", msg_obj_type,
			  dn, forwarder_txt);
	}

	if (fwdpolicy != dns_fwdpolicy_none && ISC_LIST_EMPTY(fwdrs)) {
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
#if LIBDNS_VERSION_MAJOR < 140
		isc_sockaddr_t *s1, *s2;
#else /* LIBDNS_VERSION_MAJOR >= 140 */
		dns_forwarder_t *s1, *s2;
#endif

		if (fwdpolicy != old_setting->fwdpolicy)
			fwdtbl_update_requested = ISC_TRUE;

		/* Check address lists item by item. */
#if LIBDNS_VERSION_MAJOR < 140
		for (s1 = ISC_LIST_HEAD(fwdrs), s2 = ISC_LIST_HEAD(old_setting->addrs);
#else /* LIBDNS_VERSION_MAJOR >= 140 */
		for (s1 = ISC_LIST_HEAD(fwdrs), s2 = ISC_LIST_HEAD(old_setting->fwdrs);
#endif
		     s1 != NULL && s2 != NULL && !fwdtbl_update_requested;
		     s1 = ISC_LIST_NEXT(s1, link), s2 = ISC_LIST_NEXT(s2, link))
#if LIBDNS_VERSION_MAJOR < 140
		if (!isc_sockaddr_equal(s1, s2)) {
#else /* LIBDNS_VERSION_MAJOR >= 140 */
		if (!isc_sockaddr_equal(&s1->addr, &s2->addr) ||
		    s1->dscp != s2->dscp) {
#endif
			fwdtbl_update_requested = ISC_TRUE;
		}

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
			if (zone_isempty(zone)) {
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
#if LIBDNS_VERSION_MAJOR < 140
		result = dns_fwdtable_add(inst->view->fwdtable, name, &fwdrs,
					  fwdpolicy);
#else /* LIBDNS_VERSION_MAJOR >= 140 */
		result = dns_fwdtable_addfwd(inst->view->fwdtable, name, &fwdrs,
					     fwdpolicy);
#endif
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
	if (ISC_LIST_HEAD(fwdrs) !=
	    ISC_LIST_HEAD(inst_fwdlist(inst))) {
		while(!ISC_LIST_EMPTY(fwdrs)) {
#if LIBDNS_VERSION_MAJOR < 140
			isc_sockaddr_t *fwdr = NULL;
#else /* LIBDNS_VERSION_MAJOR >= 140 */
			dns_forwarder_t *fwdr = NULL;
#endif
			fwdr = ISC_LIST_HEAD(fwdrs);
			ISC_LIST_UNLINK(fwdrs, fwdr, link);
			SAFE_MEM_PUT_PTR(inst->mctx, fwdr);
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
		run_exclusive_enter(inst, &lock_state);
		result = dns_view_flushcache(inst->view);
		run_exclusive_exit(inst, lock_state);
		if (result == ISC_R_SUCCESS)
			result = orig_result;
	}
	return result;
}

/* Parse the config object entry */
static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
ldap_parse_configentry(ldap_entry_t *entry, ldap_instance_t *inst)
{
	isc_result_t result;

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
						entry);
	if (result != ISC_R_SUCCESS && result != ISC_R_IGNORE)
		goto cleanup;

	result = setting_update_from_ldap_entry("sync_ptr",
						inst->global_settings,
						"idnsAllowSyncPTR",
						entry);
	if (result != ISC_R_SUCCESS && result != ISC_R_IGNORE)
		goto cleanup;

cleanup:
	/* Configuration errors are not fatal. */
	/* TODO: log something? */
	return ISC_R_SUCCESS;
}

/* Parse the forward zone entry */
static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
ldap_parse_fwd_zoneentry(ldap_entry_t *entry, ldap_instance_t *inst)
{
	const char *dn;
	ldap_valuelist_t values;
	char name_txt[DNS_NAME_FORMATSIZE];
	isc_result_t result;

	REQUIRE(entry != NULL);
	REQUIRE(inst != NULL);

	/* Derive the DNS name of the zone from the DN. */
	dn = entry->dn;

	CHECK(ldap_entry_getvalues(entry, "idnsZoneActive", &values));
	if (HEAD(values) != NULL &&
	    strcasecmp(HEAD(values)->value, "TRUE") != 0) {
		/* Zone is not active */
		result = ldap_delete_zone2(inst, &entry->fqdn,
					   ISC_TRUE, ISC_FALSE);
		goto cleanup;
	}

	/* Zone is active */
	result = configure_zone_forwarders(entry, inst, &entry->fqdn);
	if (result != ISC_R_DISABLED && result != ISC_R_SUCCESS) {
		log_error_r("forward zone '%s': could not configure forwarding", dn);
		goto cleanup;
	}

	result = fwdr_add_zone(inst->fwd_register, &entry->fqdn);
	if (result != ISC_R_EXISTS && result != ISC_R_SUCCESS) {
		dns_name_format(&entry->fqdn, name_txt, DNS_NAME_FORMATSIZE);
		log_error_r("failed to add forward zone '%s' "
			    "to the forwarding register", name_txt);
		goto cleanup;
	}
	result = ISC_R_SUCCESS;
	dns_name_format(&entry->fqdn, name_txt, DNS_NAME_FORMATSIZE);
	log_info("forward zone '%s': loaded", name_txt);

cleanup:
	return result;
}

/**
 * Compute minimal diff between rdatalist and rdataset iterator. This produces
 * minimal diff applicable to a database.
 */
static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
diff_ldap_rbtdb(isc_mem_t *mctx, dns_name_t *name, ldapdb_rdatalist_t *ldap_rdatalist,
		    dns_rdatasetiter_t *rbt_rds_iter, dns_diff_t *diff) {
	isc_result_t result;
	dns_rdataset_t rbt_rds;
	dns_rdatalist_t *l;

	dns_rdataset_init(&rbt_rds);

	/* FIXME: rbt_rds_iter == NULL || ldap_rdatalist == NULL */
	for (result = dns_rdatasetiter_first(rbt_rds_iter);
	     result == ISC_R_SUCCESS;
	     result = dns_rdatasetiter_next(rbt_rds_iter)) {
		dns_rdatasetiter_current(rbt_rds_iter, &rbt_rds);
		CHECK(rdataset_to_diff(mctx, DNS_DIFFOP_DEL, name, &rbt_rds,
				       diff));
		dns_rdataset_disassociate(&rbt_rds);
	}

	for (l = HEAD(*ldap_rdatalist);
	     l != NULL;
	     l = NEXT(l, link)) {
		result = rdatalist_to_diff(mctx, DNS_DIFFOP_ADD, name, l, diff);
		if (result != ISC_R_SUCCESS && result != ISC_R_NOMORE)
			goto cleanup;
	}
	if (result == ISC_R_NOMORE)
		result = ISC_R_SUCCESS;

cleanup:
	return result;
}

/**
 * Process strictly minimal diff and detect if data were changed
 * and return latest SOA RR.
 *
 * @pre Input diff has to be minimal, i.e. it can't contain DEL & ADD operation
 *      for the same data under the same name and TTL.
 *
 * @pre If the tuple list contains SOA RR, then exactly one SOA RR deletion
 *      has to precede exactly one SOA RR addition.
 *      (Each SOA RR deletion has to have matching addition.)
 *
 * @param[in]	diff		Input diff. List of tuples can be empty.
 * @param[out]	soa_latest	Pointer to last added SOA RR from tuple list.
 *				Result can be NULL if there is no added SOA RR
 *				in the tuple list.
 * @param[out]	data_changed	ISC_TRUE if any data other than SOA serial were
 * 				changed. ISC_FALSE if nothing (except SOA
 * 				serial) was changed.
 *
 */
static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
diff_analyze_serial(dns_diff_t *diff, dns_difftuple_t **soa_latest,
		    isc_boolean_t *data_changed) {
	dns_difftuple_t *t = NULL;
	dns_rdata_t *del_soa = NULL; /* last seen SOA with op == DEL */
	dns_difftuple_t *tmp_tuple = NULL; /* tuple used for SOA comparison */
	isc_result_t result = ISC_R_SUCCESS;
	int ret;

	REQUIRE(DNS_DIFF_VALID(diff));
	REQUIRE(soa_latest != NULL && *soa_latest == NULL);
	REQUIRE(data_changed != NULL);

	*data_changed = ISC_FALSE;
	for (t = HEAD(diff->tuples);
	     t != NULL;
	     t = NEXT(t, link)) {
		INSIST(tmp_tuple == NULL);
		if (t->rdata.type != dns_rdatatype_soa)
			*data_changed = ISC_TRUE;
		else { /* SOA is always special case */
			if (t->op == DNS_DIFFOP_DEL ||
			    t->op == DNS_DIFFOP_DELRESIGN) {
				/* delete operation has to precede add */
				INSIST(del_soa == NULL);
				del_soa = &t->rdata;
			} else if (t->op == DNS_DIFFOP_ADD ||
				   t->op == DNS_DIFFOP_ADDRESIGN) {
				/* add operation has to follow a delete */
				*soa_latest = t;

				/* we are adding SOA without preceding delete
				 * -> we are initializing new empty zone */
				if (del_soa == NULL) {
					*data_changed = ISC_TRUE;
				} else if (*data_changed == ISC_FALSE) {
					/* detect if fields other than serial
					 * were changed (compute only if necessary) */
					CHECK(dns_difftuple_copy(t, &tmp_tuple));
					dns_soa_setserial(dns_soa_getserial(del_soa),
							  &tmp_tuple->rdata);
					ret = dns_rdata_compare(del_soa,
								&tmp_tuple->rdata);
					*data_changed = ISC_TF(ret != 0);
				}
				if (tmp_tuple != NULL)
					dns_difftuple_free(&tmp_tuple);
				/* re-start the SOA delete-add search cycle */
				del_soa = NULL;
			} else {
				INSIST("unexpected diff: op != ADD || DEL"
				       == NULL);
			}
		}
	}
	/* SOA deletions & additions has to create self-contained couples */
	INSIST(del_soa == NULL && tmp_tuple == NULL);

cleanup:
	if (tmp_tuple != NULL)
		dns_difftuple_free(&tmp_tuple);
	return result;
}

/**
 * Replace SOA serial in LDAP for given zone.
 *
 * @param[in]	inst
 * @param[in]	zone	Zone name.
 * @param[in]	serial	New serial.
 *
 */
static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
ldap_replace_serial(ldap_instance_t *inst, dns_name_t *zone,
		    isc_uint32_t serial) {
	isc_result_t result;
#define MAX_SERIAL_LENGTH sizeof("4294967295") /* SOA serial is isc_uint32_t */
	char serial_char[MAX_SERIAL_LENGTH];
	char *values[2] = { serial_char, NULL };
	LDAPMod change;
	LDAPMod *changep[2] = { &change, NULL };
	ld_string_t *dn = NULL;

	REQUIRE(inst != NULL);

	CHECK(str_new(inst->mctx, &dn));
	CHECK(dnsname_to_dn(inst->zone_register, zone, zone, dn));

	change.mod_op = LDAP_MOD_REPLACE;
	change.mod_type = "idnsSOAserial";
	change.mod_values = values;
	CHECK(isc_string_printf(serial_char, MAX_SERIAL_LENGTH, "%u", serial));

	CHECK(ldap_modify_do(inst, str_buf(dn), changep, ISC_FALSE));

cleanup:
	str_destroy(&dn);
	return result;
#undef MAX_SERIAL_LENGTH
}

static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
zone_master_reconfigure_nsec3param(settings_set_t *zone_settings,
				   dns_zone_t *secure) {
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_rdata_t *nsec3p_rdata = NULL;
	dns_rdata_nsec3param_t nsec3p_rr;
	dns_name_t *origin = NULL;
	const char *nsec3p_str = NULL;
	ldap_entry_t *fake_entry = NULL;

	REQUIRE(secure != NULL);

	mctx = dns_zone_getmctx(secure);
	origin = dns_zone_getorigin(secure);
	CHECK(ldap_entry_init(mctx, &fake_entry));

	CHECK(setting_get_str("nsec3param", zone_settings, &nsec3p_str));
	dns_zone_log(secure, ISC_LOG_INFO,
		     "reconfiguring NSEC3PARAM to '%s'", nsec3p_str);
	CHECK(parse_rdata(mctx, fake_entry, dns_rdataclass_in,
			  dns_rdatatype_nsec3param, origin, nsec3p_str,
			  &nsec3p_rdata));
	CHECK(dns_rdata_tostruct(nsec3p_rdata, &nsec3p_rr, NULL));
	CHECK(dns_zone_setnsec3param(secure, nsec3p_rr.hash, nsec3p_rr.flags,
				     nsec3p_rr.iterations,
				     nsec3p_rr.salt_length, nsec3p_rr.salt,
				     ISC_TRUE));

cleanup:
	if (nsec3p_rdata != NULL) {
		isc_mem_put(mctx, nsec3p_rdata->data, nsec3p_rdata->length);
		SAFE_MEM_PUT_PTR(mctx, nsec3p_rdata);
	}
	if (fake_entry != NULL)
		ldap_entry_destroy(mctx, &fake_entry);
	return result;
}

/**
 * Reconfigure master zone according to configuration in LDAP object.
 *
 * @param[in]  raw Raw zone backed by LDAP database. In-line secure zone
 *                 will be reconfigured as necessary.
 */
static isc_result_t ATTR_NONNULL(1,2,3,5) ATTR_CHECKRESULT
zone_master_reconfigure(ldap_entry_t *entry, settings_set_t *zone_settings,
			dns_zone_t *raw, dns_zone_t *secure, isc_task_t *task) {
	isc_result_t result;
	ldap_valuelist_t values;
	isc_mem_t *mctx = NULL;
	isc_boolean_t ssu_changed;
	dns_zone_t *inview = NULL;

	REQUIRE(entry != NULL);
	REQUIRE(zone_settings != NULL);
	REQUIRE(raw != NULL);
	REQUIRE(task != NULL);

	mctx = dns_zone_getmctx(raw);

	if (secure != NULL)
		dns_zone_attach(secure, &inview);
	else
		dns_zone_attach(raw, &inview);

	result = setting_update_from_ldap_entry("dyn_update", zone_settings,
						"idnsAllowDynUpdate", entry);
	if (result != ISC_R_SUCCESS && result != ISC_R_IGNORE)
		goto cleanup;
	ssu_changed = (result == ISC_R_SUCCESS);

	result = setting_update_from_ldap_entry("sync_ptr", zone_settings,
				       "idnsAllowSyncPTR", entry);
	if (result != ISC_R_SUCCESS && result != ISC_R_IGNORE)
		goto cleanup;

	result = setting_update_from_ldap_entry("update_policy", zone_settings,
						"idnsUpdatePolicy", entry);
	if (result != ISC_R_SUCCESS && result != ISC_R_IGNORE)
		goto cleanup;

	if (result == ISC_R_SUCCESS || ssu_changed) {
		isc_boolean_t ssu_enabled;
		const char *ssu_policy = NULL;

		CHECK(setting_get_bool("dyn_update", zone_settings, &ssu_enabled));
		if (ssu_enabled) {
			/* Get the update policy and update the zone with it. */
			CHECK(setting_get_str("update_policy", zone_settings,
					      &ssu_policy));
			dns_zone_log(raw, ISC_LOG_DEBUG(2),
				     "setting update-policy to '%s'",
				     ssu_policy);
			CHECK(configure_zone_ssutable(raw, ssu_policy));
		} else {
			/* Empty policy will prevent the update from reaching
			 * LDAP driver and error will be logged. */
			dns_zone_log(raw, ISC_LOG_DEBUG(2),
				     "update-policy is not set");
			CHECK(configure_zone_ssutable(raw, ""));
		}
	}

	/* Fetch allow-query and allow-transfer ACLs */
	result = ldap_entry_getvalues(entry, "idnsAllowQuery", &values);
	if (result == ISC_R_SUCCESS) {
		dns_zone_log(inview, ISC_LOG_DEBUG(2),
			     "setting allow-query to '%s'",
			     HEAD(values)->value);
		CHECK(configure_zone_acl(mctx, inview, &dns_zone_setqueryacl,
					 HEAD(values)->value, acl_type_query));
	} else {
		dns_zone_log(inview, ISC_LOG_DEBUG(2), "allow-query is not set");
		dns_zone_clearqueryacl(raw);
	}

	result = ldap_entry_getvalues(entry, "idnsAllowTransfer", &values);
	if (result == ISC_R_SUCCESS) {
		dns_zone_log(inview, ISC_LOG_DEBUG(2),
			     "setting allow-transfer to '%s'",
			     HEAD(values)->value);
		CHECK(configure_zone_acl(mctx, inview, &dns_zone_setxfracl,
					 HEAD(values)->value, acl_type_transfer));
	} else {
		dns_zone_log(inview, ISC_LOG_DEBUG(2),
			     "allow-transfer is not set");
		dns_zone_clearxfracl(raw);
		result = ISC_R_SUCCESS;
	}

	if (secure != NULL) {
		/* notifications should be sent from secure zone only */
		dns_zone_setnotifytype(raw, dns_notifytype_no);

		/* Magic constants are taken from zoneconf.c */
		/* sig-validity-interval */
		dns_zone_setsigvalidityinterval(secure, 2592000);

		/* re-sign */
		dns_zone_setsigresigninginterval(secure, 648000);

		/* sig-signing-signatures */
		dns_zone_setsignatures(secure, 10);

		/* sig-signing-nodes */
		dns_zone_setnodes(secure, 10);

		/* sig-signing-type */
		dns_zone_setprivatetype(secure, 65534);

		/* update-check-ksk */
		dns_zone_setoption(secure, DNS_ZONEOPT_UPDATECHECKKSK, ISC_TRUE);

		/* dnssec-loadkeys-interval */
		CHECK(dns_zone_setrefreshkeyinterval(secure, 60));

		result = setting_update_from_ldap_entry("nsec3param",
							zone_settings,
							"nsec3paramRecord",
							entry);
		if (result == ISC_R_SUCCESS)
			CHECK(zone_master_reconfigure_nsec3param(zone_settings,
								 secure));
		else if (result == ISC_R_IGNORE)
			result = ISC_R_SUCCESS;
		else
			goto cleanup;

		/* auto-dnssec = maintain */
		dns_zone_setkeyopt(secure, DNS_ZONEKEY_ALLOW, ISC_TRUE);
		dns_zone_setkeyopt(secure, DNS_ZONEKEY_MAINTAIN, ISC_TRUE);
	}

cleanup:
	if (inview != NULL)
		dns_zone_detach(&inview);
	return result;
}

/**
 * Synchronize internal RBTDB with master zone object in LDAP and update serial
 * as necessary.
 *
 * @param[in]  new_zone Is the RBTDB empty? (I.e. even without SOA record.)
 * @param[in]  version  LDAP DB opened for reading and writing.
 * @param[out] diff     Initialized diff. It will be filled with differences
 *                      between RBTDB and LDAP object + SOA serial update.
 * @param[out] new_serial     SOA serial after update;
 *                            valid if ldap_writeback = ISC_TRUE.
 * @param[out] ldap_writeback SOA serial was updated.
 * @param[out] data_changed   Other data were updated.
 *
 */
static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
zone_sync_apex(const ldap_instance_t * const inst,
	       ldap_entry_t * const entry, dns_name_t name,
	       const sync_state_t sync_state, const isc_boolean_t new_zone,
	       dns_db_t * const ldapdb, dns_db_t * const rbtdb,
	       dns_dbversion_t * const version, dns_diff_t * const diff,
	       isc_uint32_t * const new_serial,
	       isc_boolean_t * const ldap_writeback,
	       isc_boolean_t * const data_changed) {
	isc_result_t result;
	const char *fake_mname = NULL;
	ldapdb_rdatalist_t rdatalist;
	dns_rdatasetiter_t *rbt_rds_iterator = NULL;
	/* RBTDB's origin node cannot be detached until the node is non-empty.
	 * This is workaround for ISC-Bug #35080. */
	dns_dbnode_t *node = NULL;
	dns_difftuple_t *soa_tuple = NULL;
	isc_uint32_t curr_serial;

	REQUIRE(ldap_writeback != NULL);

	INIT_LIST(rdatalist);
	*ldap_writeback = ISC_FALSE; /* GCC */

	CHECK(setting_get_str("fake_mname", inst->local_settings,
			      &fake_mname));
	CHECK(ldap_parse_rrentry(inst->mctx, entry, &name, fake_mname,
				 &rdatalist));

	CHECK(dns_db_getoriginnode(rbtdb, &node));
	result = dns_db_allrdatasets(rbtdb, node, version, 0,
				     &rbt_rds_iterator);
	if (result == ISC_R_SUCCESS) {
		CHECK(diff_ldap_rbtdb(inst->mctx, &name, &rdatalist,
				      rbt_rds_iterator, diff));
		dns_rdatasetiter_destroy(&rbt_rds_iterator);
	} else if (result != ISC_R_NOTFOUND)
		goto cleanup;

	/* New zone doesn't have serial defined yet. */
	if (new_zone != ISC_TRUE)
		CHECK(dns_db_getsoaserial(rbtdb, version, &curr_serial));

	/* Detect if SOA serial is affected by the update or not.
	 * Always bump serial in case of re-synchronization. */
	CHECK(diff_analyze_serial(diff, &soa_tuple, data_changed));
	if (new_zone == ISC_TRUE || *data_changed == ISC_TRUE ||
	    sync_state != sync_finished) {
		if (soa_tuple == NULL) {
			/* The diff doesn't contain new SOA serial
			 * => generate new serial and write it back to LDAP. */
			*ldap_writeback = ISC_TRUE;
			CHECK(zone_soaserial_addtuple(inst->mctx, ldapdb,
						      version, diff, new_serial));
		} else if (new_zone == ISC_TRUE || sync_state != sync_finished ||
			   isc_serial_le(dns_soa_getserial(&soa_tuple->rdata),
					 curr_serial)) {
			/* The diff tries to send SOA serial back!
			 * => generate new serial and write it back to LDAP.
			 * Force serial update if we are adding a new zone. */
			*ldap_writeback = ISC_TRUE;
			CHECK(zone_soaserial_updatetuple(dns_updatemethod_unixtime,
							 soa_tuple, new_serial));
		} else {
			/* The diff contains new serial already
			 * => do nothing. */
			*ldap_writeback = ISC_FALSE;
		}

	} else {/* if (data_changed == ISC_FALSE) */
		*ldap_writeback = ISC_FALSE;
		if (soa_tuple == NULL) {
			/* The diff is empty => do nothing. */
			INSIST(EMPTY(diff->tuples));
		} else if (isc_serial_le(dns_soa_getserial(&soa_tuple->rdata),
					 curr_serial)) {
			/* Attempt to move serial backwards without any data
			 * => ignore it. */
			dns_diff_clear(diff);
		}/* else:
		  * The diff contains new serial already
		  * => do nothing. */
	}

cleanup:
	if (node != NULL)
		dns_db_detachnode(rbtdb, &node);
	if (rbt_rds_iterator != NULL)
		dns_rdatasetiter_destroy(&rbt_rds_iterator);
	ldapdb_rdatalist_destroy(inst->mctx, &rdatalist);
	return result;
}

/**
 * Change security status of an existing zone.
 *
 * LDAP database is detached from the original zone, the zone is deleted
 * and re-created with different parameters on top of the old LDAP database.
 */
static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
zone_security_change(ldap_entry_t * const entry, dns_name_t * const name,
		     ldap_instance_t * const inst, isc_task_t * const task) {
	isc_result_t result;
	dns_db_t *olddb = NULL;
	isc_result_t lock_state = ISC_R_IGNORE;

	CHECK(zr_get_zone_dbs(inst->zone_register, name, &olddb, NULL));

	/* Lock is necessary to ensure that no events from LDAP are lost
	 * in period where old zone was deleted but the new zone was not
	 * created yet. */
	run_exclusive_enter(inst, &lock_state);
	CHECK(ldap_delete_zone2(inst, name, ISC_FALSE, ISC_TRUE));
	CHECK(ldap_parse_master_zoneentry(entry, olddb, inst, task));

cleanup:
	run_exclusive_exit(inst, lock_state);
	if (olddb != NULL)
		dns_db_detach(&olddb);
	return result;
}

/**
 * Parse the master zone entry and configure DNS zone accordingly.
 * New zone will be created if it doesn't exist. Existing zone will be
 * updated with new settings from LDAP entry.
 *
 * This function also synchronizes data at zone apex and ensures
 * that zone serial is incremented after each change.
 *
 * @param olddb[in]  LDAP database to be used when constructing a new zone.
 *                   Empty database will be created if it is NULL.
 *                   It should be non-NULL only if reconfiguration of
 *                   an existing zone is not possible so the old zone
 *                   was deleted but the new zone should re-use the old
 *                   database.
 */
static isc_result_t
ldap_parse_master_zoneentry(ldap_entry_t * const entry, dns_db_t * const olddb,
			    ldap_instance_t * const inst,
			    isc_task_t * const task)
{
	const char *dn;
	ldap_valuelist_t values;
	dns_zone_t *raw = NULL;
	dns_zone_t *secure = NULL;
	dns_zone_t *toview = NULL;
	isc_result_t result;
	isc_result_t lock_state = ISC_R_IGNORE;
	isc_boolean_t new_zone = ISC_FALSE;
	isc_boolean_t want_secure = ISC_FALSE;
	isc_boolean_t configured = ISC_FALSE;
	isc_boolean_t activity_changed;
	isc_boolean_t isactive = ISC_FALSE;
	settings_set_t *zone_settings = NULL;
	isc_boolean_t ldap_writeback;
	isc_boolean_t data_changed = ISC_FALSE; /* GCC */
	isc_uint32_t new_serial;

	dns_db_t *rbtdb = NULL;
	dns_db_t *ldapdb = NULL;
	dns_diff_t diff;
	dns_dbversion_t *version = NULL;
	sync_state_t sync_state;

	REQUIRE(entry != NULL);
	REQUIRE(inst != NULL);
	REQUIRE(task == inst->task); /* For task-exclusive mode */

	dns_diff_init(inst->mctx, &diff);

	/* Derive the dns name of the zone from the DN. */
	dn = entry->dn;

	run_exclusive_enter(inst, &lock_state);

	result = configure_zone_forwarders(entry, inst, &entry->fqdn);
	if (result != ISC_R_SUCCESS && result != ISC_R_DISABLED)
		goto cleanup;

	result = ldap_entry_getvalues(entry, "idnsSecInlineSigning", &values);
	if (result == ISC_R_NOTFOUND || HEAD(values) == NULL)
		want_secure = ISC_FALSE;
	else
		want_secure = ISC_TF(strcasecmp(HEAD(values)->value, "TRUE")
				     == 0);

	/* Check if we are already serving given zone */
	result = zr_get_zone_ptr(inst->zone_register, &entry->fqdn,
				 &raw, &secure);
	if (result == ISC_R_NOTFOUND || result == DNS_R_PARTIALMATCH) {
		CHECK(create_zone(inst, dn, &entry->fqdn, olddb, want_secure,
				  &raw, &secure));
		new_zone = ISC_TRUE;
		log_debug(2, "created zone %s: raw %p; secure %p", dn, raw,
			  secure);
	} else if (result != ISC_R_SUCCESS)
		goto cleanup;
	else if (want_secure != ISC_TF(secure != NULL)) {
		if (want_secure == ISC_TRUE)
			dns_zone_log(raw, ISC_LOG_INFO,
				     "upgrading zone to secure");
		else
			dns_zone_log(secure, ISC_LOG_INFO,
				     "downgrading zone to insecure");
		CHECK(zone_security_change(entry, &entry->fqdn, inst, task));
		goto cleanup;
	} else { /* Zone exists and it's security status is unchanged. */
		INSIST(olddb == NULL);
	}

	CHECK(zr_get_zone_settings(inst->zone_register, &entry->fqdn,
				   &zone_settings));
	CHECK(zone_master_reconfigure(entry, zone_settings, raw, secure, task));

	/* synchronize zone origin with LDAP */
	CHECK(zr_get_zone_dbs(inst->zone_register, &entry->fqdn, &ldapdb, &rbtdb));
	CHECK(dns_db_newversion(ldapdb, &version));
	sync_state_get(inst->sctx, &sync_state);
	CHECK(zone_sync_apex(inst, entry, entry->fqdn, sync_state, new_zone,
			     ldapdb, rbtdb, version,
			     &diff, &new_serial, &ldap_writeback,
			     &data_changed));

#if RBTDB_DEBUG >= 2
	dns_diff_print(&diff, stdout);
#else
	dns_diff_print(&diff, NULL);
#endif
	if (ldap_writeback == ISC_TRUE) {
		dns_zone_log(raw, ISC_LOG_DEBUG(5), "writing new zone serial "
			     "%u to LDAP", new_serial);
		result = ldap_replace_serial(inst, &entry->fqdn, new_serial);
		if (result != ISC_R_SUCCESS)
			dns_zone_log(raw, ISC_LOG_ERROR,
				     "serial (%u) write back to LDAP failed",
				     new_serial);
	}

	if (!EMPTY(diff.tuples)) {
		if (sync_state == sync_finished && new_zone == ISC_FALSE) {
			/* write the transaction to journal */
			CHECK(zone_journal_adddiff(inst->mctx, raw, &diff));
		}

		/* commit */
		CHECK(dns_diff_apply(&diff, rbtdb, version));
		dns_db_closeversion(ldapdb, &version, ISC_TRUE);
		dns_zone_markdirty(raw);
	} else {
		/* It is necessary to release lock before calling load_zone()
		 * otherwise it will deadlock on newversion() call
		 * in journal roll-forward process! */
		dns_db_closeversion(ldapdb, &version, ISC_FALSE);
	}
	configured = ISC_TRUE;

	/* Detect active/inactive zone and activity changes */
	result = setting_update_from_ldap_entry("active", zone_settings,
						"idnsZoneActive", entry);
	if (result == ISC_R_SUCCESS) {
		activity_changed = ISC_TRUE;
	} else if (result == ISC_R_IGNORE) {
		activity_changed = ISC_FALSE;
	} else
		goto cleanup;
	CHECK(setting_get_bool("active", zone_settings, &isactive));

	/* Do zone load only if the initial LDAP synchronization is done. */
	if (sync_state != sync_finished)
		goto cleanup;

	toview = (want_secure == ISC_TRUE) ? secure : raw;
	if (isactive == ISC_TRUE) {
		if (new_zone == ISC_TRUE || activity_changed == ISC_TRUE)
			CHECK(publish_zone(task, inst, toview));
		CHECK(load_zone(toview, ISC_FALSE));
	} else if (activity_changed == ISC_TRUE) { /* Zone was deactivated */
		CHECK(unpublish_zone(inst, &entry->fqdn, entry->dn));
		dns_zone_log(toview, ISC_LOG_INFO, "zone deactivated "
			     "and removed from view");
	}

cleanup:
	dns_diff_clear(&diff);
	if (rbtdb != NULL && version != NULL)
		dns_db_closeversion(ldapdb, &version, ISC_FALSE); /* rollback */
	if (rbtdb != NULL)
		dns_db_detach(&rbtdb);
	if (ldapdb != NULL)
		dns_db_detach(&ldapdb);
	if (new_zone == ISC_TRUE && configured == ISC_FALSE) {
		/* Failure in ACL parsing or so. */
		log_error_r("zone '%s': publishing failed, rolling back due to",
			    entry->dn);
		/* TODO: verify this */
		result = ldap_delete_zone2(inst, &entry->fqdn,
					   ISC_TRUE, ISC_FALSE);
		if (result != ISC_R_SUCCESS)
			log_error_r("zone '%s': rollback failed: ", entry->dn);
	}
	run_exclusive_exit(inst, lock_state);
	if (raw != NULL)
		dns_zone_detach(&raw);
	if (secure != NULL)
		dns_zone_detach(&secure);

	return result;
}

static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
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
/**
 * @param rdatalist[in,out] Has to be empty initialized list.
 */
static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
ldap_parse_rrentry(isc_mem_t *mctx, ldap_entry_t *entry, dns_name_t *origin,
		   const char *fake_mname, ldapdb_rdatalist_t *rdatalist)
{
	isc_result_t result;
	dns_rdataclass_t rdclass;
	dns_ttl_t ttl;
	dns_rdatatype_t rdtype;
	dns_rdata_t *rdata = NULL;
	dns_rdatalist_t *rdlist = NULL;
	ldap_attribute_t *attr;
	const char *dn = "<NULL entry>";
	const char *data_str = "<NULL data>";
	ld_string_t *data_buf = NULL;

	REQUIRE(EMPTY(*rdatalist));

	CHECK(str_new(mctx, &data_buf));
	if ((entry->class & LDAP_ENTRYCLASS_MASTER) != 0)
		CHECK(add_soa_record(mctx, origin, entry, rdatalist, fake_mname));

	rdclass = ldap_entry_getrdclass(entry);
	ttl = ldap_entry_getttl(entry);

	for (result = ldap_entry_firstrdtype(entry, &attr, &rdtype);
	     result == ISC_R_SUCCESS;
	     result = ldap_entry_nextrdtype(entry, &attr, &rdtype)) {

		CHECK(findrdatatype_or_create(mctx, rdatalist, rdclass,
					      rdtype, ttl, &rdlist));
		for (result = ldap_attr_firstvalue(attr, data_buf);
		     result == ISC_R_SUCCESS;
		     result = ldap_attr_nextvalue(attr, data_buf)) {
			CHECK(parse_rdata(mctx, entry, rdclass,
					  rdtype, origin,
					  str_buf(data_buf), &rdata));
			APPEND(rdlist->rdata, rdata, link);
			rdata = NULL;
		}
		if (result != ISC_R_NOMORE)
			goto cleanup;
		rdlist = NULL;
	}
	if (result != ISC_R_NOMORE)
		goto cleanup;

	str_destroy(&data_buf);
	return ISC_R_SUCCESS;

cleanup:
	if (entry != NULL)
		dn = entry->dn;
	if (data_buf != NULL && str_len(data_buf) != 0)
		data_str = str_buf(data_buf);
	log_error_r("failed to parse RR entry: dn '%s': data '%s'", dn, data_str);
	str_destroy(&data_buf);
	return result;
}

static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
add_soa_record(isc_mem_t *mctx, dns_name_t *origin,
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
	CHECK(parse_rdata(mctx, entry, rdclass, dns_rdatatype_soa, origin,
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

static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
parse_rdata(isc_mem_t *mctx, ldap_entry_t *entry,
	    dns_rdataclass_t rdclass, dns_rdatatype_t rdtype,
	    dns_name_t *origin, const char *rdata_text, dns_rdata_t **rdatap)
{
	isc_result_t result;
	isc_consttextregion_t text;
	isc_buffer_t lex_buffer;
	isc_region_t rdatamem;
	dns_rdata_t *rdata;

	REQUIRE(entry != NULL);
	REQUIRE(rdata_text != NULL);
	REQUIRE(rdatap != NULL);

	rdata = NULL;
	rdatamem.base = NULL;

	text.base = rdata_text;
	text.length = strlen(text.base);

	isc_buffer_init(&lex_buffer, (char *)text.base, text.length);
	isc_buffer_add(&lex_buffer, text.length);
	isc_buffer_setactive(&lex_buffer, text.length);

	CHECK(isc_lex_openbuffer(entry->lex, &lex_buffer));

	isc_buffer_init(&entry->rdata_target, entry->rdata_target_mem,
			DNS_RDATA_MAXLENGTH);
	CHECK(dns_rdata_fromtext(NULL, rdclass, rdtype, entry->lex, origin,
				 0, mctx, &entry->rdata_target, NULL));

	CHECKED_MEM_GET_PTR(mctx, rdata);
	dns_rdata_init(rdata);

	rdatamem.length = isc_buffer_usedlength(&entry->rdata_target);
	CHECKED_MEM_GET(mctx, rdatamem.base, rdatamem.length);

	memcpy(rdatamem.base, isc_buffer_base(&entry->rdata_target),
	       rdatamem.length);
	dns_rdata_fromregion(rdata, rdclass, rdtype, &rdatamem);

	isc_lex_close(entry->lex);

	*rdatap = rdata;
	return ISC_R_SUCCESS;

cleanup:
	isc_lex_close(entry->lex);
	SAFE_MEM_PUT_PTR(mctx, rdata);
	if (rdatamem.base != NULL)
		isc_mem_put(mctx, rdatamem.base, rdatamem.length);

	return result;
}

/* FIXME: Tested with SASL/GSSAPI/KRB5 only */
static int ATTR_NONNULL(3) ATTR_CHECKRESULT
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
static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
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

static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
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
	case AUTH_INVALID:
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				"invalid auth_method_enum value %u",
				 auth_method_enum);
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

static isc_result_t ATTR_NONNULLS
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
		if (ldap_conn->handle == NULL)
			log_error("connection to the LDAP server was lost");
		result = ldap_connect(ldap_inst, ldap_conn, force);
		if (result == ISC_R_SUCCESS)
			log_info("successfully reconnected to LDAP server");
		break;
	}

	return result;
}

isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
ldap_modify_do(ldap_instance_t *ldap_inst, const char *dn, LDAPMod **mods,
		isc_boolean_t delete_node)
{
	int ret;
	int err_code;
	const char *operation_str;
	isc_boolean_t once = ISC_FALSE;
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
retry:
		once = ISC_TRUE;
		CHECK(handle_connection_error(ldap_inst, ldap_conn, ISC_FALSE));
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
		if (once == ISC_FALSE) {
			log_error("retrying LDAP operation (%s) on entry '%s'",
				  operation_str, dn);
			goto retry;
		}
	}

cleanup:
	ldap_pool_putconnection(ldap_inst->pool, &ldap_conn);

	return result;
}

void ATTR_NONNULLS
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

isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
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

static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
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

static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
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
		DECLARE_BUFFER(buffer, DNS_RDATA_MAXLENGTH);
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

static void ATTR_NONNULLS
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

static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
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
static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
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

static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
modify_ldap_common(dns_name_t *owner, dns_name_t *zone, ldap_instance_t *ldap_inst,
		   dns_rdatalist_t *rdlist, int mod_op, isc_boolean_t delete_node)
{
	isc_result_t result;
	isc_mem_t *mctx = ldap_inst->mctx;
	ld_string_t *owner_dn = NULL;
	LDAPMod *change[3] = { NULL };
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

	CHECK(dnsname_to_dn(ldap_inst->zone_register, owner, zone, owner_dn));
	zone_dn = strstr(str_buf(owner_dn),", ");

	if (zone_dn == NULL) { /* SOA record; owner = zone => owner_dn = zone_dn */
		zone_dn = (char *)str_buf(owner_dn);
	} else {
		zone_dn += 1; /* skip whitespace */
	}

	CHECK(dn_to_dnsname(mctx, zone_dn, &zone_name, NULL, NULL));

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
		result = sync_ptr_init(mctx, ldap_inst->view->zonetable,
				       ldap_inst->zone_register, owner, af,
				       change[0]->mod_values[0], rdlist->ttl,
				       mod_op);
		/* Silently ignore cases where the reverse zone does not exist,
		 * does not accept dynamic updates, or is not managed by this
		 * driver instance. */
		if (result == ISC_R_NOTFOUND ||
		    result == ISC_R_NOPERM ||
		    result == DNS_R_NOTAUTHORITATIVE)
			result = ISC_R_SUCCESS;
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
write_to_ldap(dns_name_t *owner, dns_name_t *zone, ldap_instance_t *ldap_inst, dns_rdatalist_t *rdlist)
{
	return modify_ldap_common(owner, zone, ldap_inst, rdlist, LDAP_MOD_ADD, ISC_FALSE);
}

isc_result_t
remove_values_from_ldap(dns_name_t *owner, dns_name_t *zone, ldap_instance_t *ldap_inst,
		 dns_rdatalist_t *rdlist, isc_boolean_t delete_node)
{
	return modify_ldap_common(owner, zone, ldap_inst, rdlist, LDAP_MOD_DELETE,
				  delete_node);
}

isc_result_t
remove_attr_from_ldap(dns_name_t *owner, dns_name_t *zone, ldap_instance_t *ldap_inst,
		      const char *attr) {
	LDAPMod *change[2] = { NULL };
	ld_string_t *dn = NULL;
	isc_result_t result;

	CHECK(str_new(ldap_inst->mctx, &dn));

	CHECK(ldap_mod_create(ldap_inst->mctx, &change[0]));
	change[0]->mod_op = LDAP_MOD_DELETE;
	CHECK(isc_string_copy(change[0]->mod_type, LDAP_ATTR_FORMATSIZE, attr));
	change[0]->mod_vals.modv_strvals = NULL; /* delete all values from given attribute */

	CHECK(dnsname_to_dn(ldap_inst->zone_register, owner, zone, dn));
	CHECK(ldap_modify_do(ldap_inst, str_buf(dn), change, ISC_FALSE));

cleanup:
	ldap_mod_free(ldap_inst->mctx, &change[0]);
	str_destroy(&dn);
	return result;
}


isc_result_t
remove_entry_from_ldap(dns_name_t *owner, dns_name_t *zone, ldap_instance_t *ldap_inst) {
	ldap_connection_t *ldap_conn = NULL;
	ld_string_t *dn = NULL;
	int ret;
	isc_result_t result;

	CHECK(str_new(ldap_inst->mctx, &dn));
	CHECK(dnsname_to_dn(ldap_inst->zone_register, owner, zone, dn));
	log_debug(2, "deleting whole node: '%s'", str_buf(dn));

	CHECK(ldap_pool_getconnection(ldap_inst->pool, &ldap_conn));
	if (ldap_conn->handle == NULL) {
		/*
		 * handle can be NULL when the first connection to LDAP wasn't
		 * successful
		 * TODO: handle this case inside ldap_pool_getconnection()?
		 */
		CHECK(ldap_connect(ldap_inst, ldap_conn, ISC_FALSE));
	}
	ret = ldap_delete_ext_s(ldap_conn->handle, str_buf(dn), NULL, NULL);
	result = (ret == LDAP_SUCCESS) ? ISC_R_SUCCESS : ISC_R_FAILURE;
	if (ret == LDAP_SUCCESS)
		goto cleanup;

	LDAP_OPT_CHECK(ldap_get_option(ldap_conn->handle, LDAP_OPT_RESULT_CODE,
		       &ret), "remove_entry_from_ldap failed to obtain "
		       "ldap error code");

	if (result != ISC_R_SUCCESS)
		log_ldap_error(ldap_conn->handle, "while deleting entry '%s'",
			       str_buf(dn));
cleanup:
	ldap_pool_putconnection(ldap_inst->pool, &ldap_conn);
	str_destroy(&dn);
	return result;
}


static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
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

static void ATTR_NONNULLS
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

static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
ldap_pool_getconnection(ldap_pool_t *pool, ldap_connection_t ** conn)
{
	ldap_connection_t *ldap_conn = NULL;
	unsigned int i;
	isc_result_t result;

	REQUIRE(pool != NULL);
	REQUIRE(conn != NULL && *conn == NULL);
	ldap_conn = *conn;

	CHECK(semaphore_wait_timed(&pool->conn_semaphore, &conn_wait_timeout));
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

static void ATTR_NONNULLS
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

static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
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

#define LDAP_ENTRYCHANGE_ALL	(LDAP_SYNC_CAPI_ADD | LDAP_SYNC_CAPI_DELETE | LDAP_SYNC_CAPI_MODIFY)

#define SYNCREPL_ADD(chgtype) (chgtype == LDAP_SYNC_CAPI_ADD)
#define SYNCREPL_DEL(chgtype) (chgtype == LDAP_SYNC_CAPI_DELETE)
#define SYNCREPL_MOD(chgtype) (chgtype == LDAP_SYNC_CAPI_MODIFY)
/* SYNCREPL_MODDN: Change in DN can be detected only via UUID->DN mapping:
 * Map UUID to (remembered) DN and compare remembered DN with new one. */
/* SYNCREPL_ANY: Initial database dump should be detected via sync_ctx state:
 * All changes received before first 'intermediate' message contain initial
 * state of the database.
#define SYNCREPL_ANY(chgtype) ((chgtype & LDAP_ENTRYCHANGE_ALL) != 0)
 */

/*
 * update_zone routine is processed asynchronously so it cannot assume
 * anything about state of ldap_inst from where it was sent. The ldap_inst
 * could have been already destroyed due server reload. The safest
 * way how to handle zone update is to refetch ldap_inst,
 * perform query to LDAP and delete&add the zone. This is expensive
 * operation but zones don't change often.
 */
static void ATTR_NONNULLS
update_zone(isc_task_t *task, isc_event_t *event)
{
	ldap_syncreplevent_t *pevent = (ldap_syncreplevent_t *)event;
	isc_result_t result ;
	ldap_instance_t *inst = NULL;
	isc_mem_t *mctx;
	dns_name_t prevname;
	ldap_entry_t *entry = pevent->entry;

	mctx = pevent->mctx;
	dns_name_init(&prevname, NULL);

	CHECK(manager_get_ldap_instance(pevent->dbname, &inst));
	INSIST(task == inst->task); /* For task-exclusive mode */

	if (SYNCREPL_DEL(pevent->chgtype)) {
		CHECK(ldap_delete_zone2(inst, &entry->fqdn,
					ISC_TRUE, ISC_FALSE));
	} else {
		if (entry->class & LDAP_ENTRYCLASS_MASTER)
			CHECK(ldap_parse_master_zoneentry(entry, NULL, inst,
							  task));
		else if (entry->class & LDAP_ENTRYCLASS_FORWARD)
			CHECK(ldap_parse_fwd_zoneentry(entry, inst));
	}

		/* This code is disabled because we don't have UUID->DN database yet.
		 if (SYNCREPL_MODDN(pevent->chgtype)) {
			if (dn_to_dnsname(inst->mctx, pevent->prevdn, &prevname, NULL)
					== ISC_R_SUCCESS) {
				CHECK(ldap_delete_zone(inst, pevent->prevdn,
				      ISC_TRUE, ISC_FALSE));
			} else {
				log_debug(5, "update_zone: old zone wasn't managed "
					     "by plugin, dn '%s'", pevent->prevdn);
			}

			// fill the cache with records from renamed zone //
			if (objclass & LDAP_ENTRYCLASS_MASTER) {
				CHECK(ldap_query(inst, NULL, &ldap_qresult_record, pevent->dn,
						LDAP_SCOPE_ONELEVEL, attrs_record, 0,
						"(objectClass=idnsRecord)"));

				for (entry_record = HEAD(ldap_qresult_record->ldap_entries);
						entry_record != NULL;
						entry_record = NEXT(entry_record, link)) {

					syncrepl_update(inst, entry_record, NULL);
				}
			}
		}
		*/
cleanup:
	if (inst != NULL) {
		sync_concurr_limit_signal(inst->sctx);
		sync_event_signal(inst->sctx, event);
		if (dns_name_dynamic(&prevname))
			dns_name_free(&prevname, inst->mctx);
	}
	if (result != ISC_R_SUCCESS)
		log_error_r("update_zone (syncrepl) failed for '%s'. "
			  "Zones can be outdated, run `rndc reload`",
			  pevent->dn);

	isc_mem_free(mctx, pevent->dbname);
	if (pevent->prevdn != NULL)
		isc_mem_free(mctx, pevent->prevdn);
	isc_mem_free(mctx, pevent->dn);
	ldap_entry_destroy(mctx, &entry);
	isc_mem_detach(&mctx);
	isc_event_free(&event);
	isc_task_detach(&task);
}

static void ATTR_NONNULLS
update_config(isc_task_t * task, isc_event_t *event)
{
	ldap_syncreplevent_t *pevent = (ldap_syncreplevent_t *)event;
	isc_result_t result;
	ldap_instance_t *inst = NULL;
	ldap_entry_t *entry = pevent->entry;
	isc_mem_t *mctx;

	mctx = pevent->mctx;

	CHECK(manager_get_ldap_instance(pevent->dbname, &inst));
	INSIST(task == inst->task); /* For task-exclusive mode */
	CHECK(ldap_parse_configentry(entry, inst));

cleanup:
	if (inst != NULL) {
		sync_concurr_limit_signal(inst->sctx);
		sync_event_signal(inst->sctx, event);
	}
	if (result != ISC_R_SUCCESS)
		log_error_r("update_config (syncrepl) failed for '%s'. "
			    "Configuration can be outdated, run `rndc reload`",
			    pevent->dn);

	ldap_entry_destroy(mctx, &entry);
	isc_mem_free(mctx, pevent->dbname);
	isc_mem_free(mctx, pevent->dn);
	isc_mem_detach(&mctx);
	isc_event_free(&event);
	isc_task_detach(&task);
}

/**
 * @brief Update record in cache.
 *
 * If it exists it is replaced with newer version.
 *
 * @param task Task indentifier.
 * @param event Internal data of type ldap_syncreplevent_t.
 */
static void ATTR_NONNULLS
update_record(isc_task_t *task, isc_event_t *event)
{
	/* syncrepl event */
	ldap_syncreplevent_t *pevent = (ldap_syncreplevent_t *)event;
	isc_result_t result;
	ldap_instance_t *inst = NULL;
	isc_mem_t *mctx;
	dns_zone_t *raw = NULL;
	dns_zone_t *secure = NULL;
	isc_boolean_t zone_found = ISC_FALSE;
	isc_boolean_t zone_reloaded = ISC_FALSE;
	isc_uint32_t serial;
	ldap_entry_t *entry = pevent->entry;
	const char *fake_mname = NULL;

	dns_db_t *rbtdb = NULL;
	dns_db_t *ldapdb = NULL;
	dns_diff_t diff;

	dns_dbversion_t *version = NULL; /* version is shared between rbtdb and ldapdb */
	dns_dbnode_t *node = NULL; /* node is shared between rbtdb and ldapdb */
	dns_rdatasetiter_t *rbt_rds_iterator = NULL;

	sync_state_t sync_state;

	mctx = pevent->mctx;
	dns_diff_init(mctx, &diff);

#ifdef RBTDB_DEBUG
	static unsigned int count = 0;
#endif

	/* Structure to be stored in the cache. */
	ldapdb_rdatalist_t rdatalist;
	INIT_LIST(rdatalist);

	/* Convert domain name from text to struct dns_name_t. */
	dns_name_t prevname;
	dns_name_t prevorigin;
	dns_name_init(&prevname, NULL);
	dns_name_init(&prevorigin, NULL);

	CHECK(manager_get_ldap_instance(pevent->dbname, &inst));
	CHECK(zr_get_zone_ptr(inst->zone_register, &entry->zone_name, &raw, &secure));
	zone_found = ISC_TRUE;

update_restart:
	rbtdb = NULL;
	ldapdb = NULL;
	ldapdb_rdatalist_destroy(mctx, &rdatalist);
	CHECK(zr_get_zone_dbs(inst->zone_register, &entry->zone_name, &ldapdb, &rbtdb));
	CHECK(dns_db_newversion(ldapdb, &version));

	CHECK(dns_db_findnode(rbtdb, &entry->fqdn, ISC_TRUE, &node));
	result = dns_db_allrdatasets(rbtdb, node, version, 0, &rbt_rds_iterator);
	if (result != ISC_R_SUCCESS && result != ISC_R_NOTFOUND)
		goto cleanup;


	/* This code is disabled because we don't have UUID->DN database yet.
	    || SYNCREPL_MODDN(pevent->chgtype)) { */
	if (SYNCREPL_DEL(pevent->chgtype)) {
		log_debug(5, "syncrepl_update: removing name from rbtdb, dn: '%s'",
			  pevent->dn);
		/* Do nothing. rdatalist is initialized to empty list,
		 * so resulting diff will remove all the data from node. */
	}

	/* TODO: double check correctness before replacing ldap_query() with
	 *       data from *event */
	/* This code is disabled because we don't have UUID->DN database yet.
	if (SYNCREPL_MODDN(pevent->chgtype)) {
		// remove previous name only if it was inside DNS subtree //
		if (dn_to_dnsname(mctx, pevent->prevdn, &prevname, &prevorigin)
				== ISC_R_SUCCESS) {
			log_debug(5, "syncrepl_update: removing name from cache, dn: '%s'",
					  pevent->prevdn);
			cache = NULL;
			zone = NULL;
			rbtdb = NULL;
			CHECK(zr_get_zone_ptr(inst->zone_register, &prevname, &zone));
			result = dns_zone_getdb(zone, &rbtdb);
			REQUIRE(result == ISC_R_SUCCESS);

			result = zr_get_zone_cache(inst->zone_register, &prevname, &cache);
			if (result == ISC_R_SUCCESS)
				CHECK(discard_from_cache(cache, &prevname));
			else if (result != ISC_R_NOTFOUND)
				goto cleanup;

		} else {
			log_debug(5, "syncrepl_update: old name wasn't managed "
					"by plugin, dn '%s'", pevent->prevdn);
		}
	}
	*/

	if (SYNCREPL_ADD(pevent->chgtype) || SYNCREPL_MOD(pevent->chgtype)) {
		/* Parse new data from LDAP. */
		log_debug(5, "syncrepl_update: updating name in rbtdb, dn: '%s'",
		          pevent->dn);
		CHECK(setting_get_str("fake_mname", inst->local_settings,
				      &fake_mname));
		CHECK(ldap_parse_rrentry(mctx, entry, &entry->zone_name, fake_mname,
					 &rdatalist));
	}

	if (rbt_rds_iterator != NULL) {
		CHECK(diff_ldap_rbtdb(mctx, &entry->fqdn, &rdatalist,
				      rbt_rds_iterator, &diff));
		dns_rdatasetiter_destroy(&rbt_rds_iterator);
	}

	sync_state_get(inst->sctx, &sync_state);
	/* No real change in RR data -> do not increment SOA serial. */
	if (HEAD(diff.tuples) != NULL) {
		if (sync_state == sync_finished) {
			CHECK(zone_soaserial_addtuple(mctx, ldapdb, version,
						      &diff, &serial));
			dns_zone_log(raw, ISC_LOG_DEBUG(5),
				     "writing new zone serial %u to LDAP",
				     serial);
			result = ldap_replace_serial(inst, &entry->zone_name, serial);
			if (result != ISC_R_SUCCESS)
				dns_zone_log(raw, ISC_LOG_ERROR,
					     "serial (%u) write back to LDAP failed",
					     serial);
		}

#if RBTDB_DEBUG >= 2
		dns_diff_print(&diff, stdout);
#else
		dns_diff_print(&diff, NULL);
#endif
		if (sync_state == sync_finished) {
			/* write the transaction to journal */
			CHECK(zone_journal_adddiff(inst->mctx, raw, &diff));
		}
		/* commit */
		CHECK(dns_diff_apply(&diff, rbtdb, version));
		dns_db_closeversion(ldapdb, &version, ISC_TRUE);
		dns_zone_markdirty(raw);
	}

	/* Check if the zone is loaded or not.
	 * No other function above returns DNS_R_NOTLOADED. */
	if (sync_state == sync_finished)
		result = dns_zone_getserial2(raw, &serial);

cleanup:
#ifdef RBTDB_DEBUG
	if (++count % 100 == 0)
		log_info("update_record: %u entries processed; inuse: %zd",
			 count, isc_mem_inuse(mctx));
#endif
	dns_diff_clear(&diff);
	if (rbt_rds_iterator != NULL)
		dns_rdatasetiter_destroy(&rbt_rds_iterator);
	if (node != NULL)
		dns_db_detachnode(rbtdb, &node);
	/* rollback */
	if (rbtdb != NULL && version != NULL)
		dns_db_closeversion(ldapdb, &version, ISC_FALSE);
	if (rbtdb != NULL)
		dns_db_detach(&rbtdb);
	if (ldapdb != NULL)
		dns_db_detach(&ldapdb);
	if (result != ISC_R_SUCCESS && zone_found && !zone_reloaded &&
	   (result == DNS_R_NOTLOADED || result == DNS_R_BADZONE)) {
		dns_zone_log(raw, ISC_LOG_DEBUG(1),
			     "reloading invalid zone after a change; "
			     "reload triggered by change in '%s'",
			     pevent->dn);
		if (secure != NULL)
			result = load_zone(secure, ISC_TRUE);
		else if (raw != NULL)
			result = load_zone(raw, ISC_TRUE);
		if (result == ISC_R_SUCCESS || result == DNS_R_UPTODATE ||
		    result == DNS_R_DYNAMIC || result == DNS_R_CONTINUE) {
			/* zone reload succeeded, fire current event again */
			log_debug(1, "restarting update_record after zone reload "
				     "caused by change in '%s'", pevent->dn);
			zone_reloaded = ISC_TRUE;
			result = dns_zone_getserial2(raw, &serial);
			if (result == ISC_R_SUCCESS)
				goto update_restart;
		} else {
			dns_zone_log(raw, ISC_LOG_ERROR,
				    "unable to reload invalid zone; "
				    "reload triggered by change in '%s':%s",
				    pevent->dn, dns_result_totext(result));
		}

	} else if (result != ISC_R_SUCCESS) {
		/* error other than invalid zone */
		log_error_r("update_record (syncrepl) failed, dn '%s' change type 0x%x. "
			  "Records can be outdated, run `rndc reload`",
			  pevent->dn, pevent->chgtype);
	}

	if (inst != NULL) {
		sync_concurr_limit_signal(inst->sctx);
		if (dns_name_dynamic(&prevname))
			dns_name_free(&prevname, inst->mctx);
		if (dns_name_dynamic(&prevorigin))
			dns_name_free(&prevorigin, inst->mctx);
	}
	if (raw != NULL)
		dns_zone_detach(&raw);
	if (secure != NULL)
		dns_zone_detach(&secure);
	ldapdb_rdatalist_destroy(mctx, &rdatalist);
	isc_mem_free(mctx, pevent->dbname);
	if (pevent->prevdn != NULL)
		isc_mem_free(mctx, pevent->prevdn);
	ldap_entry_destroy(mctx, &entry);
	isc_mem_free(mctx, pevent->dn);
	isc_mem_detach(&mctx);
	isc_event_free(&event);
	isc_task_detach(&task);
}

isc_result_t
ldap_dn_compare(const char *dn1_instr, const char *dn2_instr,
		isc_boolean_t *isequal) {
	int ret;
	isc_result_t result;
	LDAPDN dn1_ldap = NULL;
	LDAPDN dn2_ldap = NULL;
	char *dn1_outstr = NULL;
	char *dn2_outstr = NULL;

	ret = ldap_str2dn(dn1_instr, &dn1_ldap, LDAP_DN_FORMAT_LDAPV3);
	if (ret != LDAP_SUCCESS)
		CLEANUP_WITH(ISC_R_FAILURE);

	ret = ldap_str2dn(dn2_instr, &dn2_ldap, LDAP_DN_FORMAT_LDAPV3);
	if (ret != LDAP_SUCCESS)
		CLEANUP_WITH(ISC_R_FAILURE);

	ret = ldap_dn2str(dn1_ldap, &dn1_outstr, LDAP_DN_FORMAT_LDAPV3 | LDAP_DN_PEDANTIC);
	if (ret != LDAP_SUCCESS)
		CLEANUP_WITH(ISC_R_FAILURE);

	ret = ldap_dn2str(dn2_ldap, &dn2_outstr, LDAP_DN_FORMAT_LDAPV3 | LDAP_DN_PEDANTIC);
	if (ret != LDAP_SUCCESS)
		CLEANUP_WITH(ISC_R_FAILURE);

	*isequal = ISC_TF(strcasecmp(dn1_outstr, dn2_outstr) == 0);
	result = ISC_R_SUCCESS;

cleanup:
	if (dn1_ldap != NULL)
		ldap_dnfree(dn1_ldap);
	if (dn2_ldap != NULL)
		ldap_dnfree(dn2_ldap);
	if (dn1_outstr != NULL)
		ldap_memfree(dn1_outstr);
	if (dn1_outstr != NULL)
		ldap_memfree(dn2_outstr);

	return result;
}

static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
syncrepl_update(ldap_instance_t *inst, ldap_entry_t *entry, int chgtype)
{
	isc_result_t result = ISC_R_SUCCESS;
	ldap_syncreplevent_t *pevent = NULL;
	isc_event_t *wait_event = NULL;
	dns_name_t *zone_name = NULL;
	dns_zone_t *zone_ptr = NULL;
	char *dn = NULL;
	char *dbname = NULL;
	isc_mem_t *mctx = NULL;
	isc_taskaction_t action = NULL;
	isc_task_t *task = NULL;
	sync_state_t sync_state;

	REQUIRE(entry->class != LDAP_ENTRYCLASS_NONE);

	log_debug(20, "syncrepl change type: " /*"none%d,"*/ "add%d, del%d, mod%d", /* moddn%d", */
		  /* !SYNCREPL_ANY(chgtype), */ SYNCREPL_ADD(chgtype),
		  SYNCREPL_DEL(chgtype), SYNCREPL_MOD(chgtype)/*, SYNCREPL_MODDN(chgtype) */ );

	isc_mem_attach(inst->mctx, &mctx);

	CHECKED_MEM_STRDUP(mctx, entry->dn, dn);
	CHECKED_MEM_STRDUP(mctx, inst->db_name, dbname);


	if (entry->class & LDAP_ENTRYCLASS_MASTER)
		zone_name = &entry->fqdn;
	else
		zone_name = &entry->zone_name;

	/* Process ordinary records in parallel but serialize operations on
	 * master zone objects.
	 * See discussion about run_exclusive_begin() function in lock.c. */
	if ((entry->class & LDAP_ENTRYCLASS_RR) != 0 &&
	    (entry->class & LDAP_ENTRYCLASS_MASTER) == 0) {
		result = zr_get_zone_ptr(inst->zone_register, zone_name,
					 &zone_ptr, NULL);
		if (result == ISC_R_SUCCESS && dns_zone_getmgr(zone_ptr) != NULL)
			dns_zone_gettask(zone_ptr, &task);
		else {
			/* TODO: Fix race condition:
			 * zone is not (yet) present in zone register */
			log_debug(1, "TODO: DN '%s': task fallback", entry->dn);
			isc_task_attach(inst->task, &task);
			result = ISC_R_SUCCESS;
		}
	} else {
		/* For configuration object and zone object use single task
		 * to make sure that the exclusive mode actually works. */
		isc_task_attach(inst->task, &task);
	}
	REQUIRE(task != NULL);


	/* This code is disabled because we don't have UUID->DN database yet.
	if (SYNCREPL_MODDN(chgtype)) {
		CHECKED_MEM_STRDUP(mctx, prevdn_ldap, prevdn);
	}
	*/

	if ((entry->class & LDAP_ENTRYCLASS_CONFIG) != 0)
		action = update_config;
	else if ((entry->class & LDAP_ENTRYCLASS_MASTER) != 0)
		action = update_zone;
	else if ((entry->class & LDAP_ENTRYCLASS_FORWARD) != 0)
		action = update_zone;
	else if ((entry->class & LDAP_ENTRYCLASS_RR) != 0)
		action = update_record;
	else {
		log_error("unsupported objectClass: dn '%s'", dn);
		result = ISC_R_NOTIMPLEMENTED;
		goto cleanup;
	}

	/* All events for single zone are handled by one task, so we don't
	 * need to spend time with normal records. */
	if (action == update_zone || action == update_config) {
		INSIST(task == inst->task); /* For task-exclusive mode */
		sync_state_get(inst->sctx, &sync_state);
		if (sync_state == sync_init)
			CHECK(sync_task_add(inst->sctx, task));
	}

	pevent = (ldap_syncreplevent_t *)isc_event_allocate(inst->mctx,
				inst, LDAPDB_EVENT_SYNCREPL_UPDATE,
				action, NULL,
				sizeof(ldap_syncreplevent_t));

	if (pevent == NULL) {
		result = ISC_R_NOMEMORY;
		goto cleanup;
	}

	pevent->mctx = mctx;
	pevent->dbname = dbname;
	pevent->dn = dn;
	pevent->prevdn = NULL;
	pevent->chgtype = chgtype;
	pevent->entry = entry;
	wait_event = (isc_event_t *)pevent;
	isc_task_send(task, (isc_event_t **)&pevent);

	/* Lock syncrepl queue to prevent zone, config and resource records
	 * from racing with each other. */
	if (action == update_zone || action == update_config)
		CHECK(sync_event_wait(inst->sctx, wait_event));

cleanup:
	if (zone_ptr != NULL)
		dns_zone_detach(&zone_ptr);
	if (result != ISC_R_SUCCESS)
		log_error_r("syncrepl_update failed for object '%s'",
			    entry->dn);
	if (wait_event == NULL) {
		/* Event was not sent */
		sync_concurr_limit_signal(inst->sctx);

		if (dbname != NULL)
			isc_mem_free(mctx, dbname);
		if (dn != NULL)
			isc_mem_free(mctx, dn);
		if (mctx != NULL)
			isc_mem_detach(&mctx);
		ldap_entry_destroy(inst->mctx, &entry);
		if (task != NULL)
			isc_task_detach(&task);
	}
	return result;
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
static inline isc_boolean_t ATTR_NONNULLS
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
 * Called when a reference is returned by ldap_sync_init()/ldap_sync_poll().
 */
static int ATTR_NONNULLS ATTR_CHECKRESULT
ldap_sync_search_reference (
	ldap_sync_t			*ls,
	LDAPMessage			*msg ) {

	UNUSED(ls);
	UNUSED(msg);

	log_error("ldap_sync_search_reference is not yet handled");
	return LDAP_SUCCESS;
}

/*
 * Called when an entry is returned by ldap_sync_init()/ldap_sync_poll().
 * If phase is LDAP_SYNC_CAPI_ADD or LDAP_SYNC_CAPI_MODIFY,
 * the entry has been either added or modified, and thus
 * the complete view of the entry should be in the LDAPMessage.
 * If phase is LDAP_SYNC_CAPI_PRESENT or LDAP_SYNC_CAPI_DELETE,
 * only the DN should be in the LDAPMessage.
 */
int ldap_sync_search_entry (
	ldap_sync_t			*ls,
	LDAPMessage			*msg,
	struct berval			*entryUUID,
	ldap_sync_refresh_t		phase ) {

	ldap_instance_t *inst = ls->ls_private;
	ldap_entry_t *entry = NULL;
	isc_result_t result;
	metadb_node_t *node = NULL;
	isc_boolean_t mldap_open = ISC_FALSE;
	const char *ldap_base = NULL;

#ifdef RBTDB_DEBUG
	static unsigned int count = 0;
#endif

	if (inst->exiting)
		return LDAP_SUCCESS;

	CHECK(mldap_newversion(inst->mldapdb));
	mldap_open = ISC_TRUE;

	CHECK(sync_concurr_limit_wait(inst->sctx));
	if (phase == LDAP_SYNC_CAPI_ADD || phase == LDAP_SYNC_CAPI_MODIFY) {
		CHECK(ldap_entry_parse(inst->mctx, ls->ls_ld, msg, entryUUID,
					&entry));
		CHECK(mldap_entry_create(entry, inst->mldapdb, &node));
		if ((entry->class & LDAP_ENTRYCLASS_CONFIG) == 0)
			CHECK(mldap_dnsname_store(&entry->fqdn,
						  &entry->zone_name, node));
		/* commit new entry into metaLDAP DB before something breaks */
		metadb_node_close(&node);
		mldap_closeversion(inst->mldapdb, ISC_TRUE);
		mldap_open = ISC_FALSE;

	} else if (phase == LDAP_SYNC_CAPI_DELETE) {
		INSIST(setting_get_str("base", inst->local_settings,
				       &ldap_base) == ISC_R_SUCCESS);
		CHECK(ldap_entry_reconstruct(inst->mctx, inst->zone_register,
					     ldap_base, inst->mldapdb, entryUUID,
					     &entry));
		CHECK(mldap_entry_delete(inst->mldapdb, entryUUID));
		/* do not commit into DB until syncrepl_update finished */
	} else {
		log_bug("syncrepl phase %x is not supported", phase);
		CLEANUP_WITH(ISC_R_NOTIMPLEMENTED);
	}

	CHECK(syncrepl_update(inst, entry, phase));
	/* commit eventual deletion if the syncrepl event was sent */

#ifdef RBTDB_DEBUG
	if (++count % 100 == 0)
		log_info("ldap_sync_search_entry: %u entries read; inuse: %zd",
			 count, isc_mem_inuse(inst->mctx));
#endif

cleanup:
	metadb_node_close(&node);
	if (mldap_open == ISC_TRUE)
		mldap_closeversion(inst->mldapdb, ISC_TF(result == ISC_R_SUCCESS));
	if (result != ISC_R_SUCCESS) {
		log_error_r("ldap_sync_search_entry failed");
		sync_concurr_limit_signal(inst->sctx);
		/* TODO: Add 'tainted' flag to the LDAP instance. */
	}

	/* Following return code will never reach upper layers.
	 * It is limitation in ldap_sync_init() and ldap_sync_poll()
	 * provided by OpenLDAP libs at the time of writing (2013-07-22). */
	return LDAP_SUCCESS;
}

/**
 * Called when specific intermediate/final messages are returned
 * by ldap_sync_init()/ldap_sync_poll().
 * If phase is LDAP_SYNC_CAPI_PRESENTS or LDAP_SYNC_CAPI_DELETES,
 * a "presents" or "deletes" phase begins.
 * If phase is LDAP_SYNC_CAPI_DONE, a special "presents" phase
 * with refreshDone set to "TRUE" has been returned, to indicate
 * that the refresh phase of a refreshAndPersist is complete.
 * In the above cases, syncUUIDs is NULL.
 *
 * If phase is LDAP_SYNC_CAPI_PRESENTS_IDSET or
 * LDAP_SYNC_CAPI_DELETES_IDSET, syncUUIDs is an array of UUIDs
 * that are either present or have been deleted.
 *
 * @see Section @ref syncrepl-theory in syncrepl.c for the background.
 */
int ldap_sync_intermediate (
	ldap_sync_t			*ls,
	LDAPMessage			*msg,
	BerVarray			syncUUIDs,
	ldap_sync_refresh_t		phase ) {

	isc_result_t	result;
	ldap_instance_t *inst = ls->ls_private;

	UNUSED(msg);
	UNUSED(syncUUIDs);
	UNUSED(phase);

	if (inst->exiting)
		return LDAP_SUCCESS;

	if (phase == LDAP_SYNC_CAPI_DONE) {
		log_debug(1, "ldap_sync_intermediate RECEIVED");
		result = sync_barrier_wait(inst->sctx, inst->db_name);
		if (result != ISC_R_SUCCESS)
			log_error_r("sync_barrier_wait() failed for instance '%s'",
				    inst->db_name);
	}
	return LDAP_SUCCESS;
}

/*
 * Called when a searchResultDone is returned
 * by ldap_sync_init()/ldap_sync_poll().
 * In refreshAndPersist, this can only occur if the search for any reason
 * is being terminated by the server.
 */
int ATTR_NONNULLS ATTR_CHECKRESULT ldap_sync_search_result (
	ldap_sync_t			*ls,
	LDAPMessage			*msg,
	int				refreshDeletes ) {

	UNUSED(ls);
	UNUSED(msg);
	UNUSED(refreshDeletes);

	log_error("ldap_sync_search_result is not yet handled");
	return LDAP_SUCCESS;
}

static void ATTR_NONNULLS
ldap_sync_cleanup(ldap_sync_t **ldap_syncp) {
	ldap_sync_t *ldap_sync = NULL;

	REQUIRE(ldap_syncp != NULL);

	if (*ldap_syncp == NULL)
		return;

	ldap_sync = *ldap_syncp;
	ldap_sync_destroy(ldap_sync, 1);

	*ldap_syncp = NULL;
}


static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
ldap_sync_prepare(ldap_instance_t *inst, settings_set_t *settings,
		  ldap_connection_t *conn, ldap_sync_t **ldap_syncp) {
	isc_result_t result;
	const char *base = NULL;
	isc_uint32_t reconnect_interval;
	ldap_sync_t *ldap_sync = NULL;

	REQUIRE(inst != NULL);
	REQUIRE(ldap_syncp != NULL && *ldap_syncp == NULL);

	sync_state_reset(inst->sctx);

	/* Remove stale zone & journal files. */
	CHECK(cleanup_files(inst));

	/* Try to connect. */
	while (conn->handle == NULL) {
		result = ISC_R_SHUTTINGDOWN;
		CHECK_EXIT;
		CHECK(setting_get_uint("reconnect_interval", settings,
				       &reconnect_interval));

		log_error("ldap_syncrepl will reconnect in %d second%s",
			  reconnect_interval,
			  reconnect_interval == 1 ? "": "s");
		if (!sane_sleep(inst, reconnect_interval))
			CLEANUP_WITH(ISC_R_SHUTTINGDOWN);
		handle_connection_error(inst, conn, ISC_TRUE);
	}

	ldap_sync = ldap_sync_initialize(NULL);
	if (ldap_sync == NULL) {
		log_error("cannot initialize LDAP syncrepl context");
		CLEANUP_WITH(ISC_R_NOMEMORY);
	}
	ZERO_PTR(ldap_sync);

	CHECK(setting_get_str("base", settings, &base));
	ldap_sync->ls_base = ldap_strdup(base);
	if (ldap_sync->ls_base == NULL)
		CLEANUP_WITH(ISC_R_NOMEMORY);
	ldap_sync->ls_scope = LDAP_SCOPE_SUBTREE;
	ldap_sync->ls_filter = ldap_strdup("(|(objectClass=idnsConfigObject)"
					   "  (objectClass=idnsZone)"
					   "  (objectClass=idnsForwardZone)"
					   "  (objectClass=idnsRecord))");
	if (ldap_sync->ls_filter == NULL)
		CLEANUP_WITH(ISC_R_NOMEMORY);
	ldap_sync->ls_timeout = -1; /* sync_poll is blocking */
	ldap_sync->ls_ld = conn->handle;
	/* This is a hack: ldap_sync_destroy() will call ldap_unbind().
	 * We have to ensure that unbind() will not be called twice! */
	conn->handle = NULL;
	ldap_sync->ls_search_entry = ldap_sync_search_entry;
	ldap_sync->ls_search_reference = ldap_sync_search_reference;
	ldap_sync->ls_intermediate = ldap_sync_intermediate;
	ldap_sync->ls_search_result = ldap_sync_search_result;
	ldap_sync->ls_private = inst;

	result = ISC_R_SUCCESS;
	*ldap_syncp = ldap_sync;

cleanup:
	if (result != ISC_R_SUCCESS)
		ldap_sync_cleanup(&ldap_sync);

	return result;
}


/*
 * NOTE:
 * Every blocking call in syncrepl_watcher thread must be preemptible.
 */
static isc_threadresult_t
ldap_syncrepl_watcher(isc_threadarg_t arg)
{
	ldap_instance_t *inst = (ldap_instance_t *)arg;
	ldap_connection_t *conn = NULL;
	int ret;
	isc_result_t result;
	sigset_t sigset;
	ldap_sync_t *ldap_sync = NULL;
	const char *err_hint = "";

	log_debug(1, "Entering ldap_syncrepl_watcher");

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

	/* Pick connection, one is reserved purely for this thread */
	CHECK(ldap_pool_getconnection(inst->pool, &conn));

	while (!inst->exiting) {
		ldap_sync_cleanup(&ldap_sync);
		result = ldap_sync_prepare(inst, inst->global_settings,
					   conn, &ldap_sync);
		if (result != ISC_R_SUCCESS) {
			log_error_r("ldap_sync_prepare() failed, retrying "
				    "in 1 second");
			sane_sleep(inst, 1);
			continue;
		}

		log_info("LDAP instance '%s' is being synchronized, "
			 "please ignore message 'all zones loaded'",
			 inst->db_name);
		ret = ldap_sync_init(ldap_sync, LDAP_SYNC_REFRESH_AND_PERSIST);
		/* TODO: error handling, set tainted flag & do full reload? */
		if (ret != LDAP_SUCCESS) {
			if (ret == LDAP_UNAVAILABLE_CRITICAL_EXTENSION)
				err_hint = ": is RFC 4533 supported by LDAP server?";
			else
				err_hint = "";

			log_ldap_error(ldap_sync->ls_ld, "unable to start SyncRepl "
					"session%s", err_hint);
			conn->handle = NULL;
			continue;
		}

		while (!inst->exiting && ret == LDAP_SUCCESS) {
			ret = ldap_sync_poll(ldap_sync);
			if (!inst->exiting && ret != LDAP_SUCCESS) {
				log_ldap_error(ldap_sync->ls_ld,
					       "ldap_sync_poll() failed");
				/* force reconnect in sync_prepare */
				conn->handle = NULL;
			}
		}
	}

cleanup:
	log_debug(1, "Ending ldap_syncrepl_watcher");
	ldap_sync_cleanup(&ldap_sync);
	ldap_pool_putconnection(inst->pool, &conn);

	return (isc_threadresult_t)0;
}

settings_set_t *
ldap_instance_getsettings_local(ldap_instance_t *ldap_inst)
{
	return ldap_inst->local_settings;
}

const char *
ldap_instance_getdbname(ldap_instance_t *ldap_inst)
{
	return ldap_inst->db_name;
}

zone_register_t *
ldap_instance_getzr(ldap_instance_t *ldap_inst)
{
	return ldap_inst->zone_register;
}

isc_task_t *
ldap_instance_gettask(ldap_instance_t *ldap_inst)
{
	return ldap_inst->task;
}

isc_boolean_t
ldap_instance_isexiting(ldap_instance_t *ldap_inst)
{
	return ldap_inst->exiting;
}
