/*
 * Copyright (C) 2009-2015  bind-dyndb-ldap authors; see COPYING for license
 */

#include "config.h"
#define HAVE_TLS 1
#define HAVE_THREAD_LOCAL 1

#include <dns/dyndb.h>
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
#include <inttypes.h>
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
#include <isc/refcount.h>
#include <isc/timer.h>
#include <isc/serial.h>
#include <isc/string.h>

#include <isccfg/cfg.h>
#include <isccfg/grammar.h>

#include <alloca.h>
#define LDAP_DEPRECATED 1
#include <ldap.h>
#include <limits.h>
#include <regex.h>
#include <sasl/sasl.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <netdb.h>

#include "acl.h"
#include "empty_zones.h"
#include "fs.h"
#include "fwd.h"
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
#include "zone_register.h"
#include "rbt_helper.h"
#include "fwd_register.h"

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

/* These are typedefed in ldap_helper.h */
struct ldap_instance {
	isc_mem_t		*mctx;

	/* These are needed for zone creation. */
	char *			db_name;
	dns_dbimplementation_t	*db_imp;
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
	bool		exiting;
	/* Non-zero if this instance is 'tainted' by an unrecoverable problem. */
	isc_refcount_t		errors;

	/* Settings. */
	settings_set_t		*local_settings;
	settings_set_t		*global_settings;
	settings_set_t		empty_fwdz_settings;
	settings_set_t		*server_ldap_settings;

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

/* Supported authentication types. */
const ldap_auth_pair_t supported_ldap_auth[] = {
	{ AUTH_NONE,	"none"		},
	{ AUTH_SIMPLE,	"simple"	},
	{ AUTH_SASL,	"sasl"		},
	{ AUTH_INVALID, NULL		},
};

extern const settings_set_t settings_default_set;

/** Local configuration file */
static const setting_t settings_local_default[] = {
	{ "uri",			no_default_string	},
	{ "connections",		no_default_uint		},
	{ "reconnect_interval",		no_default_uint		},
	{ "timeout",			no_default_uint		},
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
	{ "ldap_hostname",		no_default_string	},
	{ "sync_ptr",			no_default_boolean	},
	{ "dyn_update",			no_default_boolean	},
	{ "verbose_checks",		no_default_boolean	},
	{ "directory",			no_default_string	},
	{ "nsec3param",			default_string("0 0 0 00")	}, /* NSEC only */
	/* Defaults for forwarding here must be overridden by values from
	 * from named.conf (i.e. copied to inst->local_settings)
	 * during start up to allow settings_set_isfilled() to pass.*/
	{ "forward_policy",		no_default_string	},
	{ "forwarders",			no_default_string	},
	{ "server_id",			no_default_string	},
	end_of_settings
};

/**
 * This is list of values configurable in dyndb section of named.conf.
 * Names and data types must match settings_local_default.
 * Settings which are not user-configurable must be omitted from this structure.
 */
static cfg_clausedef_t
dyndb_ldap_conf_clauses[] = {
	{ "auth_method",        &cfg_type_qstring,	0	},
	{ "base",               &cfg_type_qstring,	0	},
	{ "bind_dn",            &cfg_type_qstring,	0	},
	{ "connections",        &cfg_type_uint32,	0	},
	{ "directory",          &cfg_type_qstring,	0	},
	{ "dyn_update",         &cfg_type_boolean,	0	},
	{ "fake_mname",         &cfg_type_qstring,	0	},
	{ "krb5_keytab",        &cfg_type_qstring,	0	},
	{ "krb5_principal",     &cfg_type_qstring,	0	},
	{ "ldap_hostname",      &cfg_type_qstring,	0	},
	{ "password",           &cfg_type_sstring,	0	},
	{ "reconnect_interval", &cfg_type_uint32,	0	},
	{ "sasl_auth_name",     &cfg_type_qstring,	0	},
	{ "sasl_mech",          &cfg_type_qstring,	0	},
	{ "sasl_password",      &cfg_type_qstring,	0	},
	{ "sasl_realm",         &cfg_type_qstring,	0	},
	{ "sasl_user",          &cfg_type_qstring,	0	},
	{ "server_id",          &cfg_type_qstring,	0	},
	{ "sync_ptr",           &cfg_type_boolean,	0	},
	{ "timeout",            &cfg_type_uint32,	0	},
	{ "uri",                &cfg_type_qstring,	0	},
	{ "verbose_checks",     &cfg_type_boolean,	0	},
	{ NULL,			NULL,			0	}
};

static cfg_clausedef_t *
dyndb_ldap_clausulesets[] = {
	dyndb_ldap_conf_clauses,
	NULL
};

/** Entry point for configuration parser used on dyndb section of named.conf. */
static cfg_type_t cfg_type_dyndb_conf = {
	"dyndb_ldap_conf", cfg_parse_mapbody, cfg_print_mapbody,
	cfg_doc_mapbody, &cfg_rep_map, dyndb_ldap_clausulesets
};

/** Global settings from idnsConfig object. */
static setting_t settings_global_default[] = {
	{ "dyn_update",		no_default_boolean					},
	{ "sync_ptr",		no_default_boolean					},
	{ "forward_policy",	default_string("first")					},
	{ "forwarders",		default_string("{ /* uninitialized global config */ }")	},
	end_of_settings
};

/** Server-specific config from idnsServerConfig object. */
static setting_t settings_server_ldap_default[] = {
	{ "fake_mname",		no_default_string	},
	{ "forwarders",		no_default_string	},
	{ "forward_policy",	no_default_string	},
	{ "substitutionvariable_ipalocation",	no_default_string	},
	end_of_settings
};

static setting_t settings_fwdz_defaults[] = {
	{ "forward_policy",	no_default_string	},
	{ "forwarders",		no_default_string	},
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
		ldap_entry_t *entry, dns_ttl_t ttl, ldapdb_rdatalist_t *rdatalist,
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
		   const settings_set_t * const settings,
		   ldapdb_rdatalist_t *rdatalist) ATTR_NONNULLS ATTR_CHECKRESULT;

static isc_result_t ldap_connect(ldap_instance_t *ldap_inst,
		ldap_connection_t *ldap_conn, bool force) ATTR_NONNULLS ATTR_CHECKRESULT;
static isc_result_t ldap_reconnect(ldap_instance_t *ldap_inst,
		ldap_connection_t *ldap_conn, bool force) ATTR_NONNULLS ATTR_CHECKRESULT;
static isc_result_t handle_connection_error(ldap_instance_t *ldap_inst,
		ldap_connection_t *ldap_conn, bool force) ATTR_NONNULLS;

/* Functions for writing to LDAP. */
static isc_result_t ldap_rdttl_to_ldapmod(isc_mem_t *mctx,
		dns_rdatalist_t *rdlist, LDAPMod **changep) ATTR_NONNULLS ATTR_CHECKRESULT;
static isc_result_t ldap_rdatalist_to_ldapmod(isc_mem_t *mctx,
		dns_rdatalist_t *rdlist, LDAPMod **changep, int mod_op,
		bool unknown) ATTR_NONNULLS ATTR_CHECKRESULT;

static isc_result_t ldap_rdata_to_char_array(isc_mem_t *mctx,
					     dns_rdata_t *rdata_head,
					     bool unknown,
					     char ***valsp)
					     ATTR_NONNULLS ATTR_CHECKRESULT;

static void free_char_array(isc_mem_t *mctx, char ***valsp) ATTR_NONNULLS;
static isc_result_t modify_ldap_common(dns_name_t *owner, dns_name_t *zone, ldap_instance_t *ldap_inst,
		dns_rdatalist_t *rdlist, int mod_op, bool delete_node) ATTR_NONNULLS ATTR_CHECKRESULT;

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

	uint32_t uint;
	const char *sasl_mech = NULL;
	const char *sasl_user = NULL;
	const char *sasl_realm = NULL;
	const char *sasl_password = NULL;
	const char *krb5_principal = NULL;
	const char *bind_dn = NULL;
	const char *password = NULL;
	const char *dir_name = NULL;
	bool dir_default;
	ld_string_t *buff = NULL;
	char print_buff[PRINT_BUFF_SIZE];
	const char *auth_method_str = NULL;
	ldap_auth_t auth_method_enum = AUTH_INVALID;
	int s_len;

	if (strlen(inst->db_name) <= 0) {
		log_error("LDAP instance name cannot be empty");
		CLEANUP_WITH(ISC_R_UNEXPECTEDEND);
	}

	/* Use instance name as default working directory */
	CHECK(str_new(inst->mctx, &buff));
	CHECK(setting_get_str("directory", inst->local_settings, &dir_name));
	dir_default = (strlen(dir_name) == 0);
	if (dir_default == true) {
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
	/* isc_string_printf has been removed */
	s_len = snprintf(print_buff, PRINT_BUFF_SIZE, "%u", auth_method_enum);
	if (s_len < 0 || s_len >= PRINT_BUFF_SIZE) {
		CLEANUP_WITH(ISC_R_NOSPACE);
	}

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

	if (settings_set_isfilled(set) != true)
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
new_ldap_instance(isc_mem_t *mctx, const char *db_name, const char *parameters,
		  const char *file, unsigned long line,
		  const dns_dyndbctx_t *dctx, ldap_instance_t **ldap_instp)
{
	isc_result_t result;
	ldap_instance_t *ldap_inst;
	dns_forwarders_t *named_conf_forwarders = NULL;
	isc_buffer_t *forwarders_list = NULL;
	const char *forward_policy = NULL;
	uint32_t connections;
	char settings_name[PRINT_BUFF_SIZE];
	ldap_globalfwd_handleez_t *gfwdevent = NULL;
	const char *server_id = NULL;

	REQUIRE(ldap_instp != NULL && *ldap_instp == NULL);

	ldap_inst = isc_mem_get(mctx, sizeof(*(ldap_inst)));
	ZERO_PTR(ldap_inst);
	isc_refcount_init(&ldap_inst->errors, 0);
	isc_mem_attach(mctx, &ldap_inst->mctx);
	CHECKED_MEM_STRDUP(mctx, db_name, ldap_inst->db_name);
	dns_view_attach(dctx->view, &ldap_inst->view);
	dns_zonemgr_attach(dctx->zmgr, &ldap_inst->zmgr);
	isc_task_attach(dctx->task, &ldap_inst->task);

	ldap_inst->watcher = 0;
	CHECK(sync_ctx_init(ldap_inst->mctx, ldap_inst, &ldap_inst->sctx));

	/* truncation is allowed */
	snprintf(settings_name, PRINT_BUFF_SIZE,
		 SETTING_SET_NAME_LOCAL " for database %s",
		 ldap_inst->db_name);
	CHECK(settings_set_create(mctx, settings_local_default,
	      sizeof(settings_local_default), settings_name,
	      &settings_default_set, &ldap_inst->local_settings));

	/* truncation is allowed */
	snprintf(settings_name, PRINT_BUFF_SIZE,
		 SETTING_SET_NAME_GLOBAL " for database %s",
		 ldap_inst->db_name);
	CHECK(settings_set_create(mctx, settings_global_default,
	      sizeof(settings_global_default), settings_name,
	      ldap_inst->local_settings, &ldap_inst->global_settings));

	CHECK(setting_set_parse_conf(mctx, ldap_inst->db_name,
				     &cfg_type_dyndb_conf, parameters, file,
				     line, ldap_inst->local_settings));

	/* copy global forwarders setting for configuration roll back in
	 * configure_zone_forwarders() */
	result = dns_fwdtable_find(ldap_inst->view->fwdtable, dns_rootname,
				   NULL, &named_conf_forwarders);
	if (result == ISC_R_SUCCESS) {
		/* Copy forwarding config from named.conf into local_settings */
		CHECK(fwd_print_list_buff(mctx, named_conf_forwarders,
						  &forwarders_list));
		CHECK(setting_set("forwarders", ldap_inst->local_settings,
				  isc_buffer_base(forwarders_list)));
		CHECK(get_enum_description(forwarder_policy_txts,
					   named_conf_forwarders->fwdpolicy,
					   &forward_policy));
		CHECK(setting_set("forward_policy", ldap_inst->local_settings,
				  forward_policy));

		/* Make sure we disable conflicting automatic empty zones.
		 * This will be done in event to prevent the plugin from
		 * interfering with BIND start-up.
		 *
		 * Warn-only semantics is implemented in BIND RT#41441,
		 * this code can be removed when we rebase to BIND 9.11. */
		CHECK(sync_task_add(ldap_inst->sctx, ldap_inst->task));
		gfwdevent = (ldap_globalfwd_handleez_t *)isc_event_allocate(
					ldap_inst->mctx, ldap_inst,
					LDAPDB_EVENT_GLOBALFWD_HANDLEEZ,
					empty_zone_handle_globalfwd_ev,
					ldap_inst->view->zonetable,
					sizeof(ldap_globalfwd_handleez_t));
		if (gfwdevent == NULL)
			CLEANUP_WITH(ISC_R_NOMEMORY);
		/* policy == first does not override automatic empty zones */
		gfwdevent->warn_only = (named_conf_forwarders->fwdpolicy
					== dns_fwdpolicy_first);

		isc_task_send(ldap_inst->task, (isc_event_t **)&gfwdevent);

	} else if (result == ISC_R_NOTFOUND) {
		/* global forwarders are not configured */
		CHECK(setting_set("forwarders", ldap_inst->local_settings,
				  "{ /* empty list of forwarders */ }"));
		CHECK(setting_set("forward_policy", ldap_inst->local_settings,
				  "first"));
	} else {
		goto cleanup;
	}

	CHECK(validate_local_instance_settings(ldap_inst,
					       ldap_inst->local_settings));
	if (settings_set_isfilled(ldap_inst->global_settings) != true)
		CLEANUP_WITH(ISC_R_FAILURE);

	/* zero-length server_id means undefined value */
	CHECK(setting_get_str("server_id", ldap_inst->local_settings,
			      &server_id));
	if (strlen(server_id) == 0) {
		/* truncation is allowed */
		snprintf(settings_name, PRINT_BUFF_SIZE,
			 SETTING_SET_NAME_SERVER " for undefined server_id");
	} else {
		/* truncation is allowed */
		snprintf(settings_name, PRINT_BUFF_SIZE,
			 SETTING_SET_NAME_SERVER
			 " for server id %s", server_id);
	}

	CHECK(settings_set_create(mctx, settings_server_ldap_default,
	      sizeof(settings_server_ldap_default), settings_name,
	      ldap_inst->global_settings, &ldap_inst->server_ldap_settings));

	ldap_inst->empty_fwdz_settings = (settings_set_t) {
			NULL,
			"dummy LDAP zone forwarding settings",
			ldap_inst->server_ldap_settings,
			NULL,
			(setting_t *) &settings_fwdz_defaults[0]
	};

	CHECK(setting_get_uint("connections", ldap_inst->local_settings, &connections));

	CHECK(zr_create(mctx, ldap_inst, ldap_inst->server_ldap_settings,
			&ldap_inst->zone_register));
	CHECK(fwdr_create(ldap_inst->mctx, &ldap_inst->fwd_register));
	CHECK(mldap_new(mctx, &ldap_inst->mldapdb));

	/* isc_mutex_init and isc_condition_init failures are now fatal */
	isc_mutex_init(&ldap_inst->kinit_lock);

	CHECK(ldap_pool_create(mctx, connections, &ldap_inst->pool));
	CHECK(ldap_pool_connect(ldap_inst->pool, ldap_inst));

	/* Register new DNS DB implementation. */
	CHECK(dns_db_register(ldap_inst->db_name, &ldapdb_associate, ldap_inst,
			      mctx, &ldap_inst->db_imp));

	/* Start the watcher thread */
	/* isc_thread_create assert internally on failure */
	isc_thread_create(ldap_syncrepl_watcher, ldap_inst,
			  &ldap_inst->watcher);
	/*
	 * if (result != ISC_R_SUCCESS) {
	 *	ldap_inst->watcher = 0;
	 *	log_error("Failed to create syncrepl watcher thread");
	 *	goto cleanup;
	 * }
	 */

cleanup:
	if (forwarders_list != NULL)
		isc_buffer_free(&forwarders_list);
	if (result != ISC_R_SUCCESS)
		destroy_ldap_instance(&ldap_inst);
	else
		*ldap_instp = ldap_inst;

	return result;
}
#undef PRINT_BUFF_SIZE

/**
 * Send SIGUSR1 to the SyncRepl watcher thread and wait for it to terminate.
 *
 * If the thread has already been terminated and a signal can't be sent to it,
 * log an error instead. The thread is still joined, but since it is no longer
 * running, it is instantaneous and doesn't block.
 *
 * @param[in]  ldap_inst	LDAP instance with ID of watcher thread
 */
static void ATTR_NONNULLS
ldap_syncrepl_watcher_shutdown(ldap_instance_t *ldap_inst)
{
	REQUIRE(ldap_inst != NULL);

	ldap_inst->exiting = true;
	/*
	 * Wake up the watcher thread. This might look like a hack
	 * but isc_thread_t is actually pthread_t and libisc don't
	 * have any isc_thread_kill() func.
	 *
	 * We use SIGUSR1 to not to interfere with any signal
	 * used by BIND itself.
	 */
	if (pthread_kill(ldap_inst->watcher, SIGUSR1) != 0) {
		log_error("unable to send signal to SyncRepl watcher thread "
				  "(already terminated?)");
	}

	/* isc_thread_join assert internally on failure */
	isc_thread_join(ldap_inst->watcher, NULL);
}

void
destroy_ldap_instance(ldap_instance_t **ldap_instp)
{
	ldap_instance_t *ldap_inst;

	REQUIRE(ldap_instp != NULL);

	ldap_inst = *ldap_instp;
	if (ldap_inst == NULL)
		return;

	if (ldap_inst->watcher != 0) {
		ldap_syncrepl_watcher_shutdown(ldap_inst);
		ldap_inst->watcher = 0;
	}

	/* Unregister all zones already registered in BIND. */
	zr_destroy(&ldap_inst->zone_register);
	fwdr_destroy(&ldap_inst->fwd_register);
	mldap_destroy(&ldap_inst->mldapdb);

	ldap_pool_destroy(&ldap_inst->pool);
	if (ldap_inst->db_imp != NULL)
		dns_db_unregister(&ldap_inst->db_imp);
	if (ldap_inst->view != NULL)
		dns_view_detach(&ldap_inst->view);
	if (ldap_inst->zmgr != NULL)
		dns_zonemgr_detach(&ldap_inst->zmgr);
	if (ldap_inst->task != NULL)
		isc_task_detach(&ldap_inst->task);

	/* isc_mutex_init and isc_condition_init failures are now fatal */
	isc_mutex_destroy(&ldap_inst->kinit_lock);

	settings_set_free(&ldap_inst->global_settings);
	settings_set_free(&ldap_inst->local_settings);
	settings_set_free(&ldap_inst->server_ldap_settings);

	sync_ctx_free(&ldap_inst->sctx);
	/* zero out error counter (and do nothing other than that) */
	ldap_instance_untaint_finish(ldap_inst,
				     ldap_instance_untaint_start(ldap_inst));
	isc_refcount_destroy(&ldap_inst->errors);

	if (ldap_inst->db_name != NULL) {
		log_debug(1, "LDAP instance '%s' destroyed", ldap_inst->db_name);
		isc_mem_free(ldap_inst->mctx, ldap_inst->db_name);
	}
	MEM_PUT_AND_DETACH(ldap_inst);

	*ldap_instp = NULL;
}

static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
new_ldap_connection(ldap_pool_t *pool, ldap_connection_t **ldap_connp)
{
	ldap_connection_t *ldap_conn;

	REQUIRE(pool != NULL);
	REQUIRE(ldap_connp != NULL && *ldap_connp == NULL);

	ldap_conn = isc_mem_get(pool->mctx, sizeof(*(ldap_conn)));
	ZERO_PTR(ldap_conn);

	/* isc_mutex_init and isc_condition_init failures are now fatal */
	isc_mutex_init(&ldap_conn->lock);
	/*
	 * if (result != ISC_R_SUCCESS) {
	 *	SAFE_MEM_PUT_PTR(pool->mctx, ldap_conn);
	 *	return result;
	 * }
	 */

	isc_mem_attach(pool->mctx, &ldap_conn->mctx);

	*ldap_connp = ldap_conn;

	return ISC_R_SUCCESS;
}

static void
destroy_ldap_connection(ldap_connection_t **ldap_connp)
{
	ldap_connection_t *ldap_conn;

	REQUIRE(ldap_connp != NULL);

	ldap_conn = *ldap_connp;
	if (ldap_conn == NULL)
		return;

	 /* isc_mutex_init and isc_condition_init failures are now fatal */
	isc_mutex_destroy(&ldap_conn->lock);
	if (ldap_conn->handle != NULL)
		ldap_unbind_ext_s(ldap_conn->handle, NULL, NULL);

	MEM_PUT_AND_DETACH(*ldap_connp);
}

static isc_result_t ATTR_NONNULLS
cleanup_zone_files(dns_zone_t *zone) {
	isc_result_t result;
	bool failure = false;
	const char *filename = NULL;
	dns_zone_t *raw = NULL;
	int namelen;
	int s_len;
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
	s_len = snprintf(bck_filename, sizeof(bck_filename),
			 "%.*s.jbk", namelen, filename);
	if (s_len < 0 || (unsigned)s_len >= sizeof(bck_filename)) {
		CLEANUP_WITH(ISC_R_NOSPACE);
	}
	CHECK(fs_file_remove(bck_filename));

cleanup:
	failure = failure || (result != ISC_R_SUCCESS);
	if (failure == true)
		dns_zone_log(zone, ISC_LOG_ERROR,
			     "unable to remove files, expect problems");

	if (failure == true && result == ISC_R_SUCCESS)
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

	if (zone_isempty(zone) == true) {
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
		bool issecure) {
	isc_result_t result;
	ld_string_t *file_name = NULL;
	ld_string_t *key_dir = NULL;

	CHECK(zr_get_zone_path(mctx, ldap_instance_getsettings_local(inst),
			       dns_zone_getorigin(zone),
			       (issecure ? "signed" : "raw"), &file_name));
	CHECK(dns_zone_setfile(zone, str_buf(file_name), dns_masterformat_text,
			       &dns_master_style_default));
	if (issecure == true) {
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
	    const bool want_secure, dns_zone_t ** const rawp,
	    dns_zone_t ** const securep)
{
	isc_result_t result;
	dns_zone_t *raw = NULL;
	dns_zone_t *secure = NULL;
	const char *ldap_argv[1] = { inst->db_name };
	const char *rbt_argv[1] = { "rbt" };
	sync_state_t sync_state;
	isc_task_t *task = NULL;
	char zone_name[DNS_NAME_FORMATSIZE];

	REQUIRE(inst != NULL);
	REQUIRE(name != NULL);
	REQUIRE(rawp != NULL && *rawp == NULL);

	result = zone_unload_ifempty(inst->view, name);
	if (result != ISC_R_SUCCESS && result != ISC_R_NOTFOUND)
		goto cleanup;

	CHECK(dns_zone_create(&raw, inst->mctx));
	CHECK(dns_zone_setorigin(raw, name));
	dns_zone_setclass(raw, dns_rdataclass_in);
	dns_zone_settype(raw, dns_zone_master);
	/* dns_zone_setview(raw, view); */
	/* dns_zone_setdbtype is now void as it could no longer return */
	dns_zone_setdbtype(raw, sizeof(ldap_argv)/sizeof(ldap_argv[0]),
			   ldap_argv);
	CHECK(configure_paths(inst->mctx, inst, raw, false));

	if (want_secure == false) {
		CHECK(dns_zonemgr_managezone(inst->zmgr, raw));
		CHECK(cleanup_zone_files(raw));
	} else {
		CHECK(dns_zone_create(&secure, inst->mctx));
		CHECK(dns_zone_setorigin(secure, name));
		dns_zone_setclass(secure, dns_rdataclass_in);
		dns_zone_settype(secure, dns_zone_master);
		/* dns_zone_setview(secure, view); */
		/* dns_zone_setdbtype is now void as it could no longer
		 * return */
		dns_zone_setdbtype(secure, 1, rbt_argv);
		CHECK(dns_zonemgr_managezone(inst->zmgr, secure));
		CHECK(dns_zone_link(secure, raw));
		dns_zone_rekey(secure, true);
		CHECK(configure_paths(inst->mctx, inst, secure, true));
		CHECK(cleanup_zone_files(secure));
	}

	sync_state_get(inst->sctx, &sync_state);
	if (sync_state == sync_datainit) {
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
load_zone(dns_zone_t *zone, bool log) {
	isc_result_t result;
	bool zone_dynamic;
	uint32_t serial;
	dns_zone_t *raw = NULL;

	result = dns_zone_load(zone, false);
	if (result != ISC_R_SUCCESS && result != DNS_R_UPTODATE
	    && result != DNS_R_DYNAMIC && result != DNS_R_CONTINUE)
		goto cleanup;
	zone_dynamic = (result == DNS_R_DYNAMIC);

	dns_zone_getraw(zone, &raw);
	if (raw == NULL) {
		dns_zone_attach(zone, &raw);
		zone = NULL;
	}

	CHECK(dns_zone_getserial(raw, &serial));
	if (log == true)
		dns_zone_log(raw, ISC_LOG_INFO, "loaded serial %u", serial);
	if (zone != NULL) {
		result = dns_zone_getserial(zone, &serial);
		if (result == ISC_R_SUCCESS && log == true)
			dns_zone_log(zone, ISC_LOG_INFO, "loaded serial %u",
				     serial);
		/* in-line secure zone is loaded asynchonously in background */
		else if (result == DNS_R_NOTLOADED) {
			if (log == true)
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
	bool freeze = false;
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
		freeze = true;
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

	CHECK(load_zone(toview, true));
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
	bool active;

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
		if (active == true) {
			++active_cnt;
			result = activate_zone(task, inst, &name);
			if (result == ISC_R_SUCCESS)
				++published_cnt;
			result = fwd_configure_zone(settings, inst, &name);
			if (result != ISC_R_SUCCESS)
				log_error_r("could not configure forwarding");

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

/* Delete zone by dns zone name */
isc_result_t
ldap_delete_zone2(ldap_instance_t *inst, dns_name_t *name, bool lock)
{
	isc_result_t result;
	isc_result_t isforward = ISC_R_NOTFOUND;
	isc_result_t lock_state = ISC_R_IGNORE;
	bool freeze = false;
	dns_zone_t *raw = NULL;
	dns_zone_t *secure = NULL;
	dns_zone_t *foundzone = NULL;
	char zone_name_char[DNS_NAME_FORMATSIZE];

	dns_name_format(name, zone_name_char, DNS_NAME_FORMATSIZE);
	log_debug(1, "deleting zone '%s'", zone_name_char);
	if (lock)
		run_exclusive_enter(inst, &lock_state);

	/* simulate no explicit forwarding configuration */
	CHECK(fwd_configure_zone(&inst->empty_fwdz_settings, inst, name));
	isforward = fwdr_zone_ispresent(inst->fwd_register, name);
	if (isforward == ISC_R_SUCCESS)
		CHECK(fwdr_del_zone(inst->fwd_register, name));

	result = zr_get_zone_ptr(inst->zone_register, name, &raw, &secure);
	if (result == ISC_R_NOTFOUND || result == DNS_R_PARTIALMATCH) {
		if (isforward == ISC_R_SUCCESS)
			log_info("forward zone '%s': shutting down", zone_name_char);
		log_debug(1, "zone '%s' not found in zone register", zone_name_char);
		CLEANUP_WITH(ISC_R_SUCCESS);
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
			freeze = true;
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
unpublish_zone(ldap_instance_t *inst, dns_name_t *name, const char *logname) {
	isc_result_t result;
	isc_result_t lock_state = ISC_R_IGNORE;
	dns_zone_t *raw = NULL;
	dns_zone_t *secure = NULL;
	dns_zone_t *zone_in_view = NULL;
	bool freeze = false;

	CHECK(zr_get_zone_ptr(inst->zone_register, name, &raw, &secure));

	run_exclusive_enter(inst, &lock_state);
	if (inst->view->frozen) {
		freeze = true;
		dns_view_thaw(inst->view);
	}
	CHECK(dns_view_findzone(inst->view, name, &zone_in_view));
	INSIST(zone_in_view == raw || zone_in_view == secure);
	/* simulate no explicit forwarding configuration */
	CHECK(fwd_configure_zone(&inst->empty_fwdz_settings, inst, name));
	CHECK(dns_zt_unmount(inst->view->zonetable, zone_in_view));

cleanup:
	if (freeze)
		dns_view_freeze(inst->view);
	run_exclusive_exit(inst, lock_state);
	if (result != ISC_R_SUCCESS)
		log_error_r("%s un-publication failed", logname);
	if (raw != NULL)
		dns_zone_detach(&raw);
	if (secure != NULL)
		dns_zone_detach(&secure);
	if (zone_in_view != NULL)
		dns_zone_detach(&zone_in_view);

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

	result = fwd_parse_ldap(entry, inst->global_settings);
	if (result == ISC_R_SUCCESS) {
		CHECK(fwd_reconfig_global(inst));
	} else if (result != ISC_R_IGNORE)
		goto cleanup;

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

/* Parse the idnsServerConfig object entry */
static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
ldap_parse_serverconfigentry(ldap_entry_t *entry, ldap_instance_t *inst)
{
	isc_result_t result;

	/* BIND functions are thread safe, ldap instance 'inst' is locked
	 * inside setting* functions. */

	log_debug(3, "Parsing server configuration object");

	result = fwd_parse_ldap(entry, inst->server_ldap_settings);
	if (result == ISC_R_SUCCESS) {
		CHECK(fwd_reconfig_global(inst));
	} else if (result != ISC_R_IGNORE)
		goto cleanup;

	result = setting_update_from_ldap_entry("fake_mname",
						inst->server_ldap_settings,
						"idnsSOAmName",
						entry);
	if (result != ISC_R_SUCCESS && result != ISC_R_IGNORE)
		goto cleanup;

	result = setting_update_from_ldap_entry("substitutionvariable_ipalocation",
						inst->server_ldap_settings,
						"idnsSubstitutionVariable;ipalocation",
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
	ldap_valuelist_t values;
	char name_txt[DNS_NAME_FORMATSIZE];
	isc_result_t result;

	settings_set_t *fwdz_settings = NULL;

	REQUIRE(entry != NULL);
	REQUIRE(inst != NULL);

	/* Zone is active */
	CHECK(ldap_entry_getvalues(entry, "idnsZoneActive", &values));
	if (HEAD(values) != NULL &&
	    strcasecmp(HEAD(values)->value, "TRUE") != 0) {
		/* Zone is not active */
		result = ldap_delete_zone2(inst, &entry->fqdn, true);
		goto cleanup;
	}

	CHECK(settings_set_create(inst->mctx, settings_fwdz_defaults, sizeof(settings_fwdz_defaults),
				  "fake fwdz settings", inst->server_ldap_settings,
				  &fwdz_settings));
	result = fwd_parse_ldap(entry, fwdz_settings);
	if (result == ISC_R_IGNORE) {
		log_error_r("%s: invalid object: either "
			    "forwarding policy or forwarders must be set",
			    ldap_entry_logname(entry));
		goto cleanup;
	}
	CHECK(fwd_configure_zone(fwdz_settings, inst, &entry->fqdn));

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
	settings_set_free(&fwdz_settings);
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
 * @param[out]	data_changed	true if any data other than SOA serial were
 * 				changed. false if nothing (except SOA
 * 				serial) was changed.
 *
 */
static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
diff_analyze_serial(dns_diff_t *diff, dns_difftuple_t **soa_latest,
		    bool *data_changed) {
	dns_difftuple_t *t = NULL;
	dns_rdata_t *del_soa = NULL; /* last seen SOA with op == DEL */
	dns_difftuple_t *tmp_tuple = NULL; /* tuple used for SOA comparison */
	isc_result_t result = ISC_R_SUCCESS;
	int ret;

	REQUIRE(DNS_DIFF_VALID(diff));
	REQUIRE(soa_latest != NULL && *soa_latest == NULL);
	REQUIRE(data_changed != NULL);

	*data_changed = false;
	for (t = HEAD(diff->tuples);
	     t != NULL;
	     t = NEXT(t, link)) {
		INSIST(tmp_tuple == NULL);
		if (t->rdata.type != dns_rdatatype_soa)
			*data_changed = true;
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
					*data_changed = true;
				} else if (*data_changed == false) {
					/* detect if fields other than serial
					 * were changed (compute only if necessary) */
					CHECK(dns_difftuple_copy(t, &tmp_tuple));
					dns_soa_setserial(dns_soa_getserial(del_soa),
							  &tmp_tuple->rdata);
					ret = dns_rdata_compare(del_soa,
								&tmp_tuple->rdata);
					*data_changed = ret != 0;
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
		    uint32_t serial) {
	isc_result_t result;
#define MAX_SERIAL_LENGTH sizeof("4294967295") /* SOA serial is uint32_t */
	char serial_char[MAX_SERIAL_LENGTH];
	char *values[2] = { serial_char, NULL };
	LDAPMod change;
	LDAPMod *changep[2] = { &change, NULL };
	ld_string_t *dn = NULL;
	int s_len;

	REQUIRE(inst != NULL);

	CHECK(str_new(inst->mctx, &dn));
	CHECK(dnsname_to_dn(inst->zone_register, zone, zone, dn));

	change.mod_op = LDAP_MOD_REPLACE;
	change.mod_type = "idnsSOAserial";
	change.mod_values = values;
	s_len = snprintf(serial_char, MAX_SERIAL_LENGTH, "%u", serial);
	if (s_len < 0 || (unsigned)s_len >= MAX_SERIAL_LENGTH) {
		CLEANUP_WITH(ISC_R_NOSPACE);
	}

	CHECK(ldap_modify_do(inst, str_buf(dn), changep, false));

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
				     true));

cleanup:
	if (nsec3p_rdata != NULL) {
		isc_mem_put(mctx, nsec3p_rdata->data, nsec3p_rdata->length);
		SAFE_MEM_PUT_PTR(mctx, nsec3p_rdata);
	}
	if (fake_entry != NULL)
		ldap_entry_destroy(&fake_entry);
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
	bool ssu_changed;
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

	result = setting_update_from_ldap_entry("default_ttl", zone_settings,
					        "DNSdefaultTTL", entry);
	if (result == ISC_R_SUCCESS)
		log_bug("default TTL cannot be changed at run-time");
	else if (result != ISC_R_IGNORE)
		goto cleanup;

	result = setting_update_from_ldap_entry("update_policy", zone_settings,
						"idnsUpdatePolicy", entry);
	if (result != ISC_R_SUCCESS && result != ISC_R_IGNORE)
		goto cleanup;

	if (result == ISC_R_SUCCESS || ssu_changed) {
		bool ssu_enabled;
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
		dns_zone_setoption(secure, DNS_ZONEOPT_UPDATECHECKKSK, true);

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
		dns_zone_setkeyopt(secure, DNS_ZONEKEY_ALLOW, true);
		dns_zone_setkeyopt(secure, DNS_ZONEKEY_MAINTAIN, true);
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
 *                            valid if ldap_writeback = true.
 * @param[out] ldap_writeback SOA serial was updated.
 * @param[out] data_changed   Other data were updated.
 *
 */
static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
zone_sync_apex(const ldap_instance_t * const inst,
	       ldap_entry_t * const entry, dns_name_t name,
	       const sync_state_t sync_state, const bool new_zone,
	       dns_db_t * const ldapdb, dns_db_t * const rbtdb,
	       dns_dbversion_t * const version,
	       const settings_set_t * const zone_settings,
	       dns_diff_t * const diff,
	       uint32_t * const new_serial,
	       bool * const ldap_writeback,
	       bool * const data_changed) {
	isc_result_t result;
	ldapdb_rdatalist_t rdatalist;
	dns_rdatasetiter_t *rbt_rds_iterator = NULL;
	/* RBTDB's origin node cannot be detached until the node is non-empty.
	 * This is workaround for ISC-Bug #35080. */
	dns_dbnode_t *node = NULL;
	dns_difftuple_t *soa_tuple = NULL;
	uint32_t curr_serial;

	REQUIRE(ldap_writeback != NULL);

	INIT_LIST(rdatalist);
	*ldap_writeback = false; /* GCC */

	CHECK(ldap_parse_rrentry(inst->mctx, entry, &name,
				 zone_settings, &rdatalist));

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
	if (new_zone != true)
		CHECK(dns_db_getsoaserial(rbtdb, version, &curr_serial));

	/* Detect if SOA serial is affected by the update or not.
	 * Always bump serial in case of re-synchronization. */
	CHECK(diff_analyze_serial(diff, &soa_tuple, data_changed));
	if (new_zone == true || *data_changed == true ||
	    sync_state != sync_finished) {
		if (soa_tuple == NULL) {
			/* The diff doesn't contain new SOA serial
			 * => generate new serial and write it back to LDAP. */
			*ldap_writeback = true;
			CHECK(zone_soaserial_addtuple(inst->mctx, ldapdb,
						      version, diff, new_serial));
		} else if (new_zone == true || sync_state != sync_finished ||
			   isc_serial_le(dns_soa_getserial(&soa_tuple->rdata),
					 curr_serial)) {
			/* The diff tries to send SOA serial back!
			 * => generate new serial and write it back to LDAP.
			 * Force serial update if we are adding a new zone. */
			*ldap_writeback = true;
			CHECK(zone_soaserial_updatetuple(dns_updatemethod_unixtime,
							 soa_tuple, new_serial));
		} else {
			/* The diff contains new serial already
			 * => do nothing. */
			*ldap_writeback = false;
		}

	} else {/* if (data_changed == false) */
		*ldap_writeback = false;
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
	CHECK(ldap_delete_zone2(inst, name, false));
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
	ldap_valuelist_t values;
	dns_zone_t *raw = NULL;
	dns_zone_t *secure = NULL;
	dns_zone_t *toview = NULL;
	isc_result_t result;
	isc_result_t lock_state = ISC_R_IGNORE;
	bool new_zone = false;
	bool want_secure = false;
	bool configured = false;
	bool activity_changed;
	bool isactive = false;
	settings_set_t *zone_settings = NULL;
	bool ldap_writeback;
	bool data_changed = false; /* GCC */
	uint32_t new_serial;

	dns_db_t *rbtdb = NULL;
	dns_db_t *ldapdb = NULL;
	dns_diff_t diff;
	dns_dbversion_t *version = NULL;
	sync_state_t sync_state;

	REQUIRE(entry != NULL);
	REQUIRE(inst != NULL);
	REQUIRE(task == inst->task); /* For task-exclusive mode */

	dns_diff_init(inst->mctx, &diff);

	run_exclusive_enter(inst, &lock_state);

	result = ldap_entry_getvalues(entry, "idnsSecInlineSigning", &values);
	if (result == ISC_R_NOTFOUND || HEAD(values) == NULL)
		want_secure = false;
	else
		want_secure = (strcasecmp(HEAD(values)->value, "TRUE") == 0);

	/* Check if we are already serving given zone */
	result = zr_get_zone_ptr(inst->zone_register, &entry->fqdn,
				 &raw, &secure);
	if (result == ISC_R_NOTFOUND || result == DNS_R_PARTIALMATCH) {
		CHECK(create_zone(inst, entry->dn, &entry->fqdn, olddb,
				  want_secure, &raw, &secure));
		new_zone = true;
		log_debug(2, "created %s: raw %p; secure %p",
			  ldap_entry_logname(entry), raw, secure);
	} else if (result != ISC_R_SUCCESS)
		goto cleanup;
	else if (want_secure != (secure != NULL)) {
		if (want_secure == true)
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
	result = fwd_parse_ldap(entry, zone_settings);
	if (result != ISC_R_SUCCESS && result != ISC_R_IGNORE)
		goto cleanup;
	/* synchronize zone origin with LDAP */
	CHECK(zr_get_zone_dbs(inst->zone_register, &entry->fqdn, &ldapdb, &rbtdb));
	CHECK(dns_db_newversion(ldapdb, &version));
	sync_state_get(inst->sctx, &sync_state);
	CHECK(zone_sync_apex(inst, entry, entry->fqdn, sync_state, new_zone,
			     ldapdb, rbtdb, version, zone_settings,
			     &diff, &new_serial, &ldap_writeback,
			     &data_changed));

#if RBTDB_DEBUG >= 2
	dns_diff_print(&diff, stdout);
#else
	dns_diff_print(&diff, NULL);
#endif
	if (ldap_writeback == true) {
		dns_zone_log(raw, ISC_LOG_DEBUG(5), "writing new zone serial "
			     "%u to LDAP", new_serial);
		result = ldap_replace_serial(inst, &entry->fqdn, new_serial);
		if (result != ISC_R_SUCCESS)
			dns_zone_log(raw, ISC_LOG_ERROR,
				     "serial (%u) write back to LDAP failed",
				     new_serial);
	}

	if (!EMPTY(diff.tuples)) {
		if (sync_state == sync_finished && new_zone == false) {
			/* write the transaction to journal */
			CHECK(zone_journal_adddiff(inst->mctx, raw, &diff));
		}

		/* commit */
		CHECK(dns_diff_apply(&diff, rbtdb, version));
		dns_db_closeversion(ldapdb, &version, true);
		dns_zone_markdirty(raw);
	} else {
		/* It is necessary to release lock before calling load_zone()
		 * otherwise it will deadlock on newversion() call
		 * in journal roll-forward process! */
		dns_db_closeversion(ldapdb, &version, false);
	}
	configured = true;

	/* Detect active/inactive zone and activity changes */
	result = setting_update_from_ldap_entry("active", zone_settings,
						"idnsZoneActive", entry);
	if (result == ISC_R_SUCCESS) {
		activity_changed = true;
	} else if (result == ISC_R_IGNORE) {
		activity_changed = false;
	} else
		goto cleanup;
	CHECK(setting_get_bool("active", zone_settings, &isactive));

	/* Do zone load only if the initial LDAP synchronization is done. */
	if (sync_state != sync_finished)
		goto cleanup;

	toview = (want_secure == true) ? secure : raw;
	if (isactive == true) {
		if (new_zone == true || activity_changed == true)
			CHECK(publish_zone(task, inst, toview));
		CHECK(load_zone(toview, false));
		CHECK(fwd_configure_zone(zone_settings, inst, &entry->fqdn));
	} else if (activity_changed == true) { /* Zone was deactivated */
		CHECK(unpublish_zone(inst, &entry->fqdn,
				     ldap_entry_logname(entry)));
		/* emulate "no explicit forwarding config" */
		CHECK(fwd_configure_zone(&inst->empty_fwdz_settings, inst,
					 &entry->fqdn));
		dns_zone_log(toview, ISC_LOG_INFO, "zone deactivated "
			     "and removed from view");
	}

cleanup:
	dns_diff_clear(&diff);
	if (rbtdb != NULL && version != NULL)
		dns_db_closeversion(ldapdb, &version, false); /* rollback */
	if (rbtdb != NULL)
		dns_db_detach(&rbtdb);
	if (ldapdb != NULL)
		dns_db_detach(&ldapdb);
	if (new_zone == true && configured == false) {
		/* Failure in ACL parsing or so. */
		log_error_r("%s: publishing failed, rolling back due to",
			    ldap_entry_logname(entry));
		/* TODO: verify this */
		result = ldap_delete_zone2(inst, &entry->fqdn, true);
		if (result != ISC_R_SUCCESS)
			log_error_r("%s: rollback failed: ",
				    ldap_entry_logname(entry));
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
		rdlist = isc_mem_get(mctx, sizeof(*(rdlist)));

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
 * Replace occurrences of \{variable_name\} with respective strings from
 * settings tree. Remaining parts of the original string are just copied
 * into the output.
 *
 * Double-escaped strings \\{ \\} do not trigger substitution.
 * Nested references will expand only innermost variable: \{\{var1\}\}
 * Non-matching parentheses and other garbage will be copied verbatim
 * without trigerring an error.
 *
 * @retval  ISC_R_SUCCESS  Output string is valid. Caller must deallocate output.
 * @retval  ISC_R_IGNORE   Some variables used in the template are not defined
 *                         in settings tree. Substitution was terminated
 *                         prematurely and output is not available.
 * @retval  others         Unexpected errors.
 */
static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
ldap_substitute_rr_template(isc_mem_t *mctx, const settings_set_t * set,
			    ld_string_t *orig_val, ld_string_t **output) {
	isc_result_t result;
	regex_t regex;
	regmatch_t matches[3];
	size_t processed = 0;
	char *tmp = NULL;
	const char *setting_name;
	setting_t *setting;
	ld_string_t *replaced = NULL;

	/* match \{variable_name\} in the text
	 * \{ and \} must not be double-escaped like \\{ or \\} */
	if (regcomp(&regex,
		    "\\(^\\|[^\\]\\)" /* character preceding \{ = matches[1] */
		    "\\\\{"
		    "\\([a-zA-Z0-9_-]\\+\\)" /* variable name = matches[2] */
		    "\\\\}",
		    0) != 0)
		CLEANUP_WITH(ISC_R_UNEXPECTED);

	CHECK(str_new(mctx, &replaced));
	CHECKED_MEM_STRDUP(mctx, str_buf(orig_val), tmp);

	while (regexec(&regex, tmp + processed,
		       sizeof(matches)/sizeof(regmatch_t),
		       matches, 0) == 0)
	{
		/* derelativize offsets to make sure they
		 * always start from tmp instead of tmp + processed */
		for (size_t i = 0; i < sizeof(matches)/sizeof(regmatch_t); i++) {
			matches[i].rm_so += processed;
			matches[i].rm_eo += processed;
		}
		/* copy verbatim part of the string which precedes the \{ */
		CHECK(str_cat_char_len(replaced,
				       tmp + processed,
				       matches[1].rm_eo - processed));

		/* find value for given variable name in settings tree */
		setting_name = tmp + matches[2].rm_so;
		tmp[matches[2].rm_eo] = '\0';
		setting = NULL;
		result = setting_find(setting_name, set, true,
				      true, &setting);
		if (result != ISC_R_SUCCESS) {
			log_debug(5, "setting '%s' is not defined so it "
				  "cannot be substituted into template '%s'",
				  setting_name, str_buf(orig_val));
			CLEANUP_WITH(ISC_R_IGNORE);
		}
		if (setting->type != ST_STRING) {
			log_bug("setting '%s' it not string so it cannot be "
				"substituted", setting_name);
			CLEANUP_WITH(ISC_R_NOTIMPLEMENTED);
		}
		CHECK(str_cat_char(replaced, setting->value.value_char));

		/* end offset of previous match = matches[0].rm_eo */
		processed = matches[0].rm_eo;
	};

	/* copy remaining part of the string */
	CHECK(str_cat_char(replaced, tmp + processed));

	*output = replaced;
	replaced = NULL;
	result = ISC_R_SUCCESS;

cleanup:
	if (tmp != NULL)
		isc_mem_free(mctx, tmp);

	str_destroy(&replaced);
	return result;
}

/**
 * Substitute strings into idnsTemplateAttributes
 * and parse results into list of rdatas.
 *
 * idnsTemplateAttribute must have exactly one sub-type like "TXTRecord"
 * (e.g. "idnsTemplateAttribute;TXTRecord"). The sub-type specifies target type.
 *
 * @warning Substitution currently works only for *Record attributes
 *          and cannot be used for anything else.
 *
 * @retval  ISC_R_SUCCESS  A template exists in the entry and values
 *                         were successfully substituted into it.
 *                         Rdatalist contains new rdata.
 * @retval  ISC_R_IGNORE   No template was found or variables
 *                         do not have defined values. Ignore output.
 */
static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
ldap_parse_rrentry_template(isc_mem_t *mctx, ldap_entry_t *entry,
			    dns_name_t *origin,
			    const settings_set_t * const settings,
			    ldapdb_rdatalist_t *rdatalist)
{
	isc_result_t result;
	ldap_attribute_t *attr;
	ld_string_t *orig_val = NULL;
	ld_string_t *new_val = NULL;
	dns_rdata_t *rdata = NULL;
	dns_rdataclass_t rdclass;
	dns_ttl_t ttl;
	dns_rdatatype_t rdtype;
	dns_rdatalist_t *rdlist = NULL;
	bool did_something = false;

	CHECK(str_new(mctx, &orig_val));
	rdclass = ldap_entry_getrdclass(entry);
	ttl = ldap_entry_getttl(entry, settings);

	while ((attr = ldap_entry_nextattr(entry)) != NULL) {
		if (strncasecmp(LDAP_RDATATYPE_TEMPLATE_PREFIX,
				attr->name,
				LDAP_RDATATYPE_TEMPLATE_PREFIX_LEN) != 0)
			continue;

		result = ldap_attribute_to_rdatatype(attr->name, &rdtype);
		if (result != ISC_R_SUCCESS) {
			log_bug("%s: substitution into '%s' is not supported",
				ldap_entry_logname(entry),
				attr->name + LDAP_RDATATYPE_TEMPLATE_PREFIX_LEN);
			continue;
		}

		CHECK(findrdatatype_or_create(mctx, rdatalist, rdclass,
					      rdtype, ttl, &rdlist));
		for (result = ldap_attr_firstvalue(attr, orig_val);
		     result == ISC_R_SUCCESS;
		     result = ldap_attr_nextvalue(attr, orig_val)) {
			str_destroy(&new_val);
			CHECK(ldap_substitute_rr_template(mctx, settings,
							  orig_val, &new_val));
			log_debug(10, "%s: substituted '%s' '%s' -> '%s'",
				  ldap_entry_logname(entry), attr->name,
				  str_buf(orig_val), str_buf(new_val));
			CHECK(parse_rdata(mctx, entry, rdclass, rdtype, origin,
					  str_buf(new_val), &rdata));
			APPEND(rdlist->rdata, rdata, link);
			rdata = NULL;
			did_something = true;
		}
	}

cleanup:
	str_destroy(&orig_val);
	str_destroy(&new_val);
	if (result == ISC_R_NOMORE || result == ISC_R_SUCCESS)
		result = did_something ? ISC_R_SUCCESS : ISC_R_IGNORE;

	return result;
}

/**
 * Parse object containing DNS records and substitute idnsAttributeTemplates
 * into it if they are defined.
 *
 * idnsAttributeTemplates take precedence over all statically defined
 * attributes with RRs.
 * All static RRs are ignored if substitution was successful.
 *
 * @pre rdatalist is empty initialized list.
 *
 * @param rdatalist[in,out]
 */
static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
ldap_parse_rrentry(isc_mem_t *mctx, ldap_entry_t *entry, dns_name_t *origin,
		   const settings_set_t * const settings,
		   ldapdb_rdatalist_t *rdatalist)
{
	isc_result_t result;
	dns_rdataclass_t rdclass;
	dns_ttl_t ttl;
	dns_rdatatype_t rdtype;
	dns_rdata_t *rdata = NULL;
	dns_rdatalist_t *rdlist = NULL;
	ldap_attribute_t *attr;
	const char *data_str = "<NULL data>";
	ld_string_t *data_buf = NULL;
	const char *fake_mname;

	REQUIRE(EMPTY(*rdatalist));

	ttl = ldap_entry_getttl(entry, settings);
	rdclass = ldap_entry_getrdclass(entry);
	if ((entry->class & LDAP_ENTRYCLASS_MASTER) != 0) {
		CHECK(setting_get_str("fake_mname", settings, &fake_mname));
		CHECK(add_soa_record(mctx, origin, entry, ttl, rdatalist,
				     fake_mname));
	}

	if ((entry->class & LDAP_ENTRYCLASS_TEMPLATE) != 0) {
		result = ldap_parse_rrentry_template(mctx, entry, origin,
						     settings, rdatalist);
		if (result == ISC_R_SUCCESS)
			/* successful substitution overrides all constants */
			return result;
		else if (result != ISC_R_IGNORE)
			goto cleanup;
	}

	CHECK(str_new(mctx, &data_buf));
	for (result = ldap_entry_firstrdtype(entry, &attr, &rdtype);
	     result == ISC_R_SUCCESS;
	     result = ldap_entry_nextrdtype(entry, &attr, &rdtype)) {
		/* If we reached this point and found a template attribute,
		 * skip it because it was not translated above due to missing
		 * defaults or some other errors. */
		if (((entry->class & LDAP_ENTRYCLASS_TEMPLATE) != 0) &&
		    strncasecmp(LDAP_RDATATYPE_TEMPLATE_PREFIX,
				attr->name,
				LDAP_RDATATYPE_TEMPLATE_PREFIX_LEN) == 0)
			continue;

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
	if (data_buf != NULL && str_len(data_buf) != 0)
		data_str = str_buf(data_buf);
	log_error_r("failed to parse RR entry: %s: data '%s'",
		    ldap_entry_logname(entry), data_str);
	str_destroy(&data_buf);
	return result;
}

static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
add_soa_record(isc_mem_t *mctx, dns_name_t *origin,
	       ldap_entry_t *entry, dns_ttl_t ttl, ldapdb_rdatalist_t *rdatalist,
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
				      ttl, &rdlist));

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

	rdata = isc_mem_get(mctx, sizeof(*(rdata)));
	dns_rdata_init(rdata);

	rdatamem.length = isc_buffer_usedlength(&entry->rdata_target);
	rdatamem.base = isc_mem_get(mctx, rdatamem.length);

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
					      ldap_inst->server_ldap_settings,
					      (const char **)&in->result));
			in->len = strlen(in->result);
			ret = LDAP_SUCCESS;
			break;
		case SASL_CB_GETREALM:
			log_debug(4, "got request for SASL_CB_GETREALM");
			CHECK(setting_get_str("sasl_realm",
					      ldap_inst->server_ldap_settings,
					      (const char **)&in->result));
			in->len = strlen(in->result);
			ret = LDAP_SUCCESS;
			break;
		case SASL_CB_AUTHNAME:
			log_debug(4, "got request for SASL_CB_AUTHNAME");
			CHECK(setting_get_str("sasl_auth_name",
					      ldap_inst->server_ldap_settings,
					      (const char **)&in->result));
			in->len = strlen(in->result);
			ret = LDAP_SUCCESS;
			break;
		case SASL_CB_PASS:
			log_debug(4, "got request for SASL_CB_PASS");
			CHECK(setting_get_str("sasl_password",
					      ldap_inst->server_ldap_settings,
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
	     bool force)
{
	LDAP *ld = NULL;
	int ret;
	int version;
	struct timeval timeout;
	isc_result_t result = ISC_R_FAILURE;
	const char *uri = NULL;
	const char *ldap_hostname = NULL;
	uint32_t timeout_sec;

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

	CHECK(setting_get_uint("timeout", ldap_inst->server_ldap_settings,
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
	       bool force)
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
	uint32_t reconnect_interval;

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
				       ldap_inst->server_ldap_settings,
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
		CHECK(setting_get_str("bind_dn", ldap_inst->server_ldap_settings,
				      &bind_dn));
		CHECK(setting_get_str("password", ldap_inst->server_ldap_settings,
				      &password));
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
			bool force)
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
		if (ldap_conn->handle == NULL && force == false)
			log_error("connection to the LDAP server was lost");
		result = ldap_connect(ldap_inst, ldap_conn, force);
		if (result == ISC_R_SUCCESS)
			log_info("successfully reconnected to LDAP server");
		break;
	}

	return result;
}

/**
 * Apply LDAP modifications.
 *
 * @retval ISC_R_SUCCESS
 * @retval DNS_R_UNKNOWN = LDAP_OBJECT_CLASS_VIOLATION
 *                       or LDAP_INSUFFICIENT_ACCESS. Most likely an attribute
 *                       for a DNS RR type cannot be added because it is not
 *                       present in the LDAP schema.
 */
isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
ldap_modify_do(ldap_instance_t *ldap_inst, const char *dn, LDAPMod **mods,
		bool delete_node)
{
	int ret;
	int err_code;
	const char *operation_str;
	bool once = false;
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
		once = true;
		CHECK(handle_connection_error(ldap_inst, ldap_conn, false));
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
	/* attempt to manipulate attribute failed - likely a unknown RR type */
	if (err_code == LDAP_OBJECT_CLASS_VIOLATION
	    || err_code == LDAP_INSUFFICIENT_ACCESS) /* this is for 389 DS */
		CLEANUP_WITH(DNS_R_UNKNOWN);

	/* do not error out if we are trying to delete an
	 * unexisting attribute */
	if ((mods[0]->mod_op & ~LDAP_MOD_BVALUES) != LDAP_MOD_DELETE ||
	    err_code != LDAP_NO_SUCH_ATTRIBUTE) {
		result = ISC_R_FAILURE;
		if (once == false) {
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

	REQUIRE(changep != NULL && *changep == NULL);

	change = isc_mem_get(mctx, sizeof(*(change)));
	ZERO_PTR(change);
	change->mod_type = isc_mem_get(mctx, LDAP_ATTR_FORMATSIZE);

	*changep = change;
	return ISC_R_SUCCESS;
}

/**
 * @param[in]  rdlist
 * @param[out] changep
 * @param[in]  mod_op  LDAP operation as integer used in LDAPMod.
 * @param[in]  generic Use generic (RFC 3597) syntax.
 */
static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
ldap_rdatalist_to_ldapmod(isc_mem_t *mctx, dns_rdatalist_t *rdlist,
			  LDAPMod **changep, int mod_op, bool unknown)
{
	isc_result_t result;
	LDAPMod *change = NULL;
	char **vals = NULL;

	CHECK(ldap_mod_create(mctx, &change));
	CHECK(rdatatype_to_ldap_attribute(rdlist->type, change->mod_type,
					  LDAP_ATTR_FORMATSIZE, unknown));
	CHECK(ldap_rdata_to_char_array(mctx, HEAD(rdlist->rdata), unknown,
				       &vals));

	change->mod_op = mod_op;
	change->mod_values = vals;

	*changep = change;
	return ISC_R_SUCCESS;

cleanup:
	ldap_mod_free(mctx, &change);

	return result;
}

/**
 * Convert list of DNS Rdata to array of LDAP values.
 *
 * @param[in]  unknown  true  = use generic (RFC 3597) format,
 *                      false = use record-specific syntax (if available).
 */
static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
ldap_rdata_to_char_array(isc_mem_t *mctx, dns_rdata_t *rdata_head,
			 bool unknown, char ***valsp)
{
	isc_result_t result = ISC_R_FAILURE;
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

	vals = isc_mem_allocate(mctx, vals_size);
	memset(vals, 0, vals_size);

	rdata = rdata_head;
	for (i = 0; i < rdata_count && rdata != NULL; i++) {
		DECLARE_BUFFER(buffer, /* RFC 3597 format is hex string */
			       DNS_RDATA_MAXLENGTH * 2 + sizeof("\\# 65535 "));
		isc_region_t region;

		/* Convert rdata to text. */
		INIT_BUFFER(buffer);
		if (unknown == false)
			CHECK(dns_rdata_totext(rdata, NULL, &buffer));
		else
			CHECK(rdata_to_generic(rdata, &buffer));
		isc_buffer_usedregion(&buffer, &region);

		/* Now allocate the string with the right size. */
		vals[i] = isc_mem_allocate(mctx, region.length + 1);
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
	/* isc_string_copy has been removed */
	if (strlcpy(change->mod_type, "dnsTTL", LDAP_ATTR_FORMATSIZE)
	   >= LDAP_ATTR_FORMATSIZE) {
		CLEANUP_WITH(ISC_R_NOSPACE);
	}

	vals = isc_mem_allocate(mctx, 2 * sizeof(char *));
	memset(vals, 0, 2 * sizeof(char *));
	change->mod_values = vals;

	vals[0] = isc_mem_allocate(mctx, str_len(ttlval) + 1);
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
	isc_result_t result = ISC_R_SUCCESS;
	dns_rdata_soa_t soa;
	int s_len;
	LDAPMod change[5];
	LDAPMod *changep[6] = {
		&change[0], &change[1], &change[2], &change[3], &change[4],
		NULL
	};

	REQUIRE(ldap_inst != NULL);

/* all values in SOA record are uint32_t, i.e. max. 2^32-1 */
#define MAX_SOANUM_LENGTH (10 + 1)
#define SET_LDAP_MOD(index, name) \
	change[index].mod_op = LDAP_MOD_REPLACE; \
	change[index].mod_type = "idnsSOA" #name; \
	change[index].mod_values = alloca(2 * sizeof(char *)); \
	change[index].mod_values[0] = alloca(MAX_SOANUM_LENGTH); \
	change[index].mod_values[1] = NULL; \
	s_len = snprintf(change[index].mod_values[0], MAX_SOANUM_LENGTH, \
			 "%u", soa.name); \
	if (s_len < 0 || s_len >= MAX_SOANUM_LENGTH) { \
		CLEANUP_WITH(ISC_R_NOSPACE); \
	}

	dns_rdata_tostruct(rdata, (void *)&soa, ldap_inst->mctx);

	SET_LDAP_MOD(0, serial);
	SET_LDAP_MOD(1, refresh);
	SET_LDAP_MOD(2, retry);
	SET_LDAP_MOD(3, expire);
	SET_LDAP_MOD(4, minimum);

	dns_rdata_freestruct((void *)&soa);

	result = ldap_modify_do(ldap_inst, zone_dn, changep, false);

cleanup:
	return result;

#undef MAX_SOANUM_LENGTH
#undef SET_LDAP_MOD
}

static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
modify_ldap_common(dns_name_t *owner, dns_name_t *zone, ldap_instance_t *ldap_inst,
		   dns_rdatalist_t *rdlist, int mod_op, bool delete_node)
{
	isc_result_t result;
	isc_mem_t *mctx = ldap_inst->mctx;
	ld_string_t *owner_dn = NULL;
	LDAPMod *change[3] = { NULL };
	bool zone_sync_ptr;
	char **vals = NULL;
	dns_name_t zone_name;
	char *zone_dn = NULL;
	settings_set_t *zone_settings = NULL;
	int af; /* address family */
	bool unknown_type = false;

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
	INSIST(dns_name_equal(zone, &zone_name) == true);

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

	if (mod_op == LDAP_MOD_ADD) {
		/* for now always replace the ttl on add */
		CHECK(ldap_rdttl_to_ldapmod(mctx, rdlist, &change[1]));
	}

	/* First, try to store data into named attribute like "URIRecord".
	 * If that fails, try to store the data into "UnknownRecord;TYPE256". */
	unknown_type = false;
	do {
		ldap_mod_free(mctx, &change[0]);
		CHECK(ldap_rdatalist_to_ldapmod(mctx, rdlist, &change[0],
						mod_op, unknown_type));
		result = ldap_modify_do(ldap_inst, str_buf(owner_dn), change,
					delete_node);
		unknown_type = !unknown_type; /* try again with unknown type */
	} while (result == DNS_R_UNKNOWN && unknown_type == true);

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
		/* Following call will not work if A/AAAA records are unknown. */
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
	return modify_ldap_common(owner, zone, ldap_inst, rdlist, LDAP_MOD_ADD, false);
}

isc_result_t
remove_values_from_ldap(dns_name_t *owner, dns_name_t *zone, ldap_instance_t *ldap_inst,
		 dns_rdatalist_t *rdlist, bool delete_node)
{
	return modify_ldap_common(owner, zone, ldap_inst, rdlist, LDAP_MOD_DELETE,
				  delete_node);
}

/**
 * Delete named attribute 'URIRecord'
 * and equivalent attribute 'UnknownRecord;TYPE256' too.
 */
isc_result_t
remove_rdtype_from_ldap(dns_name_t *owner, dns_name_t *zone,
		      ldap_instance_t *ldap_inst, dns_rdatatype_t type) {
	char attr[LDAP_ATTR_FORMATSIZE];
	LDAPMod *change[2] = { NULL };
	ld_string_t *dn = NULL;
	isc_result_t result;
	bool unknown_type = false;

	CHECK(str_new(ldap_inst->mctx, &dn));
	CHECK(dnsname_to_dn(ldap_inst->zone_register, owner, zone, dn));

	do {
		CHECK(ldap_mod_create(ldap_inst->mctx, &change[0]));
		change[0]->mod_op = LDAP_MOD_DELETE;
		/* delete all values from given attribute */
		change[0]->mod_vals.modv_strvals = NULL;
		CHECK(rdatatype_to_ldap_attribute(type, attr, sizeof(attr),
						  unknown_type));
		if (strlcpy(change[0]->mod_type, attr, LDAP_ATTR_FORMATSIZE)
		    >= LDAP_ATTR_FORMATSIZE) {
			CLEANUP_WITH(ISC_R_NOSPACE);
		}
		CHECK(ldap_modify_do(ldap_inst, str_buf(dn), change, false));
		ldap_mod_free(ldap_inst->mctx, &change[0]);
		unknown_type = !unknown_type;
	} while (unknown_type == true);

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
		CHECK(ldap_connect(ldap_inst, ldap_conn, false));
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

	pool = isc_mem_get(mctx, sizeof(*pool));
	ZERO_PTR(pool);
	isc_mem_attach(mctx, &pool->mctx);
	
	CHECK(semaphore_init(&pool->conn_semaphore, connections));
	pool->conns = isc_mem_get(mctx,
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
		result = ldap_connect(ldap_inst, ldap_conn, false);
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
	ldap_instance_t *inst = pevent->inst;
	isc_mem_t *mctx;
	dns_name_t prevname;
	ldap_entry_t *entry = pevent->entry;

	mctx = pevent->mctx;
	dns_name_init(&prevname, NULL);

	REQUIRE(inst != NULL);
	INSIST(task == inst->task); /* For task-exclusive mode */

	if (SYNCREPL_DEL(pevent->chgtype)) {
		CHECK(ldap_delete_zone2(inst, &entry->fqdn, true));
	} else {
		if (entry->class & LDAP_ENTRYCLASS_MASTER)
			CHECK(ldap_parse_master_zoneentry(entry, NULL, inst,
							  task));
		else if (entry->class & LDAP_ENTRYCLASS_FORWARD)
			CHECK(ldap_parse_fwd_zoneentry(entry, inst));
		else
			FATAL_ERROR(__FILE__, __LINE__,
				    "update_zone: unexpected entry class");
	}

cleanup:
	sync_concurr_limit_signal(inst->sctx);
	sync_event_signal(inst->sctx, pevent);
	if (dns_name_dynamic(&prevname))
		dns_name_free(&prevname, inst->mctx);

	if (result != ISC_R_SUCCESS)
		log_error_r("update_zone (syncrepl) failed for %s. "
			    "Zones can be outdated, run `rndc reload`",
			    ldap_entry_logname(entry));

	if (pevent->prevdn != NULL)
		isc_mem_free(mctx, pevent->prevdn);
	ldap_entry_destroy(&entry);
	isc_mem_detach(&mctx);
	isc_event_free(&event);
	isc_task_detach(&task);
}

static void ATTR_NONNULLS
update_config(isc_task_t * task, isc_event_t *event)
{
	ldap_syncreplevent_t *pevent = (ldap_syncreplevent_t *)event;
	isc_result_t result;
	ldap_instance_t *inst = pevent->inst;
	ldap_entry_t *entry = pevent->entry;
	isc_mem_t *mctx;

	mctx = pevent->mctx;

	REQUIRE(inst != NULL);
	INSIST(task == inst->task); /* For task-exclusive mode */
	CHECK(ldap_parse_configentry(entry, inst));

cleanup:
	sync_concurr_limit_signal(inst->sctx);
	sync_event_signal(inst->sctx, pevent);

	if (result != ISC_R_SUCCESS)
		log_error_r("update_config (syncrepl) failed for %s. "
			    "Configuration can be outdated, run `rndc reload`",
			    ldap_entry_logname(entry));

	ldap_entry_destroy(&entry);
	isc_mem_detach(&mctx);
	isc_event_free(&event);
	isc_task_detach(&task);
}

static void ATTR_NONNULLS
update_serverconfig(isc_task_t * task, isc_event_t *event)
{
	ldap_syncreplevent_t *pevent = (ldap_syncreplevent_t *)event;
	isc_result_t result;
	ldap_instance_t *inst = pevent->inst;
	ldap_entry_t *entry = pevent->entry;
	isc_mem_t *mctx;

	mctx = pevent->mctx;

	REQUIRE(inst != NULL);
	INSIST(task == inst->task); /* For task-exclusive mode */
	CHECK(ldap_parse_serverconfigentry(entry, inst));

cleanup:
	sync_concurr_limit_signal(inst->sctx);
	sync_event_signal(inst->sctx, pevent);

	if (result != ISC_R_SUCCESS)
		log_error_r("update_serverconfig (syncrepl) failed for %s. "
			    "Configuration can be outdated, run `rndc reload`",
			    ldap_entry_logname(entry));

	ldap_entry_destroy(&entry);
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
	ldap_instance_t *inst = pevent->inst;
	isc_mem_t *mctx;
	settings_set_t *zone_settings = NULL;
	dns_zone_t *raw = NULL;
	dns_zone_t *secure = NULL;
	bool zone_found = false;
	bool zone_reloaded = false;
	uint32_t serial;
	ldap_entry_t *entry = pevent->entry;

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

	REQUIRE(inst != NULL);
	CHECK(zr_get_zone_ptr(inst->zone_register, &entry->zone_name, &raw, &secure));
	zone_found = true;

update_restart:
	rbtdb = NULL;
	ldapdb = NULL;
	zone_settings = NULL;
	ldapdb_rdatalist_destroy(mctx, &rdatalist);
	CHECK(zr_get_zone_dbs(inst->zone_register, &entry->zone_name, &ldapdb, &rbtdb));
	CHECK(dns_db_newversion(ldapdb, &version));

	CHECK(dns_db_findnode(rbtdb, &entry->fqdn, true, &node));
	result = dns_db_allrdatasets(rbtdb, node, version, 0, &rbt_rds_iterator);
	if (result != ISC_R_SUCCESS && result != ISC_R_NOTFOUND)
		goto cleanup;


	/* This code is disabled because we don't have UUID->DN database yet.
	    || SYNCREPL_MODDN(pevent->chgtype)) { */
	if (SYNCREPL_DEL(pevent->chgtype)) {
		log_debug(5, "syncrepl_update: removing name from rbtdb, "
			  "%s", ldap_entry_logname(entry));
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
		log_debug(5, "syncrepl_update: updating name in rbtdb, "
			  "%s", ldap_entry_logname(entry));
		CHECK(zr_get_zone_settings(inst->zone_register,
					   &entry->zone_name, &zone_settings));
		CHECK(ldap_parse_rrentry(mctx, entry, &entry->zone_name,
					 zone_settings, &rdatalist));
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
		dns_db_closeversion(ldapdb, &version, true);
		dns_zone_markdirty(raw);
	}

	/* Check if the zone is loaded or not.
	 * No other function above returns DNS_R_NOTLOADED. */
	if (sync_state == sync_finished)
		result = dns_zone_getserial(raw, &serial);

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
		dns_db_closeversion(ldapdb, &version, false);
	if (rbtdb != NULL)
		dns_db_detach(&rbtdb);
	if (ldapdb != NULL)
		dns_db_detach(&ldapdb);
	if (result != ISC_R_SUCCESS && zone_found && !zone_reloaded &&
	   (result == DNS_R_NOTLOADED || result == DNS_R_BADZONE)) {
		dns_zone_log(raw, ISC_LOG_DEBUG(1),
			     "reloading invalid zone after a change; "
			     "reload triggered by change in %s",
			     ldap_entry_logname(entry));
		if (secure != NULL)
			result = load_zone(secure, true);
		else if (raw != NULL)
			result = load_zone(raw, true);
		if (result == ISC_R_SUCCESS || result == DNS_R_UPTODATE ||
		    result == DNS_R_DYNAMIC || result == DNS_R_CONTINUE) {
			/* zone reload succeeded, fire current event again */
			log_debug(1, "restarting update_record after zone reload "
				     "caused by change in %s",
				     ldap_entry_logname(entry));
			zone_reloaded = true;
			result = dns_zone_getserial(raw, &serial);
			if (result == ISC_R_SUCCESS)
				goto update_restart;
		} else {
			dns_zone_log(raw, ISC_LOG_ERROR,
				    "unable to reload invalid zone; "
				    "reload triggered by change in %s: %s",
				    ldap_entry_logname(entry),
				    dns_result_totext(result));
		}

	} else if (result != ISC_R_SUCCESS) {
		/* error other than invalid zone */
		log_error_r("update_record (syncrepl) failed, %s change type "
			    "0x%x. Records can be outdated, run `rndc reload`",
			    ldap_entry_logname(entry), pevent->chgtype);
	}

	sync_concurr_limit_signal(inst->sctx);
	if (dns_name_dynamic(&prevname))
		dns_name_free(&prevname, inst->mctx);
	if (dns_name_dynamic(&prevorigin))
		dns_name_free(&prevorigin, inst->mctx);

	if (raw != NULL)
		dns_zone_detach(&raw);
	if (secure != NULL)
		dns_zone_detach(&secure);
	ldapdb_rdatalist_destroy(mctx, &rdatalist);
	if (pevent->prevdn != NULL)
		isc_mem_free(mctx, pevent->prevdn);
	ldap_entry_destroy(&entry);
	isc_mem_detach(&mctx);
	isc_event_free(&event);
	isc_task_detach(&task);
}

isc_result_t
ldap_dn_compare(const char *dn1_instr, const char *dn2_instr,
		bool *isequal) {
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

	*isequal = (strcasecmp(dn1_outstr, dn2_outstr) == 0);
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

/**
 * Create asynchronous ISC event to execute update_config()/zone()/record()
 * in a task associated with affected DNS zone.
 *
 * @param[in,out] entryp  (Possibly fake) LDAP entry to parse.
 * @param[in]     chgtype One of LDAP_SYNC_CAPI_ADD/MODIFY/DELETE.
 *
 * @pre entryp is valid LDAP entry with class, DNS names, DN, etc.
 *
 * @post entryp is NULL.
 */
static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
syncrepl_update(ldap_instance_t *inst, ldap_entry_t **entryp, int chgtype)
{
	isc_result_t result = ISC_R_SUCCESS;
	ldap_syncreplevent_t *pevent = NULL;
	ldap_entry_t *entry = NULL;
	dns_name_t *zone_name = NULL;
	dns_zone_t *zone_ptr = NULL;
	isc_taskaction_t action = NULL;
	isc_task_t *task = NULL;
	bool synchronous;

	REQUIRE(inst != NULL);
	REQUIRE(entryp != NULL);
	entry = *entryp;
	REQUIRE(entry->class != LDAP_ENTRYCLASS_NONE);

	log_debug(20, "syncrepl_update change type: add%d, del%d, mod%d",
		  SYNCREPL_ADD(chgtype), SYNCREPL_DEL(chgtype),
		  SYNCREPL_MOD(chgtype));

	if (entry->class & LDAP_ENTRYCLASS_MASTER)
		zone_name = &entry->fqdn;
	else
		zone_name = &entry->zone_name;

	/* Process ordinary records in parallel but serialize operations on
	 * master zone objects.
	 * See discussion about run_exclusive_begin() function in lock.c. */
	if ((entry->class & LDAP_ENTRYCLASS_RR) != 0 &&
	    (entry->class & LDAP_ENTRYCLASS_MASTER) == 0) {
		CHECK(zr_get_zone_ptr(inst->zone_register, zone_name,
				      &zone_ptr, NULL));
		dns_zone_gettask(zone_ptr, &task);
		synchronous = false;
	} else {
		/* For configuration object and zone object use single task
		 * to make sure that the exclusive mode actually works. */
		isc_task_attach(inst->task, &task);
		synchronous = true;
	}
	REQUIRE(task != NULL);


	/* This code is disabled because we don't have UUID->DN database yet.
	if (SYNCREPL_MODDN(chgtype)) {
		CHECKED_MEM_STRDUP(mctx, prevdn_ldap, prevdn);
	}
	*/

	if ((entry->class & LDAP_ENTRYCLASS_CONFIG) != 0)
		action = update_config;
	else if ((entry->class & LDAP_ENTRYCLASS_SERVERCONFIG) != 0)
		action = update_serverconfig;
	else if ((entry->class & LDAP_ENTRYCLASS_MASTER) != 0)
		action = update_zone;
	else if ((entry->class & LDAP_ENTRYCLASS_FORWARD) != 0)
		action = update_zone;
	else if ((entry->class & LDAP_ENTRYCLASS_RR) != 0)
		action = update_record;
	else {
		log_error("unsupported objectClass: dn '%s'", entry->dn);
		result = ISC_R_NOTIMPLEMENTED;
		goto cleanup;
	}

	pevent = (ldap_syncreplevent_t *)isc_event_allocate(inst->mctx,
				inst, LDAPDB_EVENT_SYNCREPL_UPDATE,
				action, NULL,
				sizeof(ldap_syncreplevent_t));

	if (pevent == NULL) {
		result = ISC_R_NOMEMORY;
		goto cleanup;
	}

	pevent->mctx = NULL;
	isc_mem_attach(inst->mctx, &pevent->mctx);
	pevent->inst = inst;
	pevent->prevdn = NULL;
	pevent->chgtype = chgtype;
	pevent->entry = entry;

	/* Lock syncrepl queue to prevent zone, config and resource records
	 * from racing with each other. */
	CHECK(sync_event_send(inst->sctx, task, &pevent, synchronous));
	*entryp = NULL; /* event handler will deallocate the LDAP entry */

cleanup:
	if (zone_ptr != NULL)
		dns_zone_detach(&zone_ptr);
	if (result != ISC_R_SUCCESS)
		log_error_r("syncrepl_update failed for %s",
			    ldap_entry_logname(entry));
	if (pevent != NULL) {
		/* Event was not sent */
		sync_concurr_limit_signal(inst->sctx);
		if (pevent->mctx != NULL)
			isc_mem_detach(&pevent->mctx);
		ldap_entry_destroy(entryp);
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
 * Returns false if we should terminate, true otherwise.
 */
static inline bool ATTR_NONNULLS
sane_sleep(const ldap_instance_t *inst, unsigned int timeout)
{
	unsigned int remains = timeout;

	while (remains && !inst->exiting)
		remains = sleep(remains);

	if (remains)
		log_debug(99, "sane_sleep: interrupted");

	return inst->exiting ? false : true;
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
	static bool once = false;

	if (once)
		return;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = &noop_handler;

	ret = sigaction(SIGUSR1, &sa, &oldsa);
	RUNTIME_CHECK(ret == 0); /* If sigaction fails, it's a bug */

	/* Don't attempt to replace already existing handler */
	RUNTIME_CHECK(oldsa.sa_handler == NULL);

	once = true;
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
	ldap_entry_t *old_entry = NULL;
	ldap_entry_t *new_entry = NULL;
	isc_result_t result;
	metadb_node_t *node = NULL;
	bool mldap_open = false;
	bool modrdn = false;

#ifdef RBTDB_DEBUG
	static unsigned int count = 0;
#endif

	if (inst->exiting)
		return LDAP_SUCCESS;

	CHECK(mldap_newversion(inst->mldapdb));
	mldap_open = true;

	CHECK(sync_concurr_limit_wait(inst->sctx));
	log_debug(20, "ldap_sync_search_entry phase: %x", phase);

	/* MODIFY can be rename: get old name from metaDB */
	if (phase == LDAP_SYNC_CAPI_DELETE || phase == LDAP_SYNC_CAPI_MODIFY) {
		CHECK(ldap_entry_reconstruct(inst->mctx, inst->mldapdb,
					     entryUUID, &old_entry));
	}
	if (phase == LDAP_SYNC_CAPI_ADD || phase == LDAP_SYNC_CAPI_MODIFY) {
		CHECK(ldap_entry_parse(inst->mctx, ls->ls_ld, msg, entryUUID,
				       &new_entry));
	}
	/* detect type of modification */
	if (phase == LDAP_SYNC_CAPI_MODIFY) {
		if (old_entry->class != new_entry->class)
			log_error("unsupported operation: "
				  "object class in %s changed: "
				  "rndc reload might be necessary",
				  ldap_entry_logname(new_entry));
		if ((old_entry->class
		    & (LDAP_ENTRYCLASS_CONFIG | LDAP_ENTRYCLASS_SERVERCONFIG))
		    == 0)
			modrdn = !(dns_name_equal(&old_entry->zone_name,
						  &new_entry->zone_name)
				   && dns_name_equal(&old_entry->fqdn,
						     &new_entry->fqdn));
		if (modrdn == true) {
			log_debug(1, "detected entry rename: %s -> %s",
				  ldap_entry_logname(old_entry),
				  ldap_entry_logname(new_entry));
			if (old_entry->class != LDAP_ENTRYCLASS_RR)
				log_bug("LDAP MODRDN is supported only for "
					"records, not zones or configs; %s; "
					"rndc reload might be necessary",
					ldap_entry_logname(new_entry));
		}
	}
	if (phase == LDAP_SYNC_CAPI_DELETE || modrdn == true) {
		/* delete old entry from zone and metaDB */
		CHECK(syncrepl_update(inst, &old_entry, LDAP_SYNC_CAPI_DELETE));
		CHECK(mldap_entry_delete(inst->mldapdb, entryUUID));
	}
	if (phase == LDAP_SYNC_CAPI_ADD || phase == LDAP_SYNC_CAPI_MODIFY) {
		/* store new state into metaDB */
		CHECK(mldap_entry_create(new_entry, inst->mldapdb, &node));
		if ((new_entry->class
		    & (LDAP_ENTRYCLASS_CONFIG | LDAP_ENTRYCLASS_SERVERCONFIG))
		    == 0)
			CHECK(mldap_dnsname_store(&new_entry->fqdn,
						  &new_entry->zone_name, node));
		/* commit new entry into metaLDAP DB before something breaks */
		metadb_node_close(&node);
		mldap_closeversion(inst->mldapdb, true);
		mldap_open = false;
		/* re-add entry under new DN, if necessary */
		CHECK(syncrepl_update(inst, &new_entry,
		                      (modrdn == true)
					      ? LDAP_SYNC_CAPI_ADD : phase));
	}
	if (phase != LDAP_SYNC_CAPI_ADD && phase != LDAP_SYNC_CAPI_MODIFY &&
	    phase != LDAP_SYNC_CAPI_DELETE) {
		log_bug("syncrepl phase %x is not supported", phase);
		CLEANUP_WITH(ISC_R_NOTIMPLEMENTED);
	}

#ifdef RBTDB_DEBUG
	if (++count % 100 == 0)
		log_info("ldap_sync_search_entry: %u entries read; inuse: %zd",
			 count, isc_mem_inuse(inst->mctx));
#endif

cleanup:
	metadb_node_close(&node);
	if (mldap_open == true)
		/* commit metaDB changes if the syncrepl event was sent */
		mldap_closeversion(inst->mldapdb, (result == ISC_R_SUCCESS));
	if (result != ISC_R_SUCCESS) {
		log_error_r("ldap_sync_search_entry failed");
		sync_concurr_limit_signal(inst->sctx);
		/* TODO: Add 'tainted' flag to the LDAP instance. */
	}
	ldap_entry_destroy(&old_entry);
	ldap_entry_destroy(&new_entry);

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
	metadb_iter_t *mldap_iter = NULL;
	char entryUUID_buf[16];
	struct berval entryUUID = { .bv_len = sizeof(entryUUID_buf),
				    .bv_val = entryUUID_buf };
	sync_state_t state;

	UNUSED(msg);
	UNUSED(syncUUIDs);

	if (inst->exiting)
		goto cleanup;

	log_debug(1, "ldap_sync_intermediate 0x%x", phase);
	if (phase != LDAP_SYNC_CAPI_DONE)
		goto cleanup;

	sync_state_get(inst->sctx, &state);
	if (state == sync_datainit) {
		result = sync_barrier_wait(inst->sctx, inst);
		if (result != ISC_R_SUCCESS) {
			log_error_r("%s: sync_barrier_wait() failed for "
				    "instance '%s'", __func__, inst->db_name);
			goto cleanup;
		}
	}

	for (result = mldap_iter_deadnodes_start(inst->mldapdb, &mldap_iter,
						 &entryUUID);
	     result == ISC_R_SUCCESS;
	     result = mldap_iter_deadnodes_next(inst->mldapdb, &mldap_iter,
					        &entryUUID)) {
		ldap_sync_search_entry(ls, NULL, &entryUUID,
				       LDAP_SYNC_CAPI_DELETE);

	}
	if (result != ISC_R_SUCCESS && result != ISC_R_NOMORE)
		log_error_r("mldap_iter_deadnodes_* failed, run rndc reload");

cleanup:
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
	isc_result_t	result;
	ldap_instance_t *inst = ls->ls_private;
	sync_state_t state;

	UNUSED(msg);
	UNUSED(refreshDeletes);

	log_debug(1, "ldap_sync_search_result");

	if (inst->exiting)
		goto cleanup;

	/* This place can be reached only if:
	 * a) initial config synchronization is done
	 * b) config is re-synchronized after reconnect to LDAP */
	sync_state_get(inst->sctx, &state);
	INSIST(state == sync_configinit || state == sync_finished);

	if (state == sync_configinit) {
		result = sync_barrier_wait(inst->sctx, inst);
		if (result != ISC_R_SUCCESS) {
			log_error_r("%s: sync_barrier_wait() failed for "
				    "instance '%s'", __func__, inst->db_name);
			goto cleanup;
		}
	}
	log_info("LDAP configuration for instance '%s' synchronized",
		 inst->db_name);

cleanup:
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

/**
 * Initialize ldap_sync_t structure. Is has to be freed by ldap_sync_cleanup().
 * In case of failure, the conn parameter may be invalid and LDAP connection
 * needs to be re-established.
 *
 * @param[in]  filter  LDAP filter to be used in SyncRepl session
 */
static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
ldap_sync_prepare(ldap_instance_t *inst, settings_set_t *settings,
		  const char *filter, ldap_connection_t *conn,
		  ldap_sync_t **ldap_syncp) {
	isc_result_t result;
	const char *base = NULL;
	ldap_sync_t *ldap_sync = NULL;

	REQUIRE(inst != NULL);
	REQUIRE(ldap_syncp != NULL && *ldap_syncp == NULL);

	/* Remove stale zone & journal files. */
	CHECK(cleanup_files(inst));

	if(conn->handle == NULL)
		CLEANUP_WITH(ISC_R_NOTCONNECTED);

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
	ldap_sync->ls_filter = ldap_strdup(filter);
	if (ldap_sync->ls_filter == NULL)
		CLEANUP_WITH(ISC_R_NOMEMORY);
	log_debug(1, "LDAP syncrepl filter = '%s'", ldap_sync->ls_filter);
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

/**
 * Start one SyncRepl session and process all events produced by it.
   LDAP_SYNC_REFRESH_AND_PERSIST mode returns only if an error occurred.
 *
 * @post Conn is unbound and invalid. The connection needs to be re-established.
 *
 * @param[in]  conn          Valid and bound LDAP connection.
 * @param[in]  filter_objcs  LDAP filter specifying objects which should
 *                           be retrieved during this session. The supplied
 *                           filter will be ORed filter specifying configuration
 *                           objects which always need to be retrieved.
 * @param[in]  mode          LDAP_SYNC_REFRESH_AND_PERSIST
 *                           or LDAP_SYNC_REFRESH_ONLY
 *
 * @retval ISC_R_SUCCESS      LDAP_SYNC_REFRESH_ONLY mode finished,
 *                            all events were sent (not necessarily processed)
 * @retval ISC_R_NOTCONNECTED Unable to start SyncRepl session.
 * @retval others             Errors, some events might or might not be sent.
 */
static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
ldap_sync_doit(ldap_instance_t *inst, ldap_connection_t *conn,
	       const char * const filter_objcs, int mode) {
	isc_result_t result;
	int ret;
	int s_len;
	ldap_sync_t *ldap_sync = NULL;
	const char *err_hint = "";
	char filter[1024];
	const char config_template[] =
		"(|"
		"  (objectClass=idnsConfigObject)"
		"  %s%s%s"
		"%s"
		")";
	const char *server_id = NULL;

	/* request idnsServerConfig object only if server_id is specified */
	CHECK(setting_get_str("server_id", inst->server_ldap_settings, &server_id));
	if (strlen(server_id) == 0) {
		s_len = snprintf(filter, sizeof(filter),
				 config_template, "", "", "", filter_objcs);
		if (s_len < 0 || (unsigned)s_len >= sizeof(filter)) {
			CLEANUP_WITH(ISC_R_NOSPACE);
		}
	} else {
		s_len = snprintf(filter, sizeof(filter),
				 config_template,
				 "  (&(objectClass=idnsServerConfigObject)"
				 "    (idnsServerId=", server_id, "))",
				 filter_objcs);
		if (s_len < 0 || (unsigned)s_len >= sizeof(filter)) {
			CLEANUP_WITH(ISC_R_NOSPACE);
		}
	}

	result = ldap_sync_prepare(inst, inst->server_ldap_settings,
				   filter, conn, &ldap_sync);
	if (result != ISC_R_SUCCESS) {
		log_error_r("ldap_sync_prepare() failed, retrying "
			    "in 1 second");
		sane_sleep(inst, 1);
		goto cleanup;
	}

	ret = ldap_sync_init(ldap_sync, mode);
	/* TODO: error handling, set tainted flag & do full reload? */
	if (ret != LDAP_SUCCESS) {
		if (ret == LDAP_UNAVAILABLE_CRITICAL_EXTENSION)
			err_hint = ": is RFC 4533 supported by LDAP server?";
		else
			err_hint = "";

		log_ldap_error(ldap_sync->ls_ld, "unable to start SyncRepl "
				"session%s", err_hint);
		conn->handle = NULL;
		CLEANUP_WITH(ISC_R_NOTCONNECTED);
	}

	while (!inst->exiting && ret == LDAP_SUCCESS
	       && mode == LDAP_SYNC_REFRESH_AND_PERSIST) {
		ret = ldap_sync_poll(ldap_sync);
		if (!inst->exiting && ret != LDAP_SUCCESS) {
			log_ldap_error(ldap_sync->ls_ld,
				       "ldap_sync_poll() failed");
			/* force reconnect in sync_prepare */
			conn->handle = NULL;
		}
	}

cleanup:
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
	uint32_t reconnect_interval;
	sync_state_t state;

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
		sync_state_get(inst->sctx, &state);
		if (state != sync_finished) {
			sync_state_reset(inst->sctx);
			CHECK(sync_task_add(inst->sctx, inst->task));
		}
		/* synchronize configuration first so configuration variables
		 * are already available during data processing */
		result = ldap_sync_doit(inst, conn, "", LDAP_SYNC_REFRESH_ONLY);
		if (result != ISC_R_SUCCESS) {
			log_error_r("LDAP configuration synchronization failed");
			goto retry;
		}

		result = ldap_connect(inst, conn, true);
		if (result != ISC_R_SUCCESS) {
			log_error_r("reconnection to LDAP failed");
			goto retry;
		}

		/* finally synchronize the data */
		sync_state_get(inst->sctx, &state);
		if (state != sync_finished)
			CHECK(sync_task_add(inst->sctx, inst->task));
		mldap_cur_generation_bump(inst->mldapdb);
		log_info("LDAP data for instance '%s' are being synchronized, "
			 "please ignore message 'all zones loaded'",
			 inst->db_name);
		result = ldap_sync_doit(inst, conn,
				        "(|(objectClass=idnsZone)"
					"  (objectClass=idnsForwardZone)"
					"  (objectClass=idnsRecord))",
					LDAP_SYNC_REFRESH_AND_PERSIST);
		if (result != ISC_R_SUCCESS) {
			log_error_r("LDAP data synchronization failed");
			goto retry;
		}

		CHECK_EXIT;

retry:
		/* Try to connect. */
		while (conn->handle == NULL) {
			CHECK_EXIT;
			CHECK(setting_get_uint("reconnect_interval",
					       inst->server_ldap_settings,
					       &reconnect_interval));

			log_error("ldap_syncrepl will reconnect in %d second%s",
				  reconnect_interval,
				  reconnect_interval == 1 ? "": "s");
			if (!sane_sleep(inst, reconnect_interval))
				CLEANUP_WITH(ISC_R_SHUTTINGDOWN);
			handle_connection_error(inst, conn, true);
		}

	}

cleanup:
	log_debug(1, "Ending ldap_syncrepl_watcher");
	ldap_pool_putconnection(inst->pool, &conn);

	return (isc_threadresult_t)0;
}

settings_set_t *
ldap_instance_getsettings_local(ldap_instance_t *ldap_inst)
{
	return ldap_inst->local_settings;
}

settings_set_t *
ldap_instance_getsettings_server(ldap_instance_t *ldap_inst)
{
	return ldap_inst->server_ldap_settings;
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

void
ldap_instance_attachview(ldap_instance_t *ldap_inst, dns_view_t **view)
{
	dns_view_attach(ldap_inst->view, view);
}

void
ldap_instance_attachmem(ldap_instance_t *ldap_inst, isc_mem_t **mctx)
{
	isc_mem_attach(ldap_inst->mctx, mctx);
}

bool
ldap_instance_isexiting(ldap_instance_t *ldap_inst)
{
	return ldap_inst->exiting;
}

/**
 * Mark LDAP instance as 'tainted' by unrecoverable error, e.g. unsupported
 * MODRDN. Full reload is required to recover consistency
 * (if it is even possible). */
void
ldap_instance_taint(ldap_instance_t *ldap_inst) {
	isc_refcount_increment0(&ldap_inst->errors);
}

bool
ldap_instance_istained(ldap_instance_t *ldap_inst) {
	return (isc_refcount_current(&ldap_inst->errors) != 0);
}

/**
 * Get number of errors from LDAP instance. This function should be called
 * before re-synchronization with LDAP is started.
 * When the re-synchronization is finished, the result of this function
 * has to be passed to ldap_instance_untaint_finish() to detect if any other
 * error occurred during the re-synchronization.
 */
unsigned int
ldap_instance_untaint_start(ldap_instance_t *ldap_inst) {
	return isc_refcount_current(&ldap_inst->errors);
}

/**
 * @retval DNS_R_CONTINUE An error occurred during re-synchronization,
 *                        it is necessary to start again.
 * @retval ISC_R_SUCCESS  Number of errors at the beginning and the end of
 *                        re-sychronization matches so no new errors occurred
 *                        during re-synchronization.
 */
isc_result_t
ldap_instance_untaint_finish(ldap_instance_t *ldap_inst, unsigned int count) {
	while (count > 0) {
		isc_refcount_decrement(&ldap_inst->errors);
		count--;
	}
	if (isc_refcount_current(&ldap_inst->errors) == 0) {
		return ISC_R_SUCCESS;
	}
	return DNS_R_CONTINUE;
}
