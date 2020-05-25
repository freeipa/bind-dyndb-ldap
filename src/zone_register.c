/*
 * Copyright (C) 2009-2014  bind-dyndb-ldap authors; see COPYING for license
 */

#include <isc/mem.h>
#include <isc/rwlock.h>
#include <isc/util.h>
#include <isc/string.h>

#include <dns/db.h>
#include <dns/rbt.h>
#include <dns/result.h>
#include <dns/zone.h>

#include "fs.h"
#include "ldap_driver.h"
#include "log.h"
#include "util.h"
#include "str.h"
#include "zone_register.h"
#include "settings.h"
#include "rbt_helper.h"

/**
 * The zone register is a red-black tree that maps a dns name of a zone to the
 * zone's pointer and it's LDAP DN. Synchronization is done by the zr_*
 * functions. The data stored in this structure is needed for conversion of
 * a dns name to DN and to get a pointer of a zone when we need to make changes
 * to it. We could use dns_view_findzone() for this, but that way we would not
 * have any assurance that the found zone is really managed by us.
 *
 * ZR contains all zones defined in LDAP including disabled zones
 * (idnsZoneActive = FALSE). Iterators return all zones including disabled ones.
 * Disabled zones are identified by "active" boolean = FALSE in settings_set_t
 * of the particular zone.
 */

struct zone_register {
	isc_mem_t	*mctx;
	isc_rwlock_t	rwlock;
	dns_rbt_t	*rbt;
	settings_set_t	*global_settings;
	ldap_instance_t *ldap_inst;
};

typedef struct {
	dns_zone_t	*raw;
	dns_zone_t	*secure;
	char		*dn;
	settings_set_t	*settings;
	dns_db_t	*ldapdb;
} zone_info_t;

/* Callback for dns_rbt_create(). */
static void delete_zone_info(void *arg1, void *arg2);

/**
 * Zone specific settings from idnsZone object:
 * NAME 'idnsZone'
 * MUST ( idnsName $ idnsZoneActive $ idnsSOAmName $ idnsSOArName $
 *        idnsSOAserial $ idnsSOArefresh $ idnsSOAretry $ idnsSOAexpire $
 *        idnsSOAminimum
 * )
 * MAY ( idnsUpdatePolicy $ idnsAllowQuery $ idnsAllowTransfer $
 *       idnsAllowSyncPTR $ idnsForwardPolicy $ idnsForwarders
 * )
 *
 * These structures are templates. They will be copied for each zone instance.
 */
static const setting_t zone_settings[] = {
	{ "active",			default_boolean(0)	},
	{ "default_ttl",		no_default_uint		},
	{ "dyn_update",			no_default_boolean	},
	{ "update_policy",		no_default_string	},
	{ "allow_query",		no_default_string	},
	{ "allow_transfer",		no_default_string	},
	{ "sync_ptr",			no_default_boolean	},
	{ "forward_policy",		no_default_string	},
	{ "forwarders",			no_default_string	},
	{ "nsec3param",			no_default_string	},
	end_of_settings
};

isc_result_t
zr_rbt_iter_init(zone_register_t *zr, rbt_iterator_t **iter,
		 dns_name_t *nodename) {
	if (zr->rbt == NULL)
		return ISC_R_NOTFOUND;

	return rbt_iter_first(zr->mctx, zr->rbt, &zr->rwlock, iter, nodename);
}

isc_mem_t *
zr_get_mctx(zone_register_t *zr) {
	REQUIRE(zr);

	return zr->mctx;
}

/**
 * Create a new zone register.
 */
isc_result_t
zr_create(isc_mem_t *mctx, ldap_instance_t *ldap_inst,
	  settings_set_t *glob_settings, zone_register_t **zrp)
{
	isc_result_t result;
	zone_register_t *zr = NULL;

	REQUIRE(ldap_inst != NULL);
	REQUIRE(glob_settings != NULL);
	REQUIRE(zrp != NULL && *zrp == NULL);

	CHECKED_MEM_GET_PTR(mctx, zr);
	ZERO_PTR(zr);
	isc_mem_attach(mctx, &zr->mctx);
	CHECK(dns_rbt_create(mctx, delete_zone_info, mctx, &zr->rbt));
	CHECK(isc_rwlock_init(&zr->rwlock, 0, 0));
	zr->global_settings = glob_settings;
	zr->ldap_inst = ldap_inst;

	*zrp = zr;
	return ISC_R_SUCCESS;

cleanup:
	if (zr != NULL) {
		if (zr->rbt != NULL)
			dns_rbt_destroy(&zr->rbt);
		MEM_PUT_AND_DETACH(zr);
	}

	return result;
}

/**
 * Destroy a zone register and unload all zones registered in it.
 *
 * @warning
 * Potentially ISC_R_NOSPACE can occur. Destroy codepath has no way to
 * return errors, so kill BIND. DNS_R_NAMETOOLONG should never happen,
 * because all names were checked while loading.
 */
void
zr_destroy(zone_register_t **zrp)
{
	DECLARE_BUFFERED_NAME(name);
	zone_register_t *zr;
	rbt_iterator_t *iter = NULL;
	isc_result_t result;

	if (zrp == NULL || *zrp == NULL)
		return;

	zr = *zrp;

	/* It is not safe to iterate over RBT and delete nodes at the same
	 * time. Restart iteration after each change. */
	do {
		INIT_BUFFERED_NAME(name);
		result = zr_rbt_iter_init(zr, &iter, &name);
		RUNTIME_CHECK(result == ISC_R_SUCCESS || result == ISC_R_NOTFOUND);
		if (result == ISC_R_SUCCESS) {
			rbt_iter_stop(&iter);
			result = ldap_delete_zone2(zr->ldap_inst,
						   &name, false);
			RUNTIME_CHECK(result == ISC_R_SUCCESS);
		}
	} while (result == ISC_R_SUCCESS);

	RWLOCK(&zr->rwlock, isc_rwlocktype_write);
	dns_rbt_destroy(&zr->rbt);
	RWUNLOCK(&zr->rwlock, isc_rwlocktype_write);
	isc_rwlock_destroy(&zr->rwlock);
	MEM_PUT_AND_DETACH(zr);

	*zrp = NULL;
}

/**
 * Get filesystem path associated with particular zone.
 *
 * Zone name will be automatically transformed before usage:
 * - root zone is translated to '@' to prevent collision with filesystem '.'
 * + using dns_name_tofilenametext():
 * - digits, hyphen and underscore are left intact
 * - letters of English alphabet are downcased
 * - all other characters are escaped using %ASCII_HEX form, e.g. '/' => '%2F'
 * - final dot is omited
 * - labels are separated with '.'
 *
 * @param[in]	settings	Set of settings with working "directory".
 * @param[in]	last_component	String to append to the zone's directory.
 * 				Nothing will be appended if it is NULL.
 * @param[out]	path	Newly allocated string with path terminated
 * 			by 'last_component'.
 * 			Caller is responsible for string deallocation.
 *
 * @code
 * Zone name           Output path
 * '.'              => '/var/named/dyndb-ldap/ipa/master/@'
 * 'test.'          => '/var/named/dyndb-ldap/ipa/master/test'
 * 'TEST.0/1.a.'    => '/var/named/dyndb-ldap/ipa/master/test.0%2F1.a'
 * @endcode
 */
isc_result_t
zr_get_zone_path(isc_mem_t *mctx, settings_set_t *settings,
		 dns_name_t *zone_name, const char *last_component,
		 ld_string_t **path) {
	const char *inst_dir = NULL;
	ld_string_t *zone_path = NULL;
	isc_result_t result;

	/* Zone name transformations */
	char name_char[DNS_NAME_FORMATSIZE];
	isc_buffer_t name_buf;
	isc_region_t name_reg;

	REQUIRE(path != NULL && *path == NULL);
	REQUIRE(dns_name_isabsolute(zone_name));

	isc_buffer_init(&name_buf, name_char, sizeof(name_char));
	CHECK(str_new(mctx, &zone_path));
	CHECK(dns_name_tofilenametext(zone_name, true, &name_buf));
	INSIST(isc_buffer_usedlength(&name_buf) > 0);

	/* Root zone is special case: replace '.' with '@'
	 * to avoid collision with self-reference in directory structure */
	if (isc_buffer_usedlength(&name_buf) == 1) {
		isc_buffer_usedregion(&name_buf, &name_reg);
		if (name_reg.base[0] == '.')
			name_reg.base[0] = '@';
	}

	/* NULL-terminate the string */
	isc_buffer_putuint8(&name_buf, '\0');
	INSIST(isc_buffer_usedlength(&name_buf) >= 2);

	CHECK(setting_get_str("directory", settings, &inst_dir));
	CHECK(str_cat_char(zone_path, inst_dir));
	CHECK(str_cat_char(zone_path, "master/"));
	CHECK(str_cat_char(zone_path, isc_buffer_base(&name_buf)));
	CHECK(str_cat_char(zone_path, "/"));
	if (last_component != NULL)
		CHECK(str_cat_char(zone_path, last_component));

cleanup:
	if (result == ISC_R_SUCCESS)
		*path = zone_path;
	else
		str_destroy(&zone_path);

	return result;
}

/**
 * Create a new zone info structure.
 */
#define PRINT_BUFF_SIZE 255
static isc_result_t ATTR_NONNULL(1,2,4,5,6,8)
create_zone_info(isc_mem_t * const mctx, dns_zone_t * const raw,
		dns_zone_t * const secure, const char * const dn,
		 settings_set_t *global_settings, ldap_instance_t *inst,
		 dns_db_t * const ldapdb, zone_info_t **zinfop)
{
	isc_result_t result;
	zone_info_t *zinfo;
	char settings_name[PRINT_BUFF_SIZE];
	ld_string_t *zone_dir = NULL;

	REQUIRE(inst != NULL);
	REQUIRE(raw != NULL);
	REQUIRE(dn != NULL);
	REQUIRE(zinfop != NULL && *zinfop == NULL);

	CHECKED_MEM_GET_PTR(mctx, zinfo);
	ZERO_PTR(zinfo);
	CHECKED_MEM_STRDUP(mctx, dn, zinfo->dn);
	dns_zone_attach(raw, &zinfo->raw);
	if (secure != NULL)
		dns_zone_attach(secure, &zinfo->secure);

	zinfo->settings = NULL;
	/* truncation is allowed */
	snprintf(settings_name, PRINT_BUFF_SIZE, SETTING_SET_NAME_ZONE " %s",
		 dn);
	CHECK(settings_set_create(mctx, zone_settings, sizeof(zone_settings),
				  settings_name, global_settings,
				  &zinfo->settings));

	/* Prepare a directory for this maybesecure */
	CHECK(zr_get_zone_path(mctx, global_settings, dns_zone_getorigin(raw),
			       "keys/", &zone_dir));
	CHECK(fs_dirs_create(str_buf(zone_dir)));

	if (ldapdb == NULL) { /* create new empty database */
		CHECK(ldapdb_create(mctx, dns_zone_getorigin(raw),
				    LDAP_DB_TYPE, LDAP_DB_RDATACLASS,
				    inst, &zinfo->ldapdb));
	} else { /* re-use existing database */
		dns_db_attach(ldapdb, &zinfo->ldapdb);
	}

cleanup:
	if (result == ISC_R_SUCCESS)
		*zinfop = zinfo;
	else
		delete_zone_info(zinfo, mctx);

	str_destroy(&zone_dir);
	return result;
}

/**
 * Delete a zone info structure. The two arguments are of type void * so the
 * function can be used as a node deleter for the red-black tree.
 */
static void ATTR_NONNULL(2)
delete_zone_info(void *arg1, void *arg2)
{
	zone_info_t *zinfo = arg1;
	isc_mem_t *mctx = arg2;

	if (zinfo == NULL)
		return;

	settings_set_free(&zinfo->settings);
	if (zinfo->dn != NULL)
		isc_mem_free(mctx, zinfo->dn);
	if (zinfo->raw != NULL)
		dns_zone_detach(&zinfo->raw);
	if (zinfo->secure != NULL)
		dns_zone_detach(&zinfo->secure);
	if (zinfo->ldapdb != NULL)
		dns_db_detach(&zinfo->ldapdb);
	SAFE_MEM_PUT_PTR(mctx, zinfo);
}

/**
 * Find a zone in ZR with origin exactly matching 'name'.
 *
 * @pre Zone registed is locked.
 */
static isc_result_t
getzinfo(zone_register_t * const zr, const dns_name_t *name,
	 zone_info_t **zinfo)
{
	isc_result_t result;
	void *data = NULL;

	REQUIRE(zr != NULL);
	REQUIRE(dns_name_isabsolute(name));
	REQUIRE(zinfo != NULL && *zinfo == NULL);

	result = dns_rbt_findname(zr->rbt, name, 0, NULL, &data);
	if (result == ISC_R_SUCCESS)
		*zinfo = data;
	else if (result == DNS_R_PARTIALMATCH)
		result = ISC_R_NOTFOUND;

	return result;
}

/**
 * Add 'zone' to the zone register 'zr' with LDAP DN 'dn'. Origin of the zone
 * must be absolute and the zone cannot already be in the zone register.
 */
isc_result_t
zr_add_zone(zone_register_t * const zr, dns_db_t * const ldapdb,
	    dns_zone_t * const raw, dns_zone_t * const secure,
	    const char * const dn)
{
	isc_result_t result;
	dns_name_t *name;
	zone_info_t *new_zinfo = NULL;
	zone_info_t *dummy = NULL;

	REQUIRE(zr != NULL);
	REQUIRE(raw != NULL);
	REQUIRE(dn != NULL);

	name = dns_zone_getorigin(raw);

	RWLOCK(&zr->rwlock, isc_rwlocktype_write);

	/*
	 * First make sure the node doesn't exist. Partial matches mean
	 * there are also child zones in the LDAP database which is allowed.
	 */
	result = getzinfo(zr, name, &dummy);
	if (result != ISC_R_NOTFOUND) {
		if (result == ISC_R_SUCCESS)
			result = ISC_R_EXISTS;
		log_error_r("failed to add zone to the zone register");
		goto cleanup;
	}

	CHECK(create_zone_info(zr->mctx, raw, secure, dn, zr->global_settings,
			       zr->ldap_inst, ldapdb, &new_zinfo));
	CHECK(dns_rbt_addname(zr->rbt, name, new_zinfo));

cleanup:
	RWUNLOCK(&zr->rwlock, isc_rwlocktype_write);

	if (result != ISC_R_SUCCESS) {
		if (new_zinfo != NULL)
			delete_zone_info(new_zinfo, zr->mctx);
	}

	return result;
}

isc_result_t
zr_del_zone(zone_register_t *zr, dns_name_t *origin)
{
	isc_result_t result;

	REQUIRE(zr != NULL);
	REQUIRE(origin != NULL);

	RWLOCK(&zr->rwlock, isc_rwlocktype_write);

	CHECK(dns_rbt_deletename(zr->rbt, origin, false));

cleanup:
	RWUNLOCK(&zr->rwlock, isc_rwlocktype_write);

	if (result == ISC_R_NOTFOUND)
		result = ISC_R_SUCCESS;

	return result;
}

/**
 * Find a zone with 'name' within in the zone register 'zr'. If an
 * exact match is found, the pointer to the LDAP DB and internal
 * RBT DB is attached to ldapdbp or rbtdbp respectively.
 *
 * @remark Caller is responsible for detaching the database pointer.
 *
 * Either ldapdbp or rbtdbp can be NULL.
 */
isc_result_t
zr_get_zone_dbs(zone_register_t *zr, const dns_name_t *name,
		dns_db_t **ldapdbp, dns_db_t **rbtdbp)
{
	isc_result_t result;
	zone_info_t *zinfo = NULL;
	dns_db_t *ldapdb = NULL;

	REQUIRE(zr != NULL);
	REQUIRE(name != NULL);
	REQUIRE(ldapdbp != NULL || rbtdbp != NULL);

	RWLOCK(&zr->rwlock, isc_rwlocktype_read);

	CHECK(getzinfo(zr, name, &zinfo));
	dns_db_attach(zinfo->ldapdb, &ldapdb);
	if (ldapdbp != NULL)
		dns_db_attach(ldapdb, ldapdbp);
	if (rbtdbp != NULL)
		dns_db_attach(ldapdb_get_rbtdb(ldapdb), rbtdbp);

cleanup:
	RWUNLOCK(&zr->rwlock, isc_rwlocktype_read);

	if (ldapdb != NULL)
		dns_db_detach(&ldapdb);

	return result;
}

/**
 * Find zone with origin 'name' in the zone register 'zr'.
 * The 'dn' will be set to the LDAP DN that corresponds to the registered zone.
 *
 * The function returns ISC_R_SUCCESS in case of exact match on zone origin.
 */
isc_result_t
zr_get_zone_dn(zone_register_t *zr, dns_name_t *name, const char **dn)
{
	isc_result_t result;
	zone_info_t *zinfo = NULL;

	REQUIRE(zr != NULL);
	REQUIRE(name != NULL);
	REQUIRE(dn != NULL && *dn == NULL);

	RWLOCK(&zr->rwlock, isc_rwlocktype_read);

	result = getzinfo(zr, name, &zinfo);
	if (result == ISC_R_SUCCESS)
		*dn = zinfo->dn;

	RWUNLOCK(&zr->rwlock, isc_rwlocktype_read);

	return result;
}

/**
 * Get zone pointers from zone register.
 *
 * @param[in]  name    Zone origin
 * @param[out] rawp    Raw zone
 * @param[out] securep Secure zone
 *
 * @pre At least one of rawp/securep has to be non-NULL.
 *
 * @remark Caller has to detach zone pointer after use.
 */
isc_result_t
zr_get_zone_ptr(zone_register_t * const zr, dns_name_t * const name,
		dns_zone_t ** const rawp, dns_zone_t ** const securep)
{
	isc_result_t result;
	zone_info_t *zinfo = NULL;

	REQUIRE(zr != NULL);
	REQUIRE(name != NULL);
	REQUIRE(rawp != NULL || securep != NULL);
	REQUIRE(rawp == NULL || *rawp == NULL);
	REQUIRE(securep == NULL || *securep == NULL);

	RWLOCK(&zr->rwlock, isc_rwlocktype_read);

	result = getzinfo(zr, name, &zinfo);
	if (result == ISC_R_SUCCESS) {
		if (rawp != NULL)
			dns_zone_attach(zinfo->raw, rawp);
		if (zinfo->secure != NULL && securep != NULL)
			dns_zone_attach(zinfo->secure, securep);
	}

	RWUNLOCK(&zr->rwlock, isc_rwlocktype_read);

	return result;
}

/**
 * Find a zone with origin 'name' within in the zone register 'zr'. If an
 * exact match is found, the pointer to the zone's settings is returned through
 * 'set'.
 */
isc_result_t
zr_get_zone_settings(zone_register_t *zr, const dns_name_t *name,
	             settings_set_t **set)
{
	isc_result_t result;
	zone_info_t *zinfo = NULL;

	REQUIRE(zr != NULL);
	REQUIRE(name != NULL);
	REQUIRE(set != NULL && *set == NULL);

	RWLOCK(&zr->rwlock, isc_rwlocktype_read);

	result = getzinfo(zr, name, &zinfo);
	if (result == ISC_R_SUCCESS)
		*set = zinfo->settings;

	RWUNLOCK(&zr->rwlock, isc_rwlocktype_read);

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
isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
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

/* Test if the existing zone is 'empty zone' per RFC 6303. */
bool ATTR_NONNULLS ATTR_CHECKRESULT
zone_isempty(dns_zone_t *zone) {
	char **argv = NULL;
	isc_mem_t *mctx = NULL;
	bool result = false;

	mctx = dns_zone_getmctx(zone);
	if (dns_zone_getdbtype(zone, &argv, mctx) != ISC_R_SUCCESS)
		CLEANUP_WITH(false);

	if (argv[0] != NULL && strcmp("_builtin", argv[0]) == 0 &&
	    argv[1] != NULL && strcmp("empty", argv[1]) == 0) {
		result = true;
	} else {
		result = false;
	}
	isc_mem_free(mctx, argv);

cleanup:
	return result;
}
