/*
 * Authors: Martin Nagy <mnagy@redhat.com>
 *
 * Copyright (C) 2009  Red Hat
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

#include <isc/mem.h>
#include <isc/rwlock.h>
#include <isc/util.h>
#include <isc/md5.h>

#include <dns/rbt.h>
#include <dns/result.h>
#include <dns/zone.h>

#include <isc/string.h>
#include <string.h>

#include "log.h"
#include "util.h"
#include "zone_register.h"
#include "rdlist.h"
#include "settings.h"
#include "rbt_helper.h"

/*
 * The zone register is a red-black tree that maps a dns name of a zone to the
 * zone's pointer and it's LDAP DN. Synchronization is done by the zr_*
 * functions. The data stored in this structure is needed for conversion of
 * a dns name to DN and to get a pointer of a zone when we need to make changes
 * to it. We could use dns_view_findzone() for this, but that way we would not
 * have any assurance that the found zone is really managed by us.
 */

struct zone_register {
	isc_mem_t	*mctx;
	isc_rwlock_t	rwlock;
	dns_rbt_t	*rbt;
	settings_set_t	*global_settings;
	ldap_instance_t *ldap_inst;
};

typedef struct {
	dns_zone_t	*zone;
	char		*dn;
	isc_uint32_t	serial; /* last value processed by plugin (!= value in DB) */
	unsigned char	digest[RDLIST_DIGESTLENGTH]; /* MD5 digest from all RRs in zone record */
	ldap_cache_t	*cache;
	settings_set_t	*settings;
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
	{ "dyn_update",			no_default_boolean	},
	{ "update_policy",		no_default_string	},
	{ "allow_query",		no_default_string	},
	{ "allow_transfer",		no_default_string	},
	{ "sync_ptr",			no_default_boolean	},
	{ "forward_policy",		no_default_string	},
	{ "forwarders",			no_default_string	},
	end_of_settings
};

isc_result_t
zr_rbt_iter_init(zone_register_t *zr, rbt_iterator_t *iter,
		 dns_name_t *nodename) {
	if (zr->rbt == NULL)
		return ISC_R_NOTFOUND;

	return rbt_iter_first(zr->mctx, zr->rbt, &zr->rwlock, iter, nodename);
}

dns_rbt_t *
zr_get_rbt(zone_register_t *zr)
{
	return zr->rbt;
}

isc_mem_t *
zr_get_mctx(zone_register_t *zr) {
	REQUIRE(zr);

	return zr->mctx;
}

/*
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
	rbt_iterator_t iter;
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
						   &name,
						   ISC_TRUE, ISC_FALSE);
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

/*
 * Create a new zone info structure.
 */
#define PRINT_BUFF_SIZE 255
static isc_result_t
create_zone_info(isc_mem_t *mctx, dns_zone_t *zone, const char *dn,
		settings_set_t *global_settings, zone_info_t **zinfop)
{
	isc_result_t result;
	zone_info_t *zinfo;
	char settings_name[PRINT_BUFF_SIZE];

	REQUIRE(zone != NULL);
	REQUIRE(dn != NULL);
	REQUIRE(zinfop != NULL && *zinfop == NULL);

	CHECKED_MEM_GET_PTR(mctx, zinfo);
	ZERO_PTR(zinfo);
	CHECKED_MEM_STRDUP(mctx, dn, zinfo->dn);
	CHECK(new_ldap_cache(mctx, global_settings, &zinfo->cache));
	dns_zone_attach(zone, &zinfo->zone);
	zinfo->settings = NULL;
	isc_string_printf_truncate(settings_name, PRINT_BUFF_SIZE,
				   SETTING_SET_NAME_ZONE " %s",
				   dn);
	CHECK(settings_set_create(mctx, zone_settings, sizeof(zone_settings),
				  settings_name, global_settings,
				  &zinfo->settings));

	*zinfop = zinfo;
	return ISC_R_SUCCESS;

cleanup:
	delete_zone_info(zinfo, mctx);
	return result;
}

/*
 * Delete a zone info structure. The two arguments are of type void * so the
 * function can be used as a node deleter for the red-black tree.
 */
static void
delete_zone_info(void *arg1, void *arg2)
{
	zone_info_t *zinfo = arg1;
	isc_mem_t *mctx = arg2;

	if (zinfo == NULL)
		return;

	destroy_ldap_cache(&zinfo->cache);
	settings_set_free(&zinfo->settings);
	isc_mem_free(mctx, zinfo->dn);
	dns_zone_detach(&zinfo->zone);
	SAFE_MEM_PUT_PTR(mctx, zinfo);
}

/*
 * Add 'zone' to the zone register 'zr' with LDAP DN 'dn'. Origin of the zone
 * must be absolute and the zone cannot already be in the zone register.
 */
isc_result_t
zr_add_zone(zone_register_t *zr, dns_zone_t *zone, const char *dn)
{
	isc_result_t result;
	dns_name_t *name;
	zone_info_t *new_zinfo = NULL;
	void *dummy = NULL;

	REQUIRE(zr != NULL);
	REQUIRE(zone != NULL);
	REQUIRE(dn != NULL);

	name = dns_zone_getorigin(zone);
	if (!dns_name_isabsolute(name)) {
		log_bug("zone with bad origin");
		return ISC_R_FAILURE;
	}

	RWLOCK(&zr->rwlock, isc_rwlocktype_write);

	/*
	 * First make sure the node doesn't exist. Partial matches mean
	 * there are also child zones in the LDAP database which is allowed.
	 */
	result = dns_rbt_findname(zr->rbt, name, 0, NULL, &dummy);
	if (result != ISC_R_NOTFOUND && result != DNS_R_PARTIALMATCH) {
		if (result == ISC_R_SUCCESS)
			result = ISC_R_EXISTS;
		log_error_r("failed to add zone to the zone register");
		goto cleanup;
	}

	CHECK(create_zone_info(zr->mctx, zone, dn, zr->global_settings,
			       &new_zinfo));
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
	zone_info_t *zinfo = NULL;

	REQUIRE(zr != NULL);
	REQUIRE(origin != NULL);

	RWLOCK(&zr->rwlock, isc_rwlocktype_write);

	result = dns_rbt_findname(zr->rbt, origin, 0, NULL, (void **)&zinfo);
	if (result == ISC_R_NOTFOUND || result == DNS_R_PARTIALMATCH) {
		/* We are done */
		result = ISC_R_SUCCESS;
		goto cleanup;
	} else if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}

	CHECK(dns_rbt_deletename(zr->rbt, origin, ISC_FALSE));

cleanup:
	RWUNLOCK(&zr->rwlock, isc_rwlocktype_write);

	return result;
}

isc_result_t
zr_flush_all_caches(zone_register_t *zr) {
	dns_rbtnodechain_t chain;
	isc_result_t result;

	dns_rbtnodechain_init(&chain, zr->mctx);
	RWLOCK(&zr->rwlock, isc_rwlocktype_write);

	result = dns_rbtnodechain_first(&chain, zr->rbt, NULL, NULL);
	while (result == DNS_R_NEWORIGIN || result == ISC_R_SUCCESS) {
		dns_rbtnode_t *node = NULL;
		ldap_cache_t *cache;

		CHECK(dns_rbtnodechain_current(&chain, NULL, NULL, &node));
		if (node->data != NULL) { /* skip auxiliary RBT nodes */
			cache = ((zone_info_t *)(node->data))->cache;
			CHECK(flush_ldap_cache(cache));
		}
		result = dns_rbtnodechain_next(&chain, NULL, NULL);
	}

cleanup:
	RWUNLOCK(&zr->rwlock, isc_rwlocktype_write);
	if (result == ISC_R_NOMORE || result == ISC_R_NOTFOUND)
		result = ISC_R_SUCCESS;

	return result;
}

isc_result_t
zr_get_zone_cache(zone_register_t *zr, dns_name_t *name, ldap_cache_t **cachep) {
	isc_result_t result;
	void *zinfo = NULL;

	REQUIRE(zr != NULL);
	REQUIRE(name != NULL);
	REQUIRE(cachep != NULL && *cachep == NULL);

	if (!dns_name_isabsolute(name)) {
		log_bug("trying to find zone with a relative name");
		return ISC_R_FAILURE;
	}

	RWLOCK(&zr->rwlock, isc_rwlocktype_read);

	result = dns_rbt_findname(zr->rbt, name, 0, NULL, &zinfo);
	if (result == DNS_R_PARTIALMATCH)
		result = ISC_R_SUCCESS;
	if (result == ISC_R_SUCCESS)
		*cachep = ((zone_info_t *)zinfo)->cache;

	RWUNLOCK(&zr->rwlock, isc_rwlocktype_read);

	return result;
}

/*
 * Find the closest match to zone with origin 'name' in the zone register 'zr'.
 * The 'matched_name' will be set to the name that was matched while finding
 * 'name' in the red-black tree. The 'dn' will be set to the LDAP DN that
 * corresponds to the registered zone.
 *
 * The function returns ISC_R_SUCCESS in case of exact or partial match.
 */
isc_result_t
zr_get_zone_dn(zone_register_t *zr, dns_name_t *name, const char **dn,
	       dns_name_t *matched_name)
{
	isc_result_t result;
	void *zinfo = NULL;

	REQUIRE(zr != NULL);
	REQUIRE(name != NULL);
	REQUIRE(dn != NULL && *dn == NULL);
	REQUIRE(matched_name != NULL);

	if (!dns_name_isabsolute(name)) {
		log_bug("trying to find zone with a relative name");
		return ISC_R_FAILURE;
	}

	RWLOCK(&zr->rwlock, isc_rwlocktype_read);

	result = dns_rbt_findname(zr->rbt, name, 0, matched_name, &zinfo);
	if (result == DNS_R_PARTIALMATCH)
		result = ISC_R_SUCCESS;
	if (result == ISC_R_SUCCESS)
		*dn = ((zone_info_t *)zinfo)->dn;

	RWUNLOCK(&zr->rwlock, isc_rwlocktype_read);

	return result;
}

/*
 * Find a zone with origin 'name' within in the zone register 'zr'. If an
 * exact match is found, the pointer to the zone is returned through 'zonep'.
 * Note that the function will attach the zone pointer and therefore the
 * caller has to detach it after use.
 */
isc_result_t
zr_get_zone_ptr(zone_register_t *zr, dns_name_t *name, dns_zone_t **zonep)
{
	isc_result_t result;
	void *zinfo = NULL;

	REQUIRE(zr != NULL);
	REQUIRE(name != NULL);
	REQUIRE(zonep != NULL && *zonep == NULL);

	if (!dns_name_isabsolute(name)) {
		log_bug("trying to find zone with a relative name");
		return ISC_R_FAILURE;
	}

	RWLOCK(&zr->rwlock, isc_rwlocktype_read);

	result = dns_rbt_findname(zr->rbt, name, 0, NULL, &zinfo);
	if (result == ISC_R_SUCCESS)
		dns_zone_attach(((zone_info_t *)zinfo)->zone, zonep);

	RWUNLOCK(&zr->rwlock, isc_rwlocktype_read);

	return result;
}

/**
 * Return last values processed by autoincrement feature.
 */
isc_result_t
zr_get_zone_serial_digest(zone_register_t *zr, dns_name_t *name,
		isc_uint32_t *serialp, unsigned char ** digestp)
{
	isc_result_t result;
	zone_info_t *zinfo = NULL;

	REQUIRE(zr != NULL);
	REQUIRE(name != NULL);
	REQUIRE(serialp != NULL);
	REQUIRE(digestp != NULL && *digestp == NULL);

	if (!dns_name_isabsolute(name)) {
		log_bug("trying to find zone with a relative name");
		return ISC_R_FAILURE;
	}

	RWLOCK(&zr->rwlock, isc_rwlocktype_read);

	result = dns_rbt_findname(zr->rbt, name, 0, NULL, (void *)&zinfo);
	if (result == ISC_R_SUCCESS) {
		*serialp = zinfo->serial;
		*digestp = zinfo->digest;
	}

	RWUNLOCK(&zr->rwlock, isc_rwlocktype_read);

	return result;
}

/*
 * Find a zone with origin 'name' within in the zone register 'zr'. If an
 * exact match is found, the pointer to the zone's settings is returned through
 * 'set'.
 */
isc_result_t
zr_get_zone_settings(zone_register_t *zr, dns_name_t *name, settings_set_t **set)
{
	isc_result_t result;
	void *zinfo = NULL;

	REQUIRE(zr != NULL);
	REQUIRE(name != NULL);
	REQUIRE(set != NULL && *set == NULL);

	if (!dns_name_isabsolute(name)) {
		log_bug("trying to find zone with a relative name");
		return ISC_R_FAILURE;
	}

	RWLOCK(&zr->rwlock, isc_rwlocktype_read);

	result = dns_rbt_findname(zr->rbt, name, 0, NULL, &zinfo);
	if (result == ISC_R_SUCCESS)
		*set = ((zone_info_t *)zinfo)->settings;

	RWUNLOCK(&zr->rwlock, isc_rwlocktype_read);

	return result;
}

/**
 * Set last SOA serial and digest from RRs processed by autoincrement feature.
 */
isc_result_t
zr_set_zone_serial_digest(zone_register_t *zr, dns_name_t *name,
		isc_uint32_t serial, unsigned char *digest)
{
	isc_result_t result;
	zone_info_t *zinfo = NULL;

	REQUIRE(zr != NULL);
	REQUIRE(name != NULL);
	REQUIRE(digest != NULL);

	if (!dns_name_isabsolute(name)) {
		log_bug("trying to find zone with a relative name");
		return ISC_R_FAILURE;
	}

	RWLOCK(&zr->rwlock, isc_rwlocktype_write);

	result = dns_rbt_findname(zr->rbt, name, 0, NULL, (void *)&zinfo);
	if (result == ISC_R_SUCCESS) {
		zinfo->serial = serial;
		memcpy(zinfo->digest, digest, RDLIST_DIGESTLENGTH);
	}

	RWUNLOCK(&zr->rwlock, isc_rwlocktype_write);

	return result;
}
