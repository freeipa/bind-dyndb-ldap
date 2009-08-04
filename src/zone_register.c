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

#include <dns/rbt.h>
#include <dns/result.h>
#include <dns/zone.h>

#include <string.h>

#include "log.h"
#include "util.h"
#include "zone_register.h"

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
};

typedef struct {
	dns_zone_t	*zone;
	char		*dn;
} zone_info_t;

/* Callback for dns_rbt_create(). */
static void delete_zone_info(void *arg1, void *arg2);

/*
 * Create a new zone register.
 */
isc_result_t
zr_create(isc_mem_t *mctx, zone_register_t **zrp)
{
	isc_result_t result;
	zone_register_t *zr = NULL;

	REQUIRE(mctx != NULL);
	REQUIRE(zrp != NULL && *zrp == NULL);

	CHECKED_MEM_GET_PTR(mctx, zr);
	ZERO_PTR(zr);
	isc_mem_attach(mctx, &zr->mctx);
	CHECK(dns_rbt_create(mctx, delete_zone_info, mctx, &zr->rbt));
	CHECK(isc_rwlock_init(&zr->rwlock, 0, 0));

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

/*
 * Destroy a zone register.
 */
void
zr_destroy(zone_register_t **zrp)
{
	zone_register_t *zr;

	if (zrp == NULL || *zrp == NULL)
		return;

	zr = *zrp;

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
static isc_result_t
create_zone_info(isc_mem_t *mctx, dns_zone_t *zone, const char *dn,
		 zone_info_t **zinfop)
{
	isc_result_t result;
	zone_info_t *zinfo;

	REQUIRE(mctx != NULL);
	REQUIRE(zone != NULL);
	REQUIRE(dn != NULL);
	REQUIRE(zinfop != NULL && *zinfop == NULL);

	CHECKED_MEM_GET_PTR(mctx, zinfo);
	CHECKED_MEM_STRDUP(mctx, dn, zinfo->dn);
	zinfo->zone = NULL;
	dns_zone_attach(zone, &zinfo->zone);

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

	REQUIRE(mctx != NULL);

	if (zinfo == NULL)
		return;

	isc_mem_free(mctx, zinfo->dn);
	dns_zone_detach(&zinfo->zone);
	isc_mem_put(mctx, zinfo, sizeof(*zinfo));
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

	/* First make sure the node doesn't exist. */
	result = dns_rbt_findname(zr->rbt, name, 0, NULL, &dummy);
	if (result != ISC_R_NOTFOUND) {
		if (result == ISC_R_SUCCESS)
			result = ISC_R_EXISTS;
		log_error_r("failed to add zone to the zone register");
		goto cleanup;
	}

	CHECK(create_zone_info(zr->mctx, zone, dn, &new_zinfo));
	CHECK(dns_rbt_addname(zr->rbt, name, new_zinfo));

cleanup:
	RWUNLOCK(&zr->rwlock, isc_rwlocktype_write);

	if (result != ISC_R_SUCCESS) {
		if (new_zinfo != NULL)
			delete_zone_info(new_zinfo, zr->mctx);
	}

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
