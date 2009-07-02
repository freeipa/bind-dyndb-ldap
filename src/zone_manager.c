/* Authors: Martin Nagy <mnagy@redhat.com>
 *
 * Copyright (C) 2009  Red Hat
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

#include <isc/mem.h>
#include <isc/once.h>
#include <isc/result.h>
#include <isc/util.h>

#include <dns/view.h>
#include <dns/zone.h>

#include <string.h>

#include "ldap_convert.h"
#include "ldap_helper.h"
#include "log.h"
#include "util.h"
#include "zone_manager.h"

struct db_instance {
	isc_mem_t		*mctx;
	char			*name;
	ldap_instance_t		*ldap_inst;
	ldap_cache_t		*ldap_cache;
	dns_zonemgr_t		*dns_zone_manager;
	LINK(db_instance_t)	link;
};

static isc_once_t initialize_once = ISC_ONCE_INIT;
static isc_mutex_t instance_list_lock;
static LIST(db_instance_t) instance_list;

static void initialize_manager(void);
static void destroy_db_instance(db_instance_t **db_instp);
static isc_result_t find_db_instance(const char *name, db_instance_t **instance);


static void
initialize_manager(void)
{
	INIT_LIST(instance_list);
	isc_mutex_init(&instance_list_lock);
}

void
destroy_manager(void)
{
	db_instance_t *db_inst;
	db_instance_t *next;

	isc_once_do(&initialize_once, initialize_manager);

	LOCK(&instance_list_lock);
	db_inst = HEAD(instance_list);
	while (db_inst != NULL) {
		next = NEXT(db_inst, link);
		UNLINK(instance_list, db_inst, link);
		destroy_db_instance(&db_inst);
		db_inst = next;
	}
	UNLOCK(&instance_list_lock);
}

static void
destroy_db_instance(db_instance_t **db_instp)
{
	db_instance_t *db_inst;

	REQUIRE(db_instp != NULL && *db_instp != NULL);

	db_inst = *db_instp;

	destroy_ldap_instance(&db_inst->ldap_inst);
	destroy_ldap_cache(&db_inst->ldap_cache);
	if (db_inst->name != NULL)
		isc_mem_free(db_inst->mctx, db_inst->name);

	isc_mem_putanddetach(&db_inst->mctx, db_inst, sizeof(*db_inst));

	*db_instp = NULL;
}

isc_result_t
manager_add_db_instance(isc_mem_t *mctx, const char *name, ldap_instance_t *ldap_inst,
			ldap_cache_t *ldap_cache, dns_zonemgr_t *zmgr)
{
	isc_result_t result;
	db_instance_t *db_inst;

	REQUIRE(mctx != NULL);
	REQUIRE(name != NULL);
	REQUIRE(ldap_inst != NULL);
	REQUIRE(ldap_cache != NULL);
	REQUIRE(zmgr != NULL);

	isc_once_do(&initialize_once, initialize_manager);

	db_inst = NULL;

	result = find_db_instance(name, &db_inst);
	if (result == ISC_R_SUCCESS) {
		db_inst = NULL;
		result = ISC_R_FAILURE;
		log_error("'%s' already exists", name);
		goto cleanup;
	} else {
		result = ISC_R_SUCCESS;
	}

	CHECKED_MEM_GET_PTR(mctx, db_inst);
	CHECKED_MEM_STRDUP(mctx, name, db_inst->name);
	db_inst->mctx = NULL;
	isc_mem_attach(mctx, &db_inst->mctx);
	db_inst->ldap_inst = ldap_inst;
	db_inst->ldap_cache = ldap_cache;
	db_inst->dns_zone_manager = zmgr;

	LOCK(&instance_list_lock);
	APPEND(instance_list, db_inst, link);
	UNLOCK(&instance_list_lock);

	refresh_zones_from_ldap(ldap_inst, name, zmgr);

	return ISC_R_SUCCESS;

cleanup:
	if (db_inst != NULL)
		destroy_db_instance(&db_inst);

	return result;
}

void
manager_refresh_zones(void)
{
	db_instance_t *db_inst;

	LOCK(&instance_list_lock);
	db_inst = HEAD(instance_list);
	while (db_inst != NULL) {
		refresh_zones_from_ldap(db_inst->ldap_inst, db_inst->name,
					db_inst->dns_zone_manager);
		db_inst = NEXT(db_inst, link);
	}

	UNLOCK(&instance_list_lock);
}

isc_result_t
manager_get_ldap_instance_and_cache(const char *name, ldap_instance_t **ldap_inst,
			      ldap_cache_t **ldap_cache)
{
	isc_result_t result;
	db_instance_t *db_inst;

	REQUIRE(name != NULL);
	REQUIRE(ldap_inst != NULL);
	REQUIRE(ldap_cache != NULL);

	isc_once_do(&initialize_once, initialize_manager);

	db_inst = NULL;
	CHECK(find_db_instance(name, &db_inst));

	*ldap_inst = db_inst->ldap_inst;
	*ldap_cache = db_inst->ldap_cache;

cleanup:
	return result;
}

static isc_result_t
find_db_instance(const char *name, db_instance_t **instance)
{
	db_instance_t *iterator;

	REQUIRE(name != NULL);
	REQUIRE(instance != NULL && *instance == NULL);

	LOCK(&instance_list_lock);
	iterator = HEAD(instance_list);
	while (iterator != NULL) {
		if (strcmp(name, iterator->name) == 0)
			break;
		iterator = NEXT(iterator, link);
	}
	UNLOCK(&instance_list_lock);

	if (iterator != NULL) {
		*instance = iterator;
		return ISC_R_SUCCESS;
	}

	return ISC_R_NOTFOUND;
}
