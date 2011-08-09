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
#include <isc/once.h>
#include <isc/result.h>
#include <isc/task.h>
#include <isc/timer.h>
#include <isc/util.h>

#include <dns/dynamic_db.h>
#include <dns/view.h>
#include <dns/zone.h>

#include <string.h>

#include "ldap_convert.h"
#include "ldap_helper.h"
#include "log.h"
#include "settings.h"
#include "util.h"
#include "zone_manager.h"

struct db_instance {
	isc_mem_t		*mctx;
	char			*name;
	ldap_instance_t		*ldap_inst;
	isc_timer_t		*timer;
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

	if (db_inst->timer != NULL)
		isc_timer_detach(&db_inst->timer);
	if (db_inst->ldap_inst != NULL)
		destroy_ldap_instance(&db_inst->ldap_inst);
	if (db_inst->name != NULL)
		isc_mem_free(db_inst->mctx, db_inst->name);

	isc_mem_putanddetach(&db_inst->mctx, db_inst, sizeof(*db_inst));

	*db_instp = NULL;
}

static void refresh_zones_action(isc_task_t *task, isc_event_t *event);

isc_result_t
manager_create_db_instance(isc_mem_t *mctx, const char *name,
			   const char * const *argv,
			   dns_dyndb_arguments_t *dyndb_args)
{
	isc_result_t result;
	db_instance_t *db_inst = NULL;
	unsigned int zone_refresh;
	isc_task_t *task;
	setting_t manager_settings[] = {
		{ "zone_refresh", default_uint(0) },
		end_of_settings
	};

	REQUIRE(mctx != NULL);
	REQUIRE(name != NULL);
	REQUIRE(dyndb_args != NULL);

	isc_once_do(&initialize_once, initialize_manager);

	result = find_db_instance(name, &db_inst);
	if (result == ISC_R_SUCCESS) {
		db_inst = NULL;
		result = ISC_R_FAILURE;
		log_error("'%s' already exists", name);
		goto cleanup;
	} else {
		result = ISC_R_SUCCESS;
	}

	/* Parse settings. */
	manager_settings[0].target = &zone_refresh;
	CHECK(set_settings(manager_settings, argv));

	CHECKED_MEM_GET_PTR(mctx, db_inst);
	ZERO_PTR(db_inst);

	isc_mem_attach(mctx, &db_inst->mctx);
	CHECKED_MEM_STRDUP(mctx, name, db_inst->name);
	task = dns_dyndb_get_task(dyndb_args);
	CHECK(new_ldap_instance(mctx, db_inst->name, argv, dyndb_args, task,
				&db_inst->ldap_inst));

	result = refresh_zones_from_ldap(db_inst->ldap_inst);
	if (result != ISC_R_SUCCESS) {
		/* In case we don't find any zones, we at least return
		 * ISC_R_SUCCESS so BIND won't exit because of this. */
		result = ISC_R_SUCCESS;
		log_error("no valid zones found");
		goto cleanup;
	}

	/* Add a timer to periodically refresh the zones. */
	if (zone_refresh) {
		isc_timermgr_t *timer_mgr;
		isc_interval_t interval;

		timer_mgr = dns_dyndb_get_timermgr(dyndb_args);
		isc_interval_set(&interval, zone_refresh, 0);

		CHECK(isc_timer_create(timer_mgr, isc_timertype_ticker, NULL,
				       &interval, task, refresh_zones_action,
				       db_inst, &db_inst->timer));
	}

	LOCK(&instance_list_lock);
	APPEND(instance_list, db_inst, link);
	UNLOCK(&instance_list_lock);

	return ISC_R_SUCCESS;

cleanup:
	if (db_inst != NULL)
		destroy_db_instance(&db_inst);

	return result;
}

static void
refresh_zones_action(isc_task_t *task, isc_event_t *event)
{
	db_instance_t *db_inst = event->ev_arg;

	UNUSED(task);

	refresh_zones_from_ldap(db_inst->ldap_inst);

	isc_event_free(&event);
}

isc_result_t
manager_get_ldap_instance(const char *name, ldap_instance_t **ldap_inst)
{
	isc_result_t result;
	db_instance_t *db_inst;

	REQUIRE(name != NULL);
	REQUIRE(ldap_inst != NULL);

	isc_once_do(&initialize_once, initialize_manager);

	db_inst = NULL;
	CHECK(find_db_instance(name, &db_inst));

	*ldap_inst = db_inst->ldap_inst;

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
