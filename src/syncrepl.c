/*
 * Authors: Petr Spacek <pspacek@redhat.com>
 *
 * Copyright (C) 2013 Red Hat
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

#include <unistd.h>

#include <isc/condition.h>
#include <isc/event.h>
#include <isc/mutex.h>
#include <isc/task.h>
#include <isc/util.h>

#include "ldap_helper.h"
#include "util.h"
#include "syncrepl.h"
#include "zone_manager.h"

#define LDAPDB_EVENT_SYNCREPL_BARRIER	(LDAPDB_EVENTCLASS + 2)

typedef struct task_element task_element_t;
struct task_element {
	isc_task_t			*task;
	ISC_LINK(task_element_t)	link;
};

/**
 * @brief Synchronisation context.
 *
 * This structure provides information necessary for detecting the end
 * of initial LDAP synchronization.
 *
 * @section syncrepl-theory RFC 4533 and bind-dyndb-ldap theory
 * LDAP delivers RFC 4533 messages via ldap_sync_init()
 * and ldap_sync_poll() calls. Each LDAP message is translated
 * by syncrepl_update() to an ISC event. This new event is sent to the task
 * associated with LDAP instance or to the task associated with particular DNS
 * zone. Each task involved in event processing is added to task list in
 * struct sync_ctx by sync_task_add() call.
 *
 * The initial synchronization is done when LDAP intermediate message
 * (with attribute refreshDone = TRUE) was received and all events generated
 * before this message were processed.
 *
 * LDAP intermediate message handler ldap_sync_intermediate() calls
 * sync_barrier_wait() and it sends sync_barrierev event to all involved tasks.
 * sync_barrier_wait() returns only if all tasks processed all sync_barrierev
 * events. As a result, all events generated before sync_barrier_wait() call
 * are processed before the call returns.
 *
 * @warning There are two assumptions:
 * 	@li Each task processes events in FIFO order.
 * 	@li The task assigned to a LDAP instance or a DNS zone never changes.
 *
 * @see ldap_sync_search_entry()
 */
struct sync_ctx {
	isc_refcount_t			task_cnt; /**< provides atomic access */
	isc_mem_t			*mctx;

	isc_mutex_t			mutex;	/**< guards rest of the structure */
	isc_condition_t			cond;	/**< for signal when task_cnt == 0 */
	sync_state_t			state;
	ISC_LIST(task_element_t)	tasks;	/**< list of tasks processing
						     events from initial
						     synchronization phase */
};

/**
 * @brief This event is used to separate event queue for particular task to
 * part 'before' and 'after' this event.
 *
 * This is auxiliary event supporting sync_barrier_wait().
 *
 * @todo Solution with inst_name is not very clever. Reference counting would
 *       be much better, but ldap_instance_t doesn't support reference counting.
 */
struct sync_barrierev {
	ISC_EVENT_COMMON(sync_barrierev_t);
	const char	*dbname;
	sync_ctx_t	*sctx;
};

/**
 * @brief Event handler for 'sync barrier event'.
 *
 * This is auxiliary event handler for events created by
 * sync_barrierev_create() and sent by sync_barrier_wait().
 *
 * Each call decrements task_cnt counter in synchronization context associated
 * with the particular event. Broadcast will be send to condition in associated
 * synchronization context when task_cnt == 0.
 */
void
barrier_decrement(isc_task_t *task, isc_event_t *event) {
	isc_result_t result = ISC_R_SUCCESS;
	ldap_instance_t *inst = NULL;
	sync_barrierev_t *bev = NULL;
	isc_uint32_t cnt;

	REQUIRE(ISCAPI_TASK_VALID(task));
	REQUIRE(event != NULL);

	bev = (sync_barrierev_t *)event;
	CHECK(manager_get_ldap_instance(bev->dbname, &inst));
	isc_refcount_decrement(&bev->sctx->task_cnt, &cnt);
	if (cnt == 0) {
		log_debug(1, "sync_barrier_wait(): barrier reached");
		LOCK(&bev->sctx->mutex);
		REQUIRE(bev->sctx->state == sync_barrier);
		bev->sctx->state = sync_finished;
		isc_condition_broadcast(&bev->sctx->cond);
		UNLOCK(&bev->sctx->mutex);
		activate_zones(task, inst);
	}

cleanup:
	if (result != ISC_R_SUCCESS)
		log_error_r("barrier_decrement() failed");
	isc_event_free(&event);
	return;
}

static isc_result_t ATTR_NONNULLS
sync_barrierev_create(sync_ctx_t *sctx, const char *inst_name,
		      sync_barrierev_t **evp) {
	sync_barrierev_t *ev = NULL;

	REQUIRE(sctx != NULL);
	REQUIRE(inst_name != NULL);
	REQUIRE(evp != NULL && *evp == NULL);

	ev = (sync_barrierev_t *)isc_event_allocate(sctx->mctx,
				sctx, LDAPDB_EVENT_SYNCREPL_BARRIER,
				barrier_decrement, NULL,
				sizeof(sync_barrierev_t));
	if (ev == NULL)
		return ISC_R_NOMEMORY;

	ev->dbname = inst_name;
	ev->sctx = sctx;
	*evp = ev;

	return ISC_R_SUCCESS;
}

/**
 * Initialize synchronization context.
 *
 * @param[in]	task	Task used for first synchronization events.
 * 			Typically the ldap_inst->task.
 * @param[out]	sctxp	The new synchronization context.
 *
 * @post state == sync_init
 * @post task_cnt == 1
 * @post tasks list contains the task
 */
isc_result_t
sync_ctx_init(isc_mem_t *mctx, isc_task_t *task, sync_ctx_t **sctxp) {
	isc_result_t result;
	sync_ctx_t *sctx = NULL;
	isc_boolean_t lock_ready = ISC_FALSE;
	isc_boolean_t cond_ready = ISC_FALSE;
	isc_boolean_t refcount_ready = ISC_FALSE;

	REQUIRE(sctxp != NULL && *sctxp == NULL);
	REQUIRE(ISCAPI_TASK_VALID(task));

	CHECKED_MEM_GET_PTR(mctx, sctx);
	ZERO_PTR(sctx);
	isc_mem_attach(mctx, &sctx->mctx);

	CHECK(isc_mutex_init(&sctx->mutex));
	lock_ready = ISC_TRUE;
	CHECK(isc_condition_init(&sctx->cond));
	cond_ready = ISC_TRUE;

	/* refcount includes ldap_inst->task implicitly */
	CHECK(isc_refcount_init(&sctx->task_cnt, 0));
	refcount_ready = ISC_TRUE;

	ISC_LIST_INIT(sctx->tasks);

	sctx->state = sync_init;
	CHECK(sync_task_add(sctx, task));

	*sctxp = sctx;
	return ISC_R_SUCCESS;

cleanup:
	if (lock_ready == ISC_TRUE)
		isc_mutex_destroy(&(*sctxp)->mutex);
	if (cond_ready == ISC_TRUE)
		isc_condition_init(&(*sctxp)->cond);
	if (refcount_ready == ISC_TRUE)
		isc_refcount_destroy(&(*sctxp)->task_cnt);
	MEM_PUT_AND_DETACH(*sctxp);
	return result;
}

void
sync_ctx_free(sync_ctx_t **sctxp) {
	sync_ctx_t *sctx = NULL;
	task_element_t *taskel = NULL;
	task_element_t *next_taskel = NULL;

	REQUIRE(sctxp != NULL);

	if (*sctxp == NULL)
		return;

	sctx = *sctxp;

	/* detach all tasks in task list, decrement refcounter to zero and
	 * deallocate whole task list */
	LOCK(&sctx->mutex);
	for (taskel = next_taskel = HEAD(sctx->tasks);
	     taskel != NULL;
	     taskel = next_taskel) {
		next_taskel = NEXT(taskel, link);
		UNLINK(sctx->tasks, taskel, link);
		isc_task_detach(&taskel->task);
		isc_refcount_decrement(&sctx->task_cnt, NULL);
		SAFE_MEM_PUT_PTR(sctx->mctx, taskel);
	}
	isc_condition_destroy(&sctx->cond);
	isc_refcount_destroy(&sctx->task_cnt);
	UNLOCK(&sctx->mutex);

	isc_mutex_destroy(&(*sctxp)->mutex);
	MEM_PUT_AND_DETACH(*sctxp);
}

void
sync_state_get(sync_ctx_t *sctx, sync_state_t *statep) {
	REQUIRE(sctx != NULL);

	LOCK(&sctx->mutex);
	*statep = sctx->state;
	UNLOCK(&sctx->mutex);
}

void
sync_state_reset(sync_ctx_t *sctx) {
	REQUIRE(sctx != NULL);

	LOCK(&sctx->mutex);
	sctx->state = sync_init;
	UNLOCK(&sctx->mutex);
}

/**
 * @brief Add task to task list in synchronization context.
 *
 * As a result, subsequent sync_barrier_wait() call will wait until all events
 * queued for the task are processed.
 */
isc_result_t
sync_task_add(sync_ctx_t *sctx, isc_task_t *task) {
	isc_result_t result = ISC_R_SUCCESS;
	isc_uint32_t cnt;
	task_element_t *newel = NULL;

	REQUIRE(sctx != NULL);
	REQUIRE(sctx->state == sync_init);
	REQUIRE(ISCAPI_TASK_VALID(task));

	CHECKED_MEM_GET_PTR(sctx->mctx, newel);
	ZERO_PTR(newel);
	ISC_LINK_INIT(newel, link);
	newel->task = NULL;
	isc_task_attach(task, &newel->task);

	LOCK(&sctx->mutex);
	ISC_LIST_APPEND(sctx->tasks, newel, link);
	isc_refcount_increment0(&sctx->task_cnt, &cnt);
	UNLOCK(&sctx->mutex);

	log_debug(2, "adding task %p to syncrepl list; %u tasks in list",
		  task, cnt);

cleanup:
	return result;
}

/**
 * Wait until all tasks in sctx->tasks list process all events enqueued
 * before sync_barrier_wait() call.
 *
 * @param[in,out]	sctx		Synchronization context
 * @param[in]		inst_name	LDAP instance name for given sctx
 *
 * @pre  sctx->state == sync_init
 * @post sctx->state == sync_finished and all tasks processed all events
 *       enqueued before sync_barrier_wait() call.
 */
isc_result_t
sync_barrier_wait(sync_ctx_t *sctx, const char *inst_name) {
	isc_result_t result;
	isc_event_t *ev = NULL;
	sync_barrierev_t *bev = NULL;
	task_element_t *taskel = NULL;
	task_element_t *next_taskel = NULL;

	LOCK(&sctx->mutex);
	REQUIRE(sctx->state == sync_init);
	if (EMPTY(sctx->tasks)) {
		log_bug("sync_barrier_wait(): called with empty task list");
		sctx->state = sync_finished;
		CLEANUP_WITH(ISC_R_SUCCESS);
	}

	sctx->state = sync_barrier;
	for (taskel = next_taskel = HEAD(sctx->tasks);
	     taskel != NULL;
	     taskel = next_taskel) {
		bev = NULL;
		CHECK(sync_barrierev_create(sctx, inst_name, &bev));
		next_taskel = NEXT(taskel, link);
		UNLINK(sctx->tasks, taskel, link);
		ev = (isc_event_t *)bev;
		isc_task_sendanddetach(&taskel->task, &ev);
		SAFE_MEM_PUT_PTR(sctx->mctx, taskel);
	}

	log_debug(1, "sync_barrier_wait(): wait until all events are processed");
	while (sctx->state != sync_finished)
		isc_condition_wait(&sctx->cond, &sctx->mutex);
	log_debug(1, "sync_barrier_wait(): all events were processed");

cleanup:
	UNLOCK(&sctx->mutex);

	if (ev != NULL)
		isc_event_free(&ev);
	return result;
}
