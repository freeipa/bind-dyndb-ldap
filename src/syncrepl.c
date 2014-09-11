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
#include <isc/time.h>
#include <isc/util.h>

#include "ldap_helper.h"
#include "util.h"
#include "semaphore.h"
#include "syncrepl.h"
#include "zone_manager.h"

#define LDAPDB_EVENT_SYNCREPL_BARRIER	(LDAPDB_EVENTCLASS + 2)
#define LDAPDB_EVENT_SYNCREPL_FINISH	(LDAPDB_EVENTCLASS + 3)

/** How many unprocessed LDAP events from syncrepl can be in event queue.
 *  Adding new events into the queue is blocked until some events
 *  are processed. */
#define LDAP_CONCURRENCY_LIMIT 100

typedef struct task_element task_element_t;
struct task_element {
	isc_task_t			*task;
	ISC_LINK(task_element_t)	link;
};

/** Timeout for thread synchronization. Conditions are re-checked every three
 * seconds to see if inst->exiting is true or not.
 *
 * The expectation is that no event will wait in queue for three seconds so
 * polling will happen once only and only during BIND shutdown. */
static const isc_interval_t shutdown_timeout = { 3, 0 };

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
	/** limit number of unprocessed LDAP events in queue
	 *  (memory consumption is one of problems) */
	semaphore_t			concurr_limit;

	isc_mutex_t			mutex;	/**< guards rest of the structure */
	isc_condition_t			cond;	/**< for signal when task_cnt == 0 */
	sync_state_t			state;
	ldap_instance_t			*inst;
	isc_event_t			*last_ev; /**< Last processed event */
	ISC_LIST(task_element_t)	tasks;	/**< list of tasks processing
						     events from initial
						     synchronization phase */
};

/**
 * @brief This event is used to separate event queue for particular task to
 * part 'before' and 'after' this event.
 *
 * This is an auxiliary event supporting sync_barrier_wait().
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
 * @brief Event handler for 'sync barrier event' - part 2.
 *
 * This is auxiliary event handler for zone loading and publishing.
 * See also barrier_decrement().
 */
void
finish(isc_task_t *task, isc_event_t *event) {
	isc_result_t result = ISC_R_SUCCESS;
	ldap_instance_t *inst = NULL;
	sync_barrierev_t *bev = NULL;

	REQUIRE(ISCAPI_TASK_VALID(task));
	REQUIRE(event != NULL);

	bev = (sync_barrierev_t *)event;
	CHECK(manager_get_ldap_instance(bev->dbname, &inst));
	log_debug(1, "sync_barrier_wait(): finish reached");
	LOCK(&bev->sctx->mutex);
	REQUIRE(bev->sctx->state == sync_barrier);
	bev->sctx->state = sync_finished;
	isc_condition_broadcast(&bev->sctx->cond);
	UNLOCK(&bev->sctx->mutex);
	activate_zones(task, inst);

cleanup:
	if (result != ISC_R_SUCCESS)
		log_error_r("syncrepl finish() failed");
	isc_event_free(&event);
	return;
}

static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
sync_finishev_create(sync_ctx_t *sctx, const char *inst_name,
		      sync_barrierev_t **evp) {
	sync_barrierev_t *ev = NULL;

	REQUIRE(sctx != NULL);
	REQUIRE(inst_name != NULL);
	REQUIRE(evp != NULL && *evp == NULL);

	ev = (sync_barrierev_t *)isc_event_allocate(sctx->mctx,
				sctx, LDAPDB_EVENT_SYNCREPL_BARRIER,
				finish, NULL,
				sizeof(sync_barrierev_t));
	if (ev == NULL)
		return ISC_R_NOMEMORY;

	ev->dbname = inst_name;
	ev->sctx = sctx;
	*evp = ev;

	return ISC_R_SUCCESS;
}

/**
 * @brief Event handler for 'sync barrier event' - part 1.
 *
 * This is auxiliary event handler for events created by
 * sync_barrierev_create() and sent by sync_barrier_wait().
 *
 * Each call decrements task_cnt counter in synchronization context associated
 * with the particular event. Broadcast will be send to condition in associated
 * synchronization context when task_cnt == 0.
 *
 * Secondly, "finish" event will be generated and sent to sctx->excl_task, i.e.
 * to inst->task when task_cnt == 0.
 * This split is necessary because we have to make sure that DNS view
 * manipulation during zone loading is done only from inst->task
 * (see run_exclusive_enter() comments).
 */
void
barrier_decrement(isc_task_t *task, isc_event_t *event) {
	isc_result_t result = ISC_R_SUCCESS;
	ldap_instance_t *inst = NULL;
	sync_barrierev_t *bev = NULL;
	sync_barrierev_t *fev = NULL;
	isc_event_t *ev = NULL;
	isc_uint32_t cnt;
	isc_boolean_t locked = ISC_FALSE;

	REQUIRE(ISCAPI_TASK_VALID(task));
	REQUIRE(event != NULL);

	bev = (sync_barrierev_t *)event;
	CHECK(manager_get_ldap_instance(bev->dbname, &inst));
	isc_refcount_decrement(&bev->sctx->task_cnt, &cnt);
	if (cnt == 0) {
		log_debug(1, "sync_barrier_wait(): barrier reached");
		LOCK(&bev->sctx->mutex);
		locked = ISC_TRUE;
		CHECK(sync_finishev_create(bev->sctx, bev->dbname, &fev));
		ev = (isc_event_t *)fev;
		isc_task_send(ldap_instance_gettask(bev->sctx->inst), &ev);
	}

cleanup:
	if (locked)
		UNLOCK(&bev->sctx->mutex);
	if (result != ISC_R_SUCCESS)
		log_error_r("barrier_decrement() failed");
	isc_event_free(&event);
	return;
}

static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
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
 * @param[in]	inst	LDAP instance associated with this synchronization ctx.
 * @param[out]	sctxp	The new synchronization context.
 *
 * @post state == sync_init
 * @post task_cnt == 1
 * @post tasks list contains the task
 */
isc_result_t
sync_ctx_init(isc_mem_t *mctx, ldap_instance_t *inst, sync_ctx_t **sctxp) {
	isc_result_t result;
	sync_ctx_t *sctx = NULL;
	isc_boolean_t lock_ready = ISC_FALSE;
	isc_boolean_t cond_ready = ISC_FALSE;
	isc_boolean_t refcount_ready = ISC_FALSE;

	REQUIRE(sctxp != NULL && *sctxp == NULL);

	CHECKED_MEM_GET_PTR(mctx, sctx);
	ZERO_PTR(sctx);
	isc_mem_attach(mctx, &sctx->mctx);

	sctx->inst = inst;

	CHECK(isc_mutex_init(&sctx->mutex));
	lock_ready = ISC_TRUE;
	CHECK(isc_condition_init(&sctx->cond));
	cond_ready = ISC_TRUE;

	/* refcount includes ldap_inst->task implicitly */
	CHECK(isc_refcount_init(&sctx->task_cnt, 0));
	refcount_ready = ISC_TRUE;

	ISC_LIST_INIT(sctx->tasks);

	sctx->state = sync_init;
	CHECK(sync_task_add(sctx, ldap_instance_gettask(sctx->inst)));

	CHECK(semaphore_init(&sctx->concurr_limit, LDAP_CONCURRENCY_LIMIT));

	*sctxp = sctx;
	return ISC_R_SUCCESS;

cleanup:
	if (lock_ready == ISC_TRUE)
		isc_mutex_destroy(&sctx->mutex);
	if (cond_ready == ISC_TRUE)
		isc_condition_init(&sctx->cond);
	if (refcount_ready == ISC_TRUE)
		isc_refcount_destroy(&sctx->task_cnt);
	MEM_PUT_AND_DETACH(sctx);
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

/**
 * Wait until there is a free slot in syncrepl 'queue' - this limits number
 * of unprocessed ISC events to #LDAP_CONCURRENCY_LIMIT.
 *
 * End of syncrepl event processing has to be signalled by
 * sync_concurr_limit_signal() call.
 */
isc_result_t
sync_concurr_limit_wait(sync_ctx_t *sctx) {
	isc_result_t result;
	isc_time_t abs_timeout;

	REQUIRE(sctx != NULL);

	while (ldap_instance_isexiting(sctx->inst) == ISC_FALSE) {
		result = isc_time_nowplusinterval(&abs_timeout,
						  &shutdown_timeout);
		INSIST(result == ISC_R_SUCCESS);

		result = semaphore_wait_timed(&sctx->concurr_limit,
					      &shutdown_timeout);
		if (result == ISC_R_SUCCESS)
			goto cleanup;
	}

	result = ISC_R_SHUTTINGDOWN;

cleanup:
	return result;
}

/**
 * Signal that syncrepl event was processed and the slot in concurrency limit
 * can be freed.
 */
void
sync_concurr_limit_signal(sync_ctx_t *sctx) {
	REQUIRE(sctx != NULL);

	semaphore_signal(&sctx->concurr_limit);
}

/**
 * Wait until given event ev is processed.
 *
 * End of event processing has to be signalled by
 * sync_event_signal() call.
 */
isc_result_t
sync_event_wait(sync_ctx_t *sctx, isc_event_t *ev) {
	isc_result_t result;
	isc_time_t abs_timeout;

	REQUIRE(sctx != NULL);

	LOCK(&sctx->mutex);
	while (sctx->last_ev != ev) {
		if (ldap_instance_isexiting(sctx->inst) == ISC_TRUE)
			CLEANUP_WITH(ISC_R_SHUTTINGDOWN);

		result = isc_time_nowplusinterval(&abs_timeout, &shutdown_timeout);
		INSIST(result == ISC_R_SUCCESS);

		WAITUNTIL(&sctx->cond, &sctx->mutex, &abs_timeout);
	}

	result = ISC_R_SUCCESS;

cleanup:
	UNLOCK(&sctx->mutex);
	return result;
}

/**
 * Signal that given syncrepl event was processed.
 */
void
sync_event_signal(sync_ctx_t *sctx, isc_event_t *ev) {
	REQUIRE(sctx != NULL);
	REQUIRE(ev != NULL);

	LOCK(&sctx->mutex);
	sctx->last_ev = ev;
	BROADCAST(&sctx->cond);
	UNLOCK(&sctx->mutex);
}
