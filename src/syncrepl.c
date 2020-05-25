/*
 * Copyright (C) 2013-2014  bind-dyndb-ldap authors; see COPYING for license
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
 * @file syncrepl.c
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
 * The initial synchronization in LDAP_SYNC_REFRESH_ONLY mode is done
 * when LDAP search result message was
 * received and all events generated before this message were processed.
 *
 * The initial synchronization in LDAP_SYNC_REFRESH_AND_PERSIST mode is done
 * when LDAP intermediate message (with attribute refreshDone = TRUE) was
 * received and all events generated before this message were processed.
 *
 * LDAP intermediate message handler ldap_sync_intermediate() calls
 * sync_barrier_wait() and it sends sync_barrierev event to all involved tasks.
 * sync_barrier_wait() returns only if all tasks processed all sync_barrierev
 * events. As a result, all events generated before sync_barrier_wait() call
 * are processed before the call returns.
 *
 * @warning There are three assumptions:
 * 	@li Each task processes events in FIFO order.
 * 	@li The task assigned to a LDAP instance or a DNS zone never changes.
 * 	@li All code which depends on machine states is executed sequentially.
 * 	    Asynchronous execution would lead to race conditions.
 * 	    This currently works because all code depending on machine state
 * 	    is directly or indirectly executed from ldap_sync_{init,poll}
 * 	    functions and is synchronous.
 *
 * @see ldap_sync_search_result()
 * @see ldap_sync_intermediate()
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
	ISC_LIST(task_element_t)	tasks;	/**< list of tasks processing
						     events from initial
						     synchronization phase */
	uint32_t			next_id;  /**< next sequential id */
	uint32_t			last_id;  /**< last processed event */
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
	ldap_instance_t	*inst;
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
	sync_barrierev_t *bev = NULL;
	sync_state_t new_state;

	REQUIRE(ISCAPI_TASK_VALID(task));
	REQUIRE(event != NULL);

	bev = (sync_barrierev_t *)event;
	log_debug(1, "sync_barrier_wait(): finish reached");
	LOCK(&bev->sctx->mutex);
	switch (bev->sctx->state) {
		case sync_configbarrier:
			new_state = sync_datainit;
			break;
		case sync_databarrier:
			new_state = sync_finished;
			break;
		case sync_configinit:
		case sync_datainit:
		case sync_finished:
		default:
			FATAL_ERROR(__FILE__, __LINE__,
				    "sync_barrier_wait(): invalid state "
				    "%u", bev->sctx->state);
	}
	sync_state_change(bev->sctx, new_state, false);
	BROADCAST(&bev->sctx->cond);
	UNLOCK(&bev->sctx->mutex);
	if (new_state == sync_finished)
		activate_zones(task, bev->inst);

	if (result != ISC_R_SUCCESS)
		log_error_r("syncrepl finish() failed");
	isc_event_free(&event);
	return;
}

static void ATTR_NONNULLS
sync_finishev_create(sync_ctx_t *sctx, ldap_instance_t *inst,
		      sync_barrierev_t **evp) {
	sync_barrierev_t *ev = NULL;

	REQUIRE(sctx != NULL);
	REQUIRE(inst != NULL);
	REQUIRE(evp != NULL && *evp == NULL);

	ev = (sync_barrierev_t *)isc_event_allocate(sctx->mctx,
				sctx, LDAPDB_EVENT_SYNCREPL_BARRIER,
				finish, NULL,
				sizeof(sync_barrierev_t));

	ev->inst = inst;
	ev->sctx = sctx;
	*evp = ev;

	return;
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
	sync_barrierev_t *bev = NULL;
	sync_barrierev_t *fev = NULL;
	isc_event_t *ev = NULL;
	bool locked = false;

	REQUIRE(ISCAPI_TASK_VALID(task));
	REQUIRE(event != NULL);

	bev = (sync_barrierev_t *)event;
	if (isc_refcount_decrement(&bev->sctx->task_cnt) == 1) {
		log_debug(1, "sync_barrier_wait(): barrier reached");
		LOCK(&bev->sctx->mutex);
		locked = true;
		sync_finishev_create(bev->sctx, bev->inst, &fev);
		ev = (isc_event_t *)fev;
		isc_task_send(ldap_instance_gettask(bev->sctx->inst), &ev);
	}

	if (locked) {
		UNLOCK(&bev->sctx->mutex);
	}
	isc_event_free(&event);
	return;
}

static void ATTR_NONNULLS
sync_barrierev_create(sync_ctx_t *sctx, ldap_instance_t *inst,
		      sync_barrierev_t **evp) {
	sync_barrierev_t *ev = NULL;

	REQUIRE(sctx != NULL);
	REQUIRE(inst != NULL);
	REQUIRE(evp != NULL && *evp == NULL);

	ev = (sync_barrierev_t *)isc_event_allocate(sctx->mctx,
				sctx, LDAPDB_EVENT_SYNCREPL_BARRIER,
				barrier_decrement, NULL,
				sizeof(sync_barrierev_t));

	ev->inst = inst;
	ev->sctx = sctx;
	*evp = ev;

	return;
}

/**
 * Initialize synchronization context.
 *
 * @param[in]	inst	LDAP instance associated with this synchronization ctx.
 * @param[out]	sctxp	The new synchronization context.
 *
 * @post state == sync_configinit
 * @post task_cnt == 1
 * @post tasks list contains the task
 */
isc_result_t
sync_ctx_init(isc_mem_t *mctx, ldap_instance_t *inst, sync_ctx_t **sctxp) {
	isc_result_t result;
	sync_ctx_t *sctx = NULL;
	bool lock_ready = false;
	bool cond_ready = false;
	bool refcount_ready = false;

	REQUIRE(sctxp != NULL && *sctxp == NULL);

	sctx = isc_mem_get(mctx, sizeof(*(sctx)));
	ZERO_PTR(sctx);
	isc_mem_attach(mctx, &sctx->mctx);

	sctx->inst = inst;

	/* isc_mutex_init failures are now fatal */
	isc_mutex_init(&sctx->mutex);
	lock_ready = true;
	/* isc_mutex_init failures are now fatal */
	isc_condition_init(&sctx->cond);
	cond_ready = true;

	/* refcount includes ldap_inst->task implicitly */
	isc_refcount_init(&sctx->task_cnt, 0);
	refcount_ready = true;

	ISC_LIST_INIT(sctx->tasks);

	sctx->state = sync_configinit;
	CHECK(sync_task_add(sctx, ldap_instance_gettask(sctx->inst)));

	CHECK(semaphore_init(&sctx->concurr_limit, LDAP_CONCURRENCY_LIMIT));

	*sctxp = sctx;
	return ISC_R_SUCCESS;

cleanup:
	if (lock_ready == true) {
		/* isc_mutex_destroy failures are now fatal */
		isc_mutex_destroy(&sctx->mutex);
	}
	if (cond_ready == true)
		RUNTIME_CHECK(isc_condition_destroy(&sctx->cond)
			      == ISC_R_SUCCESS);
	if (refcount_ready == true)
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
		(void)isc_refcount_decrement(&sctx->task_cnt);
		SAFE_MEM_PUT_PTR(sctx->mctx, taskel);
	}
	RUNTIME_CHECK(isc_condition_destroy(&sctx->cond) == ISC_R_SUCCESS);
	isc_refcount_destroy(&sctx->task_cnt);
	UNLOCK(&sctx->mutex);

	/* isc_mutex_destroy is void now */
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

/**
 * Change state of synchronization finite state machine.
 *
 * @param[in] lock Request to lock sctx. This is a workaround for missing
 *                 support recursive mutexes in ISC mutex API.
 *
 * @warning Caller has to ensure that sctx is properly locked either externally
 *          or by lock = true parameter. Attempt to lock sctx recursively
 *          will lead to deadlock.
 */
void
sync_state_change(sync_ctx_t *sctx, sync_state_t new_state, bool lock) {
	REQUIRE(sctx != NULL);

	if (lock == true)
		LOCK(&sctx->mutex);

	switch (sctx->state) {
	case sync_configinit:
		/* initial synchronization is finished
		 * and ldap_sync_search_result() was called */
		INSIST(new_state == sync_configbarrier);
		break;

	case sync_configbarrier:
		/* sync_barrier_wait(sync_configinit) finished */
		INSIST(new_state == sync_datainit);
		break;

	case sync_datainit:
		/* refresh phase is finished
		 * and ldap_sync_intermediate() was called */
		INSIST(new_state == sync_databarrier);
		break;

	case sync_databarrier:
		/* sync_barrier_wait(sync_databarrier) finished */
		INSIST(new_state == sync_finished);
		break;

	case sync_finished:
		/* state finished cannot be taken back, ever */
	default:
		fatal_error("invalid synchronization state change %u -> %u",
			    sctx->state, new_state);
	}

	sctx->state = new_state;
	log_debug(1, "sctx state %u reached", new_state);
	if (lock == true)
		UNLOCK(&sctx->mutex);
}

/**
 * Reset state of synchronization finite state machine.
 * Reset can be done only before reaching state finished,
 * i.e. when one of initial synchronizations in ldap_syncrepl_watcher failed.
 *
 * @warning The reset can reliably work only if all state transitions
 *          are synchronous. This is necessary to prevent race conditions
 *          between reset and events depending on particular state.
 */
void
sync_state_reset(sync_ctx_t *sctx) {
	REQUIRE(sctx != NULL);

	LOCK(&sctx->mutex);

	switch (sctx->state) {
	case sync_configinit:
	case sync_configbarrier:
	case sync_datainit:
	case sync_databarrier:
		sctx->state = sync_configinit;
		break;

	case sync_finished:
		/* state finished cannot be taken back, ever */
	default:
		fatal_error("invalid attempt to reset synchronization state");
	}

	log_debug(1, "sctx state %u reached (reset)", sctx->state);
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
	task_element_t *newel = NULL;

	REQUIRE(sctx != NULL);
	REQUIRE(ISCAPI_TASK_VALID(task));

	newel = isc_mem_get(sctx->mctx, sizeof(*(newel)));
	ZERO_PTR(newel);
	ISC_LINK_INIT(newel, link);
	newel->task = NULL;
	isc_task_attach(task, &newel->task);

	LOCK(&sctx->mutex);
	REQUIRE(sctx->state == sync_configinit || sctx->state == sync_datainit);
	ISC_LIST_APPEND(sctx->tasks, newel, link);
	isc_refcount_increment0(&sctx->task_cnt);
	UNLOCK(&sctx->mutex);

	log_debug(2, "adding task %p to syncrepl list; %lu tasks in list",
		  task, isc_refcount_current(&sctx->task_cnt));

	return ISC_R_SUCCESS;
}

/**
 * Wait until all tasks in sctx->tasks list process all events enqueued
 * before sync_barrier_wait() call.
 *
 * @param[in,out]	sctx		Synchronization context
 * @param[in]		inst_name	LDAP instance name for given sctx
 *
 * @pre  sctx->state == sync_configinit || sync_datainit
 * @post sctx->state == sync_finished and all tasks processed all events
 *       enqueued before sync_barrier_wait() call.
 */
isc_result_t
sync_barrier_wait(sync_ctx_t *sctx, ldap_instance_t *inst) {
	isc_event_t *ev = NULL;
	sync_barrierev_t *bev = NULL;
	sync_state_t barrier_state;
	sync_state_t final_state;
	task_element_t *taskel = NULL;
	task_element_t *next_taskel = NULL;

	LOCK(&sctx->mutex);
	REQUIRE(sctx->state == sync_configinit || sctx->state == sync_datainit);
	REQUIRE(!EMPTY(sctx->tasks));

	switch (sctx->state) {
		case sync_configinit:
			barrier_state = sync_configbarrier;
			final_state = sync_datainit;
			break;
		case sync_datainit:
			barrier_state = sync_databarrier;
			final_state = sync_finished;
			break;
		case sync_configbarrier:
		case sync_databarrier:
		case sync_finished:
		default:
			FATAL_ERROR(__FILE__, __LINE__,
				    "sync_barrier_wait(): invalid state "
				    "%u", sctx->state);
	}

	sync_state_change(sctx, barrier_state, false);
	for (taskel = next_taskel = HEAD(sctx->tasks);
	     taskel != NULL;
	     taskel = next_taskel) {
		bev = NULL;
		sync_barrierev_create(sctx, inst, &bev);
		next_taskel = NEXT(taskel, link);
		UNLINK(sctx->tasks, taskel, link);
		ev = (isc_event_t *)bev;
		isc_task_sendanddetach(&taskel->task, &ev);
		SAFE_MEM_PUT_PTR(sctx->mctx, taskel);
	}

	log_debug(1, "sync_barrier_wait(): wait until all events are processed");
	while (sctx->state != final_state)
		WAIT(&sctx->cond, &sctx->mutex);
	log_debug(1, "sync_barrier_wait(): all events were processed");

	UNLOCK(&sctx->mutex);

	if (ev != NULL) {
		isc_event_free(&ev);
	}
	return ISC_R_SUCCESS;
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

	while (ldap_instance_isexiting(sctx->inst) == false) {
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
 * Send ISC event to specified task and optionally wait until given event
 * is processed.
 *
 * End of event processing has to be signaled by
 * @see sync_event_signal() call.
 */
isc_result_t
sync_event_send(sync_ctx_t *sctx, isc_task_t *task, ldap_syncreplevent_t **ev,
		bool synchronous) {
	isc_result_t result;
	isc_time_t abs_timeout;
	uint32_t seqid;
	bool locked = false;

	REQUIRE(sctx != NULL);

	LOCK(&sctx->mutex);
	locked = true;
	/* overflow is not a problem as long as the modulo is smaller than
	 * constant used by sync_concurr_limit_wait() */
	(*ev)->seqid = seqid = ++sctx->next_id % 0xffffffff;
	isc_task_send(task, (isc_event_t **)ev);
	while (synchronous == true && sctx->last_id != seqid) {
		if (ldap_instance_isexiting(sctx->inst) == true)
			CLEANUP_WITH(ISC_R_SHUTTINGDOWN);

		result = isc_time_nowplusinterval(&abs_timeout, &shutdown_timeout);
		INSIST(result == ISC_R_SUCCESS);

		WAITUNTIL(&sctx->cond, &sctx->mutex, &abs_timeout);
	}

	result = ISC_R_SUCCESS;

cleanup:
	if (locked == true)
		UNLOCK(&sctx->mutex);
	return result;
}

/**
 * Signal that given syncrepl event was processed.
 */
void
sync_event_signal(sync_ctx_t *sctx, ldap_syncreplevent_t *ev) {
	REQUIRE(sctx != NULL);
	REQUIRE(ev != NULL);

	LOCK(&sctx->mutex);
	sctx->last_id = ev->seqid;
	BROADCAST(&sctx->cond);
	UNLOCK(&sctx->mutex);
}
