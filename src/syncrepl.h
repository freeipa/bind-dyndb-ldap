/*
 * Copyright (C) 2013-2014  bind-dyndb-ldap authors; see COPYING for license
 */

#ifndef SYNCREPL_H_
#define SYNCREPL_H_

/**
 * SyncRepl state is stored inside ldap_instance_t.
 * Attributes in ldap_instance_t are be modified in new_ldap_instance function,
 * which means server is started or reloaded (running single-thread).
 * Before modifying at other places, switch to single-thread mode via
 * isc_task_beginexclusive() and then return back via isc_task_endexclusive()!
 */
typedef struct sync_ctx		sync_ctx_t;
typedef enum sync_state		sync_state_t;
typedef struct sync_barrierev	sync_barrierev_t;

enum sync_state {
	sync_configinit,	/**< initial config synchronization in progress;
				     expecting LDAP result message */
	sync_configbarrier,	/**< waiting until all tasks process events
				     generated during initial synchronization */
	sync_datainit,		/**< initial data synchronization in progress;
				     expecting LDAP intermediate message
				     with refreshDone = TRUE */
	sync_databarrier,	/**< waiting until all tasks process data events
				     generated during initial synchronization */
	sync_finished	/**< initial synchronization done; all events generated
			     during initial synchronization were processed */
};

isc_result_t
sync_ctx_init(isc_mem_t *mctx, ldap_instance_t *inst, sync_ctx_t **sctxp) ATTR_NONNULLS ATTR_CHECKRESULT;

void
sync_ctx_free(sync_ctx_t **statep);

void
sync_state_get(sync_ctx_t *sctx, sync_state_t *statep) ATTR_NONNULLS;

void
sync_state_change(sync_ctx_t *sctx, sync_state_t new_state, isc_boolean_t lock) ATTR_NONNULLS;

void
sync_state_reset(sync_ctx_t *sctx) ATTR_NONNULLS;

isc_result_t
sync_task_add(sync_ctx_t *sctx, isc_task_t *task) ATTR_NONNULLS ATTR_CHECKRESULT;

isc_result_t
sync_barrier_wait(sync_ctx_t *sctx, const char *inst_name) ATTR_NONNULLS ATTR_CHECKRESULT;

isc_result_t
sync_concurr_limit_wait(sync_ctx_t *sctx) ATTR_NONNULLS ATTR_CHECKRESULT;

void
sync_concurr_limit_signal(sync_ctx_t *sctx) ATTR_NONNULLS;

isc_result_t
sync_event_wait(sync_ctx_t *sctx, isc_event_t *ev) ATTR_NONNULLS ATTR_CHECKRESULT;

void
sync_event_signal(sync_ctx_t *sctx, isc_event_t *ev) ATTR_NONNULLS;

#endif /* SYNCREPL_H_ */
