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
	sync_init,	/**< initial synchronisation in progress;
			     expecting LDAP intermediate message
			     with refreshDone = TRUE */
	sync_barrier,	/**< waiting until all tasks process events generated
			     during initial synchronisation phase*/
	sync_finished	/**< initial synchronisation done; all events generated
			     during initial synchronisation were processed */
};

isc_result_t
sync_ctx_init(isc_mem_t *mctx, isc_task_t *task, sync_ctx_t **sctxp) ATTR_NONNULLS ATTR_CHECKRESULT;

void
sync_ctx_free(sync_ctx_t **statep);

void
sync_state_get(sync_ctx_t *sctx, sync_state_t *statep) ATTR_NONNULLS;

void
sync_state_reset(sync_ctx_t *sctx) ATTR_NONNULLS;

isc_result_t
sync_task_add(sync_ctx_t *sctx, isc_task_t *task) ATTR_NONNULLS ATTR_CHECKRESULT;

isc_result_t
sync_barrier_wait(sync_ctx_t *sctx, const char *inst_name) ATTR_NONNULLS ATTR_CHECKRESULT;

void ATTR_NONNULLS
sync_concurr_limit_wait(sync_ctx_t *sctx) ATTR_NONNULLS;

void ATTR_NONNULLS
sync_concurr_limit_signal(sync_ctx_t *sctx) ATTR_NONNULLS;

void
sync_event_wait(sync_ctx_t *sctx, isc_event_t *ev) ATTR_NONNULLS;

void
sync_event_signal(sync_ctx_t *sctx, isc_event_t *ev) ATTR_NONNULLS;

#endif /* SYNCREPL_H_ */
