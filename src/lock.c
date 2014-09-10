/*
 * Authors: Petr Spacek <pspacek@redhat.com>
 *
 * Copyright (C) 2014 Red Hat
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

#include <isc/task.h>
#include <isc/util.h>

#include "lock.h"

/**
 * Lock BIND dispatcher and allow only single task to run.
 *
 * @warning
 * All calls to isc_task_beginexclusive() have to operate on the same task
 * otherwise it would not be possible to distinguish recursive locking
 * from real conflict on the dispatcher lock.
 * For this reason this wrapper function always works with inst->task.
 * As a result, this function have to be be called only from inst->task.
 *
 * Recursive locking is allowed. Auxiliary variable pointed to by "statep"
 * stores information if last run_exclusive_enter() operation really locked
 * something or if the lock was called recursively and was no-op.
 *
 * The pair (inst, state) used for run_exclusive_enter() has to be
 * used for run_exclusive_exit().
 *
 * @param[in]  	  inst   The instance with the only task which is allowed to run.
 * @param[in,out] statep Lock state: ISC_R_SUCCESS or ISC_R_LOCKBUSY
 */
void
run_exclusive_enter(ldap_instance_t *inst, isc_result_t *statep)
{
	REQUIRE(statep != NULL);
	REQUIRE(*statep == ISC_R_IGNORE);

	*statep = isc_task_beginexclusive(ldap_instance_gettask(inst));
	RUNTIME_CHECK(*statep == ISC_R_SUCCESS || *statep == ISC_R_LOCKBUSY);
}

/**
 * Exit task-exclusive mode.
 *
 * @param[in] inst  The instance used for previous run_exclusive_enter() call.
 * @param[in] state Lock state as returned by run_exclusive_enter().
 */
void
run_exclusive_exit(ldap_instance_t *inst, isc_result_t state)
{
	if (state == ISC_R_SUCCESS)
		isc_task_endexclusive(ldap_instance_gettask(inst));
	else
		/* Unlocking recursive lock or the lock was never locked. */
		INSIST(state == ISC_R_LOCKBUSY || state == ISC_R_IGNORE);

	return;
}
