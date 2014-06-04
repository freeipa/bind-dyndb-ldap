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
 * Lock BIND dispatcher and allow only single task to run. This function
 * blocks until task-exclusive mode is entered.
 *
 * Recursive locking is allowed. Auxiliary variable pointed to by "statep"
 * stores information if last run_exclusive_enter() operation really locked
 * something or if the lock was called recursively and was no-op.
 *
 * The pair (task, state) used for run_exclusive_enter() has to be
 * used for run_exclusive_exit().
 *
 * @param[in]  	  task   The only task allowed to run.
 * @param[in,out] statep Lock state: ISC_R_SUCCESS or ISC_R_LOCKBUSY
 */
void
run_exclusive_enter(isc_task_t *task, isc_result_t *statep)
{
	REQUIRE(statep != NULL);
	REQUIRE(*statep == ISC_R_IGNORE);

	*statep = isc_task_beginexclusive(task);
	RUNTIME_CHECK(*statep == ISC_R_SUCCESS || *statep == ISC_R_LOCKBUSY);
}

/**
 * Exit task-exclusive mode.
 *
 * @param task[in]  The only task allowed to run at the moment.
 * @param state[in] Lock state as returned by run_exclusive_enter().
 */
void
run_exclusive_exit(isc_task_t *task, isc_result_t state)
{
	if (state == ISC_R_SUCCESS)
		isc_task_endexclusive(task);
	else
		/* Unlocking recursive lock or the lock was never locked. */
		INSIST(state == ISC_R_LOCKBUSY || state == ISC_R_IGNORE);

	return;
}
