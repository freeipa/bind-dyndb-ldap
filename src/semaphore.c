/*
 * Copyright (C) 2008-2014  bind-dyndb-ldap authors; see COPYING for license
 */

/*
 * Note: This implementation doesn't prevent from starvation. This means that
 * if a thread signals the semaphore and then waits for it, it may catch it's
 * own signal. However, for our purposes, this shouldn't be needed.
 */

#include <isc/condition.h>
#include <isc/result.h>
#include <isc/util.h>
#include <isc/time.h>

#include "semaphore.h"
#include "util.h"

/*
 * Timer setting for deadlock detection. Format: seconds, nanoseconds.
 * These values will be overwriten during initialization
 * from set_settings() with max(setting+SEM_WAIT_TIMEOUT_ADD, curr_value).
 *
 * Initial value can be useful in early phases of initialization.
 */
isc_interval_t conn_wait_timeout = { 3, 0 };

/*
 * Initialize a semaphore.
 *
 * sem - allocated semaphore that will be initialized
 * value - number of times we can acquire the semaphore.
 */
isc_result_t
semaphore_init(semaphore_t *sem, int value)
{
	isc_result_t result = ISC_R_SUCCESS;

	REQUIRE(sem != NULL);
	REQUIRE(value > 0);

	sem->value = value;
	/* isc_mutex_init and isc_condition_init failures are now fatal */
	isc_mutex_init(&sem->mutex);
	isc_condition_init(&sem->cond);
	/*
	 * if (result != ISC_R_SUCCESS) {
	 *	// isc_mutex_destroy failures are now fatal
	 *	isc_mutex_destroy(&sem->mutex);
	 * }
	 */

	return result;
}

/*
 * Destroy a semaphore.
 *
 * sem - semaphore to be destroyed.
 */
void
semaphore_destroy(semaphore_t *sem)
{
	if (sem == NULL)
		return;

	/* isc_mutex_destroy is now fatal */
	isc_mutex_destroy(&sem->mutex);
	RUNTIME_CHECK(isc_condition_destroy(&sem->cond) == ISC_R_SUCCESS);
}

/**
 * Wait on semaphore. This operation will try to acquire a lock on the
 * semaphore. If the semaphore is already acquired as many times at it allows,
 * the function will block until someone releases the lock.
 */
void
semaphore_wait(semaphore_t *sem)
{
	REQUIRE(sem != NULL);

	LOCK(&sem->mutex);
	while (sem->value <= 0)
		WAIT(&sem->cond, &sem->mutex);
	sem->value--;

	UNLOCK(&sem->mutex);
}

/**
 * Wait on semaphore. This operation will try to acquire a lock on the
 * semaphore. If the semaphore is already acquired as many times at it allows,
 * the function will block until someone releases the lock OR timeout expires.
 *
 * @return ISC_R_SUCCESS or ISC_R_TIMEDOUT or other errors from ISC libs
 */
isc_result_t
semaphore_wait_timed(semaphore_t *const sem,
		     const isc_interval_t * const timeout)
{
	isc_result_t result;
	isc_time_t abs_timeout;
	REQUIRE(sem != NULL);

	CHECK(isc_time_nowplusinterval(&abs_timeout, timeout));
	LOCK(&sem->mutex);

	while (sem->value <= 0)
		CHECK(WAITUNTIL(&sem->cond, &sem->mutex, &abs_timeout));
	sem->value--;

cleanup:
	UNLOCK(&sem->mutex);
	return result;
}

/*
 * Release the semaphore. This will make sure that another thread (probably
 * already waiting) will be able to acquire the semaphore.
 */
void
semaphore_signal(semaphore_t *sem)
{
	REQUIRE(sem != NULL);

	LOCK(&sem->mutex);

	sem->value++;
	if (sem->value >= 0)
		SIGNAL(&sem->cond);

	UNLOCK(&sem->mutex);
}
