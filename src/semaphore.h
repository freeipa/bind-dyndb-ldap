/*
 * Copyright (C) 2008-2014  bind-dyndb-ldap authors; see COPYING for license
 */

#ifndef _LD_SEMAPHORE_H_
#define _LD_SEMAPHORE_H_

#include <isc/condition.h>
#include <isc/mutex.h>

#include "util.h"

/* Multiplier for to user-defined connection parameter 'timeout'. */
#define SEM_WAIT_TIMEOUT_MUL 6 /* times */
extern isc_interval_t conn_wait_timeout;

/*
 * Semaphore can be "acquired" multiple times. However, it has a maximum
 * number of times someone can acquire him. If a semaphore is already acquired
 * more times than allowed, it will block until other thread release its,
 */
struct semaphore {
	int value;		/* Maximum number of times you can LOCK()) */
	isc_mutex_t mutex;	/* Mutex protecting this whole struct.     */
	isc_condition_t cond;	/* Condition used for waiting on release.  */
};

typedef struct semaphore	semaphore_t;

/* Public functions. */
isc_result_t	semaphore_init(semaphore_t *sem, int value) ATTR_NONNULLS ATTR_CHECKRESULT;
void		semaphore_destroy(semaphore_t *sem) ATTR_NONNULLS;
void		semaphore_wait(semaphore_t *sem) ATTR_NONNULLS;
isc_result_t	semaphore_wait_timed(semaphore_t *sem,
				     const isc_interval_t * const timeout)
				     ATTR_NONNULLS ATTR_CHECKRESULT;
void		semaphore_signal(semaphore_t *sem) ATTR_NONNULLS;

#endif /* !_LD_SEMAPHORE_H_ */
