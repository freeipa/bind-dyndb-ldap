#ifndef _LD_RBT_HELPER_H_
#define _LD_RBT_HELPER_H_

#include <isc/rwlock.h>
#include <dns/rbt.h>
#include "util.h"

struct rbt_iterator {
	unsigned int		magic;
	isc_mem_t		*mctx;
	dns_rbt_t		*rbt;
	isc_rwlock_t		*rwlock;
	isc_rwlocktype_t	locktype;
	dns_rbtnodechain_t	chain;
};

typedef struct rbt_iterator	rbt_iterator_t;

isc_result_t
rbt_iter_first(isc_mem_t *mctx, dns_rbt_t *rbt, isc_rwlock_t *rwlock,
	       rbt_iterator_t *iter, dns_name_t *nodename);

isc_result_t
rbt_iter_next(rbt_iterator_t *iter, dns_name_t *nodename);

void
rbt_iter_stop(rbt_iterator_t *iter);

#endif /* !_LD_RBT_HELPER_H_ */
