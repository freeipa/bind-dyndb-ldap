/*
 * Copyright (C) 2013-2014  bind-dyndb-ldap authors; see COPYING for license
 */

#ifndef _LD_RBT_HELPER_H_
#define _LD_RBT_HELPER_H_

#include <isc/rwlock.h>
#include <dns/rbt.h>
#include "util.h"

typedef struct rbt_iterator	rbt_iterator_t;

isc_result_t
rbt_iter_first(isc_mem_t *mctx, dns_rbt_t *rbt, isc_rwlock_t *rwlock,
	       rbt_iterator_t **iter, dns_name_t *nodename) ATTR_NONNULLS ATTR_CHECKRESULT;

isc_result_t
rbt_iter_next(rbt_iterator_t **iter, dns_name_t *nodename) ATTR_NONNULLS ATTR_CHECKRESULT;

void
rbt_iter_stop(rbt_iterator_t **iter) ATTR_NONNULLS;

#endif /* !_LD_RBT_HELPER_H_ */
