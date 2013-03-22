#include <dns/rbt.h>

#include "rbt_helper.h"

#define LDAPDB_RBTITER_MAGIC ISC_MAGIC('L', 'D', 'P', 'I')

/**
 * Copy the RBT node name, i.e. copies the name pointed to by RBT iterator.
 *
 * @param[in]  iter     Initialized RBT iterator.
 * @param[out] nodename Target dns_name suitable for rbt_fullnamefromnode() call.
 *
 * @pre Nodename has pre-allocated storage space.
 *
 * @retval ISC_R_SUCCESS   Actual name was copied to nodename.
 * @retval ISC_R_NOTFOUND  Iterator doesn't point to any node.
 * @retval DNS_R_EMPTYNAME Iterator points to name without assigned data,
 *                         nodename is unchanged.
 * @retval others          Errors from dns_name_concatenate() and others.
 *
 */
static isc_result_t
rbt_iter_getnodename(rbt_iterator_t *iter, dns_name_t *nodename) {
	isc_result_t result;
	dns_rbtnode_t *node = NULL;

	REQUIRE(iter != NULL);
	REQUIRE(nodename != NULL);
	REQUIRE(ISC_MAGIC_VALID(iter, LDAPDB_RBTITER_MAGIC));

	CHECK(dns_rbtnodechain_current(&iter->chain, NULL, NULL, &node));
	if (node->data == NULL)
		return DNS_R_EMPTYNAME;

	CHECK(dns_rbt_fullnamefromnode(node, nodename));
	result = ISC_R_SUCCESS;

cleanup:
	return result;
}

/**
 * Initialize RBT iterator, lock RBT and copy name of the first node with
 * non-NULL data. Empty RBT nodes (with data == NULL) are ignored.
 *
 * RBT remains locked after iterator initialization. RBT has to be
 * unlocked by reaching end of iteration or explicit rbt_iter_stop() call.
 *
 * @param[in,out] rwlock   guard for RBT, will be read-locked
 * @param[out]    iter     iterator structure, will be initialized
 * @param[out]    nodename dns_name with pre-allocated storage
 *
 * @pre Nodename has pre-allocated storage space.
 *
 * @retval ISC_R_SUCCESS   Node with non-NULL data found,
 *                         RBT is in locked state, iterator is valid,
 *                         nodename holds copy of actual RBT node name.
 * @retval ISC_R_NOTFOUND  Node with non-NULL data is not present,
 *                         RBT is in unlocked state, iterator is invalid.
 * @retval others          Any error from rbt_iter_getnodename() and
 *                         rbt_iter_next().
 */
isc_result_t
rbt_iter_first(isc_mem_t *mctx, dns_rbt_t *rbt, isc_rwlock_t *rwlock,
	       rbt_iterator_t *iter, dns_name_t *nodename) {

	isc_result_t result;

	REQUIRE(rbt != NULL);
	REQUIRE(rwlock != NULL);
	REQUIRE(iter != NULL);

	ZERO_PTR(iter);

	isc_mem_attach(mctx, &iter->mctx);
	dns_rbtnodechain_init(&iter->chain, mctx);
	iter->rbt = rbt;
	iter->rwlock = rwlock;
	iter->locktype = isc_rwlocktype_read;
	iter->magic = LDAPDB_RBTITER_MAGIC;

	RWLOCK(iter->rwlock, iter->locktype);

	result = dns_rbtnodechain_first(&iter->chain, rbt, NULL, NULL);
	if (result != DNS_R_NEWORIGIN) {
		rbt_iter_stop(iter);
		return result;
	}

	result = rbt_iter_getnodename(iter, nodename);
	if (result == DNS_R_EMPTYNAME)
		result = rbt_iter_next(iter, nodename);
	if (result == ISC_R_NOMORE)
		result = ISC_R_NOTFOUND;

	return result;
}

/**
 * Copy name of the next non-empty node in RBT.
 *
 * @param[in]  iter      valid iterator
 * @param[out] nodename  dns_name with pre-allocated storage
 *
 * @pre Nodename has pre-allocated storage space.
 *
 * @retval ISC_R_SUCCESS Nodename holds independent copy of RBT node name,
 *                       RBT is in locked state.
 * @retval ISC_R_NOMORE  Iteration ended, RBT is in unlocked state,
 *                       iterator is no longer valid.
 * @retval others        Errors from dns_name_concatenate() and others.
 */
isc_result_t
rbt_iter_next(rbt_iterator_t *iter, dns_name_t *nodename) {
	isc_result_t result;

	REQUIRE(iter != NULL);
	REQUIRE(ISC_MAGIC_VALID(iter, LDAPDB_RBTITER_MAGIC));
	REQUIRE(iter->locktype != isc_rwlocktype_none);

	do {
		result = dns_rbtnodechain_next(&iter->chain, NULL, NULL);
		if (result != ISC_R_SUCCESS && result != DNS_R_NEWORIGIN)
			goto cleanup;

		result = rbt_iter_getnodename(iter, nodename);
	} while (result == DNS_R_EMPTYNAME);

cleanup:
	if (result != ISC_R_SUCCESS)
		rbt_iter_stop(iter);

	return result;
}

/**
 * Stop RBT iteration and unlock RBT.
 */
void
rbt_iter_stop(rbt_iterator_t *iter) {
	REQUIRE(iter != NULL);
	REQUIRE(ISC_MAGIC_VALID(iter, LDAPDB_RBTITER_MAGIC));

	if (iter->locktype != isc_rwlocktype_none)
		isc_rwlock_unlock(iter->rwlock, iter->locktype);

	dns_rbtnodechain_invalidate(&iter->chain);
	isc_mem_detach(&(iter->mctx));
	ZERO_PTR(iter);
}
