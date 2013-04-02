#include <isc/rwlock.h>
#include <dns/name.h>

#include "rbt_helper.h"
#include "fwd_register.h"
#include "util.h"

struct fwd_register {
	isc_mem_t	*mctx;
	isc_rwlock_t	rwlock;
	dns_rbt_t	*rbt;
};

isc_result_t
fwdr_create(isc_mem_t *mctx, fwd_register_t **fwdrp)
{
	isc_result_t result;
	fwd_register_t *fwdr = NULL;

	REQUIRE(fwdrp != NULL && *fwdrp == NULL);

	CHECKED_MEM_GET_PTR(mctx, fwdr);
	ZERO_PTR(fwdr);
	isc_mem_attach(mctx, &fwdr->mctx);
	CHECK(dns_rbt_create(mctx, NULL, NULL, &fwdr->rbt));
	CHECK(isc_rwlock_init(&fwdr->rwlock, 0, 0));

	*fwdrp = fwdr;
	return ISC_R_SUCCESS;

cleanup:
	if (fwdr != NULL) {
		if (fwdr->rbt != NULL)
			dns_rbt_destroy(&fwdr->rbt);
		MEM_PUT_AND_DETACH(fwdr);
	}

	return result;
}

void
fwdr_destroy(fwd_register_t **fwdrp)
{
	fwd_register_t *fwdr;

	if (fwdrp == NULL || *fwdrp == NULL)
		return;

	fwdr = *fwdrp;

	RWLOCK(&fwdr->rwlock, isc_rwlocktype_write);
	dns_rbt_destroy(&fwdr->rbt);
	RWUNLOCK(&fwdr->rwlock, isc_rwlocktype_write);
	isc_rwlock_destroy(&fwdr->rwlock);
	MEM_PUT_AND_DETACH(fwdr);

	*fwdrp = NULL;
}

/*
 * Add forward zone to the forwarding register 'fwdr'. Origin of the zone
 * must be absolute and the zone cannot already be in the register.
 */
isc_result_t
fwdr_add_zone(fwd_register_t *fwdr, dns_name_t *name)
{
	isc_result_t result;
	void *dummy = NULL;

	REQUIRE(fwdr != NULL);
	REQUIRE(name != NULL);

	if (!dns_name_isabsolute(name)) {
		log_bug("forward zone with bad origin");
		return ISC_R_FAILURE;
	}

	RWLOCK(&fwdr->rwlock, isc_rwlocktype_write);

	/*
	 * First make sure the node doesn't exist. Partial matches mean
	 * there are also child zones in the LDAP database which is allowed.
	 */
	result = dns_rbt_findname(fwdr->rbt, name, 0, NULL, &dummy);
	if (result != ISC_R_NOTFOUND && result != DNS_R_PARTIALMATCH) {
		if (result == ISC_R_SUCCESS)
			result = ISC_R_EXISTS;
		log_error_r("failed to add forward zone to the forwarding register");
		goto cleanup;
	}

	CHECK(dns_rbt_addname(fwdr->rbt, name, FORWARDING_SET_MARK));

cleanup:
	RWUNLOCK(&fwdr->rwlock, isc_rwlocktype_write);

	return result;
}

isc_result_t
fwdr_del_zone(fwd_register_t *fwdr, dns_name_t *name)
{
	isc_result_t result;
	void *dummy = NULL;

	REQUIRE(fwdr != NULL);
	REQUIRE(name != NULL);

	RWLOCK(&fwdr->rwlock, isc_rwlocktype_write);

	result = dns_rbt_findname(fwdr->rbt, name, 0, NULL, (void **)&dummy);
	if (result == ISC_R_NOTFOUND || result == DNS_R_PARTIALMATCH) {
		/* We are done */
		CLEANUP_WITH(ISC_R_SUCCESS);
	} else if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}

	CHECK(dns_rbt_deletename(fwdr->rbt, name, ISC_FALSE));

cleanup:
	RWUNLOCK(&fwdr->rwlock, isc_rwlocktype_write);

	return result;
}

isc_result_t
fwdr_zone_ispresent(fwd_register_t *fwdr, dns_name_t *name) {

	isc_result_t result;
	void *dummy = NULL;

	REQUIRE(fwdr != NULL);
	REQUIRE(name != NULL);

	RWLOCK(&fwdr->rwlock, isc_rwlocktype_read);

	result = dns_rbt_findname(fwdr->rbt, name, 0, NULL, (void **)&dummy);
	if (result == DNS_R_PARTIALMATCH)
		CLEANUP_WITH(ISC_R_NOTFOUND);

cleanup:
	RWUNLOCK(&fwdr->rwlock, isc_rwlocktype_read);

	return result;
}

isc_result_t
fwdr_rbt_iter_init(fwd_register_t *fwdr, rbt_iterator_t **iter,
		   dns_name_t *nodename) {
	if (fwdr->rbt == NULL)
		return ISC_R_NOTFOUND;

	return rbt_iter_first(fwdr->mctx, fwdr->rbt, &fwdr->rwlock, iter,
			      nodename);
}
