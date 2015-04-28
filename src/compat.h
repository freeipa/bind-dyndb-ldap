/*
 * Copyright (C) 2009  bind-dyndb-ldap authors; see COPYING for license
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#else
#error "Can't compile without config.h"
#endif

/*
 * dns_rdatalist_fromrdataset() did not exist in older versions of libdns.
 * Add a substitude function here.
 */
#if LIBDNS_VERSION_MAJOR < 40
static inline isc_result_t
dns_rdatalist_fromrdataset(dns_rdataset_t *rdataset,
			   dns_rdatalist_t **rdatalist)
{
	REQUIRE(rdatalist != NULL && rdataset != NULL);

	*rdatalist = rdataset->private1;

	return ISC_R_SUCCESS;
}
#endif /* LIBDNS_VERSION_MAJOR < 40 */

/*
 * In older libdns versions, isc_refcount_init() was defined as a macro.
 * However, in newer versions, it is a function returning isc_result_t type.
 * This piece of code should take care of that problem.
 */
#if LIBDNS_VERSION_MAJOR < 30
#include <isc/refcount.h>

static inline isc_result_t
isc_refcount_init_func(isc_refcount_t *ref, unsigned int n)
{
	isc_refcount_init(ref, n);
	return ISC_R_SUCCESS;
}
#undef isc_refcount_init
#define isc_refcount_init isc_refcount_init_func
#endif /* LIBDNS_VERSION_MAJOR < 30 */
