/* Authors: Martin Nagy <mnagy@redhat.com>
 *
 * Copyright (C) 2009  Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 2 only
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
