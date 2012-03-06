/*
 * Authors: Adam Tkac   <atkac@redhat.com>
 *          Martin Nagy <mnagy@redhat.com>
 *
 * Copyright (C) 2009  Red Hat
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

#include <isc/mem.h>
#include <isc/result.h>
#include <isc/util.h>

#include <dns/rdata.h>
#include <dns/rdatalist.h>

#include <string.h>

#include "ldap_helper.h" /* TODO: Move things from ldap_helper here? */
#include "rdlist.h"
#include "util.h"


static isc_result_t
rdata_clone(isc_mem_t *mctx, dns_rdata_t *source, dns_rdata_t **targetp)
{
	isc_result_t result;
	dns_rdata_t *target = NULL;
	isc_region_t target_region, source_region;

	REQUIRE(source != NULL);
	REQUIRE(targetp != NULL && *targetp == NULL);

	CHECKED_MEM_GET_PTR(mctx, target);

	dns_rdata_init(target);

	dns_rdata_toregion(source, &source_region);

	CHECKED_MEM_GET(mctx, target_region.base, source_region.length);

	target_region.length = source_region.length;
	memcpy(target_region.base, source_region.base, source_region.length);
	dns_rdata_fromregion(target, source->rdclass, source->type,
			     &target_region);

	*targetp = target;

	return ISC_R_SUCCESS;

cleanup:
	SAFE_MEM_PUT_PTR(mctx, target);

	return result;
}

isc_result_t
rdatalist_clone(isc_mem_t *mctx, dns_rdatalist_t *source,
		dns_rdatalist_t **targetp)
{
	dns_rdatalist_t *target;
	dns_rdata_t *source_rdata;
	dns_rdata_t *target_rdata;
	isc_result_t result;

	REQUIRE(source != NULL);
	REQUIRE(targetp != NULL && *targetp == NULL);

	CHECKED_MEM_GET_PTR(mctx, target);

	dns_rdatalist_init(target);
	target->rdclass = source->rdclass;
	target->type = source->type;
	target->covers = source->covers;
	target->ttl = source->ttl;

	source_rdata = HEAD(source->rdata);
	while (source_rdata != NULL) {
		target_rdata = NULL;
		CHECK(rdata_clone(mctx, source_rdata, &target_rdata));
		APPEND(target->rdata, target_rdata, link);
		source_rdata = NEXT(source_rdata, link);
	}

	*targetp = target;

	return ISC_R_SUCCESS;

cleanup:
	if (target)
		free_rdatalist(mctx, target);
	SAFE_MEM_PUT_PTR(mctx, target);

	return result;
}

isc_result_t
ldap_rdatalist_copy(isc_mem_t *mctx, ldapdb_rdatalist_t source,
		    ldapdb_rdatalist_t *target)
{
	dns_rdatalist_t *rdlist;
	dns_rdatalist_t *new_rdlist;
	isc_result_t result;

	REQUIRE(target != NULL);

	INIT_LIST(*target);

	rdlist = HEAD(source);
	while (rdlist != NULL) {
		new_rdlist = NULL;
		CHECK(rdatalist_clone(mctx, rdlist, &new_rdlist));
		APPEND(*target, new_rdlist, link);

		rdlist = NEXT(rdlist, link);
	}

	return ISC_R_SUCCESS;

cleanup:
	ldapdb_rdatalist_destroy(mctx, target);

	return result;
}
