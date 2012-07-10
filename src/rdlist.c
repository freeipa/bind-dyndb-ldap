/*
 * Authors: Adam Tkac   <atkac@redhat.com>
 *          Martin Nagy <mnagy@redhat.com>
 *
 * Copyright (C) 2009-2012  Red Hat
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
#include <isc/buffer.h>
#include <isc/md5.h>

#include <dns/rdata.h>
#include <dns/rdatalist.h>

#include <string.h>
#include <stdlib.h>

#include "ldap_helper.h" /* TODO: Move things from ldap_helper here? */
#include "rdlist.h"
#include "util.h"


/* useful only for RR sorting purposes */
typedef struct rr_sort rr_sort_t;
struct rr_sort {
	dns_rdatalist_t	*rdatalist;	/* contains RR class, type, TTL */
	isc_region_t	rdatareg;	/* handle to binary area with RR data */
};

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

unsigned int
rdatalist_length(const dns_rdatalist_t *rdlist)
{
	dns_rdata_t *ptr = HEAD(rdlist->rdata);
	unsigned int length = 0;

	while (ptr != NULL) {
		length++;
		ptr = NEXT(ptr, link);
	}

	return length;
}

static int
rr_sort_compare(const void *rdl1, const void *rdl2) {
	const rr_sort_t *r1 = rdl1;
	const rr_sort_t *r2 = rdl2;
	int res;

	res = r1->rdatalist->rdclass - r2->rdatalist->rdclass;
	if (res != 0)
		return res;

	res = r1->rdatalist->type - r2->rdatalist->type;
	if (res != 0)
		return res;

	res = r1->rdatalist->ttl - r2->rdatalist->ttl;
	if (res != 0)
		return res;

	res = isc_region_compare((isc_region_t *)&r1->rdatareg,
			(isc_region_t *)&r2->rdatareg);

	return res;
}

/**
 * Compute MD5 digest from all resource records in input rrdatalist.
 * All RRs are sorted by class, type, ttl and data respectively. For this reason
 * digest should be unambigous.
 *
 * @param rdlist[in] List of RRsets. Each RRset contains a list of individual RR
 * @param digest[out] Pointer to unsigned char[RDLIST_DIGESTLENGTH] array
 * @return ISC_R_SUCCESS and MD5 digest in unsigned char array "digest"
 *         In case of any error the array will stay untouched.
 */
isc_result_t
rdatalist_digest(isc_mem_t *mctx, ldapdb_rdatalist_t *rdlist,
		unsigned char *digest) {
	isc_result_t result;
	isc_buffer_t *rrs = NULL; /* array of all resource records from input rdlist */
	unsigned int rrs_len = 0;
	isc_md5_t md5ctx;

	REQUIRE(rdlist != NULL);
	REQUIRE(digest != NULL);

	/* Compute count of RRs to avoid dynamic reallocations.
	 * The count is expected to be small number (< 20). */
	for (dns_rdatalist_t *rrset = HEAD(*rdlist);
			rrset != NULL;
			rrset = NEXT(rrset, link)) {

		rrs_len += rdatalist_length(rrset);
	}
	CHECK(isc_buffer_allocate(mctx, &rrs, rrs_len*sizeof(rr_sort_t)));

	/* Fill each rr_sort structure in array rrs with pointer to RRset
	 * and coresponding data region from each RR. rrs array will be sorted. */
	for (dns_rdatalist_t *rrset = HEAD(*rdlist);
			rrset != NULL;
			rrset = NEXT(rrset, link)) {

		for (dns_rdata_t *rr = HEAD(rrset->rdata);
				rr != NULL;
				rr = NEXT(rr, link)) {

			rr_sort_t rr_sort_rec;
			rr_sort_rec.rdatalist = rrset;
			dns_rdata_toregion(rr, &rr_sort_rec.rdatareg);

			isc_buffer_putmem(rrs, (const unsigned char *)(&rr_sort_rec),
						sizeof(rr_sort_t));
		}
	}
	qsort(isc_buffer_base(rrs), rrs_len, sizeof(rr_sort_t),	rr_sort_compare);

	isc_md5_init(&md5ctx);
	for (unsigned int i = 0; i < rrs_len; i++ ) {
		rr_sort_t *rr_rec = (rr_sort_t *)isc_buffer_base(rrs) + i;
		isc_md5_update(&md5ctx,
				(const unsigned char *)&rr_rec->rdatalist->rdclass,
				sizeof(rr_rec->rdatalist->rdclass));
		isc_md5_update(&md5ctx,
				(const unsigned char *)&rr_rec->rdatalist->type,
				sizeof(rr_rec->rdatalist->type));
		isc_md5_update(&md5ctx,
				(const unsigned char *)&rr_rec->rdatalist->ttl,
				sizeof(rr_rec->rdatalist->ttl));
		isc_md5_update(&md5ctx,
				(const unsigned char *)(rr_rec->rdatareg.base),
				rr_rec->rdatareg.length);
	}
	isc_md5_final(&md5ctx, digest);
	isc_md5_invalidate(&md5ctx);

cleanup:
	if (rrs != NULL)
		isc_buffer_free(&rrs);

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
