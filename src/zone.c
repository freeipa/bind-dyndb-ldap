/*
 * Copyright (C) 2014-2015  bind-dyndb-ldap authors; see COPYING for license
 */

#include <isc/types.h>
#include <isc/util.h>

#include <dns/diff.h>
#include <dns/journal.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/soa.h>
#include <dns/types.h>
#include <dns/soa.h>
#include <dns/update.h>
#include <dns/zone.h>

#include "util.h"

/**
 * Write given diff to zone journal. Journal will be created
 * if it does not exist yet. Diff will stay unchanged.
 */
isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
zone_journal_adddiff(isc_mem_t *mctx, dns_zone_t *zone, dns_diff_t *diff)
{
	isc_result_t result;
	dns_journal_t *journal = NULL;
	char *journal_filename = NULL;

	journal_filename = dns_zone_getjournal(zone);
	CHECK(dns_journal_open(mctx, journal_filename,
			       DNS_JOURNAL_CREATE, &journal));
	CHECK(dns_journal_write_transaction(journal, diff));

cleanup:
	if (journal != NULL)
		dns_journal_destroy(&journal);

	return result;
};

/**
 * Increment SOA serial in given diff tuple and return new numeric value.
 *
 * @pre Soa_tuple operation is ADD or ADDRESIGN and RR type is SOA.
 *
 * @param[in]		method
 * @param[in,out]	soa_tuple	Latest SOA RR in diff.
 * @param[out]		new_serial	SOA serial after incrementation.
 */
isc_result_t ATTR_NONNULL(2) ATTR_CHECKRESULT
zone_soaserial_updatetuple(dns_updatemethod_t method, dns_difftuple_t *soa_tuple,
		  isc_uint32_t *new_serial) {
	isc_uint32_t serial;

	REQUIRE(DNS_DIFFTUPLE_VALID(soa_tuple));
	REQUIRE(soa_tuple->op == DNS_DIFFOP_ADD ||
		soa_tuple->op == DNS_DIFFOP_ADDRESIGN);
	REQUIRE(soa_tuple->rdata.type == dns_rdatatype_soa);

	serial = dns_soa_getserial(&soa_tuple->rdata);
	serial = dns_update_soaserial(serial, method);
	dns_soa_setserial(serial, &soa_tuple->rdata);
	if (new_serial != NULL)
		*new_serial = serial;

	return ISC_R_SUCCESS;
}

/**
 * Generate delete-add tuples for SOA record with incremented SOA serial.
 *
 * @param[in]  db		Database to generate new SOA record for.
 * @param[in]  version		Database version to read SOA from.
 * @param[out] diff		Diff to append delete-add tuples to.
 * @param[out] new_serial	New serial value.
 */
isc_result_t ATTR_NONNULL(1,2,3,4) ATTR_CHECKRESULT
zone_soaserial_addtuple(isc_mem_t *mctx, dns_db_t *db,
			dns_dbversion_t *version, dns_diff_t *diff,
			isc_uint32_t *new_serial) {
	isc_result_t result;
	dns_difftuple_t *del = NULL;
	dns_difftuple_t *add = NULL;

	CHECK(dns_db_createsoatuple(db, version, mctx, DNS_DIFFOP_DEL, &del));
	CHECK(dns_db_createsoatuple(db, version, mctx, DNS_DIFFOP_ADD, &add));
	CHECK(zone_soaserial_updatetuple(dns_updatemethod_unixtime,
					 add, new_serial));
	dns_diff_appendminimal(diff, &del);
	dns_diff_appendminimal(diff, &add);

cleanup:
	if (del != NULL)
		dns_difftuple_free(&del);
	if (add != NULL)
		dns_difftuple_free(&add);
	return result;
}

/**
 * Add all RRs from rdataset to the diff. Create strictly minimal diff.
 */
isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
rdataset_to_diff(isc_mem_t *mctx, dns_diffop_t op, dns_name_t *name,
		dns_rdataset_t *rds, dns_diff_t *diff) {
	dns_difftuple_t *tp = NULL;
	isc_result_t result = ISC_R_SUCCESS;
	dns_rdata_t rdata;

	for (result = dns_rdataset_first(rds);
	     result == ISC_R_SUCCESS;
	     result = dns_rdataset_next(rds)) {
		dns_rdata_init(&rdata);
		dns_rdataset_current(rds, &rdata);
		CHECK(dns_difftuple_create(mctx, op, name, rds->ttl, &rdata,
					   &tp));
		dns_diff_appendminimal(diff, &tp);
	}

cleanup:
	if (result == ISC_R_NOMORE)
		result = ISC_R_SUCCESS;

	return result;
}

/**
 * Add all RRs from rdatalist to the diff. Create strictly minimal diff.
 */
isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
rdatalist_to_diff(isc_mem_t *mctx, dns_diffop_t op, dns_name_t *name,
		  dns_rdatalist_t *rdatalist, dns_diff_t *diff) {
	dns_difftuple_t *tp = NULL;
	isc_result_t result = ISC_R_SUCCESS;

	for (dns_rdata_t *rd = HEAD(rdatalist->rdata);
			  rd != NULL;
			  rd = NEXT(rd, link)) {
		CHECK(dns_difftuple_create(mctx, op, name, rdatalist->ttl, rd,
					   &tp));
		dns_diff_appendminimal(diff, &tp);
	}

cleanup:
	return result;
}
