/*
 * Copyright (C) 2014-2015  bind-dyndb-ldap authors; see COPYING for license
 */

#include <isc/types.h>

#include <dns/journal.h>
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
