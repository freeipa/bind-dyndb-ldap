#include <stdio.h>

#include <isc/result.h>
#include <isc/types.h>
#include <isc/util.h>

#include <dns/name.h>
#include <dns/zone.h>
#include <dns/zt.h>

#include "empty_zones.h"
#include "util.h"
#include "zone_register.h"

/**
 * These zones should not leak onto the Internet.
 * The list matches BIND commit 8f20f6c9d7ce5a0f0af6ee4c5361832d97b1c5d4
 * (2015-05-15T08:22+1000).
 */
const char *empty_zones[] = {
	/* RFC 1918 */
	"10.IN-ADDR.ARPA",
	"16.172.IN-ADDR.ARPA",
	"17.172.IN-ADDR.ARPA",
	"18.172.IN-ADDR.ARPA",
	"19.172.IN-ADDR.ARPA",
	"20.172.IN-ADDR.ARPA",
	"21.172.IN-ADDR.ARPA",
	"22.172.IN-ADDR.ARPA",
	"23.172.IN-ADDR.ARPA",
	"24.172.IN-ADDR.ARPA",
	"25.172.IN-ADDR.ARPA",
	"26.172.IN-ADDR.ARPA",
	"27.172.IN-ADDR.ARPA",
	"28.172.IN-ADDR.ARPA",
	"29.172.IN-ADDR.ARPA",
	"30.172.IN-ADDR.ARPA",
	"31.172.IN-ADDR.ARPA",
	"168.192.IN-ADDR.ARPA",

	/* RFC 6598 */
	"64.100.IN-ADDR.ARPA",
	"65.100.IN-ADDR.ARPA",
	"66.100.IN-ADDR.ARPA",
	"67.100.IN-ADDR.ARPA",
	"68.100.IN-ADDR.ARPA",
	"69.100.IN-ADDR.ARPA",
	"70.100.IN-ADDR.ARPA",
	"71.100.IN-ADDR.ARPA",
	"72.100.IN-ADDR.ARPA",
	"73.100.IN-ADDR.ARPA",
	"74.100.IN-ADDR.ARPA",
	"75.100.IN-ADDR.ARPA",
	"76.100.IN-ADDR.ARPA",
	"77.100.IN-ADDR.ARPA",
	"78.100.IN-ADDR.ARPA",
	"79.100.IN-ADDR.ARPA",
	"80.100.IN-ADDR.ARPA",
	"81.100.IN-ADDR.ARPA",
	"82.100.IN-ADDR.ARPA",
	"83.100.IN-ADDR.ARPA",
	"84.100.IN-ADDR.ARPA",
	"85.100.IN-ADDR.ARPA",
	"86.100.IN-ADDR.ARPA",
	"87.100.IN-ADDR.ARPA",
	"88.100.IN-ADDR.ARPA",
	"89.100.IN-ADDR.ARPA",
	"90.100.IN-ADDR.ARPA",
	"91.100.IN-ADDR.ARPA",
	"92.100.IN-ADDR.ARPA",
	"93.100.IN-ADDR.ARPA",
	"94.100.IN-ADDR.ARPA",
	"95.100.IN-ADDR.ARPA",
	"96.100.IN-ADDR.ARPA",
	"97.100.IN-ADDR.ARPA",
	"98.100.IN-ADDR.ARPA",
	"99.100.IN-ADDR.ARPA",
	"100.100.IN-ADDR.ARPA",
	"101.100.IN-ADDR.ARPA",
	"102.100.IN-ADDR.ARPA",
	"103.100.IN-ADDR.ARPA",
	"104.100.IN-ADDR.ARPA",
	"105.100.IN-ADDR.ARPA",
	"106.100.IN-ADDR.ARPA",
	"107.100.IN-ADDR.ARPA",
	"108.100.IN-ADDR.ARPA",
	"109.100.IN-ADDR.ARPA",
	"110.100.IN-ADDR.ARPA",
	"111.100.IN-ADDR.ARPA",
	"112.100.IN-ADDR.ARPA",
	"113.100.IN-ADDR.ARPA",
	"114.100.IN-ADDR.ARPA",
	"115.100.IN-ADDR.ARPA",
	"116.100.IN-ADDR.ARPA",
	"117.100.IN-ADDR.ARPA",
	"118.100.IN-ADDR.ARPA",
	"119.100.IN-ADDR.ARPA",
	"120.100.IN-ADDR.ARPA",
	"121.100.IN-ADDR.ARPA",
	"122.100.IN-ADDR.ARPA",
	"123.100.IN-ADDR.ARPA",
	"124.100.IN-ADDR.ARPA",
	"125.100.IN-ADDR.ARPA",
	"126.100.IN-ADDR.ARPA",
	"127.100.IN-ADDR.ARPA",

	/* RFC 5735 and RFC 5737 */
	"0.IN-ADDR.ARPA",	/* THIS NETWORK */
	"127.IN-ADDR.ARPA",	/* LOOPBACK */
	"254.169.IN-ADDR.ARPA",	/* LINK LOCAL */
	"2.0.192.IN-ADDR.ARPA",	/* TEST NET */
	"100.51.198.IN-ADDR.ARPA",	/* TEST NET 2 */
	"113.0.203.IN-ADDR.ARPA",	/* TEST NET 3 */
	"255.255.255.255.IN-ADDR.ARPA",	/* BROADCAST */

	/* Local IPv6 Unicast Addresses */
	"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.IP6.ARPA",
	"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.IP6.ARPA",
	/* LOCALLY ASSIGNED LOCAL ADDRESS SCOPE */
	"D.F.IP6.ARPA",
	"8.E.F.IP6.ARPA",	/* LINK LOCAL */
	"9.E.F.IP6.ARPA",	/* LINK LOCAL */
	"A.E.F.IP6.ARPA",	/* LINK LOCAL */
	"B.E.F.IP6.ARPA",	/* LINK LOCAL */

	/* Example Prefix, RFC 3849. */
	"8.B.D.0.1.0.0.2.IP6.ARPA",

	/* RFC 7534 */
	"EMPTY.AS112.ARPA",

	NULL
};

/**
 * Continue search for qname among automatic empty zones.
 *
 * @param[in,out] iter Intermediate state which must be passed to subsequent
 * 		       empty_zone_search_next() call.
 *
 * @retval ISC_R_SUCCESS A automatic empty zone which is super/sub/equal domain
 * 			 name was found and stored into the iter structure along
 * 			 with information about relation between
 * 			 qname and empty zone name.
 * @retval ISC_R_NOMORE  No other matching empty zone was found.
 * @retval others        Errors from dns_name_fromtext().
 */
isc_result_t
empty_zone_search_next(empty_zone_search_t *iter) {
	isc_result_t result;
	const char *ezchar = NULL;
	isc_buffer_t buffer;
	int order;
	unsigned int nlabels;
	dns_zone_t *zone = NULL;
	bool isempty;

	REQUIRE(iter != NULL);
	REQUIRE(iter->nextidx < sizeof(empty_zones));

	INIT_BUFFERED_NAME(iter->ezname);
	iter->namerel = dns_namereln_none;

	for (ezchar = empty_zones[iter->nextidx];
	     ezchar != NULL;
	     ezchar = empty_zones[++iter->nextidx])
	{
		isc_buffer_constinit(&buffer, ezchar, strlen(ezchar));
		isc_buffer_add(&buffer, strlen(ezchar));
		CHECK(dns_name_fromtext(&iter->ezname, &buffer, dns_rootname, 0,
					NULL));
		iter->namerel = dns_name_fullcompare(&iter->ezname,
						     &iter->qname,
						     &order, &nlabels);
		if (iter->namerel == dns_namereln_commonancestor ||
		    iter->namerel == dns_namereln_none) {
			/* empty zone and domain in question are not related */
			continue;
		} else {
			/* verify if the zone exists and is empty */
			result = dns_zt_find(iter->zonetable, &iter->ezname,
					     0, NULL, &zone);
			if (result == ISC_R_SUCCESS)
				isempty = zone_isempty(zone);
			else if (result == DNS_R_PARTIALMATCH
				 || result == ISC_R_NOTFOUND)
				isempty = false;
			else
				goto cleanup;
			if (zone != NULL)
				dns_zone_detach(&zone);
			if (isempty == false)
				continue;
			++iter->nextidx;
			CLEANUP_WITH(ISC_R_SUCCESS);
		}
	}

	result = ISC_R_NOMORE;

cleanup:
	return result;
};

/**
 * Invalidate iterator and detach its internal pointers.
 */
void
empty_zone_search_stop(empty_zone_search_t *iter) {
	REQUIRE(iter != NULL);

	if (iter->zonetable)
		dns_zt_detach(&iter->zonetable);
}

/**
 * Start search for qname among automatic empty zones.
 * The search must be finished by calling empty_zone_search_stop().
 *
 * @param[in]  qname  Name to compare with list of automatic empty zones.
 * @param[in]  ztable Zone table for affected view.
 * @param[out] iter   Intermediate state which must be passed to subsequent
 * 		      empty_zone_search_next() call. At the same time,
 * 		      the structure contains name of first matching
 * 		      automatic empty zone and relation between names.
 * @returns @see empty_zone_search_next
 */
isc_result_t
empty_zone_search_init(empty_zone_search_t *iter, const dns_name_t *qname,
                       dns_zt_t *ztable) {
	isc_result_t result;

	REQUIRE(iter != NULL);
	REQUIRE(dns_name_isabsolute(qname));

	INIT_BUFFERED_NAME(iter->qname);
	CHECK(dns_name_copy(qname, &iter->qname, NULL));

	INIT_BUFFERED_NAME(iter->ezname);
	iter->nextidx = 0;
	iter->namerel = dns_namereln_none;

	dns_zt_attach(ztable, &iter->zonetable);

	return empty_zone_search_next(iter);

cleanup:
	return result;
}

/**
 * Shutdown automatic empty zone if it is present.
 *
 * @param[in]     ezname     Empty zone name
 * @param[in,out] zonetable  Zonetable from affected view.
 *
 * @retval ISC_R_SUCCESS     Empty zone was found and unloaded.
 * @retval DNS_R_DISALLOWED  Nothing was done because the zone is not
 * 			     an automatic empty zone.
 * @retval ISC_R_NOTFOUND    No zone with given name is present in zone table.
 */
isc_result_t
empty_zone_unload(dns_name_t *ezname, dns_zt_t *zonetable)
{
	isc_result_t result;
	dns_zone_t *zone = NULL;

	CHECK(dns_zt_find(zonetable, ezname, 0, NULL, &zone));
	if (zone_isempty(zone))
		CHECK(delete_bind_zone(zonetable, &zone));
	else
		CLEANUP_WITH(DNS_R_DISALLOWED);

cleanup:
	if (zone != NULL)
		dns_zone_detach(&zone);

	if (result == DNS_R_PARTIALMATCH)
		result = ISC_R_NOTFOUND;

	return result;
}


/**
 * Detect if given name is super/sub/equal domain to any of automatic empty
 * zones. If such empty zone is found and warn_only == FALSE,
 * the conflicting empty zone will be automatically unloaded so
 * forwarding will work as configured by user.
 *
 * It allows queries to leak to the public Internet if:
 * a) The query name does not belong to forwarded domain:
 *    - empty zone = 10.in-addr.arpa
 *    - forward zone = 1.10.in-addr.arpa
 *    - qname = 2.10.in-addr.arpa
 *
 * b) Forward zone is a superdomain but
 *    it failed and user configured policy != only.
 */
isc_result_t
empty_zone_handle_conflicts(const dns_name_t *name, dns_zt_t *zonetable,
			    bool warn_only)
{
	isc_result_t result;
	bool first = true;
	empty_zone_search_t eziter = {}; /* init with zeroes */
	char name_char[DNS_NAME_FORMATSIZE];
	char ezname_char[DNS_NAME_FORMATSIZE];

	for (result = empty_zone_search_init(&eziter, name, zonetable);
	     result == ISC_R_SUCCESS;
	     result = empty_zone_search_next(&eziter))
	{
		dns_name_format(name, name_char, DNS_NAME_FORMATSIZE);
		if (warn_only == true) {
			dns_name_format(&eziter.ezname, ezname_char,
					DNS_NAME_FORMATSIZE);
			log_warn("ignoring inherited 'forward first;' for zone "
				 "'%s' - did you want 'forward only;' "
				 "to override automatic empty zone '%s'?",
				 name_char, ezname_char);
			continue;
		}

		/* Shutdown automatic empty zone if it is present. */
		result = empty_zone_unload(&eziter.ezname, zonetable);
		if (result == ISC_R_SUCCESS) {
			if (first == true) {
				log_info("shutting down automatic empty zones to "
					 "enable forwarding for domain '%s'", name_char);
				first = false;
			}
		} else if (result == DNS_R_DISALLOWED) {
			/* A normal (non-empty) zone exists:
			 * Do not change its forwarding configuration. */
			continue;
		} else if (result != ISC_R_NOTFOUND)
			goto cleanup;
	}
	if (result == ISC_R_NOMORE)
		result = ISC_R_SUCCESS;

cleanup:
	empty_zone_search_stop(&eziter);
	return result;
}

/**
 * Global forwarder is equivalent to configuring root zone to be forward zone.
 * This event handles conflict among all empty zones and the root zone.
 * (Naturally all defined empty zones are subdomains of the root.)
 */
void
empty_zone_handle_globalfwd_ev(isc_task_t *task, isc_event_t *event)
{
	ldap_globalfwd_handleez_t *pevent = NULL;

	UNUSED(task);
	REQUIRE(event != NULL);

	pevent = (ldap_globalfwd_handleez_t *)event;
	RUNTIME_CHECK(empty_zone_handle_conflicts(dns_rootname, pevent->ev_arg,
						  pevent->warn_only)
		      == ISC_R_SUCCESS);

	isc_event_free(&event);
}
