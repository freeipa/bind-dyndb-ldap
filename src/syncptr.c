/*
 * Copyright (C) 2009-2015  bind-dyndb-ldap authors; see COPYING for license
 */

#include <ldap.h>
#include <sys/socket.h>

#include <isc/event.h>
#include <isc/netaddr.h>
#include <isc/types.h>

#include <dns/byaddr.h>
#include <dns/db.h>
#include <dns/diff.h>
#include <dns/rdatasetiter.h>
#include <dns/zone.h>
#include <dns/zt.h>

#include "util.h"
#include "ldap_convert.h"
#include "ldap_entry.h"
#include "ldap_helper.h"
#include "zone.h"
#include "zone_register.h"


#define SYNCPTR_PREF    "PTR record synchronization "
#define SYNCPTR_FMTPRE  SYNCPTR_PREF "(%s) for A/AAAA '%s' "
#define SYNCPTR_FMTPOST ldap_modop_str(mod_op), a_name_str

static const char * ATTR_CHECKRESULT
ldap_modop_str(unsigned int mod_op) {
	static const char *add = "addition";
	static const char *del = "deletion";

	switch (mod_op) {
	case LDAP_MOD_ADD:
		return add;

	case LDAP_MOD_DELETE:
		return del;

	default:
		INSIST("unsupported LDAP mod_op" == NULL);
		return NULL;
	}
}

static void ATTR_NONNULLS
append_trailing_dot(char *str, unsigned int size) {
	unsigned int length = strlen(str);
	if (str[length] != '.') {
		REQUIRE(length + 1 < size);
		str[length] = '.';
		str[length+1] = '\0';
	}
}

/**
 * Find a reverse zone for given IP address.
 *
 * @param[in]  zonetable Zone table from current DNS view
 * @param[in]  af        Address family
 * @param[in]  ip_str    IP address as a string (IPv4 or IPv6)
 * @param[out] ptr_name  Full DNS domain of the reverse record
 * @param[out] zsettings Set of settings for the DNS zone
 * @param[out] zone      DNS zone containing the reverse record
 *
 * @retval ISC_R_SUCCESS DNS name derived from given IP address belongs to an
 * 			 active reverse zone managed by this LDAP instance.
 * 			 PTR record synchronization can continue.
 * @retval other	 Suitable reverse zone was not found.
 */
static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
ldap_find_ptr(dns_zt_t *zonetable, zone_register_t *zone_register, const int af,
	      const char *ip_str, dns_name_t *ptr_name,
	      settings_set_t **zsettings, dns_zone_t **zone) {
	isc_result_t result;

	REQUIRE(ip_str != NULL);

	union {
		struct in_addr v4;
		struct in6_addr v6;
	} ip;
	isc_netaddr_t isc_ip; /* internal net address representation */

	/* Get string with IP address from change request
	 * and convert it to in_addr structure. */
	if (inet_pton(af, ip_str, &ip) != 1) {
		log_bug(SYNCPTR_PREF "could not convert IP address "
			"from string '%s'", ip_str);
		CLEANUP_WITH(ISC_R_UNEXPECTED);
	}

	/* Only copy data to isc_ip stucture. */
	switch (af) {
	case AF_INET:
		isc_netaddr_fromin(&isc_ip, &ip.v4);
		break;
	case AF_INET6:
		isc_netaddr_fromin6(&isc_ip, &ip.v6);
		break;
	default:
		log_bug("unsupported address family 0x%x", af);
		CLEANUP_WITH(ISC_R_NOTIMPLEMENTED);
		break;
	}

	/*
	 * Convert IP address to PTR record.
	 *
	 * @example
	 * 192.168.0.1 -> 1.0.168.192.in-addr.arpa
	 */
	CHECK(dns_byaddr_createptrname2(&isc_ip, 0, ptr_name));

	/* Find an active zone containing owner name of the PTR record. */
	result = dns_zt_find(zonetable, ptr_name, 0, NULL, zone);
	if (result != ISC_R_SUCCESS && result != DNS_R_PARTIALMATCH)
		goto cleanup;

	/* Get LDAP zone settings.
	 * As a side-effect it checks that the zone is present in zone register,
	 * i.e. the zone is managed by this LDAP instance. */
	result = zr_get_zone_settings(zone_register, dns_zone_getorigin(*zone),
				      zsettings);
	if (result != ISC_R_SUCCESS) {
		char zone_name_str[DNS_NAME_FORMATSIZE];
		char ptr_name_str[DNS_NAME_FORMATSIZE];
		dns_name_format(dns_zone_getorigin(*zone), zone_name_str,
				DNS_NAME_FORMATSIZE);
		dns_name_format(ptr_name, ptr_name_str, DNS_NAME_FORMATSIZE);
		log_error(SYNCPTR_PREF "refused: record '%s' belongs to zone "
			  "'%s' which is not managed by LDAP driver",
			  ptr_name_str, zone_name_str);
		CLEANUP_WITH(ISC_R_UNEXPECTED);
	}

cleanup:
	if (result != ISC_R_SUCCESS) {
		if (*zone != NULL)
			dns_zone_detach(zone);
	}

	return result;
}

/**
 * Check if PTR record's value in RBTDB == name of the modified A/AAAA record.
 * Update will be refused if the PTR name contains multiple PTR records or
 * if the value in RBTDB != expected name.
 *
 * @param[in] a_name     Name of modified A/AAAA record.
 * @param[in] a_name_str Name of modified A/AAAA record as NUL terminated string.
 * @param[in] ptr_name   Name of PTR record generated from IP address in A/AAAA.
 * @param[in] zone       DNS zone containing the PTR record.
 * @param[in] ldapdb     LDAP DNS database from the zone.
 * @param[in] version    Database version for the LDAP DNS database.
 * @param[in] mod_op     LDAP_MOD_DELETE if A/AAAA record is being deleted
 *                       or LDAP_MOD_ADD if A/AAAA record is being added.
 * @param[out] rdataset  Will be set to the existing PTR RR set in the database.
 *                       RR set exists only if dns_rdataset_isassociated()
 *                       returns ISC_TRUE.
 *
 * @retval ISC_R_IGNORE  A and PTR records match, no change is required.
 * @retval ISC_R_SUCCESS Prerequisites fulfilled, update is allowed.
 * @retval other         Errors, update cannot proceed.
 *
 * @code
 * ** A record deletion **
 * ; nsupdate command:
 * update delete www.example.com. IN A	192.0.2.1
 *
 * ; PTR update will be allowed if the zone contains following data:
 * www.example.com.		A	192.0.2.1
 * 1.2.0.192.in-addr.arpa.	PTR	www.example.com.
 *
 * ; PTR update will not be allowed if the zone contains following data:
 * www.example.com.		A	192.0.2.1
 * 1.2.0.192.in-addr.arpa.	PTR	mail.example.com.
 * @endcode
 *
 * @code
 * ** A record addition **
 * ; nsupdate command:
 * update add www.example.com. 3600 IN A 192.0.2.1
 *
 * ; PTR update will be allowed if the zone does not contain A and PTR record.
 *
 * ; PTR update will not be allowed if the zone contains following data:
 * 1.2.0.192.in-addr.arpa. 	PTR	mail.example.com.
 * @endcode
 */
static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
ldap_sync_ptr_validate(dns_name_t *a_name, const char *a_name_str,
		       dns_name_t *ptr_name, dns_zone_t *zone, dns_db_t *ldapdb,
		       dns_dbversion_t *version, int mod_op,
		       dns_rdataset_t *rdataset) {
	isc_result_t result;

	char ptr_name_str[DNS_NAME_FORMATSIZE+1];
	isc_boolean_t ptr_found;
	dns_rdata_ptr_t ptr_rdata;
	char ptr_rdata_str[DNS_NAME_FORMATSIZE+1];
	isc_boolean_t ptr_a_equal = ISC_FALSE; /* GCC requires initialization */

	dns_dbnode_t *ptr_node = NULL;
	dns_fixedname_t found_name;
	dns_rdatasetiter_t *rdataset_it = NULL;
	dns_rdata_t rdata;

	dns_fixedname_init(&found_name);
	dns_rdata_init(&rdata);

	REQUIRE(a_name_str != NULL);
	REQUIRE(rdataset != NULL);

	/* Find PTR RR in database. */
	result = dns_db_find(ldapdb, ptr_name, version, dns_rdatatype_ptr,
			     DNS_DBFIND_NOWILD, 0, &ptr_node,
			     dns_fixedname_name(&found_name), rdataset, NULL);
	switch (result) {
		case ISC_R_SUCCESS:
			INSIST(dns_name_equal(dns_fixedname_name(&found_name),
					      ptr_name) == ISC_TRUE);
			ptr_found = ISC_TRUE;
			break;

		case DNS_R_NXDOMAIN:
		case DNS_R_NXRRSET:
		case DNS_R_EMPTYNAME:
			ptr_found = ISC_FALSE;
			/* PTR RR does not exist */
			break;

		default:
			/* something unexpected happened */
			log_error_r(SYNCPTR_FMTPRE "failed in dns_db_find()",
				    SYNCPTR_FMTPOST);
			goto cleanup;
	}

	/* Find the value of PTR entry. */
	if (ptr_found == ISC_TRUE) {
		INSIST(dns_rdataset_count(rdataset) > 0);
		if (dns_rdataset_count(rdataset) != 1) {
			dns_name_format(ptr_name, ptr_name_str,
					DNS_NAME_FORMATSIZE);
			append_trailing_dot(ptr_name_str, sizeof(ptr_name_str));
			log_error(SYNCPTR_FMTPRE
				  "failed: multiple PTR records under "
				  "name '%s' are not supported",
				  SYNCPTR_FMTPOST, ptr_name_str);
			CLEANUP_WITH(ISC_R_NOTIMPLEMENTED);
		}
		INSIST(dns_rdataset_first(rdataset) == ISC_R_SUCCESS);
		dns_rdataset_current(rdataset, &rdata);
		CHECK(dns_rdata_tostruct(&rdata, &ptr_rdata, NULL));

		/* Compare PTR value with name of the A/AAAA record. */
		if (dns_name_isabsolute(a_name) &&
		    dns_name_isabsolute(&ptr_rdata.ptr) &&
		    dns_name_equal(&ptr_rdata.ptr, a_name)) {
			ptr_a_equal = ISC_TRUE;
		} else {
			ptr_a_equal = ISC_FALSE;
			dns_name_format(ptr_name, ptr_name_str,
					DNS_NAME_FORMATSIZE);
			append_trailing_dot(ptr_name_str,
					    sizeof(ptr_name_str));
			dns_name_format(&ptr_rdata.ptr, ptr_rdata_str,
					DNS_NAME_FORMATSIZE);
			append_trailing_dot(ptr_rdata_str,
					    sizeof(ptr_rdata_str));
		}
	}

	if (mod_op == LDAP_MOD_DELETE) {
		if (ptr_found == ISC_FALSE) {
			log_debug(3, SYNCPTR_FMTPRE "skipped: no PTR records "
				  "found", SYNCPTR_FMTPOST);
			CLEANUP_WITH(ISC_R_IGNORE);

		} else if (ptr_a_equal == ISC_FALSE) {
			log_error(SYNCPTR_FMTPRE "failed: "
				  "existing PTR record '%s' contains unexpected "
				  "value '%s' (value '%s' expected)",
				  SYNCPTR_FMTPOST, ptr_name_str, ptr_rdata_str,
				  a_name_str);
			CLEANUP_WITH(ISC_R_UNEXPECTEDTOKEN);

		}
	} else if (mod_op == LDAP_MOD_ADD && ptr_found == ISC_TRUE) {
		if (ptr_a_equal == ISC_TRUE) {
			log_debug(3, SYNCPTR_FMTPRE "skipped: PTR record with"
				  "desired value is already present",
				  SYNCPTR_FMTPOST);
			CLEANUP_WITH(ISC_R_IGNORE);

		} else {
			log_error(SYNCPTR_FMTPRE "failed: "
				  "existing PTR record '%s' contains unexpected "
				  "value '%s' (value '%s' or no value expected)",
				  SYNCPTR_FMTPOST, ptr_name_str, ptr_rdata_str,
				  a_name_str);
			CLEANUP_WITH(DNS_R_SINGLETON);
		}
	}

	result = ISC_R_SUCCESS;

cleanup:
	if (rdataset_it != NULL)
		dns_rdatasetiter_destroy(&rdataset_it);
	if (ptr_node != NULL)
		dns_db_detachnode(ldapdb, &ptr_node);

	return result;
}

/**
 * Update PTR record to match A/AAAA record.
 *
 * @pre Reverse zone allows dynamic updates.
 *
 * @param[in]  zonetable  Zone table from current DNS view
 * @param[in]  a_name  DNS domain of modified A/AAAA record
 * @param[in]  af      Address family
 * @param[in]  ip_str  IP address as a string (IPv4 or IPv6)
 * @param[in]  mod_op  LDAP_MOD_DELETE if A/AAAA record is being deleted
 *                     or LDAP_MOD_ADD if A/AAAA record is being added.
 *
 * @retval ISC_R_SUCCESS PTR record matches A/AAAA record.
 * @retval other	 Synchronization failed - reverse zone doesn't exist,
 * 			 is not active, is not managed by this LDAP instance,
 * 			 old value in PTR record doesn't match a_name ...
 */
isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
ldap_sync_ptr(isc_mem_t *mctx, ldap_instance_t *ldap_inst, dns_zt_t * zonetable,
	      zone_register_t *zone_register, dns_name_t *a_name, const int af,
	      const char *ip_str, const int mod_op) {
	isc_result_t result;

	char a_name_str[DNS_NAME_FORMATSIZE+1];

	dns_zone_t *ptr_zone = NULL;
	struct dns_fixedname ptr_name;
	dns_rdataset_t old_rdataset;
	dns_rdata_ptr_t new_ptr_rdata;
	unsigned char new_buf[DNS_NAME_MAXWIRE];
	isc_buffer_t new_rdatabuf;
	dns_rdata_t new_rdata;

	settings_set_t *zone_settings = NULL;
	isc_boolean_t zone_dyn_update;
	dns_db_t *ldapdb = NULL;
	dns_dbversion_t *version = NULL;

	dns_diff_t diff;
	dns_difftuple_t *difftp = NULL;

	REQUIRE(mod_op == LDAP_MOD_DELETE || mod_op == LDAP_MOD_ADD);

	dns_fixedname_init(&ptr_name);
	dns_rdataset_init(&old_rdataset);

	DNS_RDATACOMMON_INIT(&new_ptr_rdata, dns_rdatatype_ptr, dns_rdataclass_in);
	isc_buffer_init(&new_rdatabuf, new_buf, sizeof(new_buf));
	dns_rdata_init(&new_rdata);
	dns_diff_init(mctx, &diff);

	/**
	 * Get string representation of PTR record value.
	 * @code
	 * a_name_str = "host.example.com."
	 * @endcode
	 */
	dns_name_format(a_name, a_name_str, DNS_NAME_FORMATSIZE);
	append_trailing_dot(a_name_str, sizeof(a_name_str));

	result = ldap_find_ptr(zonetable, zone_register, af, ip_str,
			       dns_fixedname_name(&ptr_name),
			       &zone_settings, &ptr_zone);
	if (result != ISC_R_SUCCESS) {
		log_error_r(SYNCPTR_FMTPRE "refused: "
			    "unable to find active reverse zone "
			    "for IP address '%s'", SYNCPTR_FMTPOST, ip_str);
		CLEANUP_WITH(ISC_R_NOTFOUND);
	}

	CHECK(setting_get_bool("dyn_update", zone_settings, &zone_dyn_update));
	if (!zone_dyn_update) {
		char zone_name_str[DNS_NAME_FORMATSIZE];
		dns_name_format(dns_zone_getorigin(ptr_zone), zone_name_str,
				DNS_NAME_FORMATSIZE);
		log_error(SYNCPTR_FMTPRE "refused: "
			  "IP address '%s' belongs to reverse zone '%s' "
			  "and dynamic updates are not allowed for that zone",
			  SYNCPTR_FMTPOST, ip_str, zone_name_str);
		CLEANUP_WITH(ISC_R_NOPERM);
	}

	CHECK(dns_zone_getdb(ptr_zone, &ldapdb));
	CHECK(dns_db_newversion(ldapdb, &version));
	result = ldap_sync_ptr_validate(a_name, a_name_str,
					dns_fixedname_name(&ptr_name),
					ptr_zone, ldapdb, version,
					mod_op, &old_rdataset);
	if (result == ISC_R_IGNORE)
		CLEANUP_WITH(ISC_R_SUCCESS);
	else if (result != ISC_R_SUCCESS)
		CLEANUP_WITH(DNS_R_SERVFAIL);

	/* Delete old PTR record if it exists in RBTDB. */
	if (dns_rdataset_isassociated(&old_rdataset))
		CHECK(rdataset_to_diff(mctx, DNS_DIFFOP_DEL,
				       dns_fixedname_name(&ptr_name),
				       &old_rdataset, &diff));

	if (mod_op == LDAP_MOD_ADD) {
		new_ptr_rdata.ptr = *a_name;
		CHECK(dns_rdata_fromstruct(&new_rdata, dns_rdataclass_in,
					   dns_rdatatype_ptr, &new_ptr_rdata,
					   &new_rdatabuf));
		// FIXME: inherit TTL from A/AAAA record?
		CHECK(dns_difftuple_create(mctx, DNS_DIFFOP_ADD,
					   dns_fixedname_name(&ptr_name),
					   DEFAULT_TTL, &new_rdata, &difftp));
		dns_diff_appendminimal(&diff, &difftp);
	}

	CHECK(dns_diff_apply(&diff, ldapdb, version));
	dns_db_closeversion(ldapdb, &version, ISC_TRUE);

cleanup:
	if (dns_rdataset_isassociated(&old_rdataset))
		dns_rdataset_disassociate(&old_rdataset);
	if (difftp != NULL)
		dns_difftuple_free(&difftp);
	dns_diff_clear(&diff);
	if (ldapdb != NULL) {
		/* rollback if something bad happened */
		if (version != NULL)
			dns_db_closeversion(ldapdb, &version, ISC_FALSE);
		dns_db_detach(&ldapdb);
	}
	if (ptr_zone != NULL)
		dns_zone_detach(&ptr_zone);


	return result;
}
#undef SYNCPTR_PREF
#undef SYNCPTR_FMTPRE
#undef SYNCPTR_FMTPOST
