/*
 * Authors: Martin Nagy <mnagy@redhat.com>
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

#include <isc/buffer.h>
#include <isc/mem.h>
#include <isc/util.h>

#include <dns/name.h>
#include <dns/rdatatype.h>
#include <dns/result.h>
#include <dns/types.h>

#define LDAP_DEPRECATED 1
#include <ldap.h>

#include <errno.h>
#include <strings.h>

#include "str.h"
#include "ldap_convert.h"
#include "log.h"
#include "util.h"
#include "zone_register.h"

/*
 * Consistency must be preserved in these tables.
 * ldap_dns_records[i] must always corespond to dns_records[i]
 */
const char *ldap_dns_records[] = {
	"ARecord",     "AAAARecord",  "A6Record",    "NSRecord",
	"CNAMERecord", "PTRRecord",   "SRVRecord",   "TXTRecord",   "MXRecord",
	"MDRecord",    "HINFORecord", "MINFORecord", "AFSDBRecord", "SIGRecord",
	"KEYRecord",   "LOCRecord",   "NXTRecord",   "NAPTRRecord", "KXRecord",
	"CERTRecord",  "DNAMERecord", "DSRecord",    "SSHFPRecord",
	"RRSIGRecord", "NSECRecord",  NULL
};

const char *dns_records[] = {
	"A",     "AAAA",  "A6",    "NS",
	"CNAME", "PTR",   "SRV",   "TXT",   "MX",
	"MD",    "HINFO", "MINFO", "AFSDB", "SIG",
	"KEY",   "LOC",   "NXT",   "NAPTR", "KX",
	"CERT",  "DNAME", "DS",    "SSHFP",
	"RRSIG", "NSEC",  NULL
};

static isc_result_t explode_dn(const char *dn, char ***explodedp, int notypes);
static isc_result_t explode_rdn(const char *rdn, char ***explodedp,
				int notypes);


isc_result_t
dn_to_dnsname(isc_mem_t *mctx, const char *dn, dns_name_t *target,
	      dns_name_t *otarget)
{
	isc_result_t result;
	DECLARE_BUFFERED_NAME(name);
	DECLARE_BUFFERED_NAME(origin);
	ld_string_t *str = NULL;
	ld_string_t *ostr = NULL;
	isc_buffer_t buffer;

	REQUIRE(mctx != NULL);
	REQUIRE(dn != NULL);

	INIT_BUFFERED_NAME(name);
	CHECK(str_new(mctx, &str));

	if (otarget != NULL) {
		INIT_BUFFERED_NAME(origin);
		CHECK(str_new(mctx, &ostr));
	}

	CHECK(dn_to_text(dn, str, ostr));
	str_to_isc_buffer(str, &buffer);
	CHECK(dns_name_fromtext(&name, &buffer, dns_rootname, 0, NULL));

	if (otarget != NULL) {
		str_to_isc_buffer(ostr, &buffer);
		CHECK(dns_name_fromtext(&origin, &buffer, dns_rootname, 0,
		      NULL));
	}

cleanup:
	if (result == ISC_R_SUCCESS)
		result = dns_name_dupwithoffsets(&name, mctx, target);
	else
		log_error_r("failed to convert dn %s to DNS name", dn);

	if (otarget != NULL && result == ISC_R_SUCCESS)
		result = dns_name_dupwithoffsets(&origin, mctx, otarget);

	if (result != ISC_R_SUCCESS) {
		if (dns_name_dynamic(target))
			dns_name_free(target, mctx);
		if (otarget) {
			if (dns_name_dynamic(otarget))
				dns_name_free(otarget, mctx);
		}
	}

	str_destroy(&str);
	if (otarget != NULL)
		str_destroy(&ostr);

	return result;
}

/*
 * Convert LDAP dn to DNS name.
 *
 * Example:
 * dn = "idnsName=foo, idnsName=bar, idnsName=example.org, cn=dns,"
 *      "dc=example, dc=org"
 *
 * The resulting string will be "foo.bar.example.org."
 */
isc_result_t
dn_to_text(const char *dn, ld_string_t *target, ld_string_t *origin)
{
	isc_result_t result;
	char **exploded_dn = NULL;
	char **exploded_rdn = NULL;
	unsigned int i;

	REQUIRE(dn != NULL);
	REQUIRE(target != NULL);

	result = ISC_R_SUCCESS;

	CHECK(explode_dn(dn, &exploded_dn, 0));
	str_clear(target);
	for (i = 0; exploded_dn[i] != NULL; i++) {
		if (strncasecmp(exploded_dn[i], "idnsName", 8) != 0)
			break;

		if (exploded_rdn != NULL) {
			ldap_value_free(exploded_rdn);
			exploded_rdn = NULL;
		}

		CHECK(explode_rdn(exploded_dn[i], &exploded_rdn, 1));
		CHECK(str_cat_char(target, exploded_rdn[0]));
		CHECK(str_cat_char(target, "."));
	}

	if (origin != NULL) {
		str_clear(origin);

		/*
		 * If we have DNs with only one idnsName part,
		 * treat them as absolute.
		 */

		if (i < 2)
			CHECK(str_init_char(origin, "."));
		else {
			CHECK(str_cat_char(origin, exploded_rdn[0]));
			CHECK(str_cat_char(origin, "."));
		}
			
	}

	if (str_len(target) == 0)
		CHECK(str_init_char(target, "."));

cleanup:
	if (exploded_dn != NULL)
		ldap_value_free(exploded_dn);
	if (exploded_rdn != NULL)
		ldap_value_free(exploded_rdn);

	return result;
}

static isc_result_t
explode_dn(const char *dn, char ***explodedp, int notypes)
{
	char **exploded;

	REQUIRE(dn != NULL);
	REQUIRE(explodedp != NULL && *explodedp == NULL);

	exploded = ldap_explode_dn(dn, notypes);
	if (exploded == NULL) {
		if (errno == ENOMEM) {
			return ISC_R_NOMEMORY;
		} else {
			log_error("ldap_explode_dn(\"%s\") failed, "
				  "error code %d", dn, errno);
			return ISC_R_FAILURE;
		}
	}

	*explodedp = exploded;

	return ISC_R_SUCCESS;
}

static isc_result_t
explode_rdn(const char *rdn, char ***explodedp, int notypes)
{
	char **exploded;

	REQUIRE(rdn != NULL);
	REQUIRE(explodedp != NULL && *explodedp == NULL);

	exploded = ldap_explode_rdn(rdn, notypes);
	if (exploded == NULL) {
		if (errno == ENOMEM) {
			return ISC_R_NOMEMORY;
		} else {
			log_error("ldap_explode_rdn(\"%s\") failed, "
				  "error code %d", rdn, errno);
			return ISC_R_FAILURE;
		}
	}

	*explodedp = exploded;

	return ISC_R_SUCCESS;
}

isc_result_t
dnsname_to_dn(zone_register_t *zr, dns_name_t *name, ld_string_t *target)
{
	isc_result_t result;
	int label_count;
	const char *zone_dn = NULL;

	REQUIRE(zr != NULL);
	REQUIRE(name != NULL);
	REQUIRE(target != NULL);

	/* Find the DN of the zone we belong to. */
	{
		DECLARE_BUFFERED_NAME(zone);
		int dummy;
		unsigned int common_labels;

		INIT_BUFFERED_NAME(zone);

		CHECK(zr_get_zone_dn(zr, name, &zone_dn, &zone));

		dns_name_fullcompare(name, &zone, &dummy, &common_labels);
		label_count = dns_name_countlabels(name) - common_labels;
	}

	str_clear(target);
	if (label_count > 0) {
		DECLARE_BUFFER(buffer, DNS_NAME_MAXTEXT);
		dns_name_t labels;

		INIT_BUFFER(buffer);
		dns_name_init(&labels, NULL);

		dns_name_getlabelsequence(name, 0, label_count, &labels);
		CHECK(dns_name_totext(&labels, ISC_TRUE, &buffer));

		CHECK(str_cat_char(target, "idnsName="));
		CHECK(str_cat_isc_buffer(target, &buffer));
		/* 
		 * Modification of following line can affect modify_ldap_common().
		 * See line with: char *zone_dn = strstr(str_buf(owner_dn),", ") + 1;  
		 */
		CHECK(str_cat_char(target, ", "));
	}
	CHECK(str_cat_char(target, zone_dn));

cleanup:
	return result;
}

isc_result_t
ldap_attribute_to_rdatatype(const char *ldap_attribute, dns_rdatatype_t *rdtype)
{
	isc_result_t result;
	unsigned i;
	isc_consttextregion_t region;

	for (i = 0; ldap_dns_records[i] != NULL; i++) {
		if (!strcasecmp(ldap_attribute, ldap_dns_records[i]))
			break;
	}
	if (dns_records[i] == NULL)
		return ISC_R_NOTFOUND;

	region.base = dns_records[i];
	region.length = strlen(region.base);
	result = dns_rdatatype_fromtext(rdtype, (isc_textregion_t *)&region);
	if (result != ISC_R_SUCCESS)
		log_error("dns_rdatatype_fromtext() failed");

	return result;
}

isc_result_t
rdatatype_to_ldap_attribute(dns_rdatatype_t rdtype, const char **target)
{
	unsigned i;
	char rdtype_str[DNS_RDATATYPE_FORMATSIZE];

	dns_rdatatype_format(rdtype, rdtype_str, DNS_RDATATYPE_FORMATSIZE);
	for (i = 0; dns_records[i] != NULL; i++) {
		if (!strcmp(rdtype_str, dns_records[i]))
			break;
	}
	if (ldap_dns_records[i] == NULL)
		return ISC_R_NOTFOUND;

	*target = ldap_dns_records[i];

	return ISC_R_SUCCESS;
}
