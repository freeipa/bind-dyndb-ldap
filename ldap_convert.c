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

#include <isc/buffer.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/util.h>

#include <dns/name.h>
#include <dns/rdatatype.h>
#include <dns/types.h>

#define LDAP_DEPRECATED 1
#include <ldap.h>

#include <errno.h>
#include <strings.h>

#include "str.h"
#include "ldap_convert.h"
#include "log.h"
#include "util.h"

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

static isc_result_t dn_to_text(const char *dn, const char *root_dn,
			       ld_string_t *target);
static isc_result_t explode_dn(const char *dn, char ***explodedp, int notypes);
static unsigned int count_rdns(char **exploded);


isc_result_t
dn_to_dnsname(isc_mem_t *mctx, const char *dn, const char *root_dn,
	      dns_name_t *target)
{
	isc_result_t result;
	ld_string_t *str;
	isc_buffer_t source_buffer;
	isc_buffer_t target_buffer;
	dns_name_t tmp_name;
	unsigned char target_base[DNS_NAME_MAXWIRE];

	REQUIRE(mctx != NULL);
	REQUIRE(dn != NULL);

	str = NULL;
	result = ISC_R_SUCCESS;

	/* Convert the DN into a DNS name. */
	CHECK(str_new(mctx, &str));
	CHECK(dn_to_text(dn, root_dn, str));

	/* TODO: fix this */
	isc_buffer_init(&source_buffer, str_buf(str), str_len(str) - 1);
	isc_buffer_add(&source_buffer, str_len(str) - 1);
	isc_buffer_init(&target_buffer, target_base, sizeof(target_base));

	/* Now create a dns_name_t struct. */
	dns_name_init(&tmp_name, NULL);
	dns_name_setbuffer(&tmp_name, &target_buffer);

	CHECK(dns_name_fromtext(&tmp_name, &source_buffer, dns_rootname, 0,
				NULL));

cleanup:
	if (result != ISC_R_FAILURE)
		result = dns_name_dupwithoffsets(&tmp_name, mctx, target);

	str_destroy(&str);

	return result;
}

/*
 * Convert LDAP dn to DNS name. If root_dn is not NULL then count how much RNDs
 * it contains and ignore that much trailing RNDs from dn.
 *
 * Example:
 * dn = "idnsName=foo, idnsName=bar, idnsName=example.org, cn=dns,"
 *      "dc=example, dc=org"
 * root_dn = "cn=dns, dc=example, dc=org"
 *
 * The resulting string will be "foo.bar.example.org."
 */
static isc_result_t
dn_to_text(const char *dn, const char *root_dn, ld_string_t *target)
{
	isc_result_t result;
	unsigned int count;
	char **exploded_dn = NULL;
	char **exploded_root = NULL;

	REQUIRE(dn != NULL);
	REQUIRE(target != NULL);

	result = ISC_R_SUCCESS;

	CHECK(explode_dn(dn, &exploded_dn, 1));
	count = count_rdns(exploded_dn);

	if (root_dn != NULL) {
		unsigned int count_root;

		CHECK(explode_dn(root_dn, &exploded_root, 1));
		count_root = count_rdns(exploded_root);
		if (count_root > count) {
			result = ISC_R_FAILURE;
			goto cleanup;
		}
		count -= count_root;
	}

	str_clear(target);
	for (unsigned int i = 0; exploded_dn[i] != NULL && i < count; i++) {
		str_cat_char(target, exploded_dn[i]);
		str_cat_char(target, ".");
	}

	if (str_len(target) == 0)
		str_init_char(target, ".");

cleanup:
	if (exploded_dn != NULL)
		ldap_value_free(exploded_dn);
	if (exploded_root != NULL)
		ldap_value_free(exploded_root);

	return result;
}

static isc_result_t
explode_dn(const char *dn, char ***explodedp, int notypes)
{
	isc_result_t result;
	char **exploded;

	REQUIRE(dn != NULL);
	REQUIRE(explodedp != NULL && *explodedp == NULL);

	result = ISC_R_SUCCESS;

	exploded = ldap_explode_dn(dn, notypes);
	if (exploded == NULL) {
		if (errno == ENOMEM) {
			return ISC_R_NOMEMORY;
		} else {
			log_error("ldap_explode_dn(\"%s\") failed, error code %d",
				  dn, errno);
			return ISC_R_FAILURE;
		}
	}

	*explodedp = exploded;

	return ISC_R_SUCCESS;
}

static unsigned int
count_rdns(char **exploded)
{
	unsigned int ret;

	REQUIRE(exploded != NULL);

	ret = 0;
	while (exploded[ret] != NULL)
		ret++;

	return ret;
}

/*
 * FIXME: Don't assume that the last RDN consists of the last two labels.
 */
isc_result_t
dnsname_to_dn(isc_mem_t *mctx, dns_name_t *name, const char *root_dn,
	      ld_string_t *target)
{
	isc_result_t result;
	isc_buffer_t target_buffer;
	char target_base[DNS_NAME_MAXTEXT + 1];
	ld_string_t *str;
	ld_split_t *split;
	unsigned int split_count;

	REQUIRE(mctx != NULL);
	REQUIRE(name != NULL);
	REQUIRE(target != NULL);

	str = NULL;
	split = NULL;
	CHECK(str_new(mctx, &str));
	CHECK(str_new_split(mctx, &split));
	isc_buffer_init(&target_buffer, target_base, sizeof(target_base));
	CHECK(dns_name_totext(name, isc_boolean_true, &target_buffer));

	target_base[isc_buffer_usedlength(&target_buffer)] = '\0';
	CHECK(str_init_char(str, target_base));
	CHECK(str_split(str, '.', split));
	split_count = str_split_count(split);

	for (unsigned int i = 0; i < split_count - 1; i++) {
		CHECK(str_cat_char(target, "idnsName="));
		CHECK(str_cat_char(target, str_split_get(split, i)));
		if (split_count - i > 2)
			CHECK(str_cat_char(target, ", "));
	}

	CHECK(str_cat_char(target, "."));
	CHECK(str_cat_char(target, str_split_get(split, split_count - 1)));

	if (root_dn != NULL) {
		CHECK(str_cat_char(target, ", "));
		CHECK(str_cat_char(target, root_dn));
	}

	log_error("%s", str_buf(target));
cleanup:
	str_destroy_split(&split);
	str_destroy(&str);

	return result;
}

isc_result_t
ldap_record_to_rdatatype(const char *ldap_record, dns_rdatatype_t *rdtype)
{
	isc_result_t result;
	unsigned i;
	isc_consttextregion_t region;

	for (i = 0; ldap_dns_records[i] != NULL; i++) {
		if (!strcasecmp(ldap_record, ldap_dns_records[i]))
			break;
	}
	if (dns_records[i] == NULL)
		return ISC_R_NOTFOUND;

	region.base = dns_records[i];
	region.length = strlen(region.base);
	result = dns_rdatatype_fromtext(rdtype, (isc_textregion_t *)&region);
	if (result != ISC_R_SUCCESS) {
		log_error("dns_rdatatype_fromtext() failed");
	}

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
