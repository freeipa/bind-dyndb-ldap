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
#include <isc/string.h>

#include <dns/name.h>
#include <dns/result.h>
#include <dns/types.h>

#define LDAP_DEPRECATED 1
#include <ldap.h>

#include <errno.h>
#include <strings.h>
#include <ctype.h>

#include "str.h"
#include "ldap_convert.h"
#include "log.h"
#include "util.h"
#include "zone_register.h"

static isc_result_t explode_dn(const char *dn, char ***explodedp, int notypes) ATTR_NONNULLS ATTR_CHECKRESULT;
static isc_result_t explode_rdn(const char *rdn, char ***explodedp,
				int notypes) ATTR_NONNULLS ATTR_CHECKRESULT;


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

	REQUIRE(dn != NULL);

	INIT_BUFFERED_NAME(name);
	CHECK(str_new(mctx, &str));

	if (otarget != NULL) {
		INIT_BUFFERED_NAME(origin);
		CHECK(str_new(mctx, &ostr));
	}

	CHECK(dn_to_text(dn, str, ostr));
	str_to_isc_buffer(str, &buffer);
	CHECK(dns_name_fromtext(&name, &buffer, NULL, 0, NULL));

	if (otarget != NULL) {
		str_to_isc_buffer(ostr, &buffer);
		CHECK(dns_name_fromtext(&origin, &buffer, NULL, 0, NULL));
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

/**
 * Convert LDAP DN to absolute DNS name.
 *
 * @param[in]  dn     LDAP DN with one or two idnsName components at the
 *                    beginning.
 * @param[out] target Absolute DNS name derived from the all idnsNames.
 * @param[out] origin Absolute DNS name derived from the last idnsName
 *                    component of DN, i.e. zone. Can be NULL.
 *
 * @code
 * Examples:
 * dn = "idnsName=foo, idnsName=bar, idnsName=example.org,"
 *      "cn=dns, dc=example, dc=org"
 * target = "foo.bar.example.org."
 * origin = "example.org."
 *
 * dn = "idnsname=89, idnsname=4.34.10.in-addr.arpa.",
 *      " cn=dns, dc=example, dc=org"
 * target = "89.4.34.10.in-addr.arpa."
 * origin = "4.34.10.in-addr.arpa."
 * (The dot at the end is not doubled when it's already present.)
 * @endcode
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
		if (exploded_rdn[0] == NULL || exploded_rdn[1] != NULL) {
			log_error("idnsName component of DN has to have "
				  "exactly one value: DN '%s'", dn);
			CLEANUP_WITH(ISC_R_NOTIMPLEMENTED);
		}
		CHECK(str_cat_char(target, exploded_rdn[0]));
		if (str_buf(target)[str_len(target)-1] != '.')
			CHECK(str_cat_char(target, "."));
	}

	/* filter out unsupported cases */
	if (i <= 0) {
		log_error("no idnsName component found in DN '%s'", dn);
		CLEANUP_WITH(ISC_R_UNEXPECTEDEND);
	} else if (i == 1) { /* zone only - nothing to check */
		;
	} else if (i == 2) {
		if (exploded_dn[0][strlen(exploded_dn[0])-1] == '.') {
			log_error("absolute record name in DN "
				  "is not supported: DN '%s'", dn);
			CLEANUP_WITH(ISC_R_NOTIMPLEMENTED);
		}
	} else {
		log_error("unsupported number of idnsName components in DN "
			  "'%s': %u components found", dn, i);
		CLEANUP_WITH(ISC_R_NOTIMPLEMENTED);
	}

	if (origin != NULL) {
		str_clear(origin);

		/*
		 * If we have DNs with only one idnsName part,
		 * treat them as absolute zone name, i.e. origin is root.
		 */
		if (i < 2)
			CHECK(str_init_char(origin, "."));
		else {
			CHECK(str_cat_char(origin, exploded_rdn[0]));
			if (str_buf(origin)[str_len(origin)-1] != '.')
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

/**
 * WARNING! This function is used to mangle input from network
 *          and it is security sensitive.
 *
 * Convert a string from DNS escaping to LDAP escaping.
 * The Input string dns_str is expected to be the result of dns_name_tostring().
 * The DNS label can contain any binary data as described in
 * http://tools.ietf.org/html/rfc2181#section-11 .
 *
 * DNS escaping uses 2 forms: (see dns_name_totext2() in bind/lib/dns/name.c)
 *     form "\123" = ASCII value 123 (decimal)
 *     form "\$" = character '$' is escaped with '\'
 *     WARNING! Some characters are not escaped at all (e.g. ',').
 *
 * LDAP escaping users form "\7b"  = ASCII value 7b (hexadecimal)
 *
 * Input  (DNS escaped)  example: \$.\255_aaa,bbb\127\000ccc.555.ddd-eee
 * Output (LDAP escaped) example: \24.\ff_aaa\2cbbb\7f\00ccc.555.ddd-eee
 *
 * The DNS to text functions from ISC libraries do not convert certain
 * characters (e.g. ","). This function converts \123 form to \7b form in all
 * cases. Other characters (not escaped by ISC libraries) will be additionally
 * converted to the LDAP escape form.
 * Input characters [a-zA-Z0-9._-] are left in raw ASCII form.
 *
 * If dns_str consists only of the characters in the [a-zA-Z0-9._-] set, it
 * will be checked & copied to the output buffer, without any additional escaping.
 */
isc_result_t
dns_to_ldap_dn_escape(isc_mem_t *mctx, const char * const dns_str, char ** ldap_name) {
	isc_result_t result = ISC_R_FAILURE;
	char * esc_name = NULL;
	int idx_symb_first = -1; /* index of first "nice" printable symbol in dns_str */
	int dns_idx = 0;
	int esc_idx = 0;

	REQUIRE(dns_str != NULL);
	REQUIRE(ldap_name != NULL && *ldap_name == NULL);

	int dns_str_len = strlen(dns_str);

	/**
	 * In worst case each symbol from DNS dns_str will be represented
	 * as "\xy" in ldap_name. (xy are hexadecimal digits)
	 */
	CHECKED_MEM_ALLOCATE(mctx, *ldap_name, 3 * dns_str_len + 1);
	esc_name = *ldap_name;

	for (dns_idx = 0; dns_idx < dns_str_len; dns_idx++) {
		if (isalnum(dns_str[dns_idx]) || dns_str[dns_idx] == '.'
				|| dns_str[dns_idx] == '-' || dns_str[dns_idx] == '_' ) {
			if (idx_symb_first == -1)
				idx_symb_first = dns_idx;
			continue;
		} else { /* some not very nice symbols */
			int ascii_val;
			if (idx_symb_first != -1) { /* copy previous nice part */
				int length_ok = dns_idx - idx_symb_first;
				memcpy(esc_name + esc_idx, dns_str + idx_symb_first, length_ok);
				esc_idx += length_ok;
				idx_symb_first = -1;
			}
			if (dns_str[dns_idx] != '\\') { /* not nice raw value, e.g. ',' */
				ascii_val = dns_str[dns_idx];
			} else { /* DNS escaped value, it starts with '\' */
				if (!(dns_idx + 1 < dns_str_len)) {
					CHECK(DNS_R_BADESCAPE); /* this problem should never happen */
				}
				if (isdigit(dns_str[dns_idx + 1])) { /* \123 decimal format */
					/* check if input length <= expected size */
					if (!(dns_idx + 3 < dns_str_len)) {
						CHECK(DNS_R_BADESCAPE); /* this problem should never happen */
					}
					ascii_val = 100 * (dns_str[dns_idx + 1] - '0')
							+ 10 * (dns_str[dns_idx + 2] - '0')
							+ (dns_str[dns_idx + 3] - '0');
					dns_idx += 3;
				} else { /* \$ single char format */
					ascii_val = dns_str[dns_idx + 1];
					dns_idx += 1;
				}
			}
			/* LDAP uses \xy escaping. "xy" represent two hexadecimal digits.*/
			/* TODO: optimize to bit mask & rotate & dec->hex table? */
			CHECK(isc_string_printf(esc_name + esc_idx, 4, "\\%02x", ascii_val));
			esc_idx += 3; /* isc_string_printf wrote 4 bytes including '\0' */
		}
	}
	if (idx_symb_first != -1) { /* copy last nice part */
		int length_ok = dns_idx - idx_symb_first;
		memcpy(esc_name + esc_idx, dns_str + idx_symb_first, dns_idx - idx_symb_first);
		esc_idx += length_ok;
	}
	esc_name[esc_idx] = '\0';
	return ISC_R_SUCCESS;

cleanup:
	if (result == DNS_R_BADESCAPE)
		log_bug("improperly escaped DNS string: '%s'", dns_str);

	if (*ldap_name) {
		isc_mem_free(mctx, *ldap_name);
		*ldap_name = NULL;
	}
	return result;
}

static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
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

static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
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
	char *dns_str = NULL;
	char *escaped_name = NULL;

	REQUIRE(zr != NULL);
	REQUIRE(name != NULL);
	REQUIRE(target != NULL);

	isc_mem_t * mctx = zr_get_mctx(zr);

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
		dns_name_t labels;

		dns_name_init(&labels, NULL);
		dns_name_getlabelsequence(name, 0, label_count, &labels);
		CHECK(dns_name_tostring(&labels, &dns_str, mctx));

		CHECK(dns_to_ldap_dn_escape(mctx, dns_str, &escaped_name));
		CHECK(str_cat_char(target, "idnsName="));
		CHECK(str_cat_char(target, escaped_name));
		/* 
		 * Modification of following line can affect modify_ldap_common().
		 * See line with: char *zone_dn = strstr(str_buf(owner_dn),", ") + 1;  
		 */
		CHECK(str_cat_char(target, ", "));
	}
	CHECK(str_cat_char(target, zone_dn));

cleanup:
	if (dns_str)
		isc_mem_free(mctx, dns_str);
	if (escaped_name)
		isc_mem_free(mctx, escaped_name);
	return result;
}

/**
 * Convert attribute name to dns_rdatatype.
 *
 * @param[in]  ldap_attribute String with attribute name terminated by \0.
 * @param[out] rdtype
 */
isc_result_t
ldap_attribute_to_rdatatype(const char *ldap_attribute, dns_rdatatype_t *rdtype)
{
	isc_result_t result;
	unsigned len;
	isc_consttextregion_t region;

	len = strlen(ldap_attribute);
	if (len <= LDAP_RDATATYPE_SUFFIX_LEN)
		return ISC_R_UNEXPECTEDEND;

	/* Does attribute name end with RECORD_SUFFIX? */
	if (strcasecmp(ldap_attribute + len - LDAP_RDATATYPE_SUFFIX_LEN,
		       LDAP_RDATATYPE_SUFFIX))
		return ISC_R_UNEXPECTED;

	region.base = ldap_attribute;
	region.length = len - LDAP_RDATATYPE_SUFFIX_LEN;
	result = dns_rdatatype_fromtext(rdtype, (isc_textregion_t *)&region);
	if (result != ISC_R_SUCCESS)
		log_error_r("dns_rdatatype_fromtext() failed for attribute '%s'",
			    ldap_attribute);

	return result;
}

isc_result_t
rdatatype_to_ldap_attribute(dns_rdatatype_t rdtype, char *target,
			    unsigned int size)
{
	isc_result_t result;
	char rdtype_str[DNS_RDATATYPE_FORMATSIZE];

	dns_rdatatype_format(rdtype, rdtype_str, DNS_RDATATYPE_FORMATSIZE);
	CHECK(isc_string_copy(target, size, rdtype_str));
	CHECK(isc_string_append(target, size, LDAP_RDATATYPE_SUFFIX));

	return ISC_R_SUCCESS;

cleanup:
	return result;
}

