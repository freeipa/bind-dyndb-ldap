/*
 * Authors: Martin Nagy <mnagy@redhat.com>
 *          Adam Tkac <atkac@redhat.com>
 *
 * Copyright (C) 2008, 2011  Red Hat
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

#include <dns/ttl.h>
#include <dns/types.h>

#include <isc/region.h>
#include <isc/types.h>
#include <isc/util.h>

#define LDAP_DEPRECATED 1
#include <ldap.h>

#include "ldap_convert.h"
#include "ldap_entry.h"
#include "str.h"
#include "util.h"

/* Represents values associated with LDAP attribute */

/* Represents LDAP attribute and it's values */
struct ldap_attribute {
	char			*name;
	char			**ldap_values;
	ldap_value_t		*lastval;
	ldap_valuelist_t	values;
	LINK(ldap_attribute_t)	link;
};

isc_result_t
ldap_entrylist_create(isc_mem_t *mctx, LDAP *ld, LDAPMessage *msg,
		      ldap_entrylist_t *entrylist)
{
	isc_result_t result;
	LDAPMessage *ldap_entry;
	ldap_entry_t *entry;

	REQUIRE(ld != NULL);
	REQUIRE(msg != NULL);
	REQUIRE(entrylist != NULL && EMPTY(*entrylist));

	INIT_LIST(*entrylist);

	for (ldap_entry = ldap_first_entry(ld, msg);
	     ldap_entry != NULL;
	     ldap_entry = ldap_next_entry(ld, ldap_entry)) {
		entry = NULL;
		CHECK(ldap_entry_create(mctx, ld, ldap_entry, &entry));
		APPEND(*entrylist, entry, link);
	}

	return ISC_R_SUCCESS;

cleanup:
	ldap_entrylist_destroy(mctx, entrylist);
	return result;
}

void
ldap_entrylist_destroy(isc_mem_t *mctx, ldap_entrylist_t *entrylist)
{
	ldap_entry_t *entry, *next;

	entry = HEAD(*entrylist);
	while (entry != NULL) {
		next = NEXT(entry, link);
		UNLINK(*entrylist, entry, link);
		ldap_entry_destroy(mctx, &entry);
		entry = next;
	}
}

static void
ldap_valuelist_destroy(isc_mem_t *mctx, ldap_valuelist_t *values)
{
	ldap_value_t *value, *next;

	value = HEAD(*values);
	while (value != NULL) {
		next = NEXT(value, link);
		UNLINK(*values, value, link);
		isc_mem_put(mctx, value, sizeof(*value));
		value = next;
	}
}

static void
ldap_attributelist_destroy(isc_mem_t *mctx, ldap_attributelist_t *attrlist)
{
        ldap_attribute_t *attr, *next;

        attr = HEAD(*attrlist);
        while (attr != NULL) {
                next = NEXT(attr, link);
                UNLINK(*attrlist, attr, link);
		ldap_valuelist_destroy(mctx, &attr->values);
                ldap_value_free(attr->ldap_values);
                ldap_memfree(attr->name);
                isc_mem_put(mctx, attr, sizeof(*attr));
                attr = next;
        }
}

static isc_result_t
ldap_attr_create(isc_mem_t *mctx, LDAP *ld, LDAPMessage *ldap_entry,
		 ldap_attribute_t *attr)
{
	isc_result_t result;
	char **values;
	ldap_value_t *val;

	REQUIRE(ld != NULL);
	REQUIRE(ldap_entry != NULL);
	REQUIRE(attr != NULL);

	values = ldap_get_values(ld, ldap_entry, attr->name);
	/* TODO: proper ldap error handling */
	if (values == NULL)
		return ISC_R_FAILURE;

	attr->ldap_values = values;

	for (unsigned int i = 0; values[i] != NULL; i++) {
		CHECKED_MEM_GET_PTR(mctx, val);
		val->value = values[i];
		INIT_LINK(val, link);

		APPEND(attr->values, val, link);
	}

	return ISC_R_SUCCESS;

cleanup:
	ldap_valuelist_destroy(mctx, &attr->values);
	ldap_value_free(values);

	return result;
}

isc_result_t
ldap_entry_create(isc_mem_t *mctx, LDAP *ld, LDAPMessage *ldap_entry,
                  ldap_entry_t **entryp)
{
	isc_result_t result;
	ldap_attribute_t *attr;
	char *attribute;
	BerElement *ber;
	ldap_entry_t *entry = NULL;

	REQUIRE(ld != NULL);
	REQUIRE(ldap_entry != NULL);
	REQUIRE(entryp != NULL && *entryp == NULL);

	CHECKED_MEM_GET_PTR(mctx, entry);
	ZERO_PTR(entry);
	entry->ldap_entry = ldap_entry;
	INIT_LIST(entry->attrs);
	INIT_LINK(entry, link);

	result = ISC_R_SUCCESS;

	for (attribute = ldap_first_attribute(ld, ldap_entry, &ber);
	     attribute != NULL;
	     attribute = ldap_next_attribute(ld, ldap_entry, ber)) {
		CHECKED_MEM_GET_PTR(mctx, attr);
		ZERO_PTR(attr);

		attr->name = attribute;
		INIT_LIST(attr->values);
		INIT_LINK(attr, link);
		CHECK(ldap_attr_create(mctx, ld, ldap_entry, attr));

		APPEND(entry->attrs, attr, link);
	}

	entry->dn = ldap_get_dn(ld, ldap_entry);

	if (ber != NULL)
		ber_free(ber, 0);

	*entryp = entry;

	return ISC_R_SUCCESS;

cleanup:
	if (entry != NULL)
		ldap_attributelist_destroy(mctx, &entry->attrs);

	return result;
}

void
ldap_entry_destroy(isc_mem_t *mctx, ldap_entry_t **entryp)
{
	ldap_entry_t *entry;

	REQUIRE(entryp != NULL && *entryp != NULL);

	entry = *entryp;

	ldap_attributelist_destroy(mctx, &entry->attrs);
	if (entry->dn != NULL)
		ldap_memfree(entry->dn);
	isc_mem_put(mctx, entry, sizeof(*entry));

	*entryp = NULL;
}

isc_result_t
ldap_entry_getvalues(const ldap_entry_t *entry, const char *attrname,
		     ldap_valuelist_t *values)
{
	ldap_attribute_t *attr;

	REQUIRE(entry != NULL);
	REQUIRE(attrname != NULL);
	REQUIRE(values != NULL);

	for (attr = HEAD(entry->attrs);
	     attr != NULL;
	     attr = NEXT(attr, link)) {
		if (!strcasecmp(attr->name, attrname)) {
			*values = attr->values;
			return ISC_R_SUCCESS;
		}
	}

	return ISC_R_NOTFOUND;
}

dns_rdataclass_t
ldap_entry_getrdclass(const ldap_entry_t *entry)
{
	UNUSED(entry);

	/*
	 * Not implemented for now.
	 * Probably won't ever be.
	 */

	return dns_rdataclass_in;
}

static isc_boolean_t
array_contains_nocase(const char **haystack, const char *needle)
{
	for (unsigned int i = 0; haystack[i] != NULL; i++) {
		if (strcasecmp(needle, haystack[i]) == 0)
			return ISC_TRUE;
	}

	return ISC_FALSE;
}

ldap_attribute_t*
ldap_entry_nextattr(ldap_entry_t *entry, const char **attrlist)
{
	ldap_attribute_t *attr;

        REQUIRE(entry != NULL);

	if (entry->lastattr == NULL)
		attr = HEAD(entry->attrs);
	else
		attr = NEXT(entry->lastattr, link);

	if (attrlist != NULL) {
		while (attr != NULL && !array_contains_nocase(attrlist, attr->name))
			attr = NEXT(attr, link);
	}

	if (attr != NULL)
		entry->lastattr = attr;

	return attr;
}

isc_result_t
ldap_entry_nextrdtype(ldap_entry_t *entry, ldap_attribute_t **attrp,
		      dns_rdatatype_t *rdtype)
{
	isc_result_t result;
	ldap_attribute_t *attr;

	result = ISC_R_NOTFOUND;

	while ((attr = ldap_entry_nextattr(entry, NULL)) != NULL) {
		result = ldap_attribute_to_rdatatype(attr->name, rdtype);
		/* FIXME: Emit warning in case of unknown rdtype? */
		if (result == ISC_R_SUCCESS)
			break;
	}

	if (result == ISC_R_SUCCESS)
		*attrp = attr;
	else if (result == ISC_R_NOTFOUND)
		*attrp = NULL;

	return result;
}

isc_result_t
ldap_entry_getfakesoa(ldap_entry_t *entry, const ld_string_t *fake_mname,
		      ld_string_t *target)
{
	isc_result_t result = ISC_R_NOTFOUND;
	ldap_valuelist_t values;
	int i = 0;

	const char *soa_attrs[] = {
		"idnsSOAmName", "idnsSOArName", "idnsSOAserial",
		"idnsSOArefresh", "idnsSOAretry", "idnsSOAexpire",
		"idnsSOAminimum", NULL
	};

	REQUIRE(entry != NULL);
	REQUIRE(target != NULL);
             
	str_clear(target);
	if (str_len(fake_mname) > 0) {
		i = 1;  
		CHECK(str_cat(target, fake_mname));
		CHECK(str_cat_char(target, " "));
	}
	for (; soa_attrs[i] != NULL; i++) {
		CHECK(ldap_entry_getvalues(entry, soa_attrs[i], &values));
		CHECK(str_cat_char(target, HEAD(values)->value));
		CHECK(str_cat_char(target, " "));
	}

cleanup:
	return result;
}

ldap_entryclass_t
ldap_entry_getclass(ldap_entry_t *entry)
{
	ldap_valuelist_t values;
	ldap_value_t *val;
	ldap_entryclass_t entryclass;

	REQUIRE(entry != NULL);

	entryclass = LDAP_ENTRYCLASS_NONE;

	/* XXX Can this happen? */
	if (ldap_entry_getvalues(entry, "objectClass", &values)
	    != ISC_R_SUCCESS)
		return entryclass;

	for (val = HEAD(values); val != NULL; val = NEXT(val, link)) {
		if (!strcasecmp(val->value, "idnsrecord"))
			entryclass |= LDAP_ENTRYCLASS_RR;
		else if (!strcasecmp(val->value, "idnszone"))
			entryclass |= LDAP_ENTRYCLASS_ZONE;
	}

	return entryclass;

#if 0
	/* Preserve current attribute iterator */
	lastattr = = entry->lastattr;
	entry->lastattr = NULL;

	while ((attr = ldap_entry_nextattr(entry, "objectClass")) != NULL) {
		if (!strcasecmp(attr->ldap_values[0], "idnsrecord")) {
			entryclass |= LDAP_ENTRYCLASS_RR;
		} else if (!strcasecmp(attr->ldap_values[0], "idnszone")) {
			entryclass |= LDAP_ENTRYCLASS_ZONE;
		}
	}

	entry->lastattr = lastattr;
#endif
}

ld_string_t*
ldap_attr_nextvalue(ldap_attribute_t *attr, ld_string_t *str)
{
	ldap_value_t *value;

	REQUIRE(attr != NULL);
        REQUIRE(str != NULL);

	str_clear(str);

	if (attr->lastval == NULL)
		value = HEAD(attr->values);
	else
		value = NEXT(attr->lastval, link);

	if (value != NULL)
		attr->lastval = value;
	else
		return NULL;

	str_init_char(str, value->value);

	return str;
}

#define DEFAULT_TTL 86400
dns_ttl_t
ldap_entry_getttl(const ldap_entry_t *entry)
{
	const char *ttl_attr = "dnsTTL";
	isc_textregion_t ttl_text;
	ldap_valuelist_t values;
	isc_result_t result;
	isc_uint32_t ttl;

	REQUIRE(entry != NULL);

	result = ldap_entry_getvalues(entry, ttl_attr, &values);
	if (result == ISC_R_NOTFOUND)
		return DEFAULT_TTL;

	ttl_text.base = HEAD(values)->value;
	ttl_text.length = strlen(ttl_text.base);
	result = dns_ttl_fromtext(&ttl_text, &ttl);
	if (result != ISC_R_SUCCESS)
		return DEFAULT_TTL;

	return ttl;
}

