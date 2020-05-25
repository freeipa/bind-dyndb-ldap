/*
 * Copyright (C) 2011-2014  bind-dyndb-ldap authors; see COPYING for license
 */
#include <uuid/uuid.h>

#include <dns/rdata.h>
#include <dns/ttl.h>
#include <dns/types.h>

#include <inttypes.h>
#include <isc/region.h>
#include <isc/types.h>
#include <isc/util.h>

#define LDAP_DEPRECATED 1
#include <ldap.h>

#include "ldap_convert.h"
#include "ldap_entry.h"
#include "mldap.h"
#include "metadb.h"
#include "str.h"
#include "util.h"
#include "zone_register.h"

/*
 * ldap_entry_parseclass
 *
 * Get entry class (bitwise OR of the LDAP_ENTRYCLASS_*). Note that
 * you must ldap_search for objectClass attribute!
 */
static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
ldap_entry_parseclass(ldap_entry_t *entry, ldap_entryclass_t *class);

/* Represents values associated with LDAP attribute */
static void ATTR_NONNULLS
ldap_valuelist_destroy(isc_mem_t *mctx, ldap_valuelist_t *values)
{
	ldap_value_t *value, *next;

	value = HEAD(*values);
	while (value != NULL) {
		next = NEXT(value, link);
		UNLINK(*values, value, link);
		SAFE_MEM_PUT_PTR(mctx, value);
		value = next;
	}
}

static void ATTR_NONNULLS
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
                SAFE_MEM_PUT_PTR(mctx, attr);
                attr = next;
        }
}

static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
ldap_attr_create(isc_mem_t *mctx, LDAP *ld, LDAPMessage *ldap_entry,
		 ldap_attribute_t *attr)
{
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
		val = isc_mem_get(mctx, sizeof(*(val)));
		val->value = values[i];
		INIT_LINK(val, link);

		APPEND(attr->values, val, link);
	}

	return ISC_R_SUCCESS;
}

/**
 * Allocate and initialize empty ldap_entry_t. The new entry will not contain
 * any data, it needs to be filled by ldap_entry_parse or ldap_entry_reconstruct.
 */
isc_result_t
ldap_entry_init(isc_mem_t *mctx, ldap_entry_t **entryp) {
	isc_result_t result;
	ldap_entry_t *entry = NULL;

	REQUIRE(entryp != NULL);
	REQUIRE(*entryp == NULL);

	entry = isc_mem_get(mctx, sizeof(*(entry)));
	ZERO_PTR(entry);
	isc_mem_attach(mctx, &entry->mctx);
	INIT_LIST(entry->attrs);
	INIT_LINK(entry, link);
	INIT_BUFFERED_NAME(entry->fqdn);
	INIT_BUFFERED_NAME(entry->zone_name);

	entry->rdata_target_mem = isc_mem_get(mctx, DNS_RDATA_MAXLENGTH);
	CHECK(isc_lex_create(mctx, TOKENSIZ, &entry->lex));

	*entryp = entry;

cleanup:
	if (result != ISC_R_SUCCESS)
		ldap_entry_destroy(&entry);

	return result;
}

/**
 * Create fake LDAP entry with values from metaDB. No attributes will be
 * present in the fake entry.
 *
 * @param[in]  mldap
 * @param[in]  uuid   LDAP entry UUID
 * @param[out] entryp Resulting entry. Caller has to free it.
 *
 * @warning fake entry->dn might be inaccurate
 */
isc_result_t
ldap_entry_reconstruct(isc_mem_t *mctx, mldapdb_t *mldap, struct berval *uuid,
		       ldap_entry_t **entryp) {
	isc_result_t result;
	ldap_entry_t *entry = NULL;
	ld_string_t *str = NULL;
	metadb_node_t *node = NULL;

	CHECK(str_new(mctx, &str));
	result = mldap_entry_read(mldap, uuid, &node);
	if (result != ISC_R_SUCCESS) {
		log_bug("protocol violation: "
			"attempt to reconstruct non-existing entry");
		goto cleanup;
	}
	CHECK(ldap_entry_init(mctx, &entry));

	entry->uuid = ber_dupbv(NULL, uuid);
	if (entry->uuid == NULL)
		CLEANUP_WITH(ISC_R_NOMEMORY);

	CHECK(mldap_class_get(node, &entry->class));
	if ((entry->class
	    & (LDAP_ENTRYCLASS_CONFIG | LDAP_ENTRYCLASS_SERVERCONFIG)) == 0)
		CHECK(mldap_dnsname_get(node, &entry->fqdn, &entry->zone_name));

	*entryp = entry;

cleanup:
	if (result != ISC_R_SUCCESS)
		ldap_entry_destroy(&entry);
	metadb_node_close(&node);
	str_destroy(&str);
	return result;
}

/**
 * Allocate new ldap_entry and fill it with data from LDAPMessage.
 */
isc_result_t
ldap_entry_parse(isc_mem_t *mctx, LDAP *ld, LDAPMessage *ldap_entry,
		  struct berval	*uuid, ldap_entry_t **entryp)
{
	isc_result_t result;
	ldap_attribute_t *attr = NULL;
	char *attribute;
	BerElement *ber = NULL;
	ldap_entry_t *entry = NULL;
	bool has_zone_dn;
	bool has_zone_class;

	REQUIRE(ld != NULL);
	REQUIRE(ldap_entry != NULL);
	REQUIRE(entryp != NULL);
	REQUIRE(*entryp == NULL);

	CHECK(ldap_entry_init(mctx, &entry));

	for (attribute = ldap_first_attribute(ld, ldap_entry, &ber);
	     attribute != NULL;
	     attribute = ldap_next_attribute(ld, ldap_entry, ber)) {
		attr = isc_mem_get(mctx, sizeof(*(attr)));
		ZERO_PTR(attr);

		attr->name = attribute;
		INIT_LIST(attr->values);
		INIT_LINK(attr, link);
		CHECK(ldap_attr_create(mctx, ld, ldap_entry, attr));

		APPEND(entry->attrs, attr, link);
	}
	attr = NULL;

	entry->dn = ldap_get_dn(ld, ldap_entry);
	if (entry->dn == NULL) {
		log_ldap_error(ld, "unable to get entry DN");
		CLEANUP_WITH(ISC_R_FAILURE);
	}
	entry->uuid = ber_dupbv(NULL, uuid);
	CHECK(ldap_entry_parseclass(entry, &entry->class));
	if ((entry->class & LDAP_ENTRYCLASS_TEMPLATE) != 0
	    && (entry->class
		& ~(LDAP_ENTRYCLASS_TEMPLATE | LDAP_ENTRYCLASS_RR)) != 0) {
		log_bug("idnsTemplateObject is not supported with anything "
			"else than idnsRecord: %s", ldap_entry_logname(entry));
	}

	if ((entry->class &
	    (LDAP_ENTRYCLASS_MASTER | LDAP_ENTRYCLASS_FORWARD
	     | LDAP_ENTRYCLASS_RR)) != 0)
		CHECK(dn_to_dnsname(mctx, entry->dn, &entry->fqdn,
				    &entry->zone_name, &has_zone_dn));
	else
		has_zone_dn = false;
	has_zone_class = entry->class & (LDAP_ENTRYCLASS_MASTER
					 | LDAP_ENTRYCLASS_FORWARD);
	CHECK(dn_want_zone(__func__, entry->dn, has_zone_dn, has_zone_class));


	*entryp = entry;

cleanup:
	if (ber != NULL)
		ber_free(ber, 0);
	if (result != ISC_R_SUCCESS) {
		if (entry != NULL)
			ldap_entry_destroy(&entry);
		SAFE_MEM_PUT_PTR(mctx, attr);
	}

	return result;
}

void
ldap_entry_destroy(ldap_entry_t **entryp)
{
	ldap_entry_t *entry;

	REQUIRE(entryp != NULL);

	entry = *entryp;
	if (entry == NULL)
		return;

	ldap_attributelist_destroy(entry->mctx, &entry->attrs);
	if (entry->dn != NULL)
		ldap_memfree(entry->dn);
	if (entry->uuid != NULL)
		ber_bvfree(entry->uuid);
	if (dns_name_dynamic(&entry->fqdn))
		dns_name_free(&entry->fqdn, entry->mctx);
	if (dns_name_dynamic(&entry->zone_name))
		dns_name_free(&entry->zone_name, entry->mctx);
	if (entry->lex != NULL) {
		isc_lex_close(entry->lex);
		isc_lex_destroy(&entry->lex);
	}
	if (entry->rdata_target_mem != NULL)
		SAFE_MEM_PUT(entry->mctx, entry->rdata_target_mem,
			     DNS_RDATA_MAXLENGTH);
	str_destroy(&entry->logname);

	MEM_PUT_AND_DETACH(entry);

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

	INIT_LIST(*values);

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

ldap_attribute_t*
ldap_entry_nextattr(ldap_entry_t *entry)
{
	ldap_attribute_t *attr;

        REQUIRE(entry != NULL);

	if (entry->lastattr == NULL)
		attr = HEAD(entry->attrs);
	else
		attr = NEXT(entry->lastattr, link);

	if (attr != NULL)
		entry->lastattr = attr;

	return attr;
}

isc_result_t
ldap_entry_firstrdtype(ldap_entry_t *entry, ldap_attribute_t **attrp,
		       dns_rdatatype_t *rdtype)
{
	REQUIRE(entry != NULL);

	entry->lastattr = NULL;
	return ldap_entry_nextrdtype(entry, attrp, rdtype);
}

isc_result_t
ldap_entry_nextrdtype(ldap_entry_t *entry, ldap_attribute_t **attrp,
		      dns_rdatatype_t *rdtype)
{
	isc_result_t result;
	ldap_attribute_t *attr;

	result = ISC_R_NOTFOUND;

	while ((attr = ldap_entry_nextattr(entry)) != NULL) {
		result = ldap_attribute_to_rdatatype(attr->name, rdtype);
		/* FIXME: Emit warning in case of unknown rdtype? */
		if (result == ISC_R_SUCCESS)
			break;
	}

	if (result == ISC_R_SUCCESS)
		*attrp = attr;
	else {
		result = ISC_R_NOMORE;
		*attrp = NULL;
	}

	return result;
}

isc_result_t
ldap_entry_getfakesoa(ldap_entry_t *entry, const char *fake_mname,
		      ld_string_t *target)
{
	isc_result_t result = ISC_R_NOTFOUND;
	ldap_valuelist_t values;
	int i = 0;

	const char *soa_serial_attr = "idnsSOAserial";
	const char *soa_attrs[] = {
		"idnsSOAmName", "idnsSOArName", soa_serial_attr,
		"idnsSOArefresh", "idnsSOAretry", "idnsSOAexpire",
		"idnsSOAminimum", NULL
	};

	REQUIRE(entry != NULL);
	REQUIRE(target != NULL);
             
	str_clear(target);
	if (strlen(fake_mname) > 0) {
		i = 1;  
		CHECK(str_cat_char(target, fake_mname));
		CHECK(str_cat_char(target, " "));
	}
	for (; soa_attrs[i] != NULL; i++) {
		result = ldap_entry_getvalues(entry, soa_attrs[i], &values);
		/** Workaround for
		 *  https://bugzilla.redhat.com/show_bug.cgi?id=894131
		 *  DNS zones created on remote IPA 3.0 server don't have
		 *  idnsSOAserial attribute present in LDAP. */
		if (result == ISC_R_NOTFOUND
		    && soa_attrs[i] == soa_serial_attr) {
			/* idnsSOAserial is missing! Read it as 1. */
			CHECK(str_cat_char(target, "1 "));
			continue;
		} else if (result != ISC_R_SUCCESS)
			goto cleanup;

		CHECK(str_cat_char(target, HEAD(values)->value));
		CHECK(str_cat_char(target, " "));
	}

cleanup:
	/* TODO: check for memory leaks */
	return result;
}

isc_result_t
ldap_entry_parseclass(ldap_entry_t *entry, ldap_entryclass_t *class)
{
	ldap_valuelist_t values;
	ldap_value_t *val;
	ldap_entryclass_t entryclass;

	REQUIRE(entry != NULL);
	REQUIRE(class != NULL);

	entryclass = LDAP_ENTRYCLASS_NONE;

	/* ObjectClass will be missing if search parameters didn't request
	 * objectClass attribute. */
	if (ldap_entry_getvalues(entry, "objectClass", &values)
	    != ISC_R_SUCCESS) {
		log_error("entry without supported objectClass: %s",
			  ldap_entry_logname(entry));
		return ISC_R_UNEXPECTED;
	}

	for (val = HEAD(values); val != NULL; val = NEXT(val, link)) {
		if (!strcasecmp(val->value, "idnsrecord"))
			entryclass |= LDAP_ENTRYCLASS_RR;
		else if (!strcasecmp(val->value, "idnsTemplateObject"))
			entryclass |= LDAP_ENTRYCLASS_TEMPLATE;
		else if (!strcasecmp(val->value, "idnszone"))
			entryclass |= LDAP_ENTRYCLASS_MASTER;
		else if (!strcasecmp(val->value, "idnsforwardzone"))
			entryclass |= LDAP_ENTRYCLASS_FORWARD;
		else if (!strcasecmp(val->value, "idnsconfigobject"))
			entryclass |= LDAP_ENTRYCLASS_CONFIG;
		else if (!strcasecmp(val->value, "idnsServerConfigObject"))
			entryclass |= LDAP_ENTRYCLASS_SERVERCONFIG;
	}

	if (class == LDAP_ENTRYCLASS_NONE) {
		log_error("%s has no supported object class",
			  ldap_entry_logname(entry));
		return ISC_R_NOTIMPLEMENTED;

	} else if ((entryclass & LDAP_ENTRYCLASS_MASTER) &&
		   (entryclass & LDAP_ENTRYCLASS_FORWARD)) {
		log_error("%s has to have type either "
			  "'master' or 'forward'", ldap_entry_logname(entry));
		return ISC_R_UNEXPECTED;
	}

	*class = entryclass;
	return ISC_R_SUCCESS;
}

isc_result_t
ldap_attr_firstvalue(ldap_attribute_t *attr, ld_string_t *str)
{
	REQUIRE(attr != NULL);
	REQUIRE(str != NULL);

	attr->lastval = NULL;
	return ldap_attr_nextvalue(attr, str);
}

isc_result_t
ldap_attr_nextvalue(ldap_attribute_t *attr, ld_string_t *str)
{
	isc_result_t result;
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
		return ISC_R_NOMORE;

	CHECK(str_init_char(str, value->value));

cleanup:
	return result;
}

dns_ttl_t
ldap_entry_getttl(ldap_entry_t *entry, const settings_set_t * settings)
{
	const char *ttl_attr = "dnsTTL";
	isc_textregion_t ttl_text;
	ldap_valuelist_t values;
	isc_result_t result;
	uint32_t ttl;

	REQUIRE(entry != NULL);

	CHECK(ldap_entry_getvalues(entry, ttl_attr, &values));

	ttl_text.base = HEAD(values)->value;
	ttl_text.length = strlen(ttl_text.base);
	CHECK(dns_ttl_fromtext(&ttl_text, &ttl));
	if (ttl > 0x7fffffffUL) {
		log_error("%s: entry TTL %u > MAXTTL, setting TTL to 0",
			  ldap_entry_logname(entry), ttl);
		ttl = 0;
	}
	return ttl;

cleanup:
	INSIST(setting_get_uint("default_ttl", settings, &ttl) == ISC_R_SUCCESS);
	return ttl;
}

/**
 * Convert a combination of LDAP_ENTRYCLASS_* to a string.
 */
const char *
ldap_entry_getclassname(const ldap_entryclass_t class) {
	if ((class & LDAP_ENTRYCLASS_MASTER) != 0)
		return "master zone";
	else if ((class & LDAP_ENTRYCLASS_FORWARD) != 0)
		return "forward zone";
	else if ((class & LDAP_ENTRYCLASS_CONFIG) != 0)
		return "config object";
	else if ((class & LDAP_ENTRYCLASS_SERVERCONFIG) != 0)
		return "server config object";
	else if ((class & LDAP_ENTRYCLASS_RR) != 0
		 && (class & LDAP_ENTRYCLASS_TEMPLATE) != 0)
		return "resource record template";
	else if ((class & LDAP_ENTRYCLASS_RR) != 0)
		return "resource record";
	else if (class != 0)
		return "entry with unknown combination of object classes";
	else
		return "entry with empty object class";
}

/**
 * Return human-readable entry identifier.
 * The identifier is guaranteed to be non-NULL so it can be used without
 * further checking.
 */
const char *
ldap_entry_logname(ldap_entry_t * const entry) {
	isc_result_t result;
	ld_string_t *str = NULL;
	char uuid_buf[sizeof("01234567-89ab-cdef-0123-456789abcdef")];

	if (entry->logname != NULL)
		return str_buf(entry->logname);

	CHECK(str_new(entry->mctx, &str));
	CHECK(str_cat_char(str, ldap_entry_getclassname(entry->class)));
	if (entry->dn) {
		if (str_len(str) > 0)
			CHECK(str_cat_char(str, " "));
		CHECK(str_cat_char(str, "DN '"));
		CHECK(str_cat_char(str, entry->dn));
		CHECK(str_cat_char(str, "'"));
	} else if (entry->uuid) {
		INSIST(entry->uuid->bv_len == 16);
		uuid_unparse((*(const uuid_t *) entry->uuid->bv_val), uuid_buf);
		if (str_len(str) > 0)
			CHECK(str_cat_char(str, " "));
		CHECK(str_cat_char(str, "entryUUID "));
		CHECK(str_cat_char(str, uuid_buf));
	}
	/* sanity check */
	if (str == NULL || str_len(str) <= 0)
		goto cleanup;
	entry->logname = str;
	return str_buf(entry->logname);

cleanup:
	str_destroy(&str);
	return "<failed to obtain LDAP entry identifier>";
}
