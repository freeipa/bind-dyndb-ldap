/* Authors: Martin Nagy <mnagy@redhat.com>
 *          Adam Tkac <atkac@redhat.com>
 *
 * Copyright (C) 2008, 2009  Red Hat
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

#include <dns/rdata.h>
#include <dns/rdataclass.h>
#include <dns/rdatalist.h>
#include <dns/rdatatype.h>
#include <dns/result.h>
#include <dns/ttl.h>
#include <dns/view.h>
#include <dns/zone.h>

#include <isc/buffer.h>
#include <isc/lex.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/region.h>
#include <isc/util.h>

#define LDAP_DEPRECATED 1
#include <ldap.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>

#include "ldap_convert.h"
#include "ldap_helper.h"
#include "log.h"
#include "semaphore.h"
#include "settings.h"
#include "str.h"
#include "util.h"


/* Max type length definitions, from lib/dns/master.c */
#define MINTSIZ (65535 - 12 - 1 - 2 - 2 - 4 - 2)
#define TOKENSIZ (8*1024)

/*
 * LDAP related typedefs and structs.
 */

typedef struct ldap_auth_pair	ldap_auth_pair_t;
typedef struct settings		settings_t;
typedef struct ldap_value	ldap_value_t;
typedef struct ldap_attribute	ldap_attribute_t;
typedef struct ldap_entry	ldap_entry_t;
typedef LIST(ldap_value_t)	ldap_value_list_t;
typedef LIST(ldap_attribute_t)	ldap_attribute_list_t;
typedef LIST(ldap_entry_t)	ldap_entry_list_t;

/* Authentication method. */
typedef enum ldap_auth {
	AUTH_INVALID = 0,
	AUTH_NONE,
	AUTH_SIMPLE,
	AUTH_SASL,
} ldap_auth_t;

struct ldap_auth_pair {
	enum ldap_auth value;	/* Value actually passed to ldap_bind(). */
	char *name;	/* String representation used in configuration file */
};

/* These are typedefed in ldap_helper.h */
struct ldap_db {
	isc_mem_t		*mctx;
	dns_view_t		*view;

	/* List of LDAP connections. */
	semaphore_t		conn_semaphore;
	LIST(ldap_instance_t)	conn_list;

	/* Settings. */
	ld_string_t		*host;
	ld_string_t		*base;
	unsigned int		connections;
	ldap_auth_t		auth_method;
};

struct ldap_instance {
	ldap_db_t		*database;
	isc_mutex_t		lock;
	LINK(ldap_instance_t)	link;
	ld_string_t		*query_string;
	ld_string_t		*base;

	LDAP			*handle;
	LDAPMessage		*result;

	/* Parsing. */
	isc_lex_t		*lex;
	isc_buffer_t		rdata_target;
	unsigned char		*rdata_target_mem;

	/* Cache. */
	ldap_entry_list_t	ldap_entries;
	isc_boolean_t		cache_active;

	/* Temporary stuff. */
	LDAPMessage		*entry;
	BerElement		*ber;
	char			*attribute;
	char			**values;
	char			*dn;
};

struct ldap_entry {
	LDAPMessage		*entry;
	ldap_attribute_t	*last_attr;
	ldap_attribute_list_t	attributes;
	LINK(ldap_entry_t)	link;
};

struct ldap_attribute {
	char			*name;
	char			**ldap_values;
	ldap_value_t		*last_value;
	ldap_value_list_t	values;
	LINK(ldap_attribute_t)	link;
};

struct ldap_value {
	char			*value;
	LINK(ldap_value_t)	link;
};


/*
 * Constants.
 */

extern const char *ldapdb_impname;

/* Supported authentication types. */
const ldap_auth_pair_t supported_ldap_auth[] = {
	{ AUTH_NONE,	"none"		},
#if 0
	{ AUTH_SIMPLE,	"simple"	},
	{ AUTH_SASL,	"sasl"		},
#endif
	{ AUTH_INVALID, NULL		},
};

/*
 * Forward declarations.
 */

/* TODO: reorganize this stuff & clean it up. */
static isc_result_t new_ldap_instance(ldap_db_t *ldap_db,
		ldap_instance_t **ldap_instp);
static void destroy_ldap_instance(ldap_instance_t **ldap_instp);
static isc_result_t add_or_modify_zone(ldap_db_t *ldap_db, const char *dn,
		const char *db_name, dns_zonemgr_t *zmgr);

static isc_result_t findrdatatype_or_create(isc_mem_t *mctx,
		ldapdb_rdatalist_t *rdatalist, ldap_entry_t *entry,
		dns_rdatatype_t rdtype, dns_rdatalist_t **rdlistp);
static isc_result_t add_soa_record(isc_mem_t *mctx, ldap_instance_t *ldap_inst,
		dns_name_t *name, ldap_entry_t *entry,
		ldapdb_rdatalist_t *rdatalist);
static dns_rdataclass_t get_rdataclass(ldap_entry_t *ldap_entry);
static dns_ttl_t get_ttl(ldap_entry_t *ldap_entry);
static isc_result_t get_values(const ldap_entry_t *entry,
		const char *attr_name, ldap_value_list_t *values);
static isc_result_t get_soa_record(ldap_entry_t *entry, ld_string_t *target);
static ldap_attribute_t *get_next_attr(ldap_entry_t *entry,
		const char **attr_list);
static ldap_value_t *get_next_value(ldap_attribute_t *attr);
static isc_boolean_t array_contains_nocase(const char **haystack,
		const char *needle);
static isc_result_t get_next_rdatatype(ldap_entry_t *entry,
		ldap_attribute_t **attr, dns_rdatatype_t *rdtype);
static isc_result_t get_next_rdatatext(ldap_attribute_t *attr,
		ld_string_t *rdata_text);
static isc_result_t parse_rdata(isc_mem_t *mctx, ldap_instance_t *ldap_inst,
		dns_rdataclass_t rdclass, dns_rdatatype_t rdtype,
		dns_name_t *origin, const char *rdata_text,
		dns_rdata_t **rdatap);

static isc_result_t cache_query_results(ldap_instance_t *inst);
static isc_result_t fill_ldap_entry(ldap_instance_t *inst,
		ldap_entry_t *ldap_entry);
static isc_result_t fill_ldap_attribute(ldap_instance_t *inst,
		ldap_attribute_t *ldap_attr);
static void free_query_cache(ldap_instance_t *inst);
static void free_ldap_attributes(isc_mem_t *mctx, ldap_entry_t *entry);
static void free_ldap_values(isc_mem_t *mctx, ldap_attribute_t *attr);


static const LDAPMessage *next_entry(ldap_instance_t *inst);
static const char *get_dn(ldap_instance_t *inst);

static ldap_instance_t * get_connection(ldap_db_t *ldap_db);
static void put_connection(ldap_instance_t *ldap_inst);
static isc_result_t ldap_connect(ldap_instance_t *ldap_inst);
static isc_result_t ldap_query(ldap_instance_t *ldap_inst, const char *base,
		int scope, char **attrs, int attrsonly, const char *filter, ...);


isc_result_t
new_ldap_db(isc_mem_t *mctx, dns_view_t *view, ldap_db_t **ldap_dbp,
	    const char * const *argv)
{
	unsigned int i;
	isc_result_t result;
	ldap_db_t *ldap_db;
	ldap_instance_t *ldap_inst;
	setting_t ldap_settings[] = {
		{ "host",	 no_default_string, NULL },
		{ "connections", default_uint(1),   NULL },
		{ "base",	 no_default_string, NULL },
		end_of_settings
	};

	REQUIRE(mctx != NULL);
	REQUIRE(view != NULL);
	REQUIRE(ldap_dbp != NULL && *ldap_dbp == NULL);

	ldap_db = isc_mem_get(mctx, sizeof(ldap_db_t));
	if (ldap_db == NULL)
		return ISC_R_NOMEMORY;

	ZERO_PTR(ldap_db);

	isc_mem_attach(mctx, &ldap_db->mctx);
	ldap_db->view = view;
	/* commented out for now, cause named to hang */
	//dns_view_attach(view, &ldap_db->view);

	INIT_LIST(ldap_db->conn_list);
	ldap_db->auth_method = AUTH_NONE;	/* todo: should be in settings */

	CHECK(str_new(ldap_db->mctx, &ldap_db->host));
	CHECK(str_new(ldap_db->mctx, &ldap_db->base));

	ldap_settings[0].target = ldap_db->host;
	ldap_settings[1].target = &ldap_db->connections;
	ldap_settings[2].target = ldap_db->base;

	CHECK(set_settings(ldap_settings, argv));
	if (ldap_db->connections < 1) {
		log_error("at least one connection is required");
		result = ISC_R_FAILURE;
		goto cleanup;
	}

	CHECK(semaphore_init(&ldap_db->conn_semaphore, ldap_db->connections));

	for (i = 0; i < ldap_db->connections; i++) {
		ldap_inst = NULL;
		CHECK(new_ldap_instance(ldap_db, &ldap_inst));
		ldap_connect(ldap_inst);
		APPEND(ldap_db->conn_list, ldap_inst, link);
	}

	*ldap_dbp = ldap_db;

	return ISC_R_SUCCESS;

cleanup:
	destroy_ldap_db(&ldap_db);

	return result;
}

void
destroy_ldap_db(ldap_db_t **ldap_dbp)
{
	ldap_db_t *ldap_db;
	ldap_instance_t *elem;
	ldap_instance_t *next;

	REQUIRE(ldap_dbp != NULL && *ldap_dbp != NULL);

	ldap_db = *ldap_dbp;

	elem = HEAD(ldap_db->conn_list);
	while (elem != NULL) {
		next = NEXT(elem, link);
		UNLINK(ldap_db->conn_list, elem, link);
		destroy_ldap_instance(&elem);
		elem = next;
	}

	str_destroy(&ldap_db->host);
	str_destroy(&ldap_db->base);

	semaphore_destroy(&ldap_db->conn_semaphore);
	/* commented out for now, causes named to hang */
	//dns_view_detach(&ldap_db->view);

	isc_mem_putanddetach(&ldap_db->mctx, ldap_db, sizeof(ldap_db_t));

	*ldap_dbp = NULL;
}

static isc_result_t
new_ldap_instance(ldap_db_t *ldap_db, ldap_instance_t **ldap_instp)
{
	isc_result_t result;
	ldap_instance_t *ldap_inst;

	REQUIRE(ldap_db != NULL);
	REQUIRE(ldap_instp != NULL && *ldap_instp == NULL);

	ldap_inst = isc_mem_get(ldap_db->mctx, sizeof(ldap_instance_t));
	if (ldap_inst == NULL)
		return ISC_R_NOMEMORY;

	ZERO_PTR(ldap_inst);

	ldap_inst->database = ldap_db;
	INIT_LINK(ldap_inst, link);
	result = isc_mutex_init(&ldap_inst->lock);
	if (result != ISC_R_SUCCESS) {
		isc_mem_put(ldap_db->mctx, ldap_db, sizeof(ldap_instance_t));
		return result;
	}

	CHECK(str_new(ldap_db->mctx, &ldap_inst->query_string));
	CHECK(str_new(ldap_db->mctx, &ldap_inst->base));

	CHECK(isc_lex_create(ldap_db->mctx, TOKENSIZ, &ldap_inst->lex));
	CHECKED_MEM_GET(ldap_db->mctx, ldap_inst->rdata_target_mem, MINTSIZ);

	*ldap_instp = ldap_inst;

	return ISC_R_SUCCESS;

cleanup:
	destroy_ldap_instance(&ldap_inst);

	return result;
}

static void
destroy_ldap_instance(ldap_instance_t **ldap_instp)
{
	ldap_instance_t *ldap_inst;

	REQUIRE(ldap_instp != NULL && *ldap_instp != NULL);

	ldap_inst = *ldap_instp;
	DESTROYLOCK(&ldap_inst->lock);
	if (ldap_inst->handle != NULL)
		ldap_unbind_ext_s(ldap_inst->handle, NULL, NULL);

	str_destroy(&ldap_inst->query_string);
	str_destroy(&ldap_inst->base);

	if (ldap_inst->lex != NULL)
		isc_lex_destroy(&ldap_inst->lex);
	if (ldap_inst->rdata_target_mem != NULL) {
		isc_mem_put(ldap_inst->database->mctx,
			    ldap_inst->rdata_target_mem, MINTSIZ);
	}

	isc_mem_put(ldap_inst->database->mctx, *ldap_instp, sizeof(ldap_instance_t));
	*ldap_instp = NULL;
}

/* TODO: Delete old zones. */
isc_result_t
refresh_zones_from_ldap(ldap_db_t *ldap_db, const char *name,
			dns_zonemgr_t *zmgr)
{
	isc_result_t result = ISC_R_SUCCESS;
	ldap_instance_t *ldap_inst;
	char *attrs[] = {
		"idnsName", NULL
	};

	REQUIRE(ldap_db != NULL);
	REQUIRE(name != NULL);

	log_debug(2, "refreshing list of zones");

	ldap_inst = get_connection(ldap_db);

	ldap_query(ldap_inst, str_buf(ldap_db->base), LDAP_SCOPE_SUBTREE,
		   attrs, 0, "(objectClass=idnsZone)");

	while (next_entry(ldap_inst))
		CHECK(add_or_modify_zone(ldap_db, get_dn(ldap_inst), name, zmgr));

cleanup:
	put_connection(ldap_inst);

	log_debug(2, "finished refreshing list of zones");

	return result;
}

static const char *
get_dn(ldap_instance_t *inst)
{
	if (inst->dn) {
		ldap_memfree(inst->dn);
		inst->dn = NULL;
	}

	if (inst->handle && inst->entry)
		inst->dn = ldap_get_dn(inst->handle, inst->entry);

	return inst->dn;

}

static isc_result_t
add_or_modify_zone(ldap_db_t *ldap_db, const char *dn, const char *db_name,
		   dns_zonemgr_t *zmgr)
{
	isc_result_t result;
	dns_zone_t *zone;
	dns_name_t name;
	dns_acl_t *updateacl = NULL;
	const char *argv[2];

	REQUIRE(ldap_db != NULL);
	REQUIRE(dn != NULL);
	REQUIRE(db_name != NULL);

	argv[0] = ldapdb_impname;
	argv[1] = db_name;

	zone = NULL;
	dns_name_init(&name, NULL);

	CHECK(dn_to_dnsname(ldap_db->mctx, dn, str_buf(ldap_db->base), &name));

	/* If the zone doesn't exist, create it. */
	result = dns_view_findzone(ldap_db->view, &name, &zone);
	if (result == ISC_R_NOTFOUND) {
		CHECK(dns_zone_create(&zone, ldap_db->mctx));
		dns_zone_setview(zone, ldap_db->view);
		CHECK(dns_zone_setorigin(zone, &name));
		dns_zone_setclass(zone, dns_rdataclass_in);
		dns_zone_settype(zone, dns_zone_master);
		CHECK(dns_zone_setdbtype(zone, 2, argv));

		/* XXX Temporary set update ACLs to any */
		CHECK(dns_acl_any(ldap_db->mctx, &updateacl));
		dns_zone_setupdateacl(zone, updateacl);
		dns_acl_detach(&updateacl);

		CHECK(dns_zonemgr_managezone(zmgr, zone));
		CHECK(dns_view_addzone(ldap_db->view, zone));
	} else if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}

	/*
	 * ACLs:
	 * dns_zone_setqueryacl()
	 * dns_zone_setqueryonacl()
	 * dns_zone_setupdateacl()
	 * dns_zone_setforwardacl()
	 * dns_zone_setxfracl()
	 */

	/*
	 * maybe?
	 * dns_zone_setnotifytype()
	 * dns_zone_setalsonotify()
	 */

cleanup:
	if (dns_name_dynamic(&name))
		dns_name_free(&name, ldap_db->mctx);
	if (zone != NULL)
		dns_zone_detach(&zone);

	return result;
}

static isc_result_t
findrdatatype_or_create(isc_mem_t *mctx, ldapdb_rdatalist_t *rdatalist,
			ldap_entry_t *entry, dns_rdatatype_t rdtype,
			dns_rdatalist_t **rdlistp)
{
	isc_result_t result;
	dns_rdatalist_t *rdlist = NULL;
	dns_ttl_t ttl;

	REQUIRE(rdatalist != NULL);
	REQUIRE(entry != NULL);
	REQUIRE(rdlistp != NULL);

	*rdlistp = NULL;

	ttl = get_ttl(entry);

	result = ldapdb_rdatalist_findrdatatype(rdatalist, rdtype, &rdlist);
	if (result != ISC_R_SUCCESS) {
		CHECKED_MEM_GET_PTR(mctx, rdlist);

		dns_rdatalist_init(rdlist);
		rdlist->rdclass = get_rdataclass(entry);
		rdlist->type = rdtype;
		rdlist->ttl = ttl;
		APPEND(*rdatalist, rdlist, link);
		result = ISC_R_SUCCESS;
	} else {
		/*
		 * No support for different TTLs yet.
		 */
		if (rdlist->ttl != ttl)
			result = ISC_R_FAILURE;
	}

	*rdlistp = rdlist;
	return ISC_R_SUCCESS;

cleanup:
	SAFE_MEM_PUT_PTR(mctx, rdlist);

	return result;
}

/*
 * ldapdb_rdatalist_t related functions.
 */
isc_result_t
ldapdb_rdatalist_findrdatatype(ldapdb_rdatalist_t *rdatalist,
			       dns_rdatatype_t rdtype,
			       dns_rdatalist_t **rdlistp)
{
	dns_rdatalist_t *rdlist;

	REQUIRE(rdatalist != NULL);
	REQUIRE(rdlistp != NULL && *rdlistp == NULL);

	rdlist = HEAD(*rdatalist);
	while (rdlist != NULL && rdlist->type != rdtype) {
		rdlist = NEXT(rdlist, link);
	}

	*rdlistp = rdlist;

	return (rdlist == NULL) ? ISC_R_NOTFOUND : ISC_R_SUCCESS;
}

void
ldapdb_rdatalist_destroy(isc_mem_t *mctx, ldapdb_rdatalist_t *rdatalist)
{
	dns_rdatalist_t *rdlist;

	REQUIRE(rdatalist != NULL);

	while (!EMPTY(*rdatalist)) {
		rdlist = HEAD(*rdatalist);
		free_rdatalist(mctx, rdlist);
		UNLINK(*rdatalist, rdlist, link);
		isc_mem_put(mctx, rdlist, sizeof(*rdlist));
	}
}

void
free_rdatalist(isc_mem_t *mctx, dns_rdatalist_t *rdlist)
{
	dns_rdata_t *rdata;
	isc_region_t r;

	REQUIRE(rdlist != NULL);

	while (!EMPTY(rdlist->rdata)) {
		rdata = HEAD(rdlist->rdata);
		UNLINK(rdlist->rdata, rdata, link);
		dns_rdata_toregion(rdata, &r);
		isc_mem_put(mctx, r.base, r.length);
		isc_mem_put(mctx, rdata, sizeof(*rdata));
	}
}

isc_result_t
ldapdb_rdatalist_get(isc_mem_t *mctx, ldap_db_t *ldap_db, dns_name_t *name,
		     ldapdb_rdatalist_t *rdatalist)
{
	isc_result_t result;
	ldap_instance_t *ldap_inst;
	ldap_entry_t *entry;
	ldap_attribute_t *attr;
	ld_string_t *string = NULL;

	dns_rdataclass_t rdclass;
	dns_ttl_t ttl;
	dns_rdatatype_t rdtype;
	dns_rdata_t *rdata = NULL;
	dns_rdatalist_t *rdlist = NULL;

	REQUIRE(mctx != NULL);
	REQUIRE(ldap_db != NULL);
	REQUIRE(name != NULL);
	REQUIRE(rdatalist != NULL);

	ldap_inst = get_connection(ldap_db);

	INIT_LIST(*rdatalist);
	CHECK(str_new(mctx, &string));
	CHECK(dnsname_to_dn(mctx, name, str_buf(ldap_db->base), string));

	CHECK(ldap_query(ldap_inst, str_buf(string), LDAP_SCOPE_BASE, NULL, 0,
				"(objectClass=idnsRecord)"));
	CHECK(cache_query_results(ldap_inst));

	if (EMPTY(ldap_inst->ldap_entries)) {
		result = ISC_R_NOTFOUND;
		goto cleanup;
	}

	for (entry = HEAD(ldap_inst->ldap_entries);
	     entry != NULL;
	     entry = NEXT(entry, link)) {

		result = add_soa_record(mctx, ldap_inst, name, entry,
					rdatalist);
		if (result != ISC_R_SUCCESS && result != ISC_R_NOTFOUND)
			goto cleanup;

		rdclass = get_rdataclass(entry);
		ttl = get_ttl(entry);

		for (result = get_next_rdatatype(entry, &attr, &rdtype);
		     result == ISC_R_SUCCESS;
		     result = get_next_rdatatype(entry, &attr, &rdtype)) {

			CHECK(findrdatatype_or_create(mctx, rdatalist, entry,
						      rdtype, &rdlist));
			for (result = get_next_rdatatext(attr, string);
			     result == ISC_R_SUCCESS;
			     result = get_next_rdatatext(attr, string)) {
				CHECK(parse_rdata(mctx, ldap_inst, rdclass,
						  rdtype, name, str_buf(string),
						  &rdata));
				APPEND(rdlist->rdata, rdata, link);
				rdata = NULL;
			}
			rdlist = NULL;
		}
	}

	result = ISC_R_SUCCESS;

cleanup:
	put_connection(ldap_inst);
	str_destroy(&string);

	if (result != ISC_R_SUCCESS)
		ldapdb_rdatalist_destroy(mctx, rdatalist);

	return result;
}

static dns_rdataclass_t
get_rdataclass(ldap_entry_t *ldap_entry)
{
	UNUSED(ldap_entry);

	/*
	 * Not implemented for now.
	 * Probably won't ever be.
	 */

	return dns_rdataclass_in;
}

static dns_ttl_t
get_ttl(ldap_entry_t *ldap_entry)
{
	UNUSED(ldap_entry);

	/*
	 * TODO: Not implemented yet.
	 */
#if 0
	isc_textregion_t ttl_text;

	ttl_text.base = "86400";
	ttl_text.length = strlen(ttl_text.base);
	result = dns_ttl_fromtext(&ttl_text, &ttl);
	if (result != ISC_R_SUCCESS) {
		seen_error = ISC_TRUE;
		break;
	}
#endif

	return 86400;
}

static isc_result_t
get_soa_record(ldap_entry_t *entry, ld_string_t *target)
{
	isc_result_t result;
	ldap_value_list_t values;

	const char *soa_attrs[] = {
		"idnsSOAmName", "idnsSOArName", "idnsSOAserial",
		"idnsSOArefresh", "idnsSOAretry", "idnsSOAexpire",
		"idnsSOAminimum", NULL
	};

	REQUIRE(entry != NULL);
	REQUIRE(target != NULL);

	str_clear(target);
	for (unsigned i = 0; soa_attrs[i] != NULL; i++) {
		CHECK(get_values(entry, soa_attrs[i], &values));
		CHECK(str_cat_char(target, HEAD(values)->value));
		CHECK(str_cat_char(target, " "));
	}

cleanup:
	return result;
}

static isc_result_t
add_soa_record(isc_mem_t *mctx, ldap_instance_t *ldap_inst, dns_name_t *name,
	       ldap_entry_t *entry, ldapdb_rdatalist_t *rdatalist)
{
	isc_result_t result;
	ld_string_t *string = NULL;
	dns_rdataclass_t rdclass;
	dns_rdata_t *rdata = NULL;
	dns_rdatalist_t *rdlist = NULL;

	CHECK(str_new(mctx, &string));

	CHECK(get_soa_record(entry, string));
	rdclass = get_rdataclass(entry);

	CHECK(get_soa_record(entry, string));
	CHECK(parse_rdata(mctx, ldap_inst, rdclass, dns_rdatatype_soa, name,
			  str_buf(string), &rdata));

	CHECK(findrdatatype_or_create(mctx, rdatalist, entry, dns_rdatatype_soa,
				      &rdlist));

	APPEND(rdlist->rdata, rdata, link);

cleanup:
	str_destroy(&string);
	if (result != ISC_R_SUCCESS)
		SAFE_MEM_PUT_PTR(mctx, rdata);

	return result;
}

static isc_result_t
get_next_rdatatype(ldap_entry_t *entry, ldap_attribute_t **attrp,
		   dns_rdatatype_t *rdtype)
{
	isc_result_t result;
	ldap_attribute_t *attr;

	result = ISC_R_NOTFOUND;

	for (attr = get_next_attr(entry, NULL);
	     attr != NULL;
	     attr = get_next_attr(entry, NULL)) {
		result = ldap_record_to_rdatatype(attr->name, rdtype);
		if (result == ISC_R_SUCCESS)
			break;
	}

	if (result == ISC_R_SUCCESS)
		*attrp = attr;
	else if (result == ISC_R_NOTFOUND)
		*attrp = NULL;

	return result;
}

static isc_result_t
get_next_rdatatext(ldap_attribute_t *attr, ld_string_t *rdata_text)
{
	ldap_value_t *value;

	REQUIRE(attr != NULL);
	REQUIRE(rdata_text != NULL);

	str_clear(rdata_text);

	value = get_next_value(attr);
	if (value == NULL)
		return ISC_R_NOTFOUND;

	str_init_char(rdata_text, value->value);

	return ISC_R_SUCCESS;
}

static isc_result_t
parse_rdata(isc_mem_t *mctx, ldap_instance_t *ldap_inst,
	    dns_rdataclass_t rdclass, dns_rdatatype_t rdtype,
	    dns_name_t *origin, const char *rdata_text, dns_rdata_t **rdatap)
{
	isc_result_t result;
	isc_consttextregion_t text;
	isc_buffer_t lex_buffer;
	isc_region_t rdatamem;
	dns_rdata_t *rdata;

	REQUIRE(mctx != NULL);
	REQUIRE(ldap_inst != NULL);
	REQUIRE(rdata_text != NULL);
	REQUIRE(rdatap != NULL);

	rdata = NULL;
	rdatamem.base = NULL;

	text.base = rdata_text;
	text.length = strlen(text.base);

	isc_buffer_init(&lex_buffer, text.base, text.length);
	isc_buffer_add(&lex_buffer, text.length);
	isc_buffer_setactive(&lex_buffer, text.length);

	CHECK(isc_lex_openbuffer(ldap_inst->lex, &lex_buffer));

	isc_buffer_init(&ldap_inst->rdata_target, ldap_inst->rdata_target_mem,
			MINTSIZ);
	CHECK(dns_rdata_fromtext(NULL, rdclass, rdtype, ldap_inst->lex, origin,
				 0, mctx, &ldap_inst->rdata_target, NULL));

	CHECKED_MEM_GET_PTR(mctx, rdata);
	dns_rdata_init(rdata);

	rdatamem.length = isc_buffer_usedlength(&ldap_inst->rdata_target);
	CHECKED_MEM_GET(mctx, rdatamem.base, rdatamem.length);

	memcpy(rdatamem.base, isc_buffer_base(&ldap_inst->rdata_target),
	       rdatamem.length);
	dns_rdata_fromregion(rdata, rdclass, rdtype, &rdatamem);

	isc_lex_close(ldap_inst->lex);

	*rdatap = rdata;
	return ISC_R_SUCCESS;

cleanup:
	isc_lex_close(ldap_inst->lex);
	if (rdata != NULL)
		isc_mem_put(mctx, rdata, sizeof(*rdata));
	if (rdatamem.base != NULL)
		isc_mem_put(mctx, rdatamem.base, rdatamem.length);

	return result;
}

static ldap_attribute_t *
get_next_attr(ldap_entry_t *entry, const char **attr_list)
{
	ldap_attribute_t *attr;

	REQUIRE(entry != NULL);

	if (entry->last_attr == NULL)
		attr = HEAD(entry->attributes);
	else
		attr = NEXT(entry->last_attr, link);

	if (attr_list != NULL) {
		while (attr != NULL && !array_contains_nocase(attr_list, attr->name))
			attr = NEXT(attr, link);
	}

	if (attr != NULL)
		entry->last_attr = attr;

	return attr;
}

static isc_result_t
get_values(const ldap_entry_t *entry, const char *attr_name,
	   ldap_value_list_t *values)
{
	ldap_attribute_t *attr;

	REQUIRE(entry != NULL);
	REQUIRE(attr_name != NULL);
	REQUIRE(values != NULL);

	for (attr = HEAD(entry->attributes);
	     attr != NULL;
	     attr = NEXT(attr, link)) {
		if (!strcasecmp(attr->name, attr_name)) {
			*values = attr->values;
			return ISC_R_SUCCESS;
		}
	}

	return ISC_R_NOTFOUND;
}

static ldap_value_t *
get_next_value(ldap_attribute_t *attr)
{
	ldap_value_t *value;

	REQUIRE(attr != NULL);

	if (attr->last_value == NULL)
		value = HEAD(attr->values);
	else
		value = NEXT(attr->last_value, link);

	if (value != NULL)
		attr->last_value = value;

	return value;
}

static isc_boolean_t
array_contains_nocase(const char **haystack, const char *needle)
{
	for (unsigned int i = 0; haystack[i] != NULL; i++) {
		if (strcasecmp(needle, haystack[i]) == 0)
			return isc_boolean_true;
	}

	return isc_boolean_false;
}

static ldap_instance_t *
get_connection(ldap_db_t *ldap_db)
{
	ldap_instance_t *ldap_inst;

	semaphore_wait(&ldap_db->conn_semaphore);
	ldap_inst = HEAD(ldap_db->conn_list);
	while (ldap_inst != NULL) {
		if (isc_mutex_trylock(&ldap_inst->lock) == ISC_R_SUCCESS)
			break;
		ldap_inst = NEXT(ldap_inst, link);
	}

	RUNTIME_CHECK(ldap_inst != NULL);

	INIT_LIST(ldap_inst->ldap_entries);
	/* TODO: find a clever way to not really require this */
	str_copy(ldap_inst->base, ldap_db->base);

	return ldap_inst;
}

static void
put_connection(ldap_instance_t *ldap_inst)
{
	if (ldap_inst->dn) {
		ldap_memfree(ldap_inst->dn);
		ldap_inst->dn = NULL;
	}
	if (ldap_inst->values) {
		ldap_value_free(ldap_inst->values);
		ldap_inst->values = NULL;
	}
	if (ldap_inst->attribute) {
		ldap_memfree(ldap_inst->attribute);
		ldap_inst->attribute = NULL;
	}
	if (ldap_inst->ber) {
		ber_free(ldap_inst->ber, 0);
		ldap_inst->ber = NULL;
	}
	if (ldap_inst->result) {
		ldap_msgfree(ldap_inst->result);
		ldap_inst->result = NULL;
	}

	free_query_cache(ldap_inst);

	UNLOCK(&ldap_inst->lock);
	semaphore_signal(&ldap_inst->database->conn_semaphore);
}


static isc_result_t
ldap_query(ldap_instance_t *ldap_inst, const char *base, int scope, char **attrs,
	   int attrsonly, const char *filter, ...)
{
	va_list ap;
	int ret;

	va_start(ap, filter);
	str_vsprintf(ldap_inst->query_string, filter, ap);
	va_end(ap);

	log_debug(2, "querying '%s' with '%s'", base,
		  str_buf(ldap_inst->query_string));

	ret = ldap_search_ext_s(ldap_inst->handle, base, scope,
				str_buf(ldap_inst->query_string), attrs,
				attrsonly, NULL, NULL, NULL, LDAP_NO_LIMIT,
				&ldap_inst->result);

	log_debug(2, "entry count: %d", ldap_count_entries(ldap_inst->handle,
		  ldap_inst->result));

	return ISC_R_SUCCESS;
}

static isc_result_t
cache_query_results(ldap_instance_t *inst)
{
	isc_result_t result;
	LDAP *ld;
	LDAPMessage *res;
	LDAPMessage *entry;
	ldap_entry_t *ldap_entry;

	REQUIRE(inst != NULL);
	REQUIRE(EMPTY(inst->ldap_entries));
	REQUIRE(inst->result != NULL);

	INIT_LIST(inst->ldap_entries);

	if (inst->cache_active)
		free_query_cache(inst);

	ld = inst->handle;
	res = inst->result;

	for (entry = ldap_first_entry(ld, res);
	     entry != NULL;
	     entry = ldap_next_entry(ld, entry)) {
		CHECKED_MEM_GET_PTR(inst->database->mctx, ldap_entry);
		ZERO_PTR(ldap_entry);

		ldap_entry->entry = entry;
		INIT_LIST(ldap_entry->attributes);
		INIT_LINK(ldap_entry, link);
		CHECK(fill_ldap_entry(inst, ldap_entry));

		APPEND(inst->ldap_entries, ldap_entry, link);
	}

	return ISC_R_SUCCESS;

cleanup:
	free_query_cache(inst);

	return result;
}

static isc_result_t
fill_ldap_entry(ldap_instance_t *inst, ldap_entry_t *ldap_entry)
{
	isc_result_t result;
	ldap_attribute_t *ldap_attr;
	char *attribute;
	BerElement *ber;
	LDAPMessage *entry;

	REQUIRE(inst != NULL);
	REQUIRE(ldap_entry != NULL);

	result = ISC_R_SUCCESS;
	entry = ldap_entry->entry;

	for (attribute = ldap_first_attribute(inst->handle, entry, &ber);
	     attribute != NULL;
	     attribute = ldap_next_attribute(inst->handle, entry, ber)) {
		CHECKED_MEM_GET_PTR(inst->database->mctx, ldap_attr);
		ZERO_PTR(ldap_attr);

		ldap_attr->name = attribute;
		INIT_LIST(ldap_attr->values);
		INIT_LINK(ldap_attr, link);
		CHECK(fill_ldap_attribute(inst, ldap_attr));

		APPEND(ldap_entry->attributes, ldap_attr, link);
	}

	if (ber != NULL)
		ber_free(ber, 0);

cleanup:
	if (result != ISC_R_SUCCESS) {
		free_ldap_attributes(inst->database->mctx, ldap_entry);
	}

	return result;
}

static isc_result_t
fill_ldap_attribute(ldap_instance_t *inst, ldap_attribute_t *ldap_attr)
{
	isc_result_t result;
	char **values;
	ldap_value_t *ldap_val;

	REQUIRE(inst != NULL);
	REQUIRE(ldap_attr != NULL);

	values = ldap_get_values(inst->handle, inst->result, ldap_attr->name);
	/* TODO: proper ldap error handling */
	if (values == NULL)
		return ISC_R_FAILURE;

	ldap_attr->ldap_values = values;

	for (unsigned int i = 0; values[i] != NULL; i++) {
		CHECKED_MEM_GET_PTR(inst->database->mctx, ldap_val);
		ldap_val->value = values[i];
		INIT_LINK(ldap_val, link);

		APPEND(ldap_attr->values, ldap_val, link);
	}

	return ISC_R_SUCCESS;

cleanup:
	free_ldap_values(inst->database->mctx, ldap_attr);
	ldap_value_free(values);

	return result;
}

static void
free_query_cache(ldap_instance_t *inst)
{
	ldap_entry_t *entry, *next;

	entry = HEAD(inst->ldap_entries);
	while (entry != NULL) {
		next = NEXT(entry, link);
		UNLINK(inst->ldap_entries, entry, link);
		free_ldap_attributes(inst->database->mctx, entry);
		isc_mem_put(inst->database->mctx, entry, sizeof(*entry));
		entry = next;
	}

	inst->cache_active = isc_boolean_false;
}

static void
free_ldap_attributes(isc_mem_t *mctx, ldap_entry_t *entry)
{
	ldap_attribute_t *attr, *next;

	attr = HEAD(entry->attributes);
	while (attr != NULL) {
		next = NEXT(attr, link);
		UNLINK(entry->attributes, attr, link);
		free_ldap_values(mctx, attr);
		ldap_value_free(attr->ldap_values);
		ldap_memfree(attr->name);
		isc_mem_put(mctx, attr, sizeof(*attr));
		attr = next;
	}
}

static void
free_ldap_values(isc_mem_t *mctx, ldap_attribute_t *attr)
{
	ldap_value_t *value, *next;

	value = HEAD(attr->values);
	while (value != NULL) {
		next = NEXT(value, link);
		UNLINK(attr->values, value, link);
		isc_mem_put(mctx, value, sizeof(*value));
		value = next;
	}
}

/* FIXME: this function is obsolete, remove. */
static const LDAPMessage *
next_entry(ldap_instance_t *inst)
{
	if (inst->ber) {
		ber_free(inst->ber, 0);
		inst->ber = NULL;
	}

	if (inst->handle && inst->entry)
		inst->entry = ldap_next_entry(inst->handle, inst->entry);
	else if (inst->handle && inst->result)
		inst->entry = ldap_first_entry(inst->handle, inst->result);
	else
		inst->entry = NULL;

	return inst->entry;
}


static isc_result_t
ldap_connect(ldap_instance_t *ldap_inst)
{
	LDAP *ld;
	int ret;
	ldap_db_t *ldap_db;

	REQUIRE(ldap_inst != NULL);

	ldap_db = ldap_inst->database;

	/* XXX: port should be overridable */
	ret = ldap_initialize(&ld, str_buf(ldap_db->host));
	if (ret != LDAP_SUCCESS) {
		log_error("LDAP initialization failed: %s", ldap_err2string(ret));
		goto cleanup;
	}

	/*
	ret = ldap_set_option(ld, LDAP_OPT_TIMELIMIT, (void *)&ldap_db->timeout);
	if (ret != LDAP_OPT_SUCCESS) {
		log_error("Failed to set timeout: %s", ldap_err2string(ret));
		goto cleanup;
	}
	*/

	log_debug(2, "Trying to make an LDAP connection to %s", str_buf(ldap_db->host));

	switch (ldap_db->auth_method) {
	case AUTH_NONE:
		ret = ldap_simple_bind_s(ld, NULL, NULL);
		break;
	case AUTH_SIMPLE:
		fatal_error("Simple auth not supported yet.");
		break;
	case AUTH_SASL:
		fatal_error("SASL auth not supported yet.");
		break;
	default:
		fatal_error("Bug in ldap_connect(): unsupported authentication mechanism");
		return ISC_R_UNEXPECTED;
	}

	if (ret != LDAP_SUCCESS) {
		log_error("Bind to LDAP server failed: %s", ldap_err2string(ret));
		goto cleanup;
	}

	ldap_inst->handle = ld;

	return ISC_R_SUCCESS;

cleanup:

	if (ld != NULL)
		ldap_unbind_ext_s(ld, NULL, NULL);

	return ISC_R_FAILURE;
}
