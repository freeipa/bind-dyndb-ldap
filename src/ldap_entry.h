/*
 * Copyright (C) 2011-2014  bind-dyndb-ldap authors; see COPYING for license
 */

#ifndef _LD_LDAP_ENTRY_H_
#define _LD_LDAP_ENTRY_H_

#include <isc/lex.h>
#include <isc/util.h>
#include <dns/types.h>

#include "fwd_register.h"
#include "util.h"
#include "str.h"
#include "types.h"

#define LDAP_DEPRECATED 1
#include <ldap.h>

/* Represents values associated with LDAP attribute */
typedef struct ldap_value ldap_value_t;
typedef LIST(ldap_value_t) ldap_valuelist_t;
struct ldap_value {
        char                    *value;
        LINK(ldap_value_t)      link;
};

/* Represents LDAP attribute and it's values */
typedef struct ldap_attribute	ldap_attribute_t;
typedef LIST(ldap_attribute_t)	ldap_attributelist_t;

/* Represents LDAP entry and it's attributes */
typedef unsigned char		ldap_entryclass_t;
struct ldap_entry {
	isc_mem_t		*mctx;
	char			*dn;
	struct berval		*uuid;
	ldap_entryclass_t	class;
	DECLARE_BUFFERED_NAME(fqdn);
	DECLARE_BUFFERED_NAME(zone_name);

	ldap_attribute_t	*lastattr;
	ldap_attributelist_t	attrs;
	LINK(ldap_entry_t)	link;

	/* Parsing. */
	isc_lex_t		*lex;
	isc_buffer_t		rdata_target;
	unsigned char		*rdata_target_mem;

	/* Human-readable identifier. It has to be accessed via
	 * ldap_entry_logname(). */
	ld_string_t		*logname;
};

/* Represents LDAP attribute and it's values */
struct ldap_attribute {
	char			*name;
	char			**ldap_values;
	ldap_value_t		*lastval;
	ldap_valuelist_t	values;
	LINK(ldap_attribute_t)	link;
};

#define LDAP_ENTRYCLASS_NONE	0x0
#define LDAP_ENTRYCLASS_RR	0x1
#define LDAP_ENTRYCLASS_MASTER	0x2
#define LDAP_ENTRYCLASS_CONFIG	0x4
#define LDAP_ENTRYCLASS_FORWARD	0x8

#define DEFAULT_TTL 86400

/* Max type length definitions, from lib/dns/master.c */
#define TOKENSIZ (8*1024)

isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
ldap_entry_init(isc_mem_t *mctx, ldap_entry_t **entryp);

isc_result_t
ldap_entry_parse(isc_mem_t *mctx, LDAP *ld, LDAPMessage *ldap_entry,
		  struct berval	*uuid, ldap_entry_t **entryp) ATTR_NONNULLS ATTR_CHECKRESULT;

isc_result_t
ldap_entry_reconstruct(isc_mem_t *mctx, mldapdb_t *mldap, struct berval *uuid,
		       ldap_entry_t **entryp) ATTR_NONNULLS ATTR_CHECKRESULT;

void
ldap_entry_destroy(ldap_entry_t **entryp) ATTR_NONNULLS;

isc_result_t
ldap_entry_getvalues(const ldap_entry_t *entry, const char *attrname,
		     ldap_valuelist_t *values) ATTR_NONNULLS ATTR_CHECKRESULT;

dns_rdataclass_t
ldap_entry_getrdclass(const ldap_entry_t *entry) ATTR_NONNULLS ATTR_CHECKRESULT;

ldap_attribute_t*
ldap_entry_nextattr(ldap_entry_t *entry) ATTR_NONNULLS ATTR_CHECKRESULT;

isc_result_t
ldap_entry_firstrdtype(ldap_entry_t *entry, ldap_attribute_t **attrp,
		       dns_rdatatype_t *rdtype) ATTR_NONNULLS ATTR_CHECKRESULT;

isc_result_t
ldap_entry_nextrdtype(ldap_entry_t *entry, ldap_attribute_t **attrp,
		      dns_rdatatype_t *rdtype) ATTR_NONNULLS ATTR_CHECKRESULT;

isc_result_t
ldap_entry_getfakesoa(ldap_entry_t *entry, const char *fake_mname,
		      ld_string_t *target) ATTR_NONNULLS ATTR_CHECKRESULT;

isc_result_t
ldap_attr_firstvalue(ldap_attribute_t *attr, ld_string_t *str) ATTR_NONNULLS ATTR_CHECKRESULT;

/*
 * ldap_attr_nextvalue
 *
 * Returns pointer to value in case of success, NULL if no other val is
 * available
 */
isc_result_t
ldap_attr_nextvalue(ldap_attribute_t *attr, ld_string_t *value) ATTR_NONNULLS ATTR_CHECKRESULT;

dns_ttl_t
ldap_entry_getttl(ldap_entry_t *entry) ATTR_NONNULLS ATTR_CHECKRESULT;

const char *
ldap_entry_logname(ldap_entry_t * const entry) ATTR_NONNULLS ATTR_CHECKRESULT;

#endif /* !_LD_LDAP_ENTRY_H_ */
