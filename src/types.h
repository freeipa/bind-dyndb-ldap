/*
 * Copyright (C) 2011-2013  bind-dyndb-ldap authors; see COPYING for license
 */

#ifndef _LD_TYPES_H_
#define _LD_TYPES_H_

#include <isc/event.h>
#include <inttypes.h>
#include <isc/refcount.h>
#include <dns/name.h>

#include "util.h"

/*
 * some nice words about ldapdb_rdatalist_t:
 * - it is list of all RRs which have same owner name
 * - rdata buffer is reachable only via dns_rdata_toregion()
 *
 * structure:
 *
 * class1                               class2
 * type1                                type2
 * ttl1                                 ttl2
 * rdata1 -> rdata2 -> rdata3           rdata4 -> rdata5
 * next_rdatalist              ->       next_rdatalist  ...
 */
typedef ISC_LIST(dns_rdatalist_t) ldapdb_rdatalist_t;

typedef struct enum_txt_assoc {
	int		value;
	const char	*description;
} enum_txt_assoc_t;

typedef struct ldap_instance	ldap_instance_t;
typedef struct zone_register	zone_register_t;
typedef struct mldapdb		mldapdb_t;
typedef struct ldap_entry	ldap_entry_t;
typedef struct settings_set	settings_set_t;


#define LDAPDB_EVENT_SYNCREPL_UPDATE	(LDAPDB_EVENTCLASS + 1)
typedef struct ldap_syncreplevent ldap_syncreplevent_t;
struct ldap_syncreplevent {
	ISC_EVENT_COMMON(ldap_syncreplevent_t);
	isc_mem_t *mctx;
	ldap_instance_t	*inst;
	char *prevdn;
	int chgtype;
	ldap_entry_t *entry;
	uint32_t seqid;
};

#endif /* !_LD_TYPES_H_ */
