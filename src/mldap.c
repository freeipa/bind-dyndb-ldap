/*
 * Copyright (C) 2015  bind-dyndb-ldap authors; see COPYING for license
 *
 * Meta-database for LDAP-specific information which are not represented in
 * DNS data.
 */

#include <ldap.h>
#include <stddef.h>
#include <uuid/uuid.h>

#include <isc/result.h>
#include <isc/util.h>

#include <dns/name.h>

#include "mldap.h"
#include "util.h"

/* name "ldap.uuid." */
static unsigned char uuid_rootname_ndata[]
	= { 4, 'u', 'u', 'i', 'd', 4, 'l', 'd', 'a', 'p', 0 };
static unsigned char uuid_rootname_offsets[] = { 0, 5, 10 };
static dns_name_t uuid_rootname =
{
	DNS_NAME_MAGIC,
	uuid_rootname_ndata,
	sizeof(uuid_rootname_ndata),
	sizeof(uuid_rootname_offsets),
	DNS_NAMEATTR_READONLY | DNS_NAMEATTR_ABSOLUTE,
	uuid_rootname_offsets,
	NULL,
	{ (void *)-1, (void *)-1 },
	{ NULL, NULL }
};

/**
 * Convert UUID to "01234567-89ab-cdef-0123-456789abcdef.uuid.ldap." DNS name.
 *
 * @param[in]  beruuid
 * @param[out] nameuuid
 */
void
ldap_uuid_to_mname(struct berval *beruuid, dns_name_t *nameuuid) {
	/* UUID string representation according to RFC 4122 section 3 */
	char label_buf[sizeof("01234567-89ab-cdef-0123-456789abcdef") + 1];
	/* uncompressed label format, length 36 octets; RFC 1034 section 3.1 */
	label_buf[0] = 36;

	isc_region_t label_reg;
	label_reg.base = (unsigned char *)label_buf;
	label_reg.length = sizeof(label_buf) - 1; /* omit final \0 */

	dns_name_t relative_name;
	DNS_NAME_INIT(&relative_name, NULL);

	/* RFC 4530 section 2.1 format = 16 octets is required */
	REQUIRE(beruuid != NULL && beruuid->bv_len == 16);

	/* fill-in string representation into label buffer */
	uuid_unparse((*(const uuid_t *) beruuid->bv_val), label_buf + 1);
	dns_name_fromregion(&relative_name, &label_reg);

	INSIST(dns_name_concatenate(&relative_name, &uuid_rootname,
				    nameuuid, NULL) == ISC_R_SUCCESS);

	return;
}
