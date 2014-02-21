/*
 * Authors: Adam Tkac   <atkac@redhat.com>
 *          Martin Nagy <mnagy@redhat.com>
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

#ifndef _LD_RDLIST_H_
#define _LD_RDLIST_H_

#include <isc/md5.h>

#include "types.h"

#define RDLIST_DIGESTLENGTH ISC_MD5_DIGESTLENGTH

isc_result_t
rdatalist_clone(isc_mem_t *mctx, dns_rdatalist_t *source,
		dns_rdatalist_t **targetp) ATTR_NONNULLS ATTR_CHECKRESULT;

isc_result_t
ldap_rdatalist_copy(isc_mem_t *mctx, ldapdb_rdatalist_t source,
		    ldapdb_rdatalist_t *target) ATTR_NONNULLS ATTR_CHECKRESULT;

unsigned int
rdatalist_length(const dns_rdatalist_t *rdlist) ATTR_NONNULLS ATTR_CHECKRESULT;

isc_result_t
rdatalist_digest(isc_mem_t *mctx, ldapdb_rdatalist_t *rdlist,
		unsigned char *digest) ATTR_NONNULLS ATTR_CHECKRESULT;

#endif /* !_LD_RDLIST_H_ */
