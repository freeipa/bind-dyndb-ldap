/* Authors: Martin Nagy <mnagy@redhat.com>
 *
 * Copyright (C) 2008  Red Hat
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

#include <isc/mem.h>
#include <isc/util.h>

#include <dns/result.h>

#include "log.h"

#define CHECK(op)						\
	do { result = (op);					\
		if (result != ISC_R_SUCCESS) goto cleanup;	\
	} while (0)

/*
 * Functions.
 */

isc_result_t
dynamic_driver_init(isc_mem_t *mctx, const char *name, const char * const *argv,
		    dns_view_t *view)
{
	isc_result_t result;

	UNUSED(mctx);
	UNUSED(view);

	log_debug(2, "Registering dynamic ldap driver for %s.", name);

	/* Test argv. */
	while (*argv != NULL) {
		log_debug(2, "Arg: %s", *argv);
		argv++;
	}

	/* Register our driver here. */
	log_error("Driver not implemented yet.");
	result = ISC_R_NOTIMPLEMENTED;

	return result;
}
