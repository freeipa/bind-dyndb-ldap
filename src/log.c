/*
 * Authors: Martin Nagy <mnagy@redhat.com>
 *
 * Copyright (C) 2008, 2009  Red Hat
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

#include <stdio.h>

#include <isc/formatcheck.h>
#include <isc/util.h>

#include <dns/log.h>

#include "log.h"

void
log_debug(int level, const char *format, ...)
{
	va_list args;

	va_start(args, format);
#ifndef LOG_AS_ERROR
	UNUSED(level);
	isc_log_vwrite(dns_lctx, DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_DYNDB,
		       ISC_LOG_ERROR, format, args);
#else
	isc_log_vwrite(dns_lctx, DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_DYNDB,
		       ISC_LOG_DEBUG(level), format, args);
#endif

	va_end(args);
}

void
log_error(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	isc_log_vwrite(dns_lctx, DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_DYNDB,
		       ISC_LOG_ERROR, format, args);
	va_end(args);

}
