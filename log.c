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

/*
 * Some general comments about the driver go here. ABRAKA
 */

/* Includes, group nicely and keep files ordered! ABRAKA */
#include <stdio.h>

#include <dns/log.h>

#include "log.h"

#define MSG_BUFFER_SIZE 2048

/*
 * TODO:
 * - Some compiler format checks would be nice.
 * - Change these to use isc_log_vwrite().
 * - Think about log_unexpected_file_line(), maybe use something else.
 */


void
log_debug(int level, const char *format, ...)
{
    char buf[MSG_BUFFER_SIZE];
    va_list args;

    va_start(args, format);
    vsnprintf(buf, MSG_BUFFER_SIZE, format, args);
    va_end(args);

    isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_DYNDB,
                  ISC_LOG_DEBUG(level), "%s", buf);
}

void
log_error(const char *format, ...)
{
    char buf[MSG_BUFFER_SIZE];
    va_list args;

    va_start(args, format);
    vsnprintf(buf, MSG_BUFFER_SIZE, format, args);
    va_end(args);

    isc_log_write(dns_lctx, DNS_LOGCATEGORY_DATABASE, DNS_LOGMODULE_DYNDB,
                  ISC_LOG_ERROR, "%s", buf);
}
