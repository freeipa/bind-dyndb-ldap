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

#ifndef _LD_LOG_H_
#define _LD_LOG_H_

#include <isc/error.h>
#include <dns/log.h>
#include <dns/result.h>

#ifdef LOG_AS_ERROR
#define GET_LOG_LEVEL(level)	ISC_LOG_ERROR
#else
#define GET_LOG_LEVEL(level)	(level)
#endif

#define fatal_error(...) \
	isc_error_fatal(__FILE__, __LINE__, __VA_ARGS__)

#define log_bug(fmt, ...) \
	log_error("bug in %s(): " fmt, __func__,##__VA_ARGS__)

#define log_error_r(fmt, ...) \
	log_error(fmt ": %s", ##__VA_ARGS__, dns_result_totext(result))

#define log_error_position(format, ...)				\
	log_error("[%-15s: %4d: %-21s] " format, 			\
		  __FILE__, __LINE__, __func__, ##__VA_ARGS__)

/* Basic logging functions */
#define log_error(format, ...)	\
	log_write(GET_LOG_LEVEL(ISC_LOG_ERROR), format, ##__VA_ARGS__)

#define log_info(format, ...)	\
	log_write(GET_LOG_LEVEL(ISC_LOG_INFO), format, ##__VA_ARGS__)

#define log_debug(level, format, ...)	\
	log_write(GET_LOG_LEVEL(level), format, ##__VA_ARGS__)

/* LDAP logging functions */
#define log_ldap_error(ld)						\
	do {								\
		int err;						\
		char *errmsg = "<UNKNOWN>";				\
		if (ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &err)	\
		    == LDAP_OPT_SUCCESS)				\
			errmsg = ldap_err2string(err);			\
		log_error_position("LDAP error: %s", errmsg);		\
	} while (0);							\

void
log_write(int level, const char *format, ...) ISC_FORMAT_PRINTF(2, 3);

#endif /* !_LD_LOG_H_ */
