/* Authors: Martin Nagy <mnagy@redhat.com>
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

#ifndef _LD_LOG_H_
#define _LD_LOG_H_

#include <isc/error.h>

#define fatal_error(...) \
    isc_error_fatal(__FILE__, __LINE__, __VA_ARGS__)

/*
 * Change these to use our string library.
 */

#define log_func(logstr)	log_debug(2, "%s: %s", __func__, (logstr))
#define log_func_va(logstr, ...)		\
	log_debug(2, "%s: " logstr, __func__, __VA_ARGS__)

#define log_func_enter()	log_func("entering")
#define log_func_enter_args(logstr, ...)	\
	log_func_va("entering, args: " logstr, __VA_ARGS__)

#define log_func_exit()		log_func("exiting")
#define log_func_exit_result(res)		\
	log_func_va("exiting with %s", isc_result_totext(res))

/* Basic logging functions */
void log_debug(int level, const char *format, ...) ISC_FORMAT_PRINTF(2, 3);
void log_error(const char *format, ...) ISC_FORMAT_PRINTF(1, 2);

#endif /* !_LD_LOG_H_ */
