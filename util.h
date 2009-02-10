/* Authors: Martin Nagy <mnagy@redhat.com>
 *
 * Copyright (C) 2009  Red Hat
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

#ifndef _LD_UTIL_H_
#define _LD_UTIL_H_

#define CHECK(op)						\
	do { result = (op);					\
		if (result != ISC_R_SUCCESS) goto cleanup;	\
	} while (0)

#define CHECKED_MEM_GET(m, target_ptr, s)			\
	do {							\
		(target_ptr) = isc_mem_get((m), (s));		\
		if ((target_ptr) == NULL) {			\
			result = ISC_R_NOMEMORY;		\
			goto cleanup;				\
		}						\
	} while (0)

#define CHECKED_MEM_GET_PTR(m, target_ptr)			\
	CHECKED_MEM_GET(m, target_ptr, sizeof(*(target_ptr)))

#define CHECKED_MEM_STRDUP(m, source, target)			\
	do {							\
		(target) = isc_mem_strdup((m), (source));	\
		if ((target) == NULL) {				\
			result = ISC_R_NOMEMORY;		\
			goto cleanup;				\
		}						\
	} while (0)

#define ZERO_PTR(ptr) memset((ptr), 0, sizeof(*(ptr)))

#endif /* !_LD_UTIL_H_ */
