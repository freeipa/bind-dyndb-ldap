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
	do {							\
		result = (op);					\
		if (result != ISC_R_SUCCESS)			\
			goto cleanup;				\
	} while (0)

#define CHECK_NEXT(op)						\
	do {							\
		result = (op);					\
		if (result != ISC_R_SUCCESS)			\
			goto next;				\
	} while (0)

#define CHECKED_MEM_ALLOCATE(m, target_ptr, s)			\
	do {							\
		(target_ptr) = isc_mem_allocate((m), (s));	\
		if ((target_ptr) == NULL) {			\
			result = ISC_R_NOMEMORY;		\
			goto cleanup;				\
		}						\
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

#define SAFE_MEM_PUT(m, target_ptr, target_size)		\
	do {							\
		if ((target_ptr) != NULL)			\
			isc_mem_put((m), (target_ptr),		\
				    (target_size));		\
	} while (0)

#define SAFE_MEM_PUT_PTR(m, target_ptr)				\
	SAFE_MEM_PUT((m), (target_ptr), sizeof(*(target_ptr)))

#define MEM_PUT_AND_DETACH(target_ptr)				\
	isc_mem_putanddetach(&(target_ptr)->mctx, target_ptr,	\
			     sizeof(*(target_ptr)))

#define DECLARE_BUFFER(name, len)				\
	isc_buffer_t name;					\
	unsigned char name##__base[len]

#define INIT_BUFFER(name)					\
	isc_buffer_init(&name, name##__base, sizeof(name##__base))

#define DECLARE_BUFFERED_NAME(name)				\
	dns_name_t name;					\
	DECLARE_BUFFER(name##__buffer, DNS_NAME_MAXWIRE)

#define INIT_BUFFERED_NAME(name)					\
	do {								\
		INIT_BUFFER(name##__buffer);				\
		dns_name_init(&name, NULL);				\
		dns_name_setbuffer(&name, &name##__buffer);		\
	} while (0)

#define FOR_EACH(elt, list)						\
	for ((elt) = HEAD(list); (elt) != NULL; (elt) = NEXT(elt, link))

#define FOR_EACH_UNLINK(elt, list)					     \
	do {								     \
		typeof(elt) __next_elt;					     \
		for (elt = HEAD(list); elt != NULL; elt = NEXT(elt, link)) { \
			__next_elt = NEXT(elt, link);			     \
			UNLINK(list, elt, link);

#define END_FOR_EACH_UNLINK(elt)					\
			elt = __next_elt;				\
		}							\
	} while (0)

#endif /* !_LD_UTIL_H_ */
