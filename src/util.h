/*
 * Copyright (C) 2009-2014  bind-dyndb-ldap authors; see COPYING for license
 */

#ifndef _LD_UTIL_H_
#define _LD_UTIL_H_

#include <string.h>

#include <isc/mem.h>
#include <isc/buffer.h>
#include <isc/result.h>
#include <dns/types.h>
#include <dns/name.h>
#include <dns/result.h>

#include "log.h"

extern bool verbose_checks; /* from settings.c */

#define CLEANUP_WITH(result_code)				\
	do {							\
		result = (result_code);				\
		goto cleanup;					\
	} while(0)

#define CHECK(op)						\
	do {							\
		result = (op);					\
		if (result != ISC_R_SUCCESS) {			\
			if (verbose_checks == true)		\
				log_error_position("check failed: %s",		\
						   dns_result_totext(result));	\
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

/* If no argument index list is given to the nonnull attribute,
 * all pointer arguments are marked as non-null. */
#define ATTR_NONNULLS     ATTR_NONNULL()
#if defined(__COVERITY__) || defined(__clang_analyzer__)
#define ATTR_NONNULL(...) __attribute__((nonnull(__VA_ARGS__)))
#else
#define ATTR_NONNULL(...)
#endif

#if defined(__GNUC__)
#define ATTR_CHECKRESULT __attribute__((warn_unused_result))
#else
#define ATTR_CHECKRESULT
#endif

#endif /* !_LD_UTIL_H_ */
