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

/*
 * TODO:
 * Write some test cases.
 *
 * Review all the REQUIRE() macros.
 */

#include <isc/buffer.h>
#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/region.h>
#include <isc/util.h>

#include <dns/result.h>

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "str.h"
#include "util.h"


#define ALLOC_BASE_SIZE	16

/* Custom string, these shouldn't use these directly */
struct ld_string {
	isc_mem_t	*mctx;		/* Memory context.		*/
	char		*data;		/* String is stored here.	*/
	size_t		allocated;	/* Number of bytes allocated.	*/
#if ISC_MEM_TRACKLINES
	const char	*file;		/* File where the allocation occured. */
	int		line;		/* Line in the file.		*/
#endif
};

/*
 * Private functions.
 */


/*
 * Make sure we have enough space for at least len + 1 bytes.
 * This function is private.
 */
static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
str_alloc(ld_string_t *str, size_t len)
{
	size_t new_size;
	char *new_buffer;

	REQUIRE(str != NULL);
	REQUIRE(str->mctx != NULL);

	if (str->allocated > len)
            return ISC_R_SUCCESS;

	len++;	/* Account for the last '\0'. */
	new_size = ISC_MAX(str->allocated, ALLOC_BASE_SIZE);
	while (new_size <= len)
		new_size *= 2;

	new_size *= sizeof (char);
#if ISC_MEM_TRACKLINES
	new_buffer = isc__mem_get(str->mctx, new_size, str->file, str->line);
#else
	new_buffer = isc_mem_get(str->mctx, new_size);
#endif

	if (new_buffer == NULL)
		return ISC_R_NOMEMORY;

	if (str->data != NULL) {
		memcpy(new_buffer, str->data, str->allocated);
		new_buffer[len] = '\0';
		isc_mem_put(str->mctx, str->data, str->allocated);
	} else {
		new_buffer[0] = '\0';
	}

	str->data = new_buffer;
	str->allocated = new_size;

	return ISC_R_SUCCESS;
}

/*
 * Return length of a string. This function is internal, we may decide to
 * implement caching of the string length in the future for performance
 * reasons.
 */
static size_t ATTR_NONNULLS ATTR_CHECKRESULT
str_len_internal(const ld_string_t *str)
{
	REQUIRE(str != NULL);

	if (str->allocated == 0)
		return 0;

	return strlen(str->data);
}


/*
 * Public functions.
 */


/*
 * Allocate a new string.
 */
isc_result_t
str__new(isc_mem_t *mctx, ld_string_t **new_str _STR_MEM_FLARG)
{
	ld_string_t *str;

	REQUIRE(new_str != NULL && *new_str == NULL);

#if ISC_MEM_TRACKLINES
	str = isc__mem_get(mctx, sizeof(ld_string_t), file, line);
#else
	str = isc_mem_get(mctx, sizeof(ld_string_t));
#endif
	if (str == NULL)
		return ISC_R_NOMEMORY;

	str->data = NULL;
	str->allocated = 0;
	str->mctx = NULL;

	isc_mem_attach(mctx, &str->mctx);

#if ISC_MEM_TRACKLINES
	str->file = file;
	str->line = line;
#endif

	*new_str = str;

	return ISC_R_SUCCESS;
}

/*
 * Destroy string, i.e. also free the ld_string_t struct.
 */
void
str__destroy(ld_string_t **str _STR_MEM_FLARG)
{
	if (str == NULL || *str == NULL)
            return;

	if ((*str)->allocated) {
#if ISC_MEM_TRACKLINES
		isc__mem_put((*str)->mctx, (*str)->data,
			     (*str)->allocated * sizeof(char), file, line);
#else
		isc_mem_put((*str)->mctx, (*str)->data,
			    (*str)->allocated * sizeof(char));
#endif
	}

#if ISC_MEM_TRACKLINES
	isc__mem_putanddetach(&(*str)->mctx, *str, sizeof(ld_string_t),
			      file, line);
#else
	isc_mem_putanddetach(&(*str)->mctx, *str, sizeof(ld_string_t));
#endif

	*str = NULL;
}

/*
 * Return length of a string.
 */
size_t
str_len(const ld_string_t *str)
{
	return str_len_internal(str);
}

/*
 * Return a const char * type.
 */
const char *
str_buf(const ld_string_t *src)
{
	REQUIRE(src != NULL && src->data != NULL);

	return src->data;
}

void
str_clear(ld_string_t *dest)
{
	REQUIRE(dest != NULL);

	if (dest->allocated)
		dest->data[0] = '\0';
}

/*
 * Initialize string from char *.
 */
isc_result_t
str_init_char(ld_string_t *dest, const char *src)
{
	isc_result_t result;
	size_t len;

	REQUIRE(dest != NULL);

	if (src == NULL)
            return ISC_R_SUCCESS;

	len = strlen(src);
	CHECK(str_alloc(dest, len));
	memcpy(dest->data, src, len);
	dest->data[len] = '\0';

	return ISC_R_SUCCESS;

cleanup:
	return result;
}

/*
 * Concatenate char *src to string dest.
 * TODO: make str_cat_char() simply use str_cat_char_len()
 */
isc_result_t
str_cat_char(ld_string_t *dest, const char *src)
{
	isc_result_t result;
	char *from;
	size_t dest_size;
	size_t src_size;

	REQUIRE(dest != NULL);

	if (src == NULL)
            return ISC_R_SUCCESS;

	dest_size = str_len_internal(dest);
	src_size = strlen(src);

	if (src_size == 0)
            return ISC_R_SUCCESS;

	CHECK(str_alloc(dest, dest_size + src_size));
	from = dest->data + dest_size;
	memcpy(from, src, src_size + 1);

	return ISC_R_SUCCESS;

cleanup:
	return result;
}

/*
 * A sprintf() like function.
 */
isc_result_t
str_sprintf(ld_string_t *dest, const char *format, ...)
{
	isc_result_t result;
	va_list ap;

	REQUIRE(dest != NULL);
	REQUIRE(format != NULL);

	va_start(ap, format);
	result = str_vsprintf(dest, format, ap);
	va_end(ap);

	return result;
}

isc_result_t
str_vsprintf(ld_string_t *dest, const char *format, va_list ap)
{
	int len;
	isc_result_t result;
	va_list backup;

	REQUIRE(dest != NULL);
	REQUIRE(format != NULL);

	va_copy(backup, ap);
	len = vsnprintf(dest->data, dest->allocated, format, ap);
	if (len > 0) {
		CHECK(str_alloc(dest, len));
		len = vsnprintf(dest->data, dest->allocated, format, backup);
	}

	if (len < 0) {
		result = ISC_R_FAILURE;
		goto cleanup;
	}

	result = ISC_R_SUCCESS;

cleanup:
	va_end(backup);
	return result;
}
