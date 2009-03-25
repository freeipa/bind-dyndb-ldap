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


#define IGNORE(expr)	if (expr) return
#define IGNORE_R(expr)	if (expr) return ISC_R_SUCCESS

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

struct ld_split {
	isc_mem_t	*mctx;		/* Memory context.		*/
	char		*data;		/* Splits.			*/
	size_t		allocated;	/* Number of bytes allocated.	*/
	char		*splits[LD_MAX_SPLITS];
	size_t		split_count;	/* Number of splits.		*/
};

/*
 * Private functions.
 */


/*
 * Make sure we have enough space for at least len + 1 bytes.
 * This function is private.
 */
static isc_result_t
str_alloc(ld_string_t *str, size_t len)
{
	size_t new_size;
	char *new_buffer;

	REQUIRE(str != NULL);
	REQUIRE(str->mctx != NULL);
	IGNORE_R(str->allocated > len);

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
		strncpy(new_buffer, str->data, len);
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
static size_t
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

	REQUIRE(mctx != NULL);
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
	IGNORE(str == NULL || *str == NULL);

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

/*
 * Copy string from src to dest.
 */
isc_result_t
str_copy(ld_string_t *dest, const ld_string_t *src)
{
	isc_result_t result;

	REQUIRE(dest != NULL);
	REQUIRE(src != NULL);
	IGNORE_R(src->data == NULL);

	CHECK(str_alloc(dest, str_len_internal(src)));
	strncpy(dest->data, src->data, dest->allocated);

	return ISC_R_SUCCESS;

cleanup:
	return result;
}

/*
 * Make a new string and copy src to it.
 */
isc_result_t
str_clone(ld_string_t **dest, const ld_string_t *src _STR_MEM_FLARG)
{
	isc_result_t result;

	REQUIRE(src != NULL);
	REQUIRE(dest != NULL && *dest == NULL);

	CHECK(str__new(src->mctx, dest _STR_MEM_FLARG_PASS));
	CHECK(str_copy(*dest, src));

	return ISC_R_SUCCESS;

cleanup:
	return result;
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

	REQUIRE(dest != NULL);
	IGNORE_R(src == NULL);

	CHECK(str_alloc(dest, strlen(src)));
	strncpy(dest->data, src, dest->allocated);

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
	IGNORE_R(src == NULL);

	dest_size = str_len_internal(dest);
	src_size = strlen(src);

	IGNORE_R(src_size == 0);

	CHECK(str_alloc(dest, dest_size + src_size));
	from = dest->data + dest_size;
	strncpy(from, src, src_size + 1);

	return ISC_R_SUCCESS;

cleanup:
	return result;
}

isc_result_t
str_cat_char_len(ld_string_t *dest, const char *src, size_t len)
{
	isc_result_t result;
	char *from;
	size_t dest_size;

	REQUIRE(dest != NULL);
	IGNORE_R(src == NULL);
	IGNORE_R(len == 0);

	dest_size = str_len_internal(dest);

	CHECK(str_alloc(dest, dest_size + len));
	from = dest->data + dest_size;
	strncpy(from, src, len);
	from[len] = '\0';

	return ISC_R_SUCCESS;

cleanup:
	return result;
}

isc_result_t
str_cat_isc_region(ld_string_t *dest, const isc_region_t *region)
{
	REQUIRE(dest != NULL);
	REQUIRE(region != NULL);

	return str_cat_char_len(dest, (char *)region->base, region->length);
}

isc_result_t
str_cat_isc_buffer(ld_string_t *dest, const isc_buffer_t *buffer)
{
	isc_region_t region;
	isc_buffer_t *deconst_buffer;

	REQUIRE(dest != NULL);
	REQUIRE(ISC_BUFFER_VALID(buffer));

	DE_CONST(buffer, deconst_buffer);
	isc_buffer_usedregion(deconst_buffer, &region);

	return str_cat_isc_region(dest, &region);
}

/*
 * Concatenate string src to string dest.
 */
isc_result_t
str_cat(ld_string_t *dest, const ld_string_t *src)
{
	REQUIRE(dest != NULL);
	IGNORE_R(src == NULL);
	IGNORE_R(src->data == NULL);

	return str_cat_char(dest, src->data);
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

	REQUIRE(dest != NULL);
	REQUIRE(format != NULL);

	len = vsnprintf(dest->data, dest->allocated, format, ap);
	if (len > 0) {
		CHECK(str_alloc(dest, len));
		len = vsnprintf(dest->data, dest->allocated, format, ap);
	}

	if (len < 0)
		result = ISC_R_FAILURE;

	return ISC_R_SUCCESS;

cleanup:
	return result;
}

void
str_toupper(ld_string_t *str)
{
	char *ptr;

	REQUIRE(str != NULL);

	if (str->data == NULL)
		return;

	for (ptr = str->data; *ptr != '\0'; ptr++)
		*ptr = toupper((unsigned char)*ptr);
}

void
str_to_isc_buffer(const ld_string_t *src, isc_buffer_t *dest)
{
	size_t len;

	REQUIRE(src != NULL);
	REQUIRE(dest != NULL);

	len = str_len_internal(src) - 1;

	isc_buffer_init(dest, src->data, len);
	isc_buffer_add(dest, len);
}

int
str_casecmp_char(const ld_string_t *s1, const char *s2)
{
	REQUIRE(s1 != NULL && s1->data != NULL);
	REQUIRE(s2 != NULL);

	return strcasecmp(s1->data, s2);
}

/*
 * TODO: Review.
 */
isc_result_t
str_new_split(isc_mem_t *mctx, ld_split_t **splitp)
{
	isc_result_t result;
	ld_split_t *split;

	REQUIRE(splitp != NULL && *splitp == NULL);

	CHECKED_MEM_GET_PTR(mctx, split);
	ZERO_PTR(split);
	isc_mem_attach(mctx, &split->mctx);

	*splitp = split;
	return ISC_R_SUCCESS;

cleanup:
	return result;
}

void
str_destroy_split(ld_split_t **splitp)
{
	ld_split_t *split;

	IGNORE(splitp == NULL || *splitp == NULL);

	split = *splitp;

	if (split->allocated)
		isc_mem_free(split->mctx, split->data);

	isc_mem_putanddetach(&split->mctx, split, sizeof(*split));

	*splitp = NULL;
}

static isc_result_t
str_split_initialize(ld_split_t *split, const char *str)
{
	size_t size;

	REQUIRE(split != NULL);
	REQUIRE(split->mctx != NULL);
	REQUIRE(str != NULL && *str != '\0');

	if (split->allocated != 0) {
		isc_mem_put(split->mctx, split->data, split->allocated);
		split->allocated = 0;
	}
	split->splits[0] = NULL;
	split->split_count = 0;

	size = strlen(str) + 1;
	split->data = isc_mem_strdup(split->mctx, str);
	if (split->data == NULL)
		return ISC_R_NOMEMORY;

	split->allocated = size;

	return ISC_R_SUCCESS;
}

isc_result_t
str_split(const ld_string_t *src, const char delimiter, ld_split_t *split)
{
	isc_result_t result;
	unsigned int current_pos;
	int save;

	REQUIRE(src != NULL);
	REQUIRE(delimiter != '\0');
	REQUIRE(split != NULL);

	CHECK(str_split_initialize(split, src->data));

	/* Replace all delimiters with '\0'. */
	for (unsigned int i = 0; i < split->allocated; i++) {
		if (split->data[i] == delimiter)
			split->data[i] = '\0';
	}

	/* Now save the right positions. */
	current_pos = 0;
	save = 1;
	for (unsigned int i = 0;
	     i < split->allocated && current_pos < LD_MAX_SPLITS;
	     i++) {
		if (save && split->data[i] != '\0') {
			split->splits[current_pos] = split->data + i;
			current_pos++;
			save = 0;
		} else if (split->data[i] == '\0') {
			save = 1;
		}
	}
	split->splits[current_pos] = NULL;
	split->split_count = current_pos;

	return ISC_R_SUCCESS;

cleanup:
	return result;
}

size_t
str_split_count(const ld_split_t *split)
{
	REQUIRE(split != NULL);

	return split->split_count;
}

const char *
str_split_get(const ld_split_t *split, unsigned int split_number)
{
	REQUIRE(split != NULL);
	REQUIRE(split->split_count >= split_number);

	return split->splits[split_number];
}
