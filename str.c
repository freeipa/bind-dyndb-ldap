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
 * TODO:
 * Write some test cases.
 *
 * Review all the REQUIRE() macros.
 */

#include <isc/mem.h>
#include <isc/mutex.h>
#include <isc/util.h>

#include <dns/result.h>

#include <string.h>

#include "str.h"


#define IGNORE(expr)	if (expr) return
#define IGNORE_R(expr)	if (expr) return ISC_R_SUCCESS

#define ALLOC_BASE_SIZE	16

#define CHECK(op)						\
	do { result = (op);					\
		if (result != ISC_R_SUCCESS) goto cleanup;	\
	} while (0)


/* Custom string, these shouldn't use these directly */
struct ld_string {
	char		*data;		/* String is stored here.	*/
	size_t		allocated;	/* Number of bytes allocated.	*/
	isc_mem_t	*mctx;		/* Memory context.		*/
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
static isc_result_t
str_alloc(ld_string_t *str, size_t len)
{
	size_t new_size;
	char *new_buffer;

	REQUIRE(str != NULL);
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
		isc_mem_put(str->mctx, str->data, new_size);
	} else {
		new_buffer[0] = '\0';
	}

	str->data = new_buffer;

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

#if ISC_MEM_TRACKLINES
	isc__mem_put((*str)->mctx, (void *)(*str)->data,
		    (*str)->allocated * sizeof(char), file, line);
	isc__mem_putanddetach(&(*str)->mctx, (void *)*str, sizeof(ld_string_t),
			      file, line);
#else
	isc_mem_put((*str)->mctx, (void *)(*str)->data,
		    (*str)->allocated * sizeof(char));
	isc_mem_putanddetach(&(*str)->mctx, (void *)*str, sizeof(ld_string_t));
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
 * Retrun a const char * type.
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

	CHECK(str_alloc(dest, str_len_internal(src) * sizeof(char)));
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

/*
 * Initialize string from char *.
 */
isc_result_t
str_init_char(ld_string_t *dest, const char *src)
{
	isc_result_t result;

	REQUIRE(dest != NULL);
	IGNORE_R(src == NULL);

	CHECK(str_alloc(dest, strlen(src) * sizeof(char)));
	strncpy(dest->data, src, dest->allocated);

	return ISC_R_SUCCESS;

cleanup:
	return result;
}

/*
 * Concatenate char *src to string dest.
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

	CHECK(str_alloc(dest, (dest_size + src_size) * sizeof(char)));
	from = dest->data + dest_size;
	strncpy(from, src, src_size + 1);

	return ISC_R_SUCCESS;

cleanup:
	return result;
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
