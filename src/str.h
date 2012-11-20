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

#ifndef _LD_STR_H_
#define _LD_STR_H_

#include <isc/formatcheck.h>
#include <isc/mem.h>

#define LD_MAX_SPLITS	256

#if ISC_MEM_TRACKLINES
#define _STR_MEM_FILELINE	, __FILE__, __LINE__
#define _STR_MEM_FLARG		, const char *file, int line
#define _STR_MEM_FLARG_PASS	, file, line
#else
#define _STR_MEM_FILELINE
#define _STR_MEM_FLAG
#define _STR_MEM_FLARG_PASS
#endif

typedef struct ld_string	ld_string_t;

/*
 * Public functions.
 */

#define str_new(m, s)	str__new((m), (s) _STR_MEM_FILELINE)
#define str_destroy(s)	str__destroy((s) _STR_MEM_FILELINE)

size_t str_len(const ld_string_t *str);
const char * str_buf(const ld_string_t *src);
isc_result_t str_copy(ld_string_t *dest, const ld_string_t *src);
isc_result_t str_clone(ld_string_t **dest, const ld_string_t *src _STR_MEM_FLARG);
void str_clear(ld_string_t *dest);
isc_result_t str_init_char(ld_string_t *dest, const char *src);
isc_result_t str_cat_char(ld_string_t *dest, const char *src);
isc_result_t str_cat_char_len(ld_string_t *dest, const char *src, size_t len);
isc_result_t str_cat_isc_region(ld_string_t *dest, const isc_region_t *region);
isc_result_t str_cat_isc_buffer(ld_string_t *dest, const isc_buffer_t *buffer);
isc_result_t str_cat(ld_string_t *dest, const ld_string_t *src);
isc_result_t str_sprintf(ld_string_t *dest, const char *format, ...) ISC_FORMAT_PRINTF(2, 3);
isc_result_t str_vsprintf(ld_string_t *dest, const char *format, va_list ap);
void str_toupper(ld_string_t *str);

void str_to_isc_buffer(const ld_string_t *src, isc_buffer_t *dest);

int str_casecmp_char(const ld_string_t *s1, const char *s2);

/* These are pseudo-private functions and shouldn't be called directly. */
isc_result_t str__new(isc_mem_t *mctx, ld_string_t **new_str _STR_MEM_FLARG);
void str__destroy(ld_string_t **str _STR_MEM_FLARG);

#endif /* !_LD_STR_H_ */
