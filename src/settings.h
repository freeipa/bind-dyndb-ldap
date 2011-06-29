/*
 * Authors: Martin Nagy <mnagy@redhat.com>
 *
 * Copyright (C) 2009  Red Hat
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

#ifndef _LD_SETTINGS_H_
#define _LD_SETTINGS_H_

#include <isc/types.h>

typedef struct setting	setting_t;

typedef enum {
	ST_LD_STRING,
	ST_SIGNED_INTEGER,
	ST_UNSIGNED_INTEGER,
	ST_BOOLEAN,
} setting_type_t;

struct setting {
	const char	*name;
	int		set;
	int		has_a_default;
	setting_type_t	type;
	union {
		const char	*value_char;
		signed int	value_sint;
		unsigned int	value_uint;
		isc_boolean_t	value_boolean;
	} default_value;
	void		*target;
};

/*
 * These defines are used as initializers for setting_t, for example:
 *
 * setting_t my_setting = {
 *         "name", default_string("this is the default"),
 *         &target_variable
 * }
 *
 * setting_t my_setting = {
 *         "name", no_default_string, &target_variable
 * }
 */
#define default_string(val)	0, 1, ST_LD_STRING, { .value_char = (val) }, NULL
#define default_sint(val)	0, 1, ST_SIGNED_INTEGER, { .value_sint = (val) }, NULL
#define default_uint(val)	0, 1, ST_UNSIGNED_INTEGER, { .value_uint = (val) }, NULL
#define default_boolean(val)	0, 1, ST_BOOLEAN, { .value_boolean = (val) }, NULL
/* No defaults. */
#define no_default_string	0, 0, ST_LD_STRING, { .value_char = NULL }, NULL
#define no_default_sint		0, 0, ST_SIGNED_INTEGER, { .value_sint = 0 }, NULL
#define no_default_uint		0, 0, ST_UNSIGNED_INTEGER, { .value_uint = 0 }, NULL
#define no_default_boolean	0, 1, ST_BOOLEAN, { .value_boolean = ISC_FALSE }, NULL

/* This is used in the end of setting_t arrays. */
#define end_of_settings	{ NULL, default_sint(0) }

/*
 * Prototypes.
 */
isc_result_t
set_settings(setting_t *settings, const char * const* argv);

#endif /* !_LD_SETTINGS_H_ */
