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

#include <isc/util.h>
#include <isc/mem.h>
#include <isc/result.h>

#include <ctype.h>
#include <stdlib.h>

#include "log.h"
#include "settings.h"
#include "str.h"
#include "util.h"


/*
 * Forward declarations.
 */
static int args_are_equal(const char *setting_argument,
		const char *argv_argument);
static isc_result_t set_value(isc_mem_t *mctx, setting_t *setting,
		const char *arg);
static isc_result_t set_default_value(isc_mem_t *mctx, setting_t *setting);
static const char * get_value_str(const char *arg);

isc_result_t
set_settings(isc_mem_t *mctx, setting_t settings[], const char * const* argv)
{
	isc_result_t result;
	int i, j;

	for (i = 0; argv[i] != NULL; i++) {
		for (j = 0; settings[j].name != NULL; j++) {
			if (args_are_equal(settings[j].name, argv[i])) {
				CHECK(set_value(mctx, &settings[j], argv[i]));
				break;
			}
		}
	}

	/* When all is done, check that all the required settings are set. */
	for (j = 0; settings[j].name != NULL; j++) {
		if (settings[j].set != 0)
			continue;
		if (!settings[j].has_a_default) {
			log_error("argument %s must be set", settings[j].name);
			result = ISC_R_FAILURE;
			goto cleanup;
		}
		CHECK(set_default_value(mctx, &settings[j]));
	}

	return ISC_R_SUCCESS;

cleanup:
	/* TODO: Free memory in case of error. */
	return result;
}

/*
 * Return 1 if the argument names are equal. The argv_argument also needs to
 * contain an additional space at the end.
 */
static int
args_are_equal(const char *setting_argument, const char *argv_argument)
{
	if (setting_argument == argv_argument)
		return 1;
	if (setting_argument == NULL || argv_argument == NULL)
		return 0;

	while (1) {
		if (*argv_argument == '\0')
			return 0;
		if (*setting_argument == '\0')
			break;
		if (*setting_argument != *argv_argument)
			return 0;
		setting_argument++;
		argv_argument++;
	}

	/* Now make sure we also found a space at the end of argv_argument. */
	if (*argv_argument != ' ')
		return 0;

	return 1;
}

static isc_result_t
set_value(isc_mem_t *mctx, setting_t *setting, const char *arg)
{
	isc_result_t result;
	int numeric_value;
	const char *value;
	ld_string_t **ld_string_ptr;

	value = get_value_str(arg);

	if (setting->type == ST_LD_STRING) {
		ld_string_ptr = (ld_string_t **)setting->target;

		if (setting->set)
			str_destroy(ld_string_ptr);

		CHECK(str_new(mctx, ld_string_ptr));
		CHECK(str_init_char(*ld_string_ptr, value));
	} else if (setting->type == ST_SIGNED_INTEGER ||
		   setting->type == ST_UNSIGNED_INTEGER) {
		if (*value == '\0') {
			result = ISC_R_FAILURE;
			goto cleanup;
		}
		/* TODO: better type checking. */
		numeric_value = atoi(value);
		if (setting->type == ST_SIGNED_INTEGER) {
			(*(signed *)setting->target) = (signed)numeric_value;
		} else {
			if (numeric_value < 0) {
				log_error("argument %s must be an unsigned integer", setting->name);
				result = ISC_R_FAILURE;
				goto cleanup;
			}
			(*(unsigned *)setting->target) = (unsigned)numeric_value;
		}
	} else {
		fatal_error("unknown type in function set_value()");
		result = ISC_R_FAILURE;
		goto cleanup;
	}

	setting->set = 1;

	return ISC_R_SUCCESS;

cleanup:
	return result;
}

static isc_result_t
set_default_value(isc_mem_t *mctx, setting_t *setting)
{
	switch (setting->type) {
	case ST_LD_STRING:
		return set_value(mctx, setting, setting->default_value.value_char);
		break;
	case ST_SIGNED_INTEGER:
		(*(signed *)setting->target) = setting->default_value.value_sint;
		break;
	case ST_UNSIGNED_INTEGER:
		(*(unsigned *)setting->target) = setting->default_value.value_uint;
		break;
	default:
		fatal_error("unknown type in function set_default_value()");
		return ISC_R_FAILURE;
	}

	return ISC_R_SUCCESS;
}

static const char *
get_value_str(const char *arg)
{
	while (*arg != '\0' && !isblank(*arg))
		arg++;
	while (*arg != '\0' && isblank(*arg))
		arg++;

	return arg;
}
