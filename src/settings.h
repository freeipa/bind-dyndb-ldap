/*
 * Copyright (C) 2009-2014  bind-dyndb-ldap authors; see COPYING for license
 */

#ifndef _LD_SETTINGS_H_
#define _LD_SETTINGS_H_

#include <isc/types.h>
#include "types.h"
#include "str.h"
#include "ldap_entry.h"

#define SETTING_LINE_MAXLENGTH 255
#define SETTING_NAME_SEPARATORS " \t"
#define SETTING_SET_NAME_LOCAL  "named.conf"
#define SETTING_SET_NAME_GLOBAL "LDAP idnsConfig object"
#define SETTING_SET_NAME_ZONE   "LDAP idnsZone object"

typedef struct setting	setting_t;

/* Make sure that cases in get_value_ptr() are synchronized */
typedef enum {
	ST_STRING,
	ST_UNSIGNED_INTEGER,
	ST_BOOLEAN,
} setting_type_t;

struct setting {
	const char	*name;
	setting_type_t	type;
	union {
		char		*value_char;
		isc_uint32_t	value_uint;
		isc_boolean_t	value_boolean;
	} value;
	isc_boolean_t	filled;
	isc_boolean_t	is_dynamic;
};

struct settings_set {
	isc_mem_t		*mctx;
	char			*name;
	const settings_set_t	*parent_set;
	isc_mutex_t		*lock;  /**< locks only values */
	setting_t		*first_setting;
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
#define default_string(val)	ST_STRING, { .value_char = (val) }, ISC_TRUE, ISC_FALSE
#define default_uint(val)	ST_UNSIGNED_INTEGER, { .value_uint = (val) }, ISC_TRUE, ISC_FALSE
#define default_boolean(val)	ST_BOOLEAN, { .value_boolean = (val) }, ISC_TRUE, ISC_FALSE
/* No defaults. */
#define no_default_string	ST_STRING, { .value_char = NULL }, ISC_FALSE, ISC_FALSE
#define no_default_uint		ST_UNSIGNED_INTEGER, { .value_uint = 0 }, ISC_FALSE, ISC_FALSE
#define no_default_boolean	ST_BOOLEAN, { .value_boolean = ISC_FALSE }, ISC_FALSE, ISC_FALSE

/* This is used in the end of setting_t arrays. */
#define end_of_settings	{ NULL, default_uint(0) }

/*
 * Prototypes.
 */
isc_result_t
settings_set_create(isc_mem_t *mctx, const setting_t default_settings[],
		    const unsigned int default_set_length, const char *set_name,
		    const settings_set_t *const parent_set,
		    settings_set_t **target) ATTR_NONNULLS ATTR_CHECKRESULT;

void
settings_set_free(settings_set_t **set) ATTR_NONNULLS;

isc_result_t
settings_set_fill(settings_set_t *set, const char *const *argv)
		  ATTR_NONNULLS ATTR_CHECKRESULT;

isc_boolean_t
settings_set_isfilled(settings_set_t *set) ATTR_NONNULLS ATTR_CHECKRESULT;

isc_result_t
setting_get_uint(const char * const name, const settings_set_t * const set,
		 isc_uint32_t * target) ATTR_NONNULLS ATTR_CHECKRESULT;

isc_result_t
setting_get_str(const char * const name, const settings_set_t * const set,
		const char ** target) ATTR_NONNULLS ATTR_CHECKRESULT;

isc_result_t
setting_get_bool(const char * const name, const settings_set_t * const set,
		 isc_boolean_t * target) ATTR_NONNULLS ATTR_CHECKRESULT;

isc_result_t
setting_set(const char *const name, const settings_set_t *set,
	    const char *const value) ATTR_NONNULLS ATTR_CHECKRESULT;

isc_result_t
setting_update_from_ldap_entry(const char *name, settings_set_t *set,
			       const char *attr_name, ldap_entry_t *entry)
			       ATTR_NONNULLS ATTR_CHECKRESULT;

isc_result_t
get_enum_description(const enum_txt_assoc_t *map, int value, const char **desc) ATTR_NONNULLS ATTR_CHECKRESULT;

#endif /* !_LD_SETTINGS_H_ */
