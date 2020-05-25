/*
 * Copyright (C) 2009-2014  bind-dyndb-ldap authors; see COPYING for license
 */

#include <isc/util.h>
#include <isc/mem.h>
#include <isc/task.h>
#include <isc/result.h>
#include <isc/string.h>
#include <inttypes.h>
#include <isc/parseint.h>

#include <dns/name.h>

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "log.h"
#include "settings.h"
#include "str.h"
#include "util.h"
#include "types.h"
#include "ldap_helper.h"
#include "zone_register.h"

bool verbose_checks = false; /* log each failure in CHECK() macro */

/** Built-in defaults. */
static const setting_t settings_default[] = {
	{ "default_ttl",		default_uint(86400)		}, /* Seconds */
	{ "uri",			no_default_string		}, /* User have to set this */
	{ "connections",		default_uint(2)			},
	{ "reconnect_interval",		default_uint(60)		},
	{ "timeout",			default_uint(10)		},
	{ "timeout",			default_uint(10)		},
	{ "base",	 		no_default_string		}, /* User have to set this */
	{ "auth_method",		default_string("none")		},
	{ "bind_dn",			default_string("")		},
	{ "password",			default_string("")		},
	{ "krb5_principal",		default_string("")		},
	{ "sasl_mech",			default_string("GSSAPI")	},
	{ "sasl_user",			default_string("")		},
	{ "sasl_auth_name",		default_string("")		},
	{ "sasl_realm",			default_string("")		},
	{ "sasl_password",		default_string("")		},
	{ "krb5_keytab",		default_string("")		},
	{ "fake_mname",			default_string("")		},
	{ "ldap_hostname",		default_string("")		},
	{ "sync_ptr",			default_boolean(false)	},
	{ "dyn_update",			default_boolean(false)	},
	/* Empty string as default update_policy declares zone as 'dynamic'
	 * for dns_zone_isdynamic() to prevent unwanted
	 * zone_postload() calls and warnings about serial and so on.
	 *
	 * SSU table defined by empty string contains no rules =>
	 * dns_ssutable_checkrules() will return deny. */
	{ "update_policy",		default_string("")		},
	{ "verbose_checks",		default_boolean(false)	},
	{ "directory",			default_string("")		},
	{ "server_id",			default_string("")		},
	end_of_settings
};

/** Settings set for built-in defaults. */
const settings_set_t settings_default_set = {
	NULL,
	"built-in defaults",
	NULL,
	NULL,
	(setting_t *) &settings_default[0]
};

/**
 * @param[in] name Setting name.
 * @param[in] set Set of settings to start search in.
 * @param[in] recursive Continue with search in parent sets if setting was
 *                      not found in set passed by caller.
 * @param[in] filled_only Consider settings without value as non-existent.
 * @param[out] found Pointer to found setting_t. Ignored if found is NULL.
 *
 * @pre found == NULL || (found != NULL && *found == NULL)
 *
 * @retval ISC_R_SUCCESS
 * @retval ISC_R_NOTFOUND
 */
isc_result_t
setting_find(const char *name, const settings_set_t *set,
	     bool recursive, bool filled_only,
	     setting_t **found) {

	REQUIRE(name != NULL);
	REQUIRE(found == NULL || *found == NULL);

	while (set != NULL) {
		log_debug(20, "examining set of settings '%s'", set->name);
		for (setting_t *setting = set->first_setting;
				setting->name;
				setting++) {

			if (strcmp(name, setting->name) == 0) {
				if (setting->filled || !filled_only) {
					if (found != NULL)
						*found = setting;
					log_debug(20, "setting '%s' was found "
						      "in set '%s'", name,
						      set->name);
					return ISC_R_SUCCESS;
				} else {
					break; /* continue with parent set */
				}
			}

		}
		if (recursive)
			set = set->parent_set;
		else
			break;
	}
	return ISC_R_NOTFOUND;
}

/**
 * Get value associated with a setting. Search starts in set of settings
 * passed by caller and continues in parent sets until the setting with defined
 * value is found.
 *
 * @warning
 * This function is not expected to fail because all settings should
 * have default value defined (in topmost set of settings).
 * Caller should always check the return value, regardless this assumption.
 *
 * @param[in]  type   Data type expected by caller.
 * @param[out] target Type of pointer must agree with requested setting type.
 * @retval ISC_R_SUCCESS    Required value was found and target was filled in.
 * @retval ISC_R_NOTFOUND   Value is not defined in specified set of
 *                          settings either in parent sets.
 * @retval ISC_R_UNEXPECTED Type mismatch between expected type and type
 *                          of setting in settings tree. (I.e. programming
 *                          error.)
 */
static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
setting_get(const char *const name, const setting_type_t type,
	    const settings_set_t *const set, void *target)
{
	isc_result_t result;
	setting_t *setting = NULL;

	REQUIRE(name != NULL);
	REQUIRE(target != NULL);

	CHECK(setting_find(name, set, true, true, &setting));

	if (setting->type != type) {
		log_bug("incompatible setting data type requested "
			"for name '%s' in set of settings '%s'", name, set->name);				\
		return ISC_R_UNEXPECTED;
	}

	switch (type) {
	case ST_UNSIGNED_INTEGER:
		*(uint32_t *)target = setting->value.value_uint;
		break;
	case ST_STRING:
		*(char **)target = setting->value.value_char;
		break;
	case ST_BOOLEAN:
		*(bool *)target = setting->value.value_boolean;
		break;
	default:
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "invalid setting_type_t value %u", type);
		break;
	}

	return ISC_R_SUCCESS;

cleanup:
	log_bug("setting '%s' was not found in settings tree", name);
	return result;
}

isc_result_t
setting_get_uint(const char *const name, const settings_set_t *const set,
		 uint32_t *target)
{
	return setting_get(name, ST_UNSIGNED_INTEGER, set, target);
}

isc_result_t
setting_get_str(const char *const name, const settings_set_t *const set,
		const char **target)
{
	return setting_get(name, ST_STRING, set, target);
}

isc_result_t
setting_get_bool(const char *const name, const settings_set_t *const set,
		 bool *target)
{
	return setting_get(name, ST_BOOLEAN, set, target);
}

/**
 * Convert and copy value to setting structure.
 *
 * @retval ISC_R_SUCCESS  New value was converted and copied.
 * @retval ISC_R_IGNORE   New and old values are same, no change was made.
 * @retval ISC_R_NOMEMORY
 * @retval ISC_R_UNEXPECTEDEND
 * @retval ISC_R_UNEXPECTEDTOKEN
 * @retval others         Other errors from isc_parse_uint32().
 */
static isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
set_value(isc_mem_t *mctx, const settings_set_t *set, setting_t *setting,
	  const char *value)
{
	isc_result_t result;
	uint32_t numeric_value;
	uint32_t len;

	REQUIRE(setting != NULL);
	REQUIRE(value != NULL);
	REQUIRE(set != NULL);

	/* catch attempts to modify built-in defaults */
	REQUIRE(set->lock != NULL);
	LOCK(set->lock);

	/* Check and convert new values. */
	switch (setting->type) {
	case ST_STRING:
		if (setting->filled &&
		    strcmp(setting->value.value_char, value) == 0)
			CLEANUP_WITH(ISC_R_IGNORE);
		break;

	case ST_UNSIGNED_INTEGER:
		if (*value == '\0')
			CLEANUP_WITH(ISC_R_UNEXPECTEDEND);

		result = isc_parse_uint32(&numeric_value, value, 10);
		if (result != ISC_R_SUCCESS) {
			log_error_r("setting '%s' has to be unsigned integer "
				    "(base 10)", setting->name);
			goto cleanup;
		}
		if (setting->filled &&
		    setting->value.value_uint == numeric_value)
			CLEANUP_WITH(ISC_R_IGNORE);
		break;

	case ST_BOOLEAN:
		if (strcasecmp(value, "yes") == 0 ||
		    strcasecmp(value, "true") == 0)
			numeric_value = 1;
		else if (strcasecmp(value, "no") == 0 ||
			 strcasecmp(value, "false") == 0)
			numeric_value = 0;
		else {
			log_error("unknown boolean expression "
				  "(setting '%s': value '%s')",
				  setting->name, value);
			CLEANUP_WITH(ISC_R_UNEXPECTEDTOKEN);
		}
		if (setting->filled &&
		    setting->value.value_boolean == numeric_value)
			CLEANUP_WITH(ISC_R_IGNORE);
		break;
	default:
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "invalid setting_type_t value %u", setting->type);
		break;
	}

	switch (setting->type) {
	case ST_STRING:
		len = strlen(value) + 1;
		if (setting->is_dynamic)
			isc_mem_free(mctx, setting->value.value_char);
		CHECKED_MEM_ALLOCATE(mctx, setting->value.value_char, len);
		setting->is_dynamic = true;
		CHECK(isc_string_copy(setting->value.value_char, len, value));
		break;

	case ST_UNSIGNED_INTEGER:
		setting->value.value_uint = numeric_value;
		break;

	case ST_BOOLEAN:
		setting->value.value_boolean = numeric_value;
		break;
	default:
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "invalid setting_type_t value %u", setting->type);
		break;
	}
	setting->filled = 1;
	result = ISC_R_SUCCESS;

cleanup:
	UNLOCK(set->lock);
	return result;
}

/**
 * Change value in given set of settings (non-recursively, parent sets are
 * not affected in any way). Function will fail if setting with given name is
 * not a part of set of settings.
 * Mutual exclusion is ensured by set_value().
 *
 * @warning
 * Failure in this function usually points to insufficient input validation
 * OR logic error.
 * Caller should always check the return value.
 *
 * @retval ISC_R_SUCCESS  Value was changed.
 * @retval ISC_R_IGNORE   Value wasn't changed because it is same as original.
 * @retval ISC_R_NOTFOUND Setting was not found in given set of settings.
 * @retval ISC_R_NOMEMORY
 * @retval Others         Conversion errors.
 */
isc_result_t
setting_set(const char *const name, const settings_set_t *set,
	    const char *const value)
{
	isc_result_t result;
	setting_t *setting = NULL;

	CHECK(setting_find(name, set, false, false, &setting));

	return set_value(set->mctx, set, setting, value);

cleanup:
	log_bug("setting '%s' was not found in set of settings '%s'", name,
		set->name);
	return result;
}

/**
 * Un-set value in given set of settings (non-recursively, parent sets are
 * not affected in any way). Function will fail if setting with given name is
 * not a part of set of settings.
 * Mutual exclusion is ensured by isc_task_beginexclusive().
 *
 * @warning
 * Failure in this function usually points to logic error.
 * Caller should always check return value.
 *
 * @retval ISC_R_SUCCESS  Setting was un-set.
 * @retval ISC_R_IGNORE   Setting wasn't changed because wasn't set.
 * @retval ISC_R_NOTFOUND Required setting was not found
 *                        in given set of settings.
 */
isc_result_t
setting_unset(const char *const name, const settings_set_t *set)
{
	isc_result_t result;
	setting_t *setting = NULL;

	CHECK(setting_find(name, set, false, false, &setting));

	if (!setting->filled)
		return ISC_R_IGNORE;

	LOCK(set->lock);

	switch (setting->type) {
	case ST_STRING:
		if (setting->is_dynamic)
			isc_mem_free(set->mctx, setting->value.value_char);
		setting->is_dynamic = false;
		break;

	case ST_UNSIGNED_INTEGER:
	case ST_BOOLEAN:
		break;
	default:
		UNEXPECTED_ERROR(__FILE__, __LINE__,
				 "invalid setting_type_t value %u", setting->type);
		break;
	}
	setting->filled = 0;

cleanup:
	UNLOCK(set->lock);
	if (result == ISC_R_NOTFOUND)
		log_bug("setting '%s' was not found in set of settings '%s'",
			name, set->name);

	return result;
}

/**
 * Change setting 'name' to value specified by attribute 'attr_name' in LDAP
 * entry. Setting is un-set if specified value is missing in LDAP entry.
 *
 * @warning Multi-value attributes are no supported.
 *
 * @retval ISC_R_SUCCESS  Setting was changed (set or unset).
 * @retval ISC_R_IGNORE   Setting wasn't changed because value in settings set
 *                        and LDAP entry was same.
 * @retval ISC_R_NOTFOUND Required setting was not found in given set.
 * @retval Others         Memory allocation or conversion errors.
 */
isc_result_t
setting_update_from_ldap_entry(const char *name, settings_set_t *set,
			       const char *attr_name, ldap_entry_t *entry) {
	isc_result_t result;
	setting_t *setting = NULL;
	ldap_valuelist_t values;

	CHECK(setting_find(name, set, false, false, &setting));
	result = ldap_entry_getvalues(entry, attr_name, &values);
	if (result == ISC_R_NOTFOUND || HEAD(values) == NULL) {
		CHECK(setting_unset(name, set));
		log_debug(2, "setting '%s' (%s) was deleted in object %s",
			  name, attr_name, ldap_entry_logname(entry));
		return ISC_R_SUCCESS;

	} else if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}

	if (HEAD(values) != TAIL(values)) {
		log_bug("multi-value attributes are not supported: attribute "
			"'%s' in %s", attr_name,
			ldap_entry_logname(entry));
		return ISC_R_NOTIMPLEMENTED;
	}

	CHECK(setting_set(name, set, HEAD(values)->value));
	log_debug(2, "setting '%s' (%s) was changed to '%s' in %s", name,
		  attr_name, HEAD(values)->value, ldap_entry_logname(entry));

cleanup:
	if (result == ISC_R_NOTFOUND)
		log_bug("setting '%s' was not found in settings set '%s'",
			name, set->name);
	return result;
}

/**
 * Allocate new set of settings, fill it with values from specified default set
 * and (optionally) link the new set of settings to its parent set.
 *
 * @param[in] default_settings   Array with pre-filled setting structures.
 * @param[in] default_set_length Default set length in bytes.
 * @param[in] set_name		 Human readable name for this set of settings.
 *
 * @pre target != NULL && *target == NULL
 * @pre default_settings != NULL
 * @pre default_set_length > 0, default_set_length <= sizeof(default_settings)
 *
 * @retval ISC_R_SUCCESS
 * @retval ISC_R_NOMEMORY
 *
 * @note How to create local_settings which overrides default_settings:
 * @code
 * const setting_t default_settings[] = {
 *	{ "connections",	default_uint(2)		},
 * }
 * const settings_set_t default_settings_set = {
 *	NULL,
 *	NULL,
 *	(setting_t *) &default_settings[0]
 * };
 * const setting_t local_settings[] = {
 *	{ "connections",	no_default_uint		},
 * }
 *
 * settings_set_t *local_settings = NULL;
 * result = settings_set_create(mctx, default_settings,
 * 				sizeof(default_settings), &default_settings_set,
 *				&local_settings);
 * @endcode
 */
isc_result_t
settings_set_create(isc_mem_t *mctx, const setting_t default_settings[],
		    const unsigned int default_set_length, const char *set_name,
		    const settings_set_t *const parent_set,
		    settings_set_t **target) {
	isc_result_t result = ISC_R_FAILURE;
	settings_set_t *new_set = NULL;

	REQUIRE(target != NULL && *target == NULL);
	REQUIRE(default_settings != NULL);
	REQUIRE(default_set_length > 0);

	CHECKED_MEM_ALLOCATE(mctx, new_set, default_set_length);
	ZERO_PTR(new_set);
	isc_mem_attach(mctx, &new_set->mctx);

	CHECKED_MEM_GET_PTR(mctx, new_set->lock);
	result = isc_mutex_init(new_set->lock);
	INSIST(result == ISC_R_SUCCESS);

	new_set->parent_set = parent_set;

	CHECKED_MEM_ALLOCATE(mctx, new_set->first_setting, default_set_length);
	memcpy(new_set->first_setting, default_settings, default_set_length);

	CHECKED_MEM_ALLOCATE(mctx, new_set->name, strlen(set_name) + 1);
	strcpy(new_set->name, set_name);

	*target = new_set;
	result = ISC_R_SUCCESS;

cleanup:
	if (result != ISC_R_SUCCESS)
		settings_set_free(&new_set);

	return result;
}

/**
 * Free dynamically allocated memory associated with given set of settings.
 * @pre *set is initialized set of settings, set != NULL && *set != NULL
 * @post *set == NULL
 */
void
settings_set_free(settings_set_t **set) {
	isc_mem_t *mctx = NULL;
	setting_t *s = NULL;

	if (set == NULL || *set == NULL)
		return;

	if ((*set)->mctx != NULL) {
		mctx = (*set)->mctx;

		if ((*set)->lock != NULL) {
			DESTROYLOCK((*set)->lock);
			SAFE_MEM_PUT_PTR(mctx, (*set)->lock);
		}

		for (s = (*set)->first_setting; s->name != NULL; s++) {
			if (s->is_dynamic)
				isc_mem_free(mctx, s->value.value_char);
		}
		if ((*set)->first_setting != NULL)
			isc_mem_free(mctx, (*set)->first_setting);
		isc_mem_free(mctx, (*set)->name);
		isc_mem_free(mctx, *set);
		isc_mem_detach(&mctx);
	}

	*set = NULL;
}

/**
 * Append textlen bytes from text to isc_buffer pointed to by closure.
 *
 * @pre closure is an initialized isc_buffer with autoreallocation enabled.
 */
static void
cfg_printer(void *closure, const char *text, int textlen) {
	isc_buffer_t *logbuffer = closure;

	REQUIRE(logbuffer != NULL);
	REQUIRE(logbuffer->autore == true);

	isc_buffer_putmem(logbuffer, (const unsigned char *)text, textlen);
}

/**
 * Copy values from cfg map to set of settings.
 * Only setting names specified in set of settings are copied.
 *
 * @param[in]  config
 * @param[out] set
 *
 * @retval ISC_R_SUCCESS Items listed in set of settings were copied from cfg map.
 * @retval Others        Memory or parsing errors.
 */
static isc_result_t
settings_set_fill(const cfg_obj_t *config, settings_set_t *set)
{
	isc_result_t result = ISC_R_SUCCESS;
	setting_t *setting;
	isc_buffer_t *buf_value = NULL;
	const cfg_obj_t *cfg_value;
	const char *str_value;

	REQUIRE(cfg_obj_ismap(config) == true);

	/* isc_buffer_allocate can no longer fail */
	isc_buffer_allocate(set->mctx, &buf_value, ISC_BUFFER_INCR);
	isc_buffer_setautorealloc(buf_value, true);

	for (setting = set->first_setting;
	     setting->name != NULL;
	     setting++) {
		cfg_value = NULL;
		result = cfg_map_get(config, setting->name, &cfg_value);
		if (result == ISC_R_NOTFOUND) {
			/* setting not configured in map */
			result = ISC_R_SUCCESS;
			continue;
		}
		else if (result != ISC_R_SUCCESS)
			goto cleanup;
		if (cfg_obj_isstring(cfg_value)) {
			/* this avoids additional quotes around the string */
			str_value = cfg_obj_asstring(cfg_value);
		} else {
			cfg_printx(cfg_value, 0, cfg_printer, buf_value);
			isc_buffer_putmem(buf_value, (unsigned char *)"\0", 1);
			str_value = isc_buffer_base(buf_value);
		}
		result = set_value(set->mctx, set, setting, str_value);
		if (result != ISC_R_SUCCESS && result != ISC_R_IGNORE)
			goto cleanup;
		isc_buffer_clear(buf_value);
	}

cleanup:
	if (result != ISC_R_SUCCESS)
		log_error_r("cannot parse settings for '%s'", set->name);
	if (buf_value != NULL)
		isc_buffer_free(&buf_value);
	return result;
}

/**
 * Check if all the settings in given set of setting have defined value,
 * possibly indirectly through parent set of settings.
 *
 * Error message is logged for each setting without defined value.
 *
 * @retval true  All settings have value defined.
 * @retval false At least one setting do not have defined value.
 */
bool
settings_set_isfilled(settings_set_t *set) {
	isc_result_t result;
	bool isfiled = true;

	REQUIRE(set != NULL);

	for (int i = 0; set->first_setting[i].name != NULL; i++) {
		const char *name = set->first_setting[i].name;
		result = setting_find(name, set, true, true, NULL);
		if (result != ISC_R_SUCCESS) {
			log_error_r("argument '%s' must be set "
				    "in set of settings '%s'", name, set->name);
			isfiled = false;
		}
	}
	return isfiled;
}

/**
 * Parse string with dyndb configuration and fill in settings_set_t structure.
 *
 * @param[in]  name		name of dyndb instance
 * @param[in]  cfg_type_conf	configuration grammar for ISC parser
 * @param[in]  parameters	string with complete dyndb configuration
 * @param[in]  file		name of configuration file
 * @param[in]  line		line on which config starts
 * @param[out] settings		set of settings filled with values from config
 *
 * @pre Names and data types of respective paremeters
 * 	in cfg_type_conf and set of settings must match.
 */
isc_result_t
setting_set_parse_conf(isc_mem_t *mctx, const char *name,
		       cfg_type_t *cfg_type_conf, const char *parameters,
		       const char *file, unsigned long line,
		       settings_set_t *settings)
{
	isc_result_t result;
	cfg_obj_t *config = NULL;
	isc_buffer_t in_buf;
	isc_buffer_t *log_buf = NULL;
	cfg_parser_t *parser = NULL;
	unsigned int len;

	REQUIRE(parameters != NULL);

	/* isc_buffer_allocate can no longer fail */
	isc_buffer_allocate(mctx, &log_buf, ISC_BUFFER_INCR);
	isc_buffer_setautorealloc(log_buf, true);

	len = strlen(parameters);
	isc_buffer_constinit(&in_buf, parameters, len);
	isc_buffer_add(&in_buf, len);

	CHECK(cfg_parser_create(mctx, dns_lctx, &parser));
	result = cfg_parse_buffer(parser, &in_buf, name, 0, cfg_type_conf, 0,
				  &config);
	if (result == ISC_R_SUCCESS) {
		cfg_printx(config, CFG_PRINTER_XKEY, cfg_printer, log_buf);
		cfg_obj_log(config, dns_lctx, ISC_LOG_DEBUG(10),
			    "configuration for dyndb instance '%s' "
			    "(starting in file %s on line %lu):\n"
			    "%.*s",
			    name, file, line, isc_buffer_usedlength(log_buf),
			    (char *)isc_buffer_base(log_buf));
	} else {
		log_error("configuration for dyndb instance '%s' "
			  "(starting in file %s on line %lu) is invalid",
			  name, file, line);
		cfg_print_grammar(cfg_type_conf, cfg_printer, log_buf);
		log_info("expected grammar:\n"
			 "%.*s", isc_buffer_usedlength(log_buf),
			 (char *)isc_buffer_base(log_buf));
		goto cleanup;
	}

	CHECK(settings_set_fill(config, settings));

cleanup:
	if (log_buf != NULL)
		isc_buffer_free(&log_buf);
	if (config != NULL)
		cfg_obj_destroy(parser, &config);
	if (parser != NULL)
		cfg_parser_destroy(&parser);
	return result;
}

isc_result_t
get_enum_description(const enum_txt_assoc_t *map, int value, const char **desc) {
	const enum_txt_assoc_t *record;

	REQUIRE(map != NULL);
	REQUIRE(desc != NULL && *desc == NULL);

	for (record = map;
	     record->description != NULL && record->value != -1;
	     record++) {
		if (record->value == value) {
			*desc = record->description;
			return ISC_R_SUCCESS;
		}
	}
	return ISC_R_NOTFOUND;
}

isc_result_t
get_enum_value(const enum_txt_assoc_t *map, const char *description,
	       int *value) {
	const enum_txt_assoc_t *record;

	REQUIRE(map != NULL);
	REQUIRE(description != NULL);
	REQUIRE(value != NULL);

	for (record = map;
	     record->description != NULL && record->value != -1;
	     record++) {
		if (strcasecmp(record->description, description) == 0) {
			*value = record->value;
			return ISC_R_SUCCESS;
		}
	}
	return ISC_R_NOTFOUND;
}
