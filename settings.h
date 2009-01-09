#ifndef _LD_SETTINGS_H_
#define _LD_SETTINGS_H_

typedef struct setting	setting_t;

typedef enum {
	ST_LD_STRING,
	ST_SIGNED_INTEGER,
	ST_UNSIGNED_INTEGER,
	ST_NO_DEFAULT,
} setting_type_t;

struct setting {
	const char	*name;
	int		set;
	setting_type_t	type;
	union {
		const char	*value_char;
		signed int	value_sint;
		unsigned int	value_uint;
	} default_value;
	size_t		offset;
};

/*
 * These defines are used as initializers for setting_t, for example:
 *
 * const setting_t my_setting = {
 *         "name", default_string("this is the default"),
 *         offsetof(some_struct, some_member
 * }
 */
#define default_string(value)	0, ST_LD_STRING, { .value_char = (value) }
#define default_sint(value)	0, ST_SIGNED_INTEGER, { .value_sint = (value) }
#define default_uint(value)	0, ST_UNSIGNED_INTEGER, { .value_uint = (value) }
#define default_nothing()	0, ST_NO_DEFAULT, { .value_uint = 0 }

/* This is used in the end of setting_t arrays. */
#define end_of_settings	{ NULL, default_sint(0), 0 }

#define value_char default_value.value_char
#define value_sint default_value.value_sint
#define value_uint default_value.value_uint

/*
 * Prototypes.
 */
isc_result_t
set_settings(isc_mem_t *mctx, void *target, setting_t settings[],
	     const char * const* argv);

#endif /* !_LD_SETTINGS_H_ */
