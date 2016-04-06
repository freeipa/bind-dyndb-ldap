/*
 * Copyright (C) 2008-2013  bind-dyndb-ldap authors; see COPYING for license
 */

#ifndef _LD_LOG_H_
#define _LD_LOG_H_

#include <isc/error.h>
#include <dns/log.h>
#include <dns/result.h>

#include "util.h"

#ifdef LOG_AS_ERROR
#define GET_LOG_LEVEL(level)	ISC_LOG_ERROR
#else
#define GET_LOG_LEVEL(level)	(level)
#endif

#define fatal_error(...) \
	isc_error_fatal(__FILE__, __LINE__, __VA_ARGS__)

#define log_bug(fmt, ...) \
	log_error("bug in %s(): " fmt, __func__,##__VA_ARGS__)

#define log_error_r(fmt, ...) \
	log_error(fmt ": %s", ##__VA_ARGS__, dns_result_totext(result))

#define log_error_position(format, ...)				\
	log_error("[%-15s: %4d: %-21s] " format, 			\
		  __FILE__, __LINE__, __func__, ##__VA_ARGS__)

/* Basic logging functions */
#define log_error(format, ...)	\
	log_write(GET_LOG_LEVEL(ISC_LOG_ERROR), format, ##__VA_ARGS__)

#define log_warn(format, ...)	\
	log_write(GET_LOG_LEVEL(ISC_LOG_WARNING), format, ##__VA_ARGS__)

#define log_info(format, ...)	\
	log_write(GET_LOG_LEVEL(ISC_LOG_INFO), format, ##__VA_ARGS__)

#define log_debug(level, format, ...)	\
	log_write(GET_LOG_LEVEL(level), format, ##__VA_ARGS__)

/* LDAP logging functions */
#define LOG_LDAP_ERR_PREFIX "LDAP error: "
#define log_ldap_error(ld, desc, ...)						\
	do {									\
		int err;							\
		char *errmsg = NULL;						\
		char *diagmsg = NULL;						\
		if (ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &err)		\
		    == LDAP_OPT_SUCCESS) {					\
			errmsg = ldap_err2string(err);				\
			if (ldap_get_option(ld, LDAP_OPT_DIAGNOSTIC_MESSAGE, &diagmsg)	\
			    == LDAP_OPT_SUCCESS && diagmsg != NULL) {		\
				log_error(LOG_LDAP_ERR_PREFIX "%s: %s: " desc,	\
					  errmsg, diagmsg, ##__VA_ARGS__);	\
				ldap_memfree(diagmsg);				\
			} else							\
				log_error(LOG_LDAP_ERR_PREFIX "%s: " desc,	\
					  errmsg, ##__VA_ARGS__);		\
		} else {							\
			log_error(LOG_LDAP_ERR_PREFIX				\
				  "<unable to obtain LDAP error code>: "	\
				  desc, ##__VA_ARGS__);				\
		}								\
	} while (0);

void
log_write(int level, const char *format, ...) ISC_FORMAT_PRINTF(2, 3);

#endif /* !_LD_LOG_H_ */
