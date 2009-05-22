/*
 * Copyright (C) Simo Sorce <ssorce@redhat.com> 2009
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

#define _BSD_SOURCE

#include <isc/util.h>
#include <string.h>
#include <stdlib.h>
#include <krb5.h>
#include "util.h"
#include "str.h"
#include "log.h"

#define DEFAULT_KEYTAB "FILE:/etc/named.keytab"
#define MIN_TIME 300 /* 5 minutes */

#define CHECK_KRB5(ctx, err, msg, ...)					\
	do {								\
		if (err) {						\
			log_error(msg " (%s)", ##__VA_ARGS__,		\
				  krb5_get_error_message(ctx, err));	\
			result = ISC_R_FAILURE;				\
			goto cleanup;					\
		}							\
	} while(0)

static isc_result_t
check_credentials(krb5_context context,
		  krb5_ccache ccache,
		  krb5_principal service)
{
	char *realm = NULL;
	krb5_creds creds;
	krb5_creds mcreds;
	krb5_timestamp now;
	krb5_error_code krberr;
	isc_result_t result;

	memset(&mcreds, 0, sizeof(mcreds));
	memset(&creds, 0, sizeof(creds));

	krberr = krb5_get_default_realm(context, &realm);
	CHECK_KRB5(context, krberr, "Failed to retrieve default realm");

	krberr = krb5_build_principal(context, &mcreds.server,
				      strlen(realm), realm,
				      "krbtgt", realm, NULL);
	CHECK_KRB5(context, krberr, "Failed to build tgt principal");

	/* krb5_cc_retrieve_cred filters on both server and client */
	mcreds.client = service;

	krberr = krb5_cc_retrieve_cred(context, ccache, 0, &mcreds, &creds);
	if (krberr) {
		log_debug(2, "Principal not found in cred cache (%s)",
			  krb5_get_error_message(context, krberr));
		result = ISC_R_FAILURE;
		goto cleanup;
	}

	krberr = krb5_timeofday(context, &now);
	CHECK_KRB5(context, krberr, "Failed to get timeofday");

	if (now > (creds.times.endtime + MIN_TIME)) {
		log_debug(2, "Credentials expired");
		result = ISC_R_FAILURE;
		goto cleanup;
	}

	result = ISC_R_SUCCESS;

cleanup:
	krb5_free_cred_contents(context, &creds);
	if (mcreds.server) krb5_free_principal(context, mcreds.server);
	if (realm) krb5_free_default_realm(context, realm);
	return result;
}

isc_result_t
get_krb5_tgt(isc_mem_t *mctx, const char *principal, const char *keyfile)
{
	ld_string_t *ccname = NULL;
	krb5_context context = NULL;
	krb5_keytab keytab = NULL;
	krb5_ccache ccache = NULL;
	krb5_principal kprincpw;
	krb5_creds my_creds;
	krb5_get_init_creds_opt options;
	krb5_error_code krberr;
	isc_result_t result;
	int ret;

	REQUIRE(principal != NULL && principal[0] != '\0');

	if (keyfile == NULL || keyfile[0] == '\0') {
		log_debug(2, "Using default keytab file name: %s",
			  DEFAULT_KEYTAB);
		keyfile = DEFAULT_KEYTAB;
	} else {
		if (strcmp(keyfile, "FILE:") != 0) {
			log_error("Unknown keytab file name format, "
				  "missing leading 'FILE:' prefix");
			return ISC_R_FAILURE;
		}
	}

	krberr = krb5_init_context(&context);
	if (krberr) {
		log_error("Failed to init kerberos context");
		return ISC_R_FAILURE;
	}

	/* get credentials cache */
	CHECK(str_new(mctx, &ccname));
	CHECK(str_sprintf(ccname, "MEMORY:_ld_krb5_cc_%s", principal));

	ret = setenv("KRB5CCNAME", str_buf(ccname), 1);
	if (ret == -1) {
		log_error("Failed to set KRB5CCNAME environment variable");
		result = ISC_R_FAILURE;
		goto cleanup;
	}

	krberr = krb5_cc_resolve(context, str_buf(ccname), &ccache);
	CHECK_KRB5(context, krberr,
		   "Failed to resolve ccache name %s", ccname);

	/* get krb5_principal from string */
	krberr = krb5_parse_name(context, principal, &kprincpw);
	CHECK_KRB5(context, krberr,
		   "Failed to parse the principal name %s", principal);

	/* check if we already have valid credentials */
	result = check_credentials(context, ccache, kprincpw);
	if (result == ISC_R_SUCCESS) {
		log_debug(2, "Found valid cached credentials");
		goto cleanup;
	}

	/* open keytab */
	krberr = krb5_kt_resolve(context, keyfile, &keytab);
	CHECK_KRB5(context, krberr,
		   "Failed to resolve keytab file %s", keyfile);

	memset(&my_creds, 0, sizeof(my_creds));
	memset(&options, 0, sizeof(options));

	krb5_get_init_creds_opt_set_address_list(&options, NULL);
	krb5_get_init_creds_opt_set_forwardable(&options, 0);
	krb5_get_init_creds_opt_set_proxiable(&options, 0);

	/* get tgt */
	krberr = krb5_get_init_creds_keytab(context, &my_creds, kprincpw,
					    keytab, 0, NULL, &options);
	CHECK_KRB5(context, krberr, "Failed to init credentials");

	/* store credentials in cache */
	krberr = krb5_cc_initialize(context, ccache, kprincpw);
	CHECK_KRB5(context, krberr, "Failed to initialize ccache");

	krberr = krb5_cc_store_cred(context, ccache, &my_creds);
	CHECK_KRB5(context, krberr, "Failed to store ccache");

	result = ISC_R_SUCCESS;

cleanup:
	if (ccname) str_destroy(&ccname);
	if (keytab) krb5_kt_close(context, keytab);
	if (context) krb5_free_context(context);
	return result;
}
