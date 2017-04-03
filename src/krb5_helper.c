/*
 * Copyright (C) 2009-2014  bind-dyndb-ldap authors; see COPYING for license
 */

#define _POSIX_C_SOURCE 200112L /* setenv */

#include <isc/util.h>
#include <string.h>
#include <stdlib.h>
#include <krb5.h>
#include "util.h"
#include "str.h"
#include "log.h"
#include "krb5_helper.h"

#define DEFAULT_KEYTAB "FILE:/etc/named.keytab"
#define MIN_TIME 300 /* 5 minutes */

#define CHECK_KRB5(ctx, err, msg, ...)					\
	do {								\
		if (err) {						\
			const char * errmsg = krb5_get_error_message(ctx, err);	\
			log_error(msg " (%s)", ##__VA_ARGS__, errmsg);	\
			krb5_free_error_message(ctx, errmsg);		\
			result = ISC_R_FAILURE;				\
			goto cleanup;					\
		}							\
	} while(0)

static isc_result_t ATTR_CHECKRESULT
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
	CHECK_KRB5(context, krberr, "Failed to build 'krbtgt/REALM' principal");

	/* krb5_cc_retrieve_cred filters on both server and client */
	mcreds.client = service;

	krberr = krb5_cc_retrieve_cred(context, ccache, 0, &mcreds, &creds);
	if (krberr) {
		const char * errmsg = krb5_get_error_message(context, krberr);
		log_debug(2, "Credentials are not present in cache (%s)",
			  errmsg);
		krb5_free_error_message(context, errmsg);
		result = ISC_R_FAILURE;
		goto cleanup;
	}

	krberr = krb5_timeofday(context, &now);
	CHECK_KRB5(context, krberr, "Failed to get timeofday");
	log_debug(2, "krb5_timeofday() = %ld ; creds.times.endtime = %ld",
		  (long) now, (long) creds.times.endtime);

	if (now > (creds.times.endtime - MIN_TIME)) {
		log_debug(2, "Credentials in cache expired");
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
	krb5_principal kprincpw = NULL;
	krb5_creds my_creds;
	krb5_creds * my_creds_ptr = NULL;
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
		if (strncmp(keyfile, "FILE:", 5) != 0) {
			log_error("Unknown keytab file name format, "
				  "missing leading 'FILE:' prefix");
			return ISC_R_FAILURE;
		}
	}

	krberr = krb5_init_context(&context);
	/* This will blow up with older versions of Heimdal Kerberos, but
	 * this kind of errors are not debuggable without any error message.
	 * http://mailman.mit.edu/pipermail/kerberos/2013-February/018720.html */
	CHECK_KRB5(NULL, krberr, "Kerberos context initialization failed");

	/* get credentials cache */
	CHECK(str_new(mctx, &ccname));
	CHECK(str_sprintf(ccname, "MEMORY:_ld_krb5_cc_%s", principal));

	ret = setenv("KRB5CCNAME", str_buf(ccname), 1);
	if (ret == -1) {
		log_error("Failed to set KRB5CCNAME environment variable to "
			  "'%s'", str_buf(ccname));
		result = ISC_R_FAILURE;
		goto cleanup;
	}

	krberr = krb5_cc_resolve(context, str_buf(ccname), &ccache);
	CHECK_KRB5(context, krberr,
		   "Failed to resolve credentials cache name '%s'",
		   str_buf(ccname));

	/* get krb5_principal from string */
	krberr = krb5_parse_name(context, principal, &kprincpw);
	CHECK_KRB5(context, krberr,
		   "Failed to parse the principal name '%s'", principal);

	/* check if we already have valid credentials */
	result = check_credentials(context, ccache, kprincpw);
	if (result == ISC_R_SUCCESS) {
		log_debug(2, "Found valid Kerberos credentials in cache");
		goto cleanup;
	} else {
		log_debug(2, "Attempting to acquire new Kerberos credentials");
	}

	/* open keytab */
	krberr = krb5_kt_resolve(context, keyfile, &keytab);
	CHECK_KRB5(context, krberr,
		   "Failed to resolve keytab file '%s'", keyfile);

	memset(&my_creds, 0, sizeof(my_creds));
	memset(&options, 0, sizeof(options));

	krb5_get_init_creds_opt_set_address_list(&options, NULL);
	krb5_get_init_creds_opt_set_forwardable(&options, 0);
	krb5_get_init_creds_opt_set_proxiable(&options, 0);

	/* get tgt */
	krberr = krb5_get_init_creds_keytab(context, &my_creds, kprincpw,
					    keytab, 0, NULL, &options);
	CHECK_KRB5(context, krberr, "Failed to get initial credentials (TGT) "
				    "using principal '%s' and keytab '%s'",
				    principal, keyfile);
	my_creds_ptr = &my_creds;

	/* store credentials in cache */
	krberr = krb5_cc_initialize(context, ccache, kprincpw);
	CHECK_KRB5(context, krberr, "Failed to initialize credentials cache "
				    "'%s'", str_buf(ccname));

	krberr = krb5_cc_store_cred(context, ccache, &my_creds);
	CHECK_KRB5(context, krberr, "Failed to store credentials "
				    "in credentials cache '%s'", str_buf(ccname));

	result = ISC_R_SUCCESS;

cleanup:
	if (ccname) str_destroy(&ccname);
	if (ccache) krb5_cc_close(context, ccache);
	if (keytab) krb5_kt_close(context, keytab);
	if (kprincpw) krb5_free_principal(context, kprincpw);
	if (my_creds_ptr) krb5_free_cred_contents(context, my_creds_ptr);
	if (context) krb5_free_context(context);
	return result;
}
