/*
 * Copyright (C) 2009-2014  bind-dyndb-ldap authors; see COPYING for license
 */

#ifndef _LD_ZONE_MANAGER_H_
#define _LD_ZONE_MANAGER_H_

#include <dns/types.h>

#include "types.h"

typedef struct db_instance db_instance_t;

void destroy_manager(void);

isc_result_t
manager_create_db_instance(isc_mem_t *mctx, const char *name,
			   const char * const *argv,
			   dns_dyndb_arguments_t *dyndb_args) ATTR_NONNULLS ATTR_CHECKRESULT;

isc_result_t
manager_get_ldap_instance(const char *name,
			  ldap_instance_t **ldap_inst) ATTR_NONNULLS ATTR_CHECKRESULT;

isc_result_t
manager_get_db_timer(const char *name,
			  isc_timer_t **timer) ATTR_NONNULLS ATTR_CHECKRESULT;

#endif /* !_LD_ZONE_MANAGER_H_ */
