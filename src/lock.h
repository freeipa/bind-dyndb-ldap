/*
 * Copyright (C) 2014  bind-dyndb-ldap authors; see COPYING for license
 */

#ifndef LOCK_H_
#define LOCK_H_

#include "util.h"
#include "types.h"

void ATTR_NONNULLS
run_exclusive_enter(ldap_instance_t *inst, isc_result_t *statep);

void ATTR_NONNULLS
run_exclusive_exit(ldap_instance_t *inst, isc_result_t state);

#endif /* LOCK_H_ */
