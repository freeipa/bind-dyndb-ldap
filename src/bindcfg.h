/*
 * Copyright (C) 2009-2016  bind-dyndb-ldap authors; see COPYING for license
 */

#ifndef _LD_BINDCFG_H_
#define _LD_BINDCFG_H_

#include <isccfg/cfg.h>

#include "util.h"

extern cfg_type_t *cfg_type_update_policy;
extern cfg_type_t *cfg_type_allow_query;
extern cfg_type_t *cfg_type_allow_transfer;
extern cfg_type_t *cfg_type_forwarders;

void
cfg_init_types(void);

isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
cfg_parse_strbuf(cfg_parser_t *parser, const char *string, cfg_type_t **type,
		 cfg_obj_t **objp);

#endif /* _LD_BINDCFG_H_ */
