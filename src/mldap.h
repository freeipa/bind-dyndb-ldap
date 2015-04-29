/*
 * Copyright (C) 2015  bind-dyndb-ldap authors; see COPYING for license
 */

#ifndef SRC_MLDAP_H_
#define SRC_MLDAP_H_

void
ldap_uuid_to_mname(struct berval *beruuid, dns_name_t *nameuuid);

#endif /* SRC_MLDAP_H_ */
