/* Authors: Martin Nagy <mnagy@redhat.com>
 *
 * Copyright (C) 2008  Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 2 only
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

#ifndef _LD_LDAP_HELPER_H_

typedef struct ldap_db		ldap_db_t;
typedef struct ldap_instance	ldap_instance_t;

isc_result_t new_ldap_db(isc_mem_t *mctx, ldap_db_t **ldap_dbp,
			 const char * const *argv);
void destroy_ldap_db(ldap_db_t **ldap_db);
void get_zone_list(ldap_db_t *ldap_db);

#endif /* !_LD_LDAP_HELPER_H_ */
