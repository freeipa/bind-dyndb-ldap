/* Authors: Martin Nagy <mnagy@redhat.com>
 *
 * Copyright (C) 2009  Red Hat
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

#ifndef _LD_UTIL_H_
#define _LD_UTIL_H_

#define CHECK(op)						\
	do { result = (op);					\
		if (result != ISC_R_SUCCESS) goto cleanup;	\
	} while (0)

#define ZERO_PTR(ptr, type) memset((ptr), 0, sizeof(type))

#endif /* !_LD_UTIL_H_ */
