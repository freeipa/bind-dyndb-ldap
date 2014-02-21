/*
 * Authors: Petr Spacek <pspacek@redhat.com>
 *
 * Copyright (C) 2013 Red Hat
 * see file 'COPYING' for use and warranty information
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

#ifndef FS_H_
#define FS_H_

#include "util.h"

isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
fs_dirs_create(const char *path);

isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
fs_file_remove(const char *file_name);

#endif /* FS_H_ */
