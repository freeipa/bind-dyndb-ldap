/*
 * Copyright (C) 2013-2014  bind-dyndb-ldap authors; see COPYING for license
 */

#ifndef FS_H_
#define FS_H_

#include "util.h"

isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
fs_dirs_create(const char *path);

isc_result_t ATTR_NONNULLS ATTR_CHECKRESULT
fs_file_remove(const char *file_name);

#endif /* FS_H_ */
