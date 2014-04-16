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

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>

#include <isc/dir.h>
#include <isc/file.h>
#include <isc/errno2result.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/util.h>

#include "log.h"
#include "fs.h"

static const char msg_getcwd_failed[PATH_MAX] = "<getcwd() failed>";

isc_result_t
fs_dir_create(const char *dir_name)
{
	isc_result_t result;
	char dir_curr[PATH_MAX + 1] = "";
	isc_dir_t dir_handle;
	int ret;

	REQUIRE(dir_name != NULL);

	if (getcwd(dir_curr, sizeof(dir_curr) - 1) == NULL)
		strncpy(dir_curr, msg_getcwd_failed, sizeof(dir_curr));
	ret = mkdir(dir_name, 0700);
	if (ret == 0)
		result = ISC_R_SUCCESS;
	else
		result = isc__errno2result(errno);

	if (result != ISC_R_SUCCESS && result != ISC_R_FILEEXISTS) {
		log_error_r("unable to create directory '%s', working directory "
			    "is '%s'", dir_name, dir_curr);
		return result;
	}

	/* Verify that the directory is accessible */
	isc_dir_init(&dir_handle);
	result = isc_dir_open(&dir_handle, dir_name);
	if (result == ISC_R_SUCCESS)
		isc_dir_close(&dir_handle);
	else
		log_error_r("unable to open directory '%s', working directory "
			    "is '%s'", dir_name, dir_curr);

	return result;
}

/**
 * Create directories specified by path (including all parents).
 */
isc_result_t
fs_dirs_create(const char *path) {
	isc_result_t result = ISC_R_SUCCESS;
	char curr_path[PATH_MAX + 1];
	char *end = NULL;

	CHECK(isc_string_copy(curr_path, PATH_MAX, path));

	for (end = strchr(curr_path, '/');
	     end != NULL;
	     end = strchr(end + 1, '/')) {
		*end = '\0';
		if (strcmp(curr_path, "") != 0)
			/* Absolute paths would have first component empty. */
			CHECK(fs_dir_create(curr_path));
		*end = '/';
	}
	/* Handle single-component paths and paths without trailing '/' */
	CHECK(fs_dir_create(curr_path));

cleanup:
	return result;
}

isc_result_t
fs_file_remove(const char *file_name) {
	isc_result_t result;
	char dir_curr[PATH_MAX + 1] = "";

	result = isc_file_remove(file_name);
	if (result == ISC_R_FILENOTFOUND)
		result = ISC_R_SUCCESS;
	else if (result != ISC_R_SUCCESS) {
		if (getcwd(dir_curr, sizeof(dir_curr) - 1) == NULL)
			strncpy(dir_curr, msg_getcwd_failed, sizeof(dir_curr));
		log_error_r("unable to delete file '%s', working directory "
			    "is '%s'", file_name, dir_curr);
	}

	return result;
}
