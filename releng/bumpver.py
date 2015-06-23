#!/usr/bin/env python
#
# Copyright (C) 2014  bind-dyndb-ldap authors; see COPYING for license
#

"""
Bump version number in source tree, commit and tag resulting tree.

Usage:
- bumpver.py -> bump minor version by 1
- bumpver.py 6.1 -> set major and minor versions to 6.1

Assumptions:
- README file was updated & commited by hand.

Checks:
- Working directory is clean.
- NEWS file contains notes for new version.

Actions:
- Bump version in configure.ac & bind-dyndb-ldap.spec.
- Commits bumped version.
- Tags new version.
"""

import logging
import re
from subprocess import check_output, check_call
import sys

from srcversion import FileVersion, FakeVersion

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger('bump')

def bump_version(cur_version):
    """Bump minor version by 1 OR return specified version if one was given
    on commandline. """
    if len(sys.argv) == 1:
        major = cur_version.major
        minor = cur_version.minor + 1
    elif len(sys.argv) == 2:
        try:
            major, minor = sys.argv[1].split('.')
        except ValueError:
            log.critical('Version number has to have format <major.minor>')
            sys.exit(4)

    return FakeVersion(major, minor)

def expect_clean_workdir():
    gstatus = check_output(['git', 'status', '--porcelain'])
    if gstatus.strip():
        log.critical('Working directory is not clean:\n%s', gstatus)
        sys.exit(1)

expect_clean_workdir()

# get current version
file_version = FileVersion()

# compute new version
new_version = bump_version(file_version)
log.info('New version: %s' % new_version)

# check that new version is in NEWS file
with open('NEWS') as fnews:
    regex = '(^|\n)%s.%s\n====\n' % (new_version.major, new_version.minor)
    if not re.search(regex, fnews.read()):
        log.fatal('NEWS file does not contain version %s', new_version)
        sys.exit(2)
log.debug('NEWS file seems okay')

# write new version
file_version.major = new_version.major
file_version.minor = new_version.minor

# commit version bump
log.debug('Add modified files to git index')
log.info(check_output(['git', 'add'] + file_version.files))
log.info(check_output(['git', 'commit', '-S', '-m', 'Bump NVR to %s.' % file_version]))
check_call(['git', 'show'])

# working directory should be clean if we did not mess things up
expect_clean_workdir()

# tag new version
ver_str = "v%s" % str(file_version)
check_call(['git', 'tag', '-s', '-m', 'Release %s.' % ver_str, ver_str])
