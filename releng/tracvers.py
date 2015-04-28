#!/usr/bin/env python3
#
# Copyright (C) 2014  bind-dyndb-ldap authors; see COPYING for license
#

"""
Create Trac version for each Git tag.
"""

from datetime import datetime
import logging
from subprocess import check_output, check_call

from trac import trac_autoconf

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger('tracver')

tr = trac_autoconf()

# version in Trac has format '1.2'
trac_versions = set()
for ver in tr.api.ticket.version.getAll():
    trac_versions.add("v%s" % ver)
log.debug('Trac versions: %s', trac_versions)

# version in Git is tag named like 'v1.2'
git_versions = set()
for tag in check_output(['git','tag']).decode('ascii').strip().split('\n'):
    # these are sins of young developers
    if tag == 'v0.1.0-b' or tag == 'v0.1.0-a1':
        tag = tag.translate({ord('-'): None})
    git_versions.add(tag)
log.debug('Git versions: %s', git_versions)

new_versions = git_versions - trac_versions
log.debug('New versions missing in Trac: %s', new_versions)

# add new versions to Trac
for tag in new_versions:
    time = check_output(['git', 'log', '--format=format:%ai', '%s~1..%s'
        % (tag, tag)]).decode('ascii').strip()
    time = datetime.strptime(time, "%Y-%m-%d %H:%M:%S %z")
    version = tag[1:]
    log.info('Adding version %s with timestamp %s', version, time)
    tr.api.ticket.version.create(version, {'time': time, 'description': ''})

