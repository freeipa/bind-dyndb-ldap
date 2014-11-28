#!/usr/bin/env python

"""
Interface for version information in bind-dyndb-ldap source tree.
"""

import logging
import re

log = logging.getLogger('version')

class FakeVersion(object):
    """
    Read-only object with FileVersion-like interface.
    """
    def __init__(self, major, minor):
        self._major = int(major)
        self._minor = int(minor)

    @property
    def major(self):
        return self._major

    @property
    def minor(self):
        return self._minor

    def __str__(self):
        return "%s.%s" % (self.major, self.minor)


class FileVersion(FakeVersion):
    """
    Read/write interface for version information in configure.ac
    and bind-dyndb-ldap.spec.
    """
    def __init__(self):
        self.configureac_regex = '(?<=\nAC_INIT\(\[bind-dyndb-ldap\], \[)(?P<major>[0-9]+)\.(?P<minor>[0-9]+)(?=\], \[freeipa-devel@redhat\.com\]\)\n)'
        self.files = ['configure.ac', 'contrib/bind-dyndb-ldap.spec']

    def _get_ver(self):
        """return RE match object from configure.ac"""
        with open('configure.ac') as fconfigureac:
            configureac = fconfigureac.read()
            return re.search(self.configureac_regex, configureac)

    def _write_ver(self, new_ver):
        """write new version to configure.ac and bind-dyndb-ldap.spec"""
        log.debug('Writing new version %s to configure.ac', new_ver)
        with open('configure.ac', 'r+') as fconfigureac:
            configureac = fconfigureac.read()
            new_config = re.sub(self.configureac_regex, new_ver, configureac)
            fconfigureac.seek(0)
            fconfigureac.write(new_config)
            fconfigureac.truncate()

        log.debug('Writing new version %s to bind-dyndb-ldap.spec', new_ver)
        with open('contrib/bind-dyndb-ldap.spec', 'r+') as fspec:
            # look-ahead regex requires fixed length prefix which we don't have
            regex = '(\nVersion:\s+)(\S+)(?=\n)'
            old_spec = fspec.read()
            matches = re.search(regex, old_spec)
            if not matches:
                raise ValueError('Cannot find Version line in .spec')
            replacement = matches.group(1) + new_ver
            new_spec = re.sub(regex, replacement, old_spec)
            fspec.seek(0)
            fspec.write(new_spec)
            fspec.truncate()

    @property
    def major(self):
        ver = int(self._get_ver().group("major"))
        log.debug('Major version is %s', ver)
        return ver

    @major.setter
    def major(self, value):
        new_ver = "%s.%s" % (value, self.minor)
        self._write_ver(new_ver)

    @property
    def minor(self):
        ver = int(self._get_ver().group("minor"))
        log.debug('Minor version is %s', ver)
        return ver

    @minor.setter
    def minor(self, value):
        new_ver = "%s.%s" % (self.major, value)
        self._write_ver(new_ver)

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    log.info("bind-dyndb-ldap version is %s", FileVersion())
