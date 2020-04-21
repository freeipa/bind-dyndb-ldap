#!/bin/bash -eu

function install_debuginfo() { :; }

# override install_debuginfo for the platform specifics
source "${DYNDB_LDAP_TESTS_SCRIPTS}/install-debuginfo-${DYNDB_LDAP_PLATFORM}.sh"

install_debuginfo
