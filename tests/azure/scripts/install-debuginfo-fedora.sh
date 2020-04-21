#!/bin/bash -eu

function install_debuginfo() {
    dnf makecache ||:
    dnf install -y \
        ${DYNDB_LDAP_TESTS_REPO_PATH}/distx/packages_debuginfo/*.rpm \
        gdb

    dnf debuginfo-install -y \
        389-ds-base \
        bind \
        bind-dyndb-ldap \
        certmonger \
        gssproxy \
        httpd \
        krb5-server \
        krb5-workstation \
        samba \
        sssd
}
