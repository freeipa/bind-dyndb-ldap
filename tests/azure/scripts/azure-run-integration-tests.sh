#!/bin/bash -eux

# this script is intended to be run within container
#
# distro-specifics
source "${DYNDB_LDAP_TESTS_SCRIPTS}/variables.sh"

rm -rf "$DYNDB_LDAP_TESTS_LOGSDIR"
mkdir "$DYNDB_LDAP_TESTS_LOGSDIR"
pushd "$DYNDB_LDAP_TESTS_LOGSDIR"

# Local directory for ipa-run-tests
# defined in ipa-test-config(1)
# defaults to /root/ipatests
mkdir -p /root/ipatests

tests_result=1
{ IPATEST_YAML_CONFIG=~/.ipa/ipa-test-config.yaml \
    ipa-run-tests \
    --logging-level=debug \
    --logfile-dir="$DYNDB_LDAP_TESTS_LOGSDIR" \
    --with-xunit \
    --verbose \
    $DYNDB_LDAP_TESTS_TO_IGNORE \
    $DYNDB_LDAP_TESTS_TO_RUN && tests_result=0 ; } || \
    tests_result=$?

# fix permissions on logs to be readable by Azure's user (vsts)
chmod -R o+rX "$DYNDB_LDAP_TESTS_LOGSDIR"

find "$DYNDB_LDAP_TESTS_LOGSDIR" -mindepth 1 -maxdepth 1 -not -name '.*' -type d \
    -exec tar --remove-files -czf {}.tar.gz {} \;

exit $tests_result
