#!/bin/bash -eux

if [ $# -ne 1 ]; then
    echo "Docker environment ID is not provided"
    exit 1
fi

PROJECT_ID="$1"
BUILD_REPOSITORY_LOCALPATH="${BUILD_REPOSITORY_LOCALPATH:-$(realpath .)}"

DYNDB_LDAP_TESTS_TO_RUN_VARNAME="DYNDB_LDAP_TESTS_TO_RUN_${PROJECT_ID}"
DYNDB_LDAP_TESTS_TO_RUN="${!DYNDB_LDAP_TESTS_TO_RUN_VARNAME:-}"
# in case of missing explicit list of tests to be run the Pytest run all the
# discovered tests, this is an error for this CI
[ -z "$DYNDB_LDAP_TESTS_TO_RUN" ] && { echo 'Nothing to test'; exit 1; }

DYNDB_LDAP_TESTS_ENV_NAME_VARNAME="DYNDB_LDAP_TESTS_ENV_NAME_${PROJECT_ID}"
DYNDB_LDAP_TESTS_ENV_NAME="${!DYNDB_LDAP_TESTS_ENV_NAME_VARNAME:-}"
[ -z "$DYNDB_LDAP_TESTS_ENV_NAME" ] && \
    { echo "Project name is not set for project:${PROJECT_ID}"; exit 1 ;}

DYNDB_LDAP_TESTS_TYPE_VARNAME="DYNDB_LDAP_TESTS_TYPE_${PROJECT_ID}"
DYNDB_LDAP_TESTS_TYPE="${!DYNDB_LDAP_TESTS_TYPE_VARNAME:-integration}"

# Normalize spacing and expand the list afterwards. Remove {} for the single list element case
DYNDB_LDAP_TESTS_TO_RUN=$(eval "echo {$(echo $DYNDB_LDAP_TESTS_TO_RUN | sed -e 's/[ \t]+*/,/g')}" | tr -d '{}')

DYNDB_LDAP_TESTS_TO_IGNORE_VARNAME="DYNDB_LDAP_TESTS_TO_IGNORE_${PROJECT_ID}"
DYNDB_LDAP_TESTS_TO_IGNORE="${!DYNDB_LDAP_TESTS_TO_IGNORE_VARNAME:-}"
[ -n "$DYNDB_LDAP_TESTS_TO_IGNORE" ] && \
DYNDB_LDAP_TESTS_TO_IGNORE=$(eval "echo --ignore\ {$(echo $DYNDB_LDAP_TESTS_TO_IGNORE | sed -e 's/[ \t]+*/,/g')}" | tr -d '{}')

DYNDB_LDAP_TESTS_CLIENTS_VARNAME="DYNDB_LDAP_TESTS_CLIENTS_${PROJECT_ID}"
DYNDB_LDAP_TESTS_CLIENTS="${!DYNDB_LDAP_TESTS_CLIENTS_VARNAME:-0}"

DYNDB_LDAP_TESTS_REPLICAS_VARNAME="DYNDB_LDAP_TESTS_REPLICAS_${PROJECT_ID}"
DYNDB_LDAP_TESTS_REPLICAS="${!DYNDB_LDAP_TESTS_REPLICAS_VARNAME:-0}"

DYNDB_LDAP_TESTS_CONTROLLER="${PROJECT_ID}_master_1"
DYNDB_LDAP_TESTS_LOGSDIR="${DYNDB_LDAP_TESTS_REPO_PATH}/dyndb_ldap_envs/${DYNDB_LDAP_TESTS_ENV_NAME}/${CI_RUNNER_LOGS_DIR}"

DYNDB_LDAP_TESTS_DOMAIN="${DYNDB_LDAP_TESTS_DOMAIN:-ipa.test}"
# bash4
DYNDB_LDAP_TESTS_REALM="${DYNDB_LDAP_TESTS_DOMAIN^^}"

# for base tests only 1 master is needed even if another was specified
if [ "$DYNDB_LDAP_TESTS_TYPE" == "base" ]; then
    DYNDB_LDAP_TESTS_CLIENTS="0"
    DYNDB_LDAP_TESTS_REPLICAS="0"
fi

project_dir="${DYNDB_LDAP_TESTS_ENV_WORKING_DIR}/${DYNDB_LDAP_TESTS_ENV_NAME}"
ln -sfr \
    "${DYNDB_LDAP_TESTS_DOCKERFILES}/docker-compose.yml" \
    "$project_dir"/

ln -sfr \
    "${DYNDB_LDAP_TESTS_DOCKERFILES}/seccomp.json" \
    "$project_dir"/

# will be generated later in setup_containers.py
touch "${project_dir}"/test-config.yaml

pushd "$project_dir"

BUILD_REPOSITORY_LOCALPATH="$BUILD_REPOSITORY_LOCALPATH" \
DYNDB_LDAP_DOCKER_IMAGE="${DYNDB_LDAP_DOCKER_IMAGE:-dyndb-ldap-azure-builder}" \
DYNDB_LDAP_NETWORK="${DYNDB_LDAP_NETWORK:-ipanet}" \
DYNDB_LDAP_IPV6_SUBNET="2001:db8:1:${PROJECT_ID}::/64" \
docker-compose -p "$PROJECT_ID" up \
    --scale replica="$DYNDB_LDAP_TESTS_REPLICAS" \
    --scale client="$DYNDB_LDAP_TESTS_CLIENTS" \
    --force-recreate --remove-orphans -d

popd

DYNDB_LDAP_TESTS_CLIENTS="$DYNDB_LDAP_TESTS_CLIENTS" \
DYNDB_LDAP_TESTS_REPLICAS="$DYNDB_LDAP_TESTS_REPLICAS" \
DYNDB_LDAP_TESTS_ENV_ID="$PROJECT_ID" \
DYNDB_LDAP_TESTS_ENV_WORKING_DIR="$DYNDB_LDAP_TESTS_ENV_WORKING_DIR" \
DYNDB_LDAP_TESTS_ENV_NAME="$DYNDB_LDAP_TESTS_ENV_NAME" \
DYNDB_LDAP_TEST_CONFIG_TEMPLATE="${BUILD_REPOSITORY_LOCALPATH}/tests/azure/templates/test-config-template.yaml" \
DYNDB_LDAP_TESTS_REPO_PATH="$DYNDB_LDAP_TESTS_REPO_PATH" \
DYNDB_LDAP_TESTS_DOMAIN="$DYNDB_LDAP_TESTS_DOMAIN" \
python3 setup_containers.py

# path to runner within container
tests_runner="${DYNDB_LDAP_TESTS_REPO_PATH}/${DYNDB_LDAP_TESTS_SCRIPTS}/azure-run-${DYNDB_LDAP_TESTS_TYPE}-tests.sh"

tests_result=1
{ docker exec -t \
    --env DYNDB_LDAP_TESTS_SCRIPTS="${DYNDB_LDAP_TESTS_REPO_PATH}/${DYNDB_LDAP_TESTS_SCRIPTS}" \
    --env DYNDB_LDAP_PLATFORM="$DYNDB_LDAP_PLATFORM" \
    --env DYNDB_LDAP_TESTS_DOMAIN="$DYNDB_LDAP_TESTS_DOMAIN" \
    --env DYNDB_LDAP_TESTS_REALM="$DYNDB_LDAP_TESTS_REALM" \
    --env DYNDB_LDAP_TESTS_LOGSDIR="$DYNDB_LDAP_TESTS_LOGSDIR" \
    --env DYNDB_LDAP_TESTS_TO_RUN="$DYNDB_LDAP_TESTS_TO_RUN" \
    --env DYNDB_LDAP_TESTS_TO_IGNORE="$DYNDB_LDAP_TESTS_TO_IGNORE" \
    "$DYNDB_LDAP_TESTS_CONTROLLER" \
    /bin/bash --noprofile --norc \
    -eux "$tests_runner" && tests_result=0 ; } || tests_result=$?

pushd "$project_dir"
BUILD_REPOSITORY_LOCALPATH="$BUILD_REPOSITORY_LOCALPATH" \
DYNDB_LDAP_DOCKER_IMAGE="${DYNDB_LDAP_DOCKER_IMAGE:-dyndb-ldap-azure-builder}" \
DYNDB_LDAP_NETWORK="${DYNDB_LDAP_NETWORK:-ipanet}" \
DYNDB_LDAP_IPV6_SUBNET="2001:db8:1:${PROJECT_ID}::/64" \
docker-compose -p "$PROJECT_ID" down
popd

exit $tests_result
