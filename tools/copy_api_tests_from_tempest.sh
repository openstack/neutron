#!/usr/bin/env bash

# This script is intended to allow repeatable migration of the neutron
# api tests from tempest.  The intention is to allow development to
# continue in Tempest while the migration strategy evolves.

set -e

if [[ "$#" -ne 1 ]]; then
    >&2 echo "Usage: $0 /path/to/tempest
Migrate neutron's api tests from a tempest repo."
    exit 1
fi

TEMPEST_PATH=${TEMPEST_PATH:-$1}

if [ ! -f "$TEMPEST_PATH/run_tempest.sh" ]; then
  >&2 echo "Unable to find tempest at '$TEMPEST_PATH'.  Please verify that the specified path points to a valid tempest repo."
  exit 1
fi

NEUTRON_PATH=${NEUTRON_PATH:-$(cd "$(dirname "$0")/.." && pwd)}
NEUTRON_TEST_PATH=$NEUTRON_PATH/neutron/tests

function copy_files {
    local tempest_dep_paths=(
        'tempest'
        'tempest/common'
        'tempest/common/generator'
        'tempest/common/utils'
        'tempest/services'
        'tempest/services/identity'
        'tempest/services/identity/v2'
        'tempest/services/identity/v2/json'
        'tempest/services/identity/v3'
        'tempest/services/identity/v3/json'
        'tempest/services/network'
        'tempest/services/network/json'
    )
    for tempest_dep_path in ${tempest_dep_paths[@]}; do
        local target_path=$NEUTRON_TEST_PATH/$tempest_dep_path
        if [[ ! -d "$target_path" ]]; then
            mkdir -p "$target_path"
        fi
        cp $TEMPEST_PATH/$tempest_dep_path/*.py "$target_path"
    done
    local paths_to_remove=(
        "$NEUTRON_TEST_PATH/tempest/clients.py"
    )
    for path_to_remove in ${paths_to_remove[@]}; do
        if [ -f "$path_to_remove" ]; then
            rm "$path_to_remove"
        fi
    done

    # Tests are now maintained in neutron/tests/api
    cp $TEMPEST_PATH/tempest/api/network/*.py $NEUTRON_TEST_PATH/api
    cp $TEMPEST_PATH/tempest/api/network/admin/*.py \
        $NEUTRON_TEST_PATH/api/admin
}

function rewrite_imports {
    regexes=(
        's/tempest.common.generator/neutron.tests.tempest.common.generator/'
        "s/tempest.api.network/neutron.tests.api/"
        's/tempest.test/neutron.tests.tempest.test/'
        's/from tempest.openstack.common import lockutils/from oslo_concurrency import lockutils/'
        's/from tempest.openstack.common import importutils/from oslo_utils import importutils/'
        's/tempest.openstack.common/neutron.openstack.common/'
        's/from tempest(?!_lib) import clients/from neutron.tests.api import clients/'
        's/from tempest(?!_lib)/from neutron.tests.tempest/'
        's/CONF.lock_path/CONF.oslo_concurrency.lock_path/'
    )
    files=$(find "$NEUTRON_TEST_PATH/tempest" "$NEUTRON_TEST_PATH/api" -name '*.py')
    for ((i = 0; i < ${#regexes[@]}; i++)); do
        perl -p -i -e "${regexes[$i]}" $files
    done
}

copy_files
rewrite_imports
