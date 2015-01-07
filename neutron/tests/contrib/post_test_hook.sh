#!/bin/bash

set -xe

NEUTRON_DIR="$BASE/new/neutron"
TEMPEST_DIR="$BASE/new/tempest"
SCRIPTS_DIR="/usr/local/jenkins/slave_scripts"

venv=${1:-"dsvm-functional"}

function generate_testr_results {
    # Give job user rights to access tox logs
    sudo -H -u $owner chmod o+rw .
    sudo -H -u $owner chmod o+rw -R .testrepository
    if [ -f ".testrepository/0" ] ; then
        .tox/$venv/bin/subunit-1to2 < .testrepository/0 > ./testrepository.subunit
        .tox/$venv/bin/python $SCRIPTS_DIR/subunit2html.py ./testrepository.subunit testr_results.html
        gzip -9 ./testrepository.subunit
        gzip -9 ./testr_results.html
        sudo mv ./*.gz /opt/stack/logs/
    fi
}


function dsvm_functional_prep_func {
    :
}


function api_prep_func {
    sudo chown -R $owner:stack $TEMPEST_DIR
    sudo -H -u $owner tox -e $venv --notest
    sudo -H -u $owner .tox/$venv/bin/pip install -e $TEMPEST_DIR
}


if [ "$venv" == "dsvm-functional" ]
then
    owner=stack
    prep_func="dsvm_functional_prep_func"
elif [ "$venv" == "api" ]
then
    owner=tempest
    prep_func="api_prep_func"
fi

# Set owner permissions according to job's requirements.
cd $NEUTRON_DIR
sudo chown -R $owner:stack $NEUTRON_DIR
# Prep the environment according to job's requirements.
$prep_func

# Run tests
echo "Running neutron $venv test suite"
set +e
sudo -H -u $owner tox -e $venv
testr_exit_code=$?
set -e

# Collect and parse results
generate_testr_results
exit $testr_exit_code
