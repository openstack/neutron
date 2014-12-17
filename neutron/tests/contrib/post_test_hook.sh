#!/bin/bash

set -xe

NEUTRON_DIR="$BASE/new/neutron"
SCRIPTS_DIR="/usr/local/jenkins/slave_scripts"
venv=dsvm-functional

function generate_testr_results {
    # Give job user rights to access tox logs
    sudo -H -u stack chmod o+rw -R .
    if [ -f ".testrepository/0" ] ; then
        .tox/$venv/bin/subunit-1to2 < .testrepository/0 > ./testrepository.subunit
        .tox/$venv/bin/python $SCRIPTS_DIR/subunit2html.py ./testrepository.subunit testr_results.html
        gzip -9 ./testrepository.subunit
        gzip -9 ./testr_results.html
        sudo mv ./*.gz /opt/stack/logs/
    fi
}

# Run tests as the stack user to allow sudo+rootwrap.
sudo chown -R stack:stack $NEUTRON_DIR
cd $NEUTRON_DIR

echo "Running neutron functional test suite"
set +e
sudo -H -u stack tox -e $venv
testr_exit_code=$?
set -e

generate_testr_results
exit $testr_exit_code
