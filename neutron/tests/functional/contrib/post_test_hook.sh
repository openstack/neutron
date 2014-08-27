#!/bin/bash

set -xe

NEUTRON_DIR=$BASE/new/neutron

# Run tests as the stack user to allow sudo+rootwrap.
sudo chown -R stack:stack $NEUTRON_DIR
cd $NEUTRON_DIR
echo "Running neutron functional test suite"
sudo -H -u stack tox -e dsvm-functional
