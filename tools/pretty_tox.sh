#!/usr/bin/env bash

set -o pipefail

TESTRARGS=$1
python -m neutron.openstack.common.lockutils python setup.py testr --slowest --testr-args="--subunit $TESTRARGS" | $(dirname $0)/subunit-trace.py -f
