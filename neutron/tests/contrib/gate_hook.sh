#!/bin/bash

set -ex

$BASE/new/devstack-gate/devstack-vm-gate.sh

# Add a rootwrap filter to support test-only
# configuration (e.g. a KillFilter for processes that
# use the python installed in a tox env).
FUNC_FILTER=$BASE/new/neutron/neutron/tests/functional/contrib/filters.template
sed -e "s+\$BASE_PATH+$BASE/new/neutron/.tox/dsvm-functional+" \
    $FUNC_FILTER | sudo tee /etc/neutron/rootwrap.d/functional.filters > /dev/null
