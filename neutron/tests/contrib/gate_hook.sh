#!/usr/bin/env bash


set -ex


VENV=${1:-"dsvm-functional"}


if [ "$VENV" == "dsvm-functional" ] || [ "$VENV" == "dsvm-fullstack" ]
then
    # The following need to be set before sourcing
    # configure_for_func_testing.
    GATE_DEST=$BASE/new
    GATE_STACK_USER=stack
    NEUTRON_PATH=$GATE_DEST/neutron
    PROJECT_NAME=neutron
    DEVSTACK_PATH=$GATE_DEST/devstack
    IS_GATE=True

    source $NEUTRON_PATH/tools/configure_for_func_testing.sh

    # Make the workspace owned by the stack user
    sudo chown -R $STACK_USER:$STACK_USER $BASE

    configure_host_for_func_testing
elif [ "$VENV" == "api" ]
then
    if [[ -z "$DEVSTACK_LOCAL_CONFIG" ]]; then
        export DEVSTACK_LOCAL_CONFIG="enable_plugin neutron-vpnaas git://git.openstack.org/openstack/neutron-vpnaas"
    else
        export DEVSTACK_LOCAL_CONFIG+=$'\n'"enable_plugin neutron-vpnaas git://git.openstack.org/openstack/neutron-vpnaas"
    fi
    $BASE/new/devstack-gate/devstack-vm-gate.sh
fi
