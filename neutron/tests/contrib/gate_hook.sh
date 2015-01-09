#!/bin/bash


set -ex


venv=${1:-"dsvm-functional"}


if [ "$venv" == "dsvm-functional" ]
then
    # The following need to be set before sourcing
    # configure_for_func_testing.
    GATE_DEST=$BASE/new
    GATE_STACK_USER=stack
    NEUTRON_PATH=$GATE_DEST/neutron
    DEVSTACK_PATH=$GATE_DEST/devstack
    IS_GATE=True

    source $NEUTRON_PATH/tools/configure_for_func_testing.sh

    # Make the workspace owned by the stack user
    sudo chown -R $STACK_USER:$STACK_USER $BASE

    configure_host_for_func_testing $STACK_USER
elif [ "$venv" == "api" ]
then
    $BASE/new/devstack-gate/devstack-vm-gate.sh
fi
