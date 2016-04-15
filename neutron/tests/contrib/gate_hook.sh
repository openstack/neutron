#!/usr/bin/env bash

set -ex

VENV=${1:-"dsvm-functional"}

GATE_DEST=$BASE/new
NEUTRON_PATH=$GATE_DEST/neutron
GATE_HOOKS=$NEUTRON_PATH/neutron/tests/contrib/hooks
DEVSTACK_PATH=$GATE_DEST/devstack
LOCAL_CONF=$DEVSTACK_PATH/local.conf


# Inject config from hook into localrc
function load_rc_hook {
    local hook="$1"
    config=$(cat $GATE_HOOKS/$hook)
    export DEVSTACK_LOCAL_CONFIG+="
# generated from hook '$hook'
${config}
"
}


# Inject config from hook into local.conf
function load_conf_hook {
    local hook="$1"
    cat $GATE_HOOKS/$hook >> $LOCAL_CONF
}


if [ "$VENV" == "dsvm-functional" ] || [ "$VENV" == "dsvm-fullstack" ]
then
    # The following need to be set before sourcing
    # configure_for_func_testing.
    GATE_STACK_USER=stack
    PROJECT_NAME=neutron
    IS_GATE=True

    source $DEVSTACK_PATH/functions
    source $NEUTRON_PATH/devstack/lib/ovs

    source $NEUTRON_PATH/tools/configure_for_func_testing.sh

    configure_host_for_func_testing

    if [[ "$VENV" =~ "dsvm-functional" ]]; then
        # The OVS_BRANCH variable is used by git checkout. In the case below
        # we use a commit on branch-2.5 that fixes compilation with the
        # latest ubuntu trusty kernel.
        OVS_BRANCH=8c0b419a0b9ac0141d6973dcc80306dfc6a83d31
        for package in openvswitch openvswitch-switch openvswitch-common; do
            if is_package_installed $package; then
                uninstall_package $package
            fi
        done
        compile_ovs True /usr /var
        start_new_ovs
    fi

    # Make the workspace owned by the stack user
    sudo chown -R $STACK_USER:$STACK_USER $BASE

elif [ "$VENV" == "api" -o "$VENV" == "api-pecan" -o "$VENV" == "full-pecan" -o "$VENV" == "dsvm-scenario" ]
then
    load_rc_hook api_extensions
    if [ "$VENV" == "api-pecan" -o "$VENV" == "full-pecan" ]
    then
        load_conf_hook pecan
    fi
    load_rc_hook qos
    load_rc_hook bgp

    $BASE/new/devstack-gate/devstack-vm-gate.sh
fi
