#!/usr/bin/env bash

set -ex

VENV=${1:-"dsvm-functional"}
FLAVOR=${2:-"all"}

GATE_DEST=$BASE/new
NEUTRON_PATH=$GATE_DEST/neutron
GATE_HOOKS=$NEUTRON_PATH/neutron/tests/contrib/hooks
DEVSTACK_PATH=$GATE_DEST/devstack
LOCAL_CONF=$DEVSTACK_PATH/local.conf
RALLY_EXTRA_DIR=$NEUTRON_PATH/rally-jobs/extra


# Inject config from hook into localrc
function load_rc_hook {
    local hook="$1"
    config=$(cat $GATE_HOOKS/$hook)
    export DEVSTACK_LOCAL_CONFIG+="
# generated from hook '$hook'
[[local|localrc]]
${config}
"
}


# Inject config from hook into local.conf
function load_conf_hook {
    local hook="$1"
    config=$(cat $GATE_HOOKS/$hook)
    export DEVSTACK_LOCAL_CONFIG+="
# generated from hook '$hook'
${config}
"
}


# Tweak gate configuration for our rally scenarios
function load_rc_for_rally {
    for file in $(ls $RALLY_EXTRA_DIR/*.setup); do
        config=$(cat $file)
        export DEVSTACK_LOCAL_CONFIG+="
# generated from hook '$file'
${config}
"
    done
}


case $VENV in
"dsvm-functional"|"dsvm-fullstack")
    # The following need to be set before sourcing
    # configure_for_func_testing.
    GATE_STACK_USER=stack
    PROJECT_NAME=neutron
    IS_GATE=True

    source $DEVSTACK_PATH/functions
    source $NEUTRON_PATH/devstack/lib/ovs

    source $NEUTRON_PATH/tools/configure_for_func_testing.sh

    configure_host_for_func_testing

    # Kernel modules are not needed for functional job. They are needed only
    # for fullstack because of bug present in Ubuntu Xenial kernel version
    # that makes VXLAN local tunneling fail.
    if [[ "$VENV" =~ "dsvm-functional" ]]; then
        compile_modules=False
        NEUTRON_OVERRIDE_OVS_BRANCH=v2.5.1
    fi
    upgrade_ovs_if_necessary $compile_modules

    # prepare base environment for ./stack.sh
    load_rc_hook stack_base

    # enable monitoring
    load_rc_hook dstat

    # Since we don't use devstack-gate to deploy devstack services, we need to
    # dump DEVSTACK_LOCAL_CONFIG into local.conf ourselves. Note that we should
    # dump the file before changing the ownership
    echo "$DEVSTACK_LOCAL_CONFIG" > $LOCAL_CONF

    # Make the workspace owned by the stack user
    sudo chown -R $STACK_USER:$STACK_USER $BASE

    # deploy devstack as per local.conf
    cd $DEVSTACK_PATH && sudo -H -u $GATE_STACK_USER ./stack.sh
    ;;

"api"|"api-pecan"|"full-ovsfw"|"full-pecan"|"dsvm-scenario")
    load_rc_hook api_${FLAVOR}_extensions
    load_conf_hook quotas
    load_rc_hook dns
    load_rc_hook qos
    load_rc_hook trunk
    load_conf_hook mtu
    load_conf_hook osprofiler
    if [[ "$VENV" =~ "dsvm-scenario" ]]; then
        load_conf_hook iptables_verify
        load_rc_hook ubuntu_image
    fi
    if [[ "$VENV" =~ "pecan" ]]; then
        load_conf_hook pecan
    fi
    if [[ "$VENV" =~ "ovsfw" ]]; then
        load_conf_hook ovsfw
    fi

    $BASE/new/devstack-gate/devstack-vm-gate.sh
    ;;

"rally")
    load_rc_for_rally
    $BASE/new/devstack-gate/devstack-vm-gate.sh
    ;;

*)
    echo "Unrecognized environment $VENV".
    exit 1
esac
