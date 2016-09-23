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

    if is_kernel_supported_for_ovs25; then
        # The OVS_BRANCH variable is used by git checkout. In the case below,
        # we use a current (2016-08-19) HEAD commit from branch-2.5 that contains
        # a fix for usage of VXLAN tunnels on a single node:
        # https://github.com/openvswitch/ovs/commit/741f47cf35df2bfc7811b2cff75c9bb8d05fd26f
        OVS_BRANCH=042326c3fcf61e8638fa15926f984ce5ae142f4b
        remove_ovs_packages
        compile_ovs True /usr /var
        start_new_ovs
    fi

    load_conf_hook iptables_verify
    # Make the workspace owned by the stack user
    sudo chown -R $STACK_USER:$STACK_USER $BASE
    ;;

"api"|"api-pecan"|"full-pecan"|"dsvm-scenario")
    load_rc_hook api_extensions
    # NOTE(ihrachys): note the order of hook post-* sections is significant: [quotas] hook should
    # go before other hooks modifying [DEFAULT]. See LP#1583214 for details.
    load_conf_hook quotas
    load_rc_hook dns
    load_rc_hook qos
    load_rc_hook trunk
    load_conf_hook osprofiler
    if [[ "$VENV" =~ "dsvm-scenario" ]]; then
        load_conf_hook iptables_verify
    fi
    if [[ "$VENV" =~ "pecan" ]]; then
        load_conf_hook pecan
    fi

    $BASE/new/devstack-gate/devstack-vm-gate.sh
    ;;

*)
    echo "Unrecognized environment $VENV".
    exit 1
esac
