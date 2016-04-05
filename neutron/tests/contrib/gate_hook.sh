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

    if [[ "$VENV" =~ "dsvm-functional" ]]; then
        # The OVS_BRANCH variable is used by git checkout. In the case below
        # we use a commit on branch-2.5 that fixes compilation with the
        # latest ubuntu trusty kernel.
        OVS_BRANCH=8c0b419a0b9ac0141d6973dcc80306dfc6a83d31
        remove_ovs_packages
        compile_ovs True /usr /var
        start_new_ovs
    fi

    # Make the workspace owned by the stack user
    sudo chown -R $STACK_USER:$STACK_USER $BASE
    ;;

"api"|"api-pecan"|"full-pecan"|"dsvm-scenario")
    load_rc_hook api_extensions
    # NOTE(ihrachys): note the order of hook post-* sections is significant: [quotas] hook should
    # go before other hooks modifying [DEFAULT]. See LP#1583214 for details.
    load_conf_hook quotas
    load_conf_hook sorting
    load_conf_hook pagination
    load_rc_hook qos
    load_conf_hook osprofiler
    if [[ "$VENV" =~ "pecan" ]]; then
        load_conf_hook pecan
    fi

    $BASE/new/devstack-gate/devstack-vm-gate.sh
    ;;

*)
    echo "Unrecognized environment $VENV".
    exit 1
esac
