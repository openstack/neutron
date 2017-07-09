#!/usr/bin/env bash

set -ex

VENV=${1:-"dsvm-functional"}
FLAVOR=${2:-"all"}

GATE_DEST=$BASE/new
NEUTRON_PATH=$GATE_DEST/neutron
GATE_HOOKS=$NEUTRON_PATH/neutron/tests/contrib/hooks
DEVSTACK_PATH=$GATE_DEST/devstack
LOCAL_CONF=$DEVSTACK_PATH/late-local.conf
RALLY_EXTRA_DIR=$NEUTRON_PATH/rally-jobs/extra
DSCONF=/tmp/devstack-tools/bin/dsconf

# Install devstack-tools used to produce local.conf; we can't rely on
# test-requirements.txt because the gate hook is triggered before neutron is
# installed
sudo -H pip install virtualenv
virtualenv /tmp/devstack-tools
/tmp/devstack-tools/bin/pip install -U devstack-tools==0.4.0

# Inject config from hook into localrc
function load_rc_hook {
    local hook="$1"
    local tmpfile
    local config
    tmpfile=$(tempfile)
    config=$(cat $GATE_HOOKS/$hook)
    echo "[[local|localrc]]" > $tmpfile
    $DSCONF setlc_raw $tmpfile "$config"
    $DSCONF merge_lc $LOCAL_CONF $tmpfile
    rm -f $tmpfile
}


# Inject config from hook into local.conf
function load_conf_hook {
    local hook="$1"
    $DSCONF merge_lc $LOCAL_CONF $GATE_HOOKS/$hook
}


# Tweak gate configuration for our rally scenarios
function load_rc_for_rally {
    for file in $(ls $RALLY_EXTRA_DIR/*.setup); do
        tmpfile=$(tempfile)
        config=$(cat $file)
        echo "[[local|localrc]]" > $tmpfile
        $DSCONF setlc_raw $tmpfile "$config"
        $DSCONF merge_lc $LOCAL_CONF $tmpfile
        rm -f $tmpfile
    done
}


case $VENV in
"dsvm-functional"|"dsvm-fullstack"|"dsvm-functional-python35"|"dsvm-fullstack-python35")
    # The following need to be set before sourcing
    # configure_for_func_testing.
    GATE_STACK_USER=stack
    PROJECT_NAME=neutron
    IS_GATE=True
    LOCAL_CONF=$DEVSTACK_PATH/local.conf

    source $DEVSTACK_PATH/functions
    source $NEUTRON_PATH/devstack/lib/ovs

    source $NEUTRON_PATH/tools/configure_for_func_testing.sh

    configure_host_for_func_testing

    # Because of bug present in current Ubuntu Xenial kernel version
    # we need a fix for VXLAN local tunneling.
    if [[ "$VENV" =~ "dsvm-fullstack" ]]; then
        # The OVS_BRANCH variable is used by git checkout. In the case below,
        # we use v2.6.1 openvswitch tag that contains a fix for usage of VXLAN
        # tunnels on a single node and is compatible with Ubuntu Xenial kernel:
        # https://github.com/openvswitch/ovs/commit/741f47cf35df2bfc7811b2cff75c9bb8d05fd26f
        OVS_BRANCH="v2.6.1"
        compile_ovs_kernel_module
    fi

    # prepare base environment for ./stack.sh
    load_rc_hook stack_base

    # enable monitoring
    load_rc_hook dstat
    ;;

"api"|"api-pecan"|"full-ovsfw"|"full-pecan"|"dsvm-scenario-ovs"|"dsvm-scenario-linuxbridge")
    # TODO(ihrachys) consider feeding result of ext-list into tempest.conf
    load_rc_hook api_all_extensions
    if [ "${FLAVOR}" = "dvrskip" ]; then
        load_rc_hook disable_dvr_tests
    fi
    load_conf_hook quotas
    load_rc_hook dns
    load_rc_hook qos
    load_rc_hook segments
    load_rc_hook trunk
    load_conf_hook vlan_provider
    load_conf_hook osprofiler
    if [[ "$VENV" =~ "dsvm-scenario" ]]; then
        load_rc_hook ubuntu_image
    fi
    if [[ "$VENV" =~ "dsvm-scenario-linuxbridge" ]]; then
        load_conf_hook iptables_verify
    fi
    if [[ "$VENV" =~ "pecan" ]]; then
        load_conf_hook pecan
    fi
    if [[ "$VENV" =~ "ovs" ]]; then
        load_conf_hook ovsfw
    fi
    if [[ "$VENV" != "dsvm-scenario-linuxbridge" ]]; then
        load_conf_hook tunnel_types
    fi
    if [[ "$VENV" =~ "dsvm-scenario-linuxbridge" ]]; then
        # linuxbridge doesn't support gre
        load_conf_hook linuxbridge_type_drivers
    else
        load_conf_hook openvswitch_type_drivers
    fi
    if [[ "$FLAVOR" = "dvrskip" ]]; then
        load_conf_hook disable_dvr
    fi
    ;;

"rally")
    load_rc_for_rally
    ;;

*)
    echo "Unrecognized environment $VENV".
    exit 1
esac

export DEVSTACK_LOCALCONF=$(cat $LOCAL_CONF)
$BASE/new/devstack-gate/devstack-vm-gate.sh
