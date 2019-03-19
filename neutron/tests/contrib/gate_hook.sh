#!/usr/bin/env bash

set -ex

VENV=${1:-"api"}
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
    tmpfile=$(mktemp)
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
        tmpfile=$(mktemp)
        config=$(cat $file)
        echo "[[local|localrc]]" > $tmpfile
        $DSCONF setlc_raw $tmpfile "$config"
        $DSCONF merge_lc $LOCAL_CONF $tmpfile
        rm -f $tmpfile
    done
}


case $VENV in
"api"|"api-pecan"|"full-pecan"|"dsvm-scenario-ovs")
    # TODO(ihrachys) consider feeding result of ext-list into tempest.conf
    load_rc_hook api_all_extensions
    if [ "${FLAVOR}" = "dvrskip" ]; then
        load_rc_hook disable_dvr_tests
    fi
    load_conf_hook quotas
    load_rc_hook uplink_status_propagation
    load_rc_hook dns
    load_rc_hook qos
    load_rc_hook segments
    load_rc_hook trunk
    load_rc_hook network_segment_range
    load_conf_hook vlan_provider
    load_conf_hook osprofiler
    load_conf_hook availability_zone
    load_conf_hook tunnel_types
    load_rc_hook log  # bug 1743463
    load_conf_hook openvswitch_type_drivers
    if [[ "$VENV" =~ "dsvm-scenario" ]]; then
        load_rc_hook ubuntu_image
    fi
    if [[ "$VENV" =~ "pecan" ]]; then
        load_conf_hook pecan
    fi
    if [[ "$FLAVOR" = "dvrskip" ]]; then
        load_conf_hook disable_dvr
    fi
    if [[ "$VENV" =~ "dsvm-scenario-ovs" ]]; then
        load_conf_hook dvr
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
