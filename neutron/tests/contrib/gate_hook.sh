#!/usr/bin/env bash

set -ex

VENV=${1:-"dsvm-functional"}

GATE_DEST=$BASE/new
DEVSTACK_PATH=$GATE_DEST/devstack

if [ "$VENV" == "dsvm-functional" ] || [ "$VENV" == "dsvm-fullstack" ]
then
    # The following need to be set before sourcing
    # configure_for_func_testing.
    GATE_STACK_USER=stack
    NEUTRON_PATH=$GATE_DEST/neutron
    PROJECT_NAME=neutron
    IS_GATE=True

    source $NEUTRON_PATH/tools/configure_for_func_testing.sh

    # Make the workspace owned by the stack user
    sudo chown -R $STACK_USER:$STACK_USER $BASE

    configure_host_for_func_testing
elif [ "$VENV" == "api" ]
then
    cat > $DEVSTACK_PATH/local.conf <<EOF
[[post-config|/etc/neutron/neutron_vpnaas.conf]]

[service_providers]
service_provider=VPN:openswan:neutron_vpnaas.services.vpn.service_drivers.ipsec.IPsecVPNDriver:default

EOF

    export DEVSTACK_LOCAL_CONFIG+="
enable_plugin neutron-vpnaas git://git.openstack.org/openstack/neutron-vpnaas
enable_plugin neutron git://git.openstack.org/openstack/neutron
"

    $BASE/new/devstack-gate/devstack-vm-gate.sh
fi
