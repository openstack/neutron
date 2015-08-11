#!/usr/bin/env bash

set -ex

venv=${1:-"dsvm-functional"}
GATE_DEST=$BASE/new
DEVSTACK_PATH=$GATE_DEST/devstack

if [ "$venv" == "dsvm-functional" ]
then
    # The following need to be set before sourcing
    # configure_for_func_testing.
    GATE_STACK_USER=stack
    NEUTRON_PATH=$GATE_DEST/neutron
    IS_GATE=True

    source $NEUTRON_PATH/tools/configure_for_func_testing.sh

    # Make the workspace owned by the stack user
    sudo chown -R $STACK_USER:$STACK_USER $BASE

    configure_host_for_func_testing $STACK_USER
elif [ "$venv" == "api" ]
then
    cat > $DEVSTACK_PATH/local.conf <<EOF
[[post-config|/etc/neutron/neutron_lbaas.conf]]

[service_providers]
service_provider=LOADBALANCER:Haproxy:neutron_lbaas.services.loadbalancer.drivers.haproxy.plugin_driver.HaproxyOnHostPluginDriver:default

[[post-config|/etc/neutron/neutron_vpnaas.conf]]

[service_providers]
service_provider=VPN:openswan:neutron_vpnaas.services.vpn.service_drivers.ipsec.IPsecVPNDriver:default

EOF

    export DEVSTACK_LOCAL_CONFIG+="
enable_plugin neutron-vpnaas git://git.openstack.org/openstack/neutron-vpnaas
"

    $BASE/new/devstack-gate/devstack-vm-gate.sh
fi
