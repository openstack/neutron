#!/bin/bash

function provider_setup {
    # Save the existing address from eth2 and add it to br-provider

    if ip a | grep enp0; then
        PROV_IF=enp0s9
    else
        PROV_IF=eth2
    fi

    PROVADDR=$(ip -4 addr show $PROV_IF | grep -oP "(?<=inet ).*(?= brd)")
    if [ -n "$PROVADDR" ]; then
        sudo ip addr flush dev $PROV_IF
        sudo ip addr add $PROVADDR dev br-provider
        sudo ip link set br-provider up
        sudo ovs-vsctl --may-exist add-port br-provider $PROV_IF
    fi
}
