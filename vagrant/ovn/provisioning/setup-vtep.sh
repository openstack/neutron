#!/usr/bin/env bash
OVN_DB_IP=$2

cp neutron/devstack/ovn-vtep-local.conf.sample devstack/local.conf
if [ "$1" != "" ]; then
    sed -i -e 's/<IP address of host running everything else>/'$1'/g' devstack/local.conf
fi

# Get the IP address
if ip a | grep enp0 ; then
    ipaddress=$(ip -4 addr show enp0s8 | grep -oP "(?<=inet ).*(?=/)")
else
    ipaddress=$(ip -4 addr show eth1 | grep -oP "(?<=inet ).*(?=/)")
fi

# Adjust some things in local.conf
cat << DEVSTACKEOF >> devstack/local.conf

# Set this to the address of the main DevStack host running the rest of the
# OpenStack services.
Q_HOST=$1
HOST_IP=$ipaddress
HOSTNAME=$(hostname)

OVN_SB_REMOTE=tcp:$OVN_DB_IP:6642
OVN_NB_REMOTE=tcp:$OVN_DB_IP:6641

# Enable logging to files.
LOGFILE=/opt/stack/log/stack.sh.log
DEVSTACKEOF

devstack/stack.sh
