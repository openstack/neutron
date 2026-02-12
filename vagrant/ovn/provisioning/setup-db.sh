#!/usr/bin/env bash
CONTROLLER_IP=$1

cp neutron/devstack/ovn-db-local.conf.sample devstack/local.conf
if [ "$CONTROLLER_IP" != "" ]; then
    sed -i -e 's/<IP address of host running everything else>/'$CONTROLLER_IP'/g' devstack/local.conf
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
Q_HOST=$CONTROLLER_IP
HOST_IP=$ipaddress
HOSTNAME=$(hostname)

# Enable logging to files.
LOGFILE=/opt/stack/log/stack.sh.log
DEVSTACKEOF

devstack/stack.sh
