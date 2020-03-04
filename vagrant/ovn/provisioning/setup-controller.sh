#!/usr/bin/env bash

# Script Arguments:
# $1 - ovn-db IP address
# $2 - provider network starting IP address
# $3 - provider network ending IP address
# $4 - provider network gateway
# $5 - provider network network
# $6 - ovn vm subnet
ovnip=$1
start_ip=$2
end_ip=$3
gateway=$4
network=$5
ovn_vm_subnet=$6


# Get the IP address
if ip a | grep enp0 ; then
    ipaddress=$(ip -4 addr show enp0s8 | grep -oP "(?<=inet ).*(?=/)")
else
    ipaddress=$(ip -4 addr show eth1 | grep -oP "(?<=inet ).*(?=/)")
fi

# Adjust some things in local.conf
cat << DEVSTACKEOF >> devstack/local.conf.vagrant

# Good to set these
HOST_IP=$ipaddress
HOSTNAME=$(hostname)
SERVICE_HOST_NAME=${HOST_NAME}
SERVICE_HOST=$ipaddress
OVN_SB_REMOTE=tcp:$ovnip:6642
OVN_NB_REMOTE=tcp:$ovnip:6641

# Enable logging to files.
LOGFILE=/opt/stack/log/stack.sh.log

# Disable the ovn-northd service on the controller node because the
# architecture includes a separate OVN database server.
disable_service ovn-northd

# Disable the ovn-controller service because the architecture lacks services
# on the controller node that depend on it.
disable_service ovn-controller

# Disable the ovn metadata agent.
disable_service neutron-ovn-metadata-agent

# Disable the nova compute service on the controller node because the
# architecture only deploys it on separate compute nodes.
disable_service n-cpu

# Disable cinder services and tempest to reduce deployment time.
disable_service c-api c-sch c-vol tempest

# Until OVN supports NAT, the private network IP address range
# must not conflict with IP address ranges on the host. Change
# as necessary for your environment.
NETWORK_GATEWAY=172.16.1.1
FIXED_RANGE=172.16.1.0/24

# Use provider network for public.
Q_USE_PROVIDERNET_FOR_PUBLIC=True
OVS_PHYSICAL_BRIDGE=br-provider
PHYSICAL_NETWORK=provider
PUBLIC_NETWORK_NAME=provider
PUBLIC_NETWORK_GATEWAY="$gateway"
PUBLIC_PHYSICAL_NETWORK=provider
PUBLIC_SUBNET_NAME=provider-v4
IPV6_PUBLIC_SUBNET_NAME=provider-v6
Q_FLOATING_ALLOCATION_POOL="start=$start_ip,end=$end_ip"
FLOATING_RANGE="$network"

# If the admin wants to enable this chassis to host gateway routers for
# external connectivity, then set ENABLE_CHASSIS_AS_GW to True.
# Then devstack will set ovn-cms-options with enable-chassis-as-gw
# in Open_vSwitch table's external_ids column
ENABLE_CHASSIS_AS_GW=True
DEVSTACKEOF

# Add unique post-config for DevStack here using a separate 'cat' with
# single quotes around EOF to prevent interpretation of variables such
# as $NEUTRON_CONF.

cat << 'DEVSTACKEOF' >> devstack/local.conf.vagrant

# Enable two DHCP agents per neutron subnet with support for availability
# zones. Requires two or more compute nodes.

[[post-config|/$NEUTRON_CONF]]
[DEFAULT]
network_scheduler_driver = neutron.scheduler.dhcp_agent_scheduler.AZAwareWeightScheduler
dhcp_load_type = networks
dhcp_agents_per_network = 2

# Configure the Compute service (nova) metadata API to use the X-Forwarded-For
# header sent by the Networking service metadata proxies on the compute nodes.

[[post-config|$NOVA_CONF]]
[DEFAULT]
use_forwarded_for = True
DEVSTACKEOF


sed '/#EXTRA_CONFIG/ r devstack/local.conf.vagrant' \
    neutron/devstack/ovn-local.conf.sample > devstack/local.conf


devstack/stack.sh

# Make the provider network shared and enable DHCP for its v4 subnet.
source devstack/openrc admin admin
neutron net-update --shared $PUBLIC_NETWORK_NAME
neutron subnet-update --enable_dhcp=True $PUBLIC_SUBNET_NAME

# NFS server setup
sudo apt-get update
sudo apt-get install -y nfs-kernel-server nfs-common
sudo mkdir -p /opt/stack/data/nova/instances
sudo touch /etc/exports
sudo sh -c "echo \"/opt/stack/data/nova/instances $ovn_vm_subnet(rw,sync,fsid=0,no_root_squash)\" >> /etc/exports"
sudo service nfs-kernel-server restart
sudo service nfs-idmapd restart

# Set the OVN_*_DB variables to enable OVN commands using a remote database.
echo -e "\n# Enable OVN commands using a remote database.
export OVN_NB_DB=$OVN_NB_REMOTE
export OVN_SB_DB=$OVN_SB_REMOTE" >> ~/.bash_profile

