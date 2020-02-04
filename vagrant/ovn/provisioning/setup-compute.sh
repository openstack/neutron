#!/usr/bin/env bash

# Script Arguments:
# $1 - ovn-controller IP address
# $2 - ovn-db IP address
OVN_CONTROLLER_IP=$1
OVN_DB_IP=$2

cp neutron/devstack/ovn-compute-local.conf.sample devstack/local.conf
sed -i -e 's/<IP address of host running everything else>/'$OVN_CONTROLLER_IP'/g' devstack/local.conf

sudo umount /opt/stack/data/nova/instances

# Get the IP address
if ip a | grep enp0 ; then
    ipaddress=$(ip -4 addr show enp0s8 | grep -oP "(?<=inet ).*(?=/)")
else
    ipaddress=$(ip -4 addr show eth1 | grep -oP "(?<=inet ).*(?=/)")
fi

# Fixup HOST_IP with the local IP address
sed -i -e 's/<IP address of current host>/'$ipaddress'/g' devstack/local.conf

# Adjust some things in local.conf
cat << DEVSTACKEOF >> devstack/local.conf

# Set this to the address of the main DevStack host running the rest of the
# OpenStack services.
Q_HOST=$1
HOSTNAME=$(hostname)
OVN_SB_REMOTE=tcp:$OVN_DB_IP:6642
OVN_NB_REMOTE=tcp:$OVN_DB_IP:6641

# Enable logging to files.
LOGFILE=/opt/stack/log/stack.sh.log

# Use provider network for public.
Q_USE_PROVIDERNET_FOR_PUBLIC=True
OVS_PHYSICAL_BRIDGE=br-provider
PHYSICAL_NETWORK=provider

# Until OVN supports NAT, the private network IP address range
# must not conflict with IP address ranges on the host. Change
# as necessary for your environment.
NETWORK_GATEWAY=172.16.1.1
FIXED_RANGE=172.16.1.0/24

ENABLE_CHASSIS_AS_GW=False
DEVSTACKEOF

# Add unique post-config for DevStack here using a separate 'cat' with
# single quotes around EOF to prevent interpretation of variables such
# as $Q_DHCP_CONF_FILE.

cat << 'DEVSTACKEOF' >> devstack/local.conf

# Set the availablity zone name (default is nova) for the DHCP service.
[[post-config|$Q_DHCP_CONF_FILE]]
[AGENT]
availability_zone = nova
DEVSTACKEOF

devstack/stack.sh

# Build the provider network in OVN. You can enable instances to access
# external networks such as the Internet by using the IP address of the host
# vboxnet interface for the provider network (typically vboxnet1) as the
# gateway for the subnet on the neutron provider network. Also requires
# enabling IP forwarding and configuring SNAT on the host. See the README for
# more information.

source /vagrant/provisioning/provider-setup.sh

provider_setup

# Add host route for the private network, at least until the native L3 agent
# supports NAT.
# FIXME(mkassawara): Add support for IPv6.
source devstack/openrc admin admin
ROUTER_GATEWAY=`neutron port-list -c fixed_ips -c device_owner | grep router_gateway | awk -F'ip_address'  '{ print $2 }' | cut -f3 -d\"`
sudo ip route add $FIXED_RANGE via $ROUTER_GATEWAY

# NFS Setup
sudo apt-get update
sudo apt-get install -y nfs-common
sudo mkdir -p /opt/stack/data/nova/instances
sudo chmod o+x /opt/stack/data/nova/instances
sudo chown vagrant:vagrant /opt/stack/data/nova/instances
sudo sh -c "echo \"$OVN_CONTROLLER_IP:/opt/stack/data/nova/instances /opt/stack/data/nova/instances nfs defaults 0 0\" >> /etc/fstab"
sudo mount /opt/stack/data/nova/instances
sudo chown vagrant:vagrant /opt/stack/data/nova/instances
sudo sh -c "echo \"listen_tls = 0\" >> /etc/libvirt/libvirtd.conf"
sudo sh -c "echo \"listen_tcp = 1\" >> /etc/libvirt/libvirtd.conf"
sudo sh -c "echo -n \"auth_tcp =\" >> /etc/libvirt/libvirtd.conf"
sudo sh -c 'echo " \"none\"" >> /etc/libvirt/libvirtd.conf'
sudo sh -c "sed -i 's/env libvirtd_opts\=\"\-d\"/env libvirtd_opts\=\"-d -l\"/g' /etc/init/libvirt-bin.conf"
sudo sh -c "sed -i 's/libvirtd_opts\=\"\-d\"/libvirtd_opts\=\"\-d \-l\"/g' /etc/default/libvirt-bin"
sudo /etc/init.d/libvirt-bin restart

# Set the OVN_*_DB variables to enable OVN commands using a remote database.
echo -e "\n# Enable OVN commands using a remote database.
export OVN_NB_DB=$OVN_NB_REMOTE
export OVN_SB_DB=$OVN_SB_REMOTE" >> ~/.bash_profile
