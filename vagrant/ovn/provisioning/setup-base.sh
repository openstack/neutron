#!/bin/sh

# Script Arguments:
# $1 - MTU
# $2 - ovn-db IP address
# $3 - ovn-db short name
# $4 - ovn-controller IP address
# $5 - ovn-controller short name
# $6 - ovn-compute1 IP address
# $7 - ovn-compute1 short name
# $8 - ovn-compute2 IP address
# $9 - ovn-compute2 short name
# $10 - ovn-vtep IP address
# $11 - ovn-vtep short name
MTU=$1
OVN_DB_IP=$2
OVN_DB_NAME=$3
OVN_CONTROLLER_IP=$4
OVN_CONTROLLER_NAME=$5
OVN_COMPUTE1_IP=$6
OVN_COMPUTE1_NAME=$7
OVN_COMPUTE2_IP=$8
OVN_COMPUTE2_NAME=$9
OVN_VTEP_IP=$10
OVN_VTEP_NAME=$11

BASE_PACKAGES="git bridge-utils ebtables python-pip python-dev build-essential ntp"
DEBIAN_FRONTEND=noninteractive sudo apt-get -qqy update
DEBIAN_FRONTEND=noninteractive sudo apt-get install -qqy $BASE_PACKAGES
echo export LC_ALL=en_US.UTF-8 >> ~/.bash_profile
echo export LANG=en_US.UTF-8 >> ~/.bash_profile
# FIXME(mestery): Remove once Vagrant boxes allow apt-get to work again
sudo rm -rf /var/lib/apt/lists/*
sudo apt-get install -y git

# FIXME(mestery): By default, Ubuntu ships with /bin/sh pointing to
# the dash shell.
# ..
# ..
# The dots above represent a pause as you pick yourself up off the
# floor. This means the latest version of "install_docker.sh" to load
# docker fails because dash can't interpret some of it's bash-specific
# things. It's a bug in install_docker.sh that it relies on those and
# uses a shebang of /bin/sh, but that doesn't help us if we want to run
# docker and specifically Kuryr. So, this works around that.
sudo update-alternatives --install /bin/sh sh /bin/bash 100

if [ ! -d "devstack" ]; then
    git clone https://git.openstack.org/openstack-dev/devstack.git
fi

# If available, use repositories on host to facilitate testing local changes.
# Vagrant requires that shared folders exist on the host, so additionally
# check for the ".git" directory in case the parent exists but lacks
# repository contents.

if [ ! -d "neutron/.git" ]; then
    git clone https://git.openstack.org/openstack/neutron.git
fi

# Use neutron in vagrant home directory when stacking.
sudo mkdir /opt/stack
sudo chown vagrant:vagrant /opt/stack
ln -s ~/neutron /opt/stack/neutron

# We need swap space to do any sort of scale testing with the Vagrant config.
# Without this, we quickly run out of RAM and the kernel starts whacking things.
sudo rm -f /swapfile1
sudo dd if=/dev/zero of=/swapfile1 bs=1024 count=2097152
sudo chown root:root /swapfile1
sudo chmod 0600 /swapfile1
sudo mkswap /swapfile1
sudo swapon /swapfile1

# Configure MTU on VM interfaces. Also requires manually configuring the same MTU on
# the equivalent 'vboxnet' interfaces on the host.

if ip a | grep enp0; then
    sudo ip link set dev enp0s8 mtu $MTU
    sudo ip link set dev enp0s9 mtu $MTU
else
    sudo ip link set dev eth1 mtu $MTU
    sudo ip link set dev eth2 mtu $MTU
fi

# Migration setup
sudo sh -c "echo \"$OVN_DB_IP $OVN_DB_NAME\" >> /etc/hosts"
sudo sh -c "echo \"$OVN_CONTROLLER_IP $OVN_CONTROLLER_NAME\" >> /etc/hosts"
sudo sh -c "echo \"$OVN_COMPUTE1_IP $OVN_COMPUTE1_NAME\" >> /etc/hosts"
sudo sh -c "echo \"$OVN_COMPUTE2_IP $OVN_COMPUTE2_NAME\" >> /etc/hosts"
sudo sh -c "echo \"$OVN_VTEP_IP $OVN_VTEP_NAME\" >> /etc/hosts"

# Non-interactive SSH setup
cp neutron/vagrant/ovn/provisioning/id_rsa ~/.ssh/id_rsa
cat neutron/vagrant/ovn/provisioning/id_rsa.pub >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/id_rsa
echo "Host *" >> ~/.ssh/config
echo "    StrictHostKeyChecking no" >> ~/.ssh/config
chmod 600 ~/.ssh/config
sudo mkdir /root/.ssh
chmod 700 /root/.ssh
sudo cp ~vagrant/.ssh/id_rsa /root/.ssh
sudo cp ~vagrant/.ssh/authorized_keys /root/.ssh
sudo cp ~vagrant/.ssh/config /root/.ssh/config
