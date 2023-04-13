Infrared plugin to carry out migration from ML2/OVS to OVN
==========================================================

This is an infrared plugin which can be used to carry out the migration
from ML2/OVS to OVN if the tripleo was deployed using infrared.
See http://infrared.readthedocs.io/en/stable/index.html for more information.

Before using this plugin, first deploy an ML2/OVS overcloud and then:

1. On your undercloud, install openstack-neutron-ovn-migration-tool package (https://trunk.rdoproject.org/centos9-master/component/network/current/)
   You also need to install python3-neutron and python3-openvswitch packages.

2. Run ::
   $infrared plugin add "https://opendev.org/openstack/neutron.git"

3. Start migration by running::

   $infrared  tripleo-ovn-migration  --version 13|14 \
--registry-namespace <REGISTRY_NAMESPACE> \
--registry-tag <TAG> \
--registry-prefix <PREFIX>

Using this as a standalone playbook for tripleo deployments
===========================================================
It is also possible to use the playbook main.yml with tripleo deployments.
In order to use this:

1. Create hosts inventory file like below
[undercloud]
undercloud_ip ansible_ssh_user=stack

2. Run the playbook as:
ansible-playbook main.yml  -i hosts -e install_from_package=True  -e registry_prefix=centos-binary -e registry_namespace=docker.io/tripleomaster  -e registry_localnamespace=192.168.24.1:8787/tripleomaster -e registry_tag=current-tripleo-rdo
