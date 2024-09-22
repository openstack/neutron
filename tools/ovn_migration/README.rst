Migration from ML2/OVS to ML2/OVN
=================================

Proof-of-concept ansible script for migrating an OpenStack deployment
that uses ML2/OVS to OVN.

Prerequisites:

1. Ansible 2.2 or greater.

2. ML2/OVS must be using the OVS firewall driver.

To use:

1. Create an ansible inventory with the expected set of groups and variables
   as indicated by the hosts-sample file.

2. Run the playbook::

   $ ansible-playbook migrate-to-ovn.yml -i hosts

Testing Status:

- Tested on an RDO cloud on CentOS 7.3 based on Ocata.
- The cloud had 3 controller nodes and 6 compute nodes.
- Observed network downtime was 10 seconds.
- The "--forks 10" option was used with ansible-playbook to ensure
  that commands could be run across the entire environment in parallel.

MTU:

- If migrating an ML2/OVS deployment using VXLAN tenant networks
  to an OVN deployment using Geneve for tenant networks, we have
  an unresolved issue around MTU.  The VXLAN overhead is 30 bytes.
  OVN with Geneve has an overhead of 38 bytes.  We need the tenant
  networks MTU adjusted for OVN and then we need all VMs to receive
  the updated MTU value through DHCP before the migration can take
  place.  For testing purposes, we've just hacked the Neutron code
  to indicate that the VXLAN overhead was 38 bytes instead of 30,
  bypassing the issue at migration time.
