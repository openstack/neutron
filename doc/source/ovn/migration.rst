.. _ovn_migration:

Migration Strategy
==================

This document details an in-place migration strategy from ML2/OVS to ML2/OVN
in either ovs-firewall or ovs-hybrid mode for a TripleO OpenStack deployment.

For non TripleO deployments, please refer to the file ``migration/README.rst``
and the ansible playbook ``migration/migrate-to-ovn.yml``.

Overview
--------
The migration process is orchestrated through the shell script
ovn_migration.sh, which is provided with the OVN driver.

The administrator uses ovn_migration.sh to perform readiness steps
and migration from the undercloud node.
The readiness steps, such as host inventory production, DHCP and MTU
adjustments, prepare the environment for the procedure.

Subsequent steps start the migration via Ansible.

Plan for a 24-hour wait after the reduce-dhcp-t1 step to allow VMs to catch up
with the new MTU size from the DHCP server. The default neutron ML2/OVS
configuration has a dhcp_lease_duration of 86400 seconds (24h).

Also, if there are instances using static IP assignment, the administrator
should be ready to update the MTU of those instances to the new value of 8
bytes less than the ML2/OVS (VXLAN) MTU value. For example, the typical
1500 MTU network value that makes VXLAN tenant networks use 1450 bytes of MTU
will need to change to 1442 under Geneve. Or under the same overlay network,
a GRE encapsulated tenant network would use a 1458 MTU, but again a 1442 MTU
for Geneve.

If there are instances which use DHCP but don't support lease update during
the T1 period the administrator will need to reboot them to ensure that MTU
is updated inside those instances.


Steps for migration
-------------------

Perform the following steps in the overcloud/undercloud
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. Ensure that you have updated to the latest openstack/neutron version.

Perform the following steps in the undercloud
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. Install python-networking-ovn-migration-tool.

   .. code-block:: console

      # yum install python-networking-ovn-migration-tool

2. Create a working directory on the undercloud, and copy the ansible playbooks

   .. code-block:: console

      $ mkdir ~/ovn_migration
      $ cd ~/ovn_migration
      $ cp -rfp /usr/share/ansible/networking-ovn-migration/playbooks .

3. Create  ``~/overcloud-deploy-ovn.sh`` script in your ``$HOME``.
   This script must source your stackrc file, and then execute an ``openstack
   overcloud deploy`` with your original deployment parameters, plus
   the following environment files, added to the end of the command
   in the following order:

   When your network topology is DVR and your compute nodes have connectivity
   to the external network:

   .. code-block:: none

      -e /usr/share/openstack-tripleo-heat-templates/environments/services/neutron-ovn-dvr-ha.yaml \
      -e $HOME/ovn-extras.yaml

   When your compute nodes don't have external connectivity and you don't use
   DVR:

   .. code-block:: none

      -e /usr/share/openstack-tripleo-heat-templates/environments/services/neutron-ovn-ha.yaml \
      -e $HOME/ovn-extras.yaml

   Make sure that all users have execution privileges on the script, because it
   will be called by ovn_migration.sh/ansible during the migration process.

   .. code-block:: console

      $ chmod a+x ~/overcloud-deploy-ovn.sh

4. To configure the parameters of your migration you can set the environment
   variables that will be used by ``ovn_migration.sh``. You can skip setting
   any values matching the defaults.

   * STACKRC_FILE - must point to your stackrc file in your undercloud.
     Default:  ~/stackrc

   * OVERCLOUDRC_FILE - must point to your overcloudrc file in your
     undercloud.
     Default: ~/overcloudrc

   * OVERCLOUD_OVN_DEPLOY_SCRIPT - must point to the script described in
     step 1.
     Default: ~/overcloud-deploy-ovn.sh

   * UNDERCLOUD_NODE_USER - user used on the undercloud nodes
     Default: heat-admin

   * STACK_NAME - Name or ID of the heat stack
     Default: 'overcloud'
     If the stack that is migrated differs from the default, please set this
     environment variable to the stack name or ID.

   * PUBLIC_NETWORK_NAME - Name of your public network.
     Default: 'public'.
     To support migration validation, this network must have available
     floating IPs, and those floating IPs must be pingable from the
     undercloud. If that's not possible please configure VALIDATE_MIGRATION
     to False.

   * OOO_WORKDIR - Name of TripleO working directory
     Default: '$HOME/overcloud-deploy'
     This directory contains different stacks in TripleO and its files. It
     should be configured if TripleO commands were invoked with --work-dir
     option.

   * IMAGE_NAME - Name/ID of the glance image to us for booting a test server.
     Default:'cirros'.
     If the image does not exist it will automatically download and use
     cirros during the pre-validation / post-validation process.

   * VALIDATE_MIGRATION - Create migration resources to validate the
     migration. The migration script, before starting the migration, boot a
     server and validates that the server is reachable after the migration.
     Default: False

   * SERVER_USER_NAME - User name to use for logging into the migration
     instances.
     Default: 'cirros'.

   * DHCP_RENEWAL_TIME - DHCP renewal time in seconds to configure in DHCP
     agent configuration file. This renewal time is used only temporarily
     during migration to ensure a synchronized MTU switch across the networks.
     Default: 30

   * CREATE_BACKUP - Flag to create a backup of the controllers that can be
     used as a revert mechanism.
     Default: True

   * BACKUP_MIGRATION_IP - Only used if CREATE_BACKUP is enabled, IP of the
     server that will be used as a NFS server to store the backup.
     Default: 192.168.24.1

   .. warning::

      Please note that VALIDATE_MIGRATION requires enough quota (2
      available floating ips, 2 networks, 2 subnets, 2 instances,
      and 2 routers as admin).

   For example:

   .. code-block:: console

      $ export PUBLIC_NETWORK_NAME=my-public-network
      $ ovn_migration.sh .........

5. Run ``ovn_migration.sh generate-inventory`` to generate the inventory
   file - ``hosts_for_migration`` and ``ansible.cfg``. Please review
   ``hosts_for_migration`` for correctness.

   .. code-block:: console

      $ ovn_migration.sh generate-inventory


   At this step the script will inspect the TripleO ansible inventory
   and generate an inventory of hosts, specifically tagged to work
   with the migration playbooks.


6. Run ``ovn_migration.sh reduce-dhcp-t1``

   .. code-block:: console

      $ ovn_migration.sh reduce-dhcp-t1


   This lowers the T1 parameter
   of the internal neutron DHCP servers configuring the ``dhcp_renewal_time``
   in /var/lib/config-data/puppet-generated/neutron/etc/neutron/dhcp_agent.ini
   in all the nodes where DHCP agent is running.

   We lower the T1 parameter to make sure that the instances start refreshing
   the DHCP lease quicker (every 30 seconds by default) during the migration
   proccess. The reason why we force this is to make sure that the MTU update
   happens quickly across the network during step 8, this is very important
   because during those 30 seconds there will be connectivity issues with
   bigger packets (MTU missmatchess across the network), this is also why
   step 7 is very important, even though we reduce T1, the previous T1 value
   the instances leased from the DHCP server will be much higher
   (24h by default) and we need to wait those 24h to make sure they have
   updated T1. After migration the DHCP T1 parameter returns to normal values.

7. If you are using VXLAN or GRE tenant networking, ``wait at least 24 hours``
   before continuing. This will allow VMs to catch up with the new MTU size
   of the next step.

   .. warning::

      If you are using VXLAN or GRE networks, this 24-hour wait step is critical.
      If you are using VLAN tenant networks you can proceed to the next step without delay.

   .. warning::

      If you have any instance with static IP assignment on VXLAN or
      GRE tenant networks, you must manually modify the configuration of those instances.
      If your instances don't honor the T1 parameter of DHCP they will need
      to be rebooted.
      to configure the new geneve MTU, which is the current VXLAN MTU minus 8 bytes.
      For instance, if the VXLAN-based MTU was 1450, change it to 1442.

   .. note::

      24 hours is the time based on default configuration. It actually depends on
      /var/lib/config-data/puppet-generated/neutron/etc/neutron/dhcp_agent.ini
      dhcp_renewal_time and
      /var/lib/config-data/puppet-generated/neutron/etc/neutron/neutron.conf
      dhcp_lease_duration parameters. (defaults to 86400 seconds)

   .. note::

      Please note that migrating a deployment which uses VLAN for tenant/project
      networks is not recommended at this time because of a bug in core ovn,
      full support is being worked out here:
      https://mail.openvswitch.org/pipermail/ovs-dev/2018-May/347594.html


   One way to verify that the T1 parameter has propagated to existing VMs
   is to connect to one of the compute nodes, and run ``tcpdump`` over one
   of the VM taps attached to a tenant network. If T1 propegation was a success,
   you should see that requests happen on an interval of approximately 30 seconds.

   .. code-block:: shell

      [heat-admin@overcloud-novacompute-0 ~]$ sudo tcpdump -i tap52e872c2-e6 port 67 or port 68 -n
      tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
      listening on tap52e872c2-e6, link-type EN10MB (Ethernet), capture size 262144 bytes
      13:17:28.954675 IP 192.168.99.5.bootpc > 192.168.99.3.bootps: BOOTP/DHCP, Request from fa:16:3e:6b:41:3d, length 300
      13:17:28.961321 IP 192.168.99.3.bootps > 192.168.99.5.bootpc: BOOTP/DHCP, Reply, length 355
      13:17:56.241156 IP 192.168.99.5.bootpc > 192.168.99.3.bootps: BOOTP/DHCP, Request from fa:16:3e:6b:41:3d, length 300
      13:17:56.249899 IP 192.168.99.3.bootps > 192.168.99.5.bootpc: BOOTP/DHCP, Reply, length 355

   .. note::

      This verification is not possible with cirros VMs. The cirros
      udhcpc implementation does not obey DHCP option 58 (T1). Please
      try this verification on a port that belongs to a full linux VM.
      We recommend you to check all the different types of workloads your
      system runs (Windows, different flavors of linux, etc..).

8. Run ``ovn_migration.sh reduce-mtu``.

   This lowers the MTU of the pre migration VXLAN and GRE networks. The
   tool will ignore non-VXLAN/GRE networks, so if you use VLAN for tenant
   networks it will be fine if you find this step not doing anything.

   .. code-block:: console

      $ ovn_migration.sh reduce-mtu

   This step will go network by network reducing the MTU, and tagging with
   ``adapted_mtu`` the networks which have been already handled.

   Every time a network is updated all the existing L3/DHCP agents
   connected to such network will update their internal leg MTU, instances
   will start fetching the new MTU as the DHCP T1 timer expires. As explained
   before, instances not obeying the DHCP T1 parameter will need to be
   restarted, and instances with static IP assignment will need to be manually
   updated.


9. Make TripleO ``prepare the new container images`` for OVN.

   If your deployment didn't have a containers-prepare-parameter.yaml, you can
   create one with:

   .. code-block:: console

       $ test -f $HOME/containers-prepare-parameter.yaml || \
             openstack tripleo container image prepare default \
                   --output-env-file $HOME/containers-prepare-parameter.yaml


   If you had to create the file, please make sure it's included at the end of
   your $HOME/overcloud-deploy-ovn.sh and $HOME/overcloud-deploy.sh

   Change the neutron_driver in the containers-prepare-parameter.yaml file to
   ovn:

   .. code-block:: console

      $ sed -i -E 's/neutron_driver:([ ]\w+)/neutron_driver: ovn/' $HOME/containers-prepare-parameter.yaml

   You can verify with:

   .. code-block:: shell

      $ grep neutron_driver $HOME/containers-prepare-parameter.yaml
      neutron_driver: ovn


   Then update the images:

   .. code-block:: console

      $ openstack tripleo container image prepare \
           --environment-file $HOME/containers-prepare-parameter.yaml

   .. note::

      It's important to provide the full path to your containers-prepare-parameter.yaml
      otherwise the command will finish very quickly and won't work (current
      version doesn't seem to output any error).


   During this step TripleO will build a list of containers, pull them from
   the remote registry and push them to your deployment local registry.


10. Run ``ovn_migration.sh start-migration`` to kick start the migration
    process.

    .. code-block:: console

       $ ovn_migration.sh start-migration


    During this step, this is what will happen:

    * Create pre-migration resources (network and VM) to validate existing
      deployment and final migration.

    * Update the overcloud stack to deploy OVN alongside reference
      implementation services using a temporary bridge "br-migration" instead
      of br-int.

    * Start the migration process:

      1. generate the OVN north db by running neutron-ovn-db-sync util
      2. clone the existing resources from br-int to br-migration, so OVN
         can find the same resources UUIDS over br-migration
      3. re-assign ovn-controller to br-int instead of br-migration
      4. cleanup network namespaces (fip, snat, qrouter, qdhcp),
      5. remove any unnecessary patch ports on br-int
      6. remove br-tun and br-migration ovs bridges
      7. delete qr-*, ha-* and qg-* ports from br-int (via neutron netns
         cleanup)

    * Delete neutron agents and neutron HA internal networks from the database
      via API.

    * Validate connectivity on pre-migration resources.

    * Delete pre-migration resources.

    * Create post-migration resources.

    * Validate connectivity on post-migration resources.

    * Cleanup post-migration resources.

    * Re-run deployment tool to update OVN on br-int, this step ensures
      that the TripleO database is updated with the final integration bridge.

    * Run an extra validation round to ensure the final state of the system is
      fully operational.

Migration is complete !!!
