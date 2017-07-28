.. _config-dvr-snat-ha-ovs:

=====================================
Distributed Virtual Routing with VRRP
=====================================

:ref:`deploy-ovs-ha-dvr` supports augmentation
using Virtual Router Redundancy Protocol (VRRP). Using this configuration,
virtual routers support both the ``--distributed`` and ``--ha`` options.

Similar to legacy HA routers, DVR/SNAT HA routers provide a quick fail over of
the SNAT service to a backup DVR/SNAT router on an l3-agent running on a
different node.

SNAT high availability is implemented in a manner similar to the
:ref:`deploy-lb-ha-vrrp` and :ref:`deploy-ovs-ha-vrrp` examples where
``keepalived`` uses VRRP to provide quick failover of SNAT services.

During normal operation, the master router periodically transmits *heartbeat*
packets over a hidden project network that connects all HA routers for a
particular project.

If the DVR/SNAT backup router stops receiving these packets, it assumes failure
of the master DVR/SNAT router and promotes itself to master router by
configuring IP addresses on the interfaces in the ``snat`` namespace. In
environments with more than one backup router, the rules of VRRP are followed
to select a new master router.

.. warning::

   There is a known bug with ``keepalived`` v1.2.15 and earlier which can
   cause packet loss when ``max_l3_agents_per_router`` is set to 3 or more.
   Therefore, we recommend that you upgrade to ``keepalived`` v1.2.16
   or greater when using this feature.

.. note::

   Experimental feature or incomplete documentation.


Configuration example
~~~~~~~~~~~~~~~~~~~~~

The basic deployment model consists of one controller node, two or more network
nodes, and multiple computes nodes.

Controller node configuration
-----------------------------

#. Add the following to ``/etc/neutron/neutron.conf``:

   .. code-block:: ini

      [DEFAULT]
      core_plugin = ml2
      service_plugins = router
      allow_overlapping_ips = True
      router_distributed = True
      l3_ha = True
      l3_ha_net_cidr = 169.254.192.0/18
      max_l3_agents_per_router = 3

   When the ``router_distributed = True`` flag is configured, routers created
   by all users are distributed. Without it, only privileged users can create
   distributed routers by using ``--distributed True``.

   Similarly, when the ``l3_ha = True`` flag is configured, routers created
   by all users default to HA.

   It follows that with these two flags set to ``True`` in the configuration
   file, routers created by all users will default to distributed HA routers
   (DVR HA).

   The same can explicitly be accomplished by a user with administrative
   credentials setting the flags in the :command:`neutron router-create`
   command:


   .. code-block:: console

      $ neutron router-create name-of-router --distributed=True --ha=True

   .. note::

      The *max_l3_agents_per_router* determine the number of backup
      DVR/SNAT routers which  will be instantiated.

#. Add the following to ``/etc/neutron/plugins/ml2/ml2_conf.ini``:

   .. code-block:: ini

      [ml2]
      type_drivers = flat,vxlan
      tenant_network_types = vxlan
      mechanism_drivers = openvswitch,l2population
      extension_drivers = port_security

      [ml2_type_flat]
      flat_networks = external

      [ml2_type_vxlan]
      vni_ranges = MIN_VXLAN_ID:MAX_VXLAN_ID

   Replace ``MIN_VXLAN_ID`` and ``MAX_VXLAN_ID`` with  VXLAN ID minimum and
   maximum values suitable for your environment.

   .. note::

      The first value in the ``tenant_network_types`` option becomes the
      default project network type when a regular user creates a network.

Network nodes
-------------

#. Configure the Open vSwitch agent. Add the following to
   ``/etc/neutron/plugins/ml2/openvswitch_agent.ini``:

   .. code-block:: ini

      [ovs]
      local_ip = TUNNEL_INTERFACE_IP_ADDRESS
      bridge_mappings = external:br-ex

      [agent]
      enable_distributed_routing = True
      tunnel_types = vxlan
      l2_population = True

   Replace ``TUNNEL_INTERFACE_IP_ADDRESS`` with the IP address of the interface
   that handles VXLAN project networks.

#. Configure the L3 agent. Add the following to ``/etc/neutron/l3_agent.ini``:

   .. code-block:: ini

      [DEFAULT]
      ha_vrrp_auth_password = password
      interface_driver = openvswitch
      external_network_bridge =
      agent_mode = dvr_snat

   .. note::

      The ``external_network_bridge`` option intentionally contains
      no value.

Compute nodes
-------------

#. Configure the Open vSwitch agent. Add the following to
   ``/etc/neutron/plugins/ml2/openvswitch_agent.ini``:

   .. code-block:: ini

      [ovs]
      local_ip = TUNNEL_INTERFACE_IP_ADDRESS
      bridge_mappings = external:br-ex

      [agent]
      enable_distributed_routing = True
      tunnel_types = vxlan
      l2_population = True

      [securitygroup]
      firewall_driver = neutron.agent.linux.iptables_firewall.OVSHybridIptablesFirewallDriver

#. Configure the L3 agent. Add the following to ``/etc/neutron/l3_agent.ini``:

   .. code-block:: ini

      [DEFAULT]
      interface_driver = openvswitch
      external_network_bridge =
      agent_mode = dvr

   Replace ``TUNNEL_INTERFACE_IP_ADDRESS`` with the IP address of the interface
   that handles VXLAN project networks.

Keepalived VRRP health check
----------------------------

.. include:: shared/keepalived-vrrp-healthcheck.txt

Known limitations
~~~~~~~~~~~~~~~~~

* Migrating a router from distributed only, HA only, or legacy to distributed
  HA is not supported at this time. The router must be created as distributed
  HA.
  The reverse direction is also not supported. You cannot reconfigure a
  distributed HA router to be only distributed, only HA, or legacy.

* There are certain scenarios where l2pop and distributed HA routers do not
  interact in an expected manner. These situations are the same that affect HA
  only routers and l2pop.
