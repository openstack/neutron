.. _config-mtu:

==================
MTU Considerations
==================

The Networking service uses the MTU of the underlying physical network to
calculate the MTU for virtual network components including instance network
interfaces. By default, it assumes a standard 1500-byte MTU for the
underlying physical network.

The Networking service only references the underlying physical network MTU.
Changing the underlying physical network device MTU requires configuration
of physical network devices such as switches and routers.

Jumbo frames
~~~~~~~~~~~~

The Networking service supports underlying physical networks using jumbo
frames and also enables instances to use jumbo frames minus any overlay
protocol overhead. For example, an underlying physical network with a
9000-byte MTU yields a 8950-byte MTU for instances using a VXLAN network
with IPv4 endpoints. Using IPv6 endpoints for overlay networks adds 20
bytes of overhead for any protocol.

The Networking service supports the following underlying physical network
architectures. Case 1 refers to the most common architecture. In general,
architectures should avoid cases 2 and 3.

.. note::

   After you adjust MTU configuration options in ``neutron.conf`` and
   ``ml2_conf.ini``, you should update ``mtu`` attribute for all existing
   networks that need a new MTU. (Network MTU update is available for all core
   plugins that implement the ``net-mtu-writable`` API extension.)

Case 1
------

For typical underlying physical network architectures that implement a single
MTU value, you can leverage jumbo frames using two options, one in the
``neutron.conf`` file and the other in the ``ml2_conf.ini`` file. Most
environments should use this configuration.

For example, referencing an underlying physical network with a 9000-byte MTU:

#. In the ``neutron.conf`` file:

   .. code-block:: ini

      [DEFAULT]
      global_physnet_mtu = 9000

#. In the ``ml2_conf.ini`` file:

   .. code-block:: ini

      [ml2]
      path_mtu = 9000

Case 2
------

Some underlying physical network architectures contain multiple layer-2
networks with different MTU values. You can configure each flat or VLAN
provider network in the bridge or interface mapping options of the layer-2
agent to reference a unique MTU value.

For example, referencing a 4000-byte MTU for ``provider2``, a 1500-byte
MTU for ``provider3``, and a 9000-byte MTU for other networks using the
Open vSwitch agent:

#. In the ``neutron.conf`` file:

   .. code-block:: ini

      [DEFAULT]
      global_physnet_mtu = 9000

#. In the ``openvswitch_agent.ini`` file:

   .. code-block:: ini

      [ovs]
      bridge_mappings = provider1:eth1,provider2:eth2,provider3:eth3

#. In the ``ml2_conf.ini`` file:

   .. code-block:: ini

      [ml2]
      physical_network_mtus = provider2:4000,provider3:1500
      path_mtu = 9000

Case 3
------

Some underlying physical network architectures contain a unique layer-2 network
for overlay networks using protocols such as VXLAN and GRE.

For example, referencing a 4000-byte MTU for overlay networks and a 9000-byte
MTU for other networks:

#. In the ``neutron.conf`` file:

   .. code-block:: ini

      [DEFAULT]
      global_physnet_mtu = 9000

#. In the ``ml2_conf.ini`` file:

   .. code-block:: ini

      [ml2]
      path_mtu = 4000

   .. note::

      Other networks including provider networks and flat or VLAN
      self-service networks assume the value of the ``global_physnet_mtu``
      option.

Instance network interfaces (VIFs)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The DHCP agent provides an appropriate MTU value to instances using IPv4,
while the L3 agent provides an appropriate MTU value to instances using
IPv6. IPv6 uses RA via the L3 agent because the DHCP agent only supports
IPv4. Instances using IPv4 and IPv6 should obtain the same MTU value
regardless of method.

.. note::

   If you are using an MTU value on your network below 1280, please
   read the warning listed in the
   `IPv6 configuration guide <./config-ipv6.html#project-network-considerations>`__
   before creating any subnets.

Networks with enabled vlan transparency
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In case of networks with enabled vlan transparency, if additional vlan tag is
configured inside guest VM, MTU has to be lowered by 4 bytes to make space for
additional vlan tag in the packet's header.
For example, if network's MTU is set to ``1500``, value configured for the
interfaces in the guest vm should be manually set to ``1496`` or less bytes.
