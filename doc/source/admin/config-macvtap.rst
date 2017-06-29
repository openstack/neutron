.. _config-macvtap:

========================
Macvtap mechanism driver
========================

The Macvtap mechanism driver for the ML2 plug-in generally increases
network performance of instances.

Consider the following attributes of this mechanism driver to determine
practicality in your environment:

* Supports only instance ports. Ports for DHCP and layer-3 (routing)
  services must use another mechanism driver such as Linux bridge or
  Open vSwitch (OVS).

* Supports only untagged (flat) and tagged (VLAN) networks.

* Lacks support for security groups including basic (sanity) and
  anti-spoofing rules.

* Lacks support for layer-3 high-availability mechanisms such as
  Virtual Router Redundancy Protocol (VRRP) and Distributed Virtual
  Routing (DVR).

* Only compute resources can be attached via macvtap. Attaching other
  resources like DHCP, Routers and others is not supported. Therefore run
  either OVS or linux bridge in VLAN or flat mode on the controller node.

* Instance migration requires the same values for the
  ``physical_interface_mapping`` configuration option on each compute node.
  For more information, see
  `<https://bugs.launchpad.net/neutron/+bug/1550400>`_.

Prerequisites
~~~~~~~~~~~~~

You can add this mechanism driver to an existing environment using either
the Linux bridge or OVS mechanism drivers with only provider networks or
provider and self-service networks. You can change the configuration of
existing compute nodes or add compute nodes with the Macvtap mechanism
driver. The example configuration assumes addition of compute nodes with
the Macvtap mechanism driver to the :ref:`deploy-lb-selfservice` or
:ref:`deploy-ovs-selfservice` deployment examples.

Add one or more compute nodes with the following components:

* Three network interfaces: management, provider, and overlay.
* OpenStack Networking Macvtap layer-2 agent and any dependencies.

.. note::

   To support integration with the deployment examples, this content
   configures the Macvtap mechanism driver to use the overlay network
   for untagged (flat) or tagged (VLAN) networks in addition to overlay
   networks such as VXLAN. Your physical network infrastructure
   must support VLAN (802.1q) tagging on the overlay network.

Architecture
~~~~~~~~~~~~

The Macvtap mechanism driver only applies to compute nodes. Otherwise,
the environment resembles the prerequisite deployment example.

.. image:: figures/config-macvtap-compute1.png
   :alt: Macvtap mechanism driver - compute node components

.. image:: figures/config-macvtap-compute2.png
   :alt: Macvtap mechanism driver - compute node connectivity

Example configuration
~~~~~~~~~~~~~~~~~~~~~

Use the following example configuration as a template to add support for
the Macvtap mechanism driver to an existing operational environment.

Controller node
---------------

#. In the ``ml2_conf.ini`` file:

   * Add ``macvtap`` to mechanism drivers.

     .. code-block:: ini

        [ml2]
        mechanism_drivers = macvtap

   * Configure network mappings.

     .. code-block:: ini

        [ml2_type_flat]
        flat_networks = provider,macvtap

        [ml2_type_vlan]
        network_vlan_ranges = provider,macvtap:VLAN_ID_START:VLAN_ID_END

     .. note::

        Use of ``macvtap`` is arbitrary. Only the self-service deployment
        examples require VLAN ID ranges. Replace ``VLAN_ID_START`` and
        ``VLAN_ID_END`` with appropriate numerical values.

#. Restart the following services:

   * Server

Network nodes
-------------

No changes.

Compute nodes
-------------

#. Install the Networking service Macvtap layer-2 agent.

#. In the ``neutron.conf`` file, configure common options:

   .. include:: shared/deploy-config-neutron-common.txt

#. In the ``macvtap_agent.ini`` file, configure the layer-2 agent.

   .. code-block:: ini

      [macvtap]
      physical_interface_mappings = macvtap:MACVTAP_INTERFACE

      [securitygroup]
      firewall_driver = noop

   Replace ``MACVTAP_INTERFACE`` with the name of the underlying
   interface that handles Macvtap mechanism driver interfaces.
   If using a prerequisite deployment example, replace
   ``MACVTAP_INTERFACE`` with the name of the underlying interface
   that handles overlay networks. For example, ``eth1``.

#. Start the following services:

   * Macvtap agent

Verify service operation
------------------------

#. Source the administrative project credentials.
#. Verify presence and operation of the agents:

   .. code-block:: console

      $ openstack network agent list
      +--------------------------------------+--------------------+----------+-------------------+-------+-------+---------------------------+
      | ID                                   | Agent Type         | Host     | Availability Zone | Alive | State | Binary                    |
      +--------------------------------------+--------------------+----------+-------------------+-------+-------+---------------------------+
      | 31e1bc1b-c872-4429-8fc3-2c8eba52634e | Metadata agent     | compute1 | None              | True  | UP    | neutron-metadata-agent    |
      | 378f5550-feee-42aa-a1cb-e548b7c2601f | Open vSwitch agent | compute1 | None              | True  | UP    | neutron-openvswitch-agent |
      | 7d2577d0-e640-42a3-b303-cb1eb077f2b6 | L3 agent           | compute1 | nova              | True  | UP    | neutron-l3-agent          |
      | d5d7522c-ad14-4c63-ab45-f6420d6a81dd | Metering agent     | compute1 | None              | True  | UP    | neutron-metering-agent    |
      | e838ef5c-75b1-4b12-84da-7bdbd62f1040 | DHCP agent         | compute1 | nova              | True  | UP    | neutron-dhcp-agent        |
      +--------------------------------------+--------------------+----------+-------------------+-------+-------+---------------------------+

Create initial networks
-----------------------

This mechanism driver simply changes the virtual network interface driver
for instances. Thus, you can reference the ``Create initial networks``
content for the prerequisite deployment example.

Verify network operation
------------------------

This mechanism driver simply changes the virtual network interface driver
for instances. Thus, you can reference the ``Verify network operation``
content for the prerequisite deployment example.

Network traffic flow
~~~~~~~~~~~~~~~~~~~~

This mechanism driver simply removes the Linux bridge handling security
groups on the compute nodes. Thus, you can reference the network traffic
flow scenarios for the prerequisite deployment example.
