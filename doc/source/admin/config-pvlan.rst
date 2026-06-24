.. _config-pvlan:

====================
Private VLAN (PVLAN)
====================

Private VLAN (PVLAN) is a device isolation mechanism through the application of
forwarding constraints.

Every port on a PVLAN-enabled network is assigned one of three types:

- **Promiscuous** -- can communicate with any other port on the network. This
  is the default type assigned to ports when no ``pvlan_type`` is specified.
- **Isolated** -- can communicate only with promiscuous ports. Isolated ports
  cannot communicate with each other.
- **Community** -- can communicate with other ports in the same named community
  and with promiscuous ports. Requires a ``pvlan_community`` name.

.. _contributors internal documentation: https://docs.openstack.org/neutron/latest/contributor/internals/ovn/pvlan.html

For more details on how PVLAN works with the ML2/OVN driver, check the
`contributors internal documentation`_.


Service Configuration
~~~~~~~~~~~~~~~~~~~~~

PVLAN is supported from 2026.2. The minimum neutron-lib version to run this
feature is 3.25.0. To enable the PVLAN service, add ``pvlan`` to the
``service_plugins`` setting in ``/etc/neutron/neutron.conf``:

.. code-block:: ini

     service_plugins = router,metering,log,pvlan

.. warning::

   PVLAN requires port security to be enabled on both the network and the port.

.. note::

   Security groups are compatible with PVLAN ports and act as a layer below
   PVLAN.  Security group rules are immediately applied if PVLAN is disabled on
   the network.

How to use the PVLAN Service Plugin
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Create a PVLAN-enabled network
------------------------------

Create a network with the ``--pvlan`` flag:

.. code-block:: console

   $ openstack network create my-pvlan-net --pvlan

Create a subnet and attach it to a router as usual:

.. code-block:: console

   $ openstack subnet create --network my-pvlan-net --subnet-range 10.0.0.0/24 my-pvlan-sub
   $ openstack router add subnet my-router my-pvlan-sub


Create ports with PVLAN types
-----------------------------

Create ports with different PVLAN types:

.. code-block:: console

   $ openstack port create --network my-pvlan-net \
       --pvlan-type promiscuous my-promiscuous-port

   $ openstack port create --network my-pvlan-net \
       --pvlan-type isolated my-isolated-port

   $ openstack port create --network my-pvlan-net \
       --pvlan-type community --pvlan-community web my-community-port

If ``--pvlan-type`` is omitted on a PVLAN-enabled network, the port defaults to
promiscuous.

``--pvlan-community`` is required for ``--pvlan-type community`` and is not
allowed for any other PVLAN type.

Update a port's PVLAN type
--------------------------

A port's PVLAN type can be changed after creation:

.. code-block:: console

   $ openstack port set my-port --pvlan-type isolated

To change a port to a community type, specify both the type and community name:

.. code-block:: console

   $ openstack port set my-port --pvlan-type community --pvlan-community web


Set PVLAN on an existing network
--------------------------------

PVLAN can be enabled on an existing network. All existing ports on the network
will become promiscuous by default:

.. code-block:: console

   $ openstack network set my-existing-net --pvlan

Disabling PVLAN clears the ``pvlan_type`` from all ports on the network and
removes all associated OVN port groups and ACLs:

.. code-block:: console

   $ openstack network set my-pvlan-net --no-pvlan

Field Validation
~~~~~~~~~~~~~~~~

- Setting ``pvlan_type`` on a port whose network does not have ``pvlan=true``
  raises an error.
- Setting ``pvlan_type=community`` without providing ``pvlan_community`` raises
  an error. Setting ``pvlan_community`` on a non-community port (e.g.,
  isolated) also raises an error.
- Community names must start with a letter, underscore, or period, followed by
  up to 231 alphanumeric characters, underscores, or periods.
- Special ports like metadata ports will always be promiscuous.


