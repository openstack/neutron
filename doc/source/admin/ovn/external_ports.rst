.. _ovn_external_ports:

==================
OVN External Ports
==================

The purpose of this page is to describe how
ML2/OVN leverages the use of OVN's `external ports
<https://github.com/ovn-org/ovn/commit/96080083581275afaec8bc281d6a648aff7ef39e>`_
feature.

What is it
----------

The external ports feature in OVN allows for setting up a port that lives
externally to the instance and is reponsible for replying to ARP requests
(DHCP, internal DNS, IPv6 router solicitation requests, etc...) on its
behalf. At the moment this feature is used in two use cases for ML2/OVN:

1. :ref:`SR-IOV<ovn_sriov>`
2. :ref:`Baremetal provisioning<ovn_baremetal>`

ML2/OVN will create a port of the type ``external`` for ports with the
following VNICs:

* direct
* direct-physical
* macvtap
* baremetal

These ports can be listed in OVN with following command:

.. code-block:: bash

   $ ovn-nbctl find Logical_Switch_Port type=external
   _uuid               : 105e83ae-252d-401b-a1a7-8d28ec28a359
   ha_chassis_group    : [43047e7b-4c78-4984-9788-6263fcc69885]
   type                : external
   ...

.. end

The next section will talk more about the different configurations for
scheduling these ports and how they are represented in the OVN database.

Scheduling and database information
-----------------------------------

Ports of the type ``external`` will be scheduled on nodes
marked to host these type of ports via the `ovn-cms-options
<http://www.ovn.org/support/dist-docs/ovn-controller.8.html>`_
configuration. There are two supported configurations for these nodes:

1. ``enable-chassis-as-extport-host``
2. ``enable-chassis-as-gw``

These options can be set by running the following command locally on each
node that will act as a candidate to host these ports:

.. code-block:: bash

   $ ovs-vsctl set Open_vSwitch . external-ids:ovn-cms-options=\"enable-chassis-as-extport-host\"

   $ ovs-vsctl set Open_vSwitch . external-ids:ovn-cms-options=\"enable-chassis-as-gw\"

.. end

The sections below will explain the differences between the two
configuration values.

Configuration: ``enable-chassis-as-extport-host``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When nodes in the cluster are marked with the
``enable-chassis-as-extport-host`` configuration, the ML2/OVN driver
will schedule the external ports onto these nodes. This configuration
takes precedence over ``enable-chassis-as-gw``.

With this configuration, the ML2/OVN driver will create one
``HA_Chassis_Group`` per external port and it will be named as
``neutron-extport-<Neutron Port UUID>``. For example:

.. code-block:: bash

   $ ovn-sbctl list Chassis
   _uuid               : fa24d475-9664-4a62-bb1c-52a6fa4966f7
   external_ids        : {ovn-cms-options=enable-chassis-as-extport-host, ...}
   hostname            : compute-0
   name                : "6fd9cef6-4e9d-4bde-ab82-016c2461957b"
   ...
   _uuid               : a29ee8f6-5301-45f5-b280-a43e533d4d65
   external_ids        : {ovn-cms-options=enable-chassis-as-extport-host, ...}
   hostname            : compute-1
   name                : "4fa76c10-c6ea-4ae9-b31c-bc69103fe6f9"
   ...

.. end

.. code-block:: bash

   $ ovn-nbctl list HA_Chassis_Group neutron-extport-392a77f9-7c48-4ad0-bd06-8b55bba00bd1
   _uuid               : 1249b761-24e3-414e-ae10-7e880e9d3cf8
   external_ids        : {"neutron:availability_zone_hints"=""}
   ha_chassis          : [0d6b9718-7718-45d2-a838-1deb40131442, ae6e64e7-f948-49b3-a171-c9cfb58c8b31]
   name                : neutron-extport-392a77f9-7c48-4ad0-bd06-8b55bba00bd1

.. end

Also, for HA, there will be a limit of five Chassis per
``HA_Chassis_Group``, meaning that even if there are more nodes marked
with the ``enable-chassis-as-extport-host`` option, each group will
contain up to five members. This limit has been imposed because OVN uses
BFD to monitor the connectivity of each member in the group, and having
an unlimited number of members can potentially put a lot of stress on OVN.

In general, this option is used when there are specific requirements
for ``external`` ports and they can not be scheduled on controllers or
gateway nodes. The next configuration does the opposite and uses the
nodes marked as gateway to schedule the ``external`` ports.

Configuration: ``enable-chassis-as-gw``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For the majority of use cases where there are no special requirements
for the ``external`` ports and they can be co-located with gateway ports,
this configuration should be used.

Gateway nodes are identified by the
``enable-chassis-as-gw`` and `ovn-bridge-mappings
<http://www.ovn.org/support/dist-docs/ovn-controller.8.html>`_
configurations:

.. code-block:: bash

   $ ovn-sbctl list Chassis
   _uuid               : 12b13aff-a821-4cde-a4ac-d9cf8e2c91bc
   external_ids        : {ovn-cms-options=enable-chassis-as-gw, ovn-bridge-mappings="public:br-ex", ...}
   hostname            : controller-0
   name                : "1a462946-ccfd-46a6-8abf-9dca9eb558fb"
   ...

.. end

As mentioned in the `What is it`_ section, every time a Neutron port
with a certain VNIC is created the OVN driver will create a port of the
type ``external`` in the OVN Northbound database.

When the ``enable-chassis-as-gw`` configuration is used, the ML2/OVN
driver will create one ``HA_Chassis_Group`` per network (instead
of one per external port in the previous case) and it will be named as
``neutron-<Neutron Network UUID>``.

All ``external`` ports belonging to this network will share the same
``HA_Chassis_Group`` and the group is also limited to a maximum of five
members for HA.

.. code-block:: bash

   $ ovn-nbctl list HA_Chassis_Group
   _uuid               : 43047e7b-4c78-4984-9788-6263fcc69885
   external_ids        : {"neutron:availability_zone_hints"=""}
   ha_chassis          : [3005bf84-fc95-4361-866d-bfa1c980adc8, 72c7671e-dd48-4100-9741-c47221672961]
   name                : neutron-4b2944ca-c7a3-4cf6-a9c8-6aa541a20535

.. end

High availability
-----------------

As hinted above, the ML2/OVN driver does provide high availability to the
``external`` ports. This is done via the ``HA_Chassis_Group`` mechanism
from OVN.

On every ``external`` port there will be a column called
``ha_chassis_group`` which points to the ``HA_Chassis_Group`` that the
port belongs to:

.. code-block:: bash

  $ ovn-nbctl find logical_switch_port type=external
  ha_chassis_group    : 924fd0fe-3e84-4eaa-aa1d-41103ec511e5
  name                : "287040d6-0936-4363-ae0a-2d5a239e55fa"
  type                : external
  ...

.. end

In the ``HA_Chassis_Group``, the members of each group are listed in the
``ha_chassis`` column:

.. code-block:: bash

  $ ovn-nbctl list HA_Chassis_Group 924fd0fe-3e84-4eaa-aa1d-41103ec511e5
  _uuid               : 924fd0fe-3e84-4eaa-aa1d-41103ec511e5
  external_ids        : {"neutron:availability_zone_hints"=""}
  ha_chassis          : [3005bf84-fc95-4361-866d-bfa1c980adc8, 72c7671e-dd48-4100-9741-c47221672961]
  name                : neutron-extport-287040d6-0936-4363-ae0a-2d5a239e55fa

.. end

.. note::

  There will be a maximum of five members for each group, this limit
  has been imposed because OVN uses BFD to monitor the connectivity of
  each member in the group, and having an unlimited number of members
  can potentially put a lot of stress on OVN.

.. end

When listing the members of a group there will be a column called
``priority`` that contains a numerical value, the member with the highest
``priority`` is the chassis where the ports will be scheduled on. OVN
will monitor each member via BFD protocol, and if the chassis that is
hosting the ports goes down, the ports will be automatically scheduled
on the next chassis with the highest priority that is alive.

.. code-block:: bash

   $ ovn-nbctl list HA_Chassis 3005bf84-fc95-4361-866d-bfa1c980adc8 72c7671e-dd48-4100-9741-c47221672961
   _uuid               : 3005bf84-fc95-4361-866d-bfa1c980adc8
   chassis_name        : "1a462946-ccfd-46a6-8abf-9dca9eb558fb"
   external_ids        : {}
   priority            : 32767

   _uuid               : 72c7671e-dd48-4100-9741-c47221672961
   chassis_name        : "a0cb9d55-a6da-4f84-857f-d4b674088c8c"
   external_ids        : {}
   priority            : 32766

.. end

In the example above, the Chassis with the UUID
``1a462946-ccfd-46a6-8abf-9dca9eb558fb`` is the one that is hosting the
external port ``287040d6-0936-4363-ae0a-2d5a239e55fa``.
