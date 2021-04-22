.. _ovn_sriov:

====================
SR-IOV guide for OVN
====================

The purpose of this page is to describe how SR-IOV works with OVN. Prior
to reading this document, it is recommended to first read :ref:`the
basic guide for SR-IOV<config-sriov>`.

External ports
~~~~~~~~~~~~~~

In order for SR-IOV to work with the
Neutron driver we are leveraging the `external ports
<https://github.com/ovn-org/ovn/commit/96080083581275afaec8bc281d6a648aff7ef39e>`_
feature from the OVN project. When virtual machines are booted
on hypervisors supporting SR-IOV nics, the local ovn-controllers are
unable to reply to the VM's DHCP, internal DNS, IPv6 router solicitation
requests, etc... since the hypervisor is bypassed in the SR-IOV case. OVN
then introduced the idea of having ``external`` ports which are able to
reply on behalf of those VM ports external to the hypervisor that they
are running on.

The OVN Neutron driver will create a port of the type ``external``
for ports with the following VNICs set:

* direct
* direct-physical
* macvtap

Also, ports of the type ``external`` will be scheduled on the gateway
nodes (controller or networker nodes) in HA mode by the OVN Neutron
driver. Check the `OVN Database information`_ section for more
information.

Environment setup for OVN SR-IOV
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

There are a very few differences between setting up an environment for
SR-IOV for the OVS and OVN Neutron drivers. As mentioned at the beginning
of this document, the instructions from the :ref:`the basic guide for
SR-IOV<config-sriov>` are required for getting SR-IOV working with the
OVN driver.

The only differences required for an OVN deployment are:

* When configuring the ``mechanism_drivers`` in the *ml2_conf.ini* file
  we should specify ``ovn`` driver instead of the ``openvswitch`` driver
* Disabling the Neutron DHCP agent
* Deploying the OVN Metadata agent on the gateway nodes (controller
  or networker nodes)


OVN Database information
~~~~~~~~~~~~~~~~~~~~~~~~

Before getting into the ports information, the previous sections
talks about **gateway nodes**, the OVN Neutron driver identifies
a gateway node by the ``ovn-cms-options=enable-chassis-as-gw`` and
``ovn-bridge-mappings`` options in the external_ids column from the
``Chassis`` table in the OVN Southbound database:

.. code-block:: bash

   $ ovn-sbctl list Chassis
   _uuid               : 12b13aff-a821-4cde-a4ac-d9cf8e2c91bc
   external_ids        : {ovn-cms-options=enable-chassis-as-gw, ovn-bridge-mappings="public:br-ex", ...}
   hostname            : controller-0
   name                : "1a462946-ccfd-46a6-8abf-9dca9eb558fb"
   ...

.. end

For more information about both of these options, please
take a look at the `ovn-controller documentation
<http://www.ovn.org/support/dist-docs/ovn-controller.8.html>`_.

These options can be set by running the following command locally on each
gateway node (note, the ``ovn-bridge-mappings`` will need to be adapted
to your environment):

.. code-block:: bash

   $ ovs-vsctl set Open_vSwitch . external-ids:ovn-cms-options=\"enable-chassis-as-gw\" external-ids:ovn-bridge-mappings=\"public:br-ex\"

.. end

As mentioned in the `External ports`_ section, every time a Neutron port
with a certain VNIC is created the OVN driver will create a port of the
type ``external`` in the OVN Northbound database. These ports can be
found by issuing the following command:

.. code-block:: bash

   $ ovn-nbctl find Logical_Switch_Port type=external
   _uuid               : 105e83ae-252d-401b-a1a7-8d28ec28a359
   ha_chassis_group    : [43047e7b-4c78-4984-9788-6263fcc69885]
   type                : external
   ...

.. end

The ``ha_chassis_group`` column indicates which HA Chassis Group that
port belongs to, to find that group do:

.. code-block:: bash

   # The UUID is the one from the ha_chassis_group column from
   # the Logical_Switch_Port table
   $ ovn-nbctl list HA_Chassis_Group 43047e7b-4c78-4984-9788-6263fcc69885
   _uuid               : 43047e7b-4c78-4984-9788-6263fcc69885
   external_ids        : {}
   ha_chassis          : [3005bf84-fc95-4361-866d-bfa1c980adc8, 72c7671e-dd48-4100-9741-c47221672961]
   name                : neutron-4b2944ca-c7a3-4cf6-a9c8-6aa541a20535

.. end

.. note::
  The external ports will be placed on a HA Chassis Group for the
  network that the port belongs to. Those HA Chassis Groups are named as
  ``neutron-<Neutron Network UUID>``, as seeing in the output above. You
  can also use this "name" with the ``ovn-nbctl list`` command when
  searching for a specific HA Chassis Group.

The chassis that are members of the HA Chassis Group are listed in
the ``ha_chassis`` column. Those are the gateway nodes (controller
or networker nodes) in the deployment and it's where the ``external``
ports will be scheduled. In order to find which gateway node the external
ports are scheduled on use the following command:

.. code-block:: bash

   # The UUIDs are the UUID members of the HA Chassis Group
   # (ha_chassis column from the HA_Chassis_Group table)
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

Note the ``priority`` column from the previous command, the chassis with
the highest ``priority`` from that list is the chassis that will have
the external ports scheduled on it. In our example above, the chassis
with the UUID ``1a462946-ccfd-46a6-8abf-9dca9eb558fb`` is the one.

Whenever the chassis with the highest priority goes down, the ports will
be automatically scheduled on the next chassis with the highest priority
which is alive. So, the external ports are HA out of the box.

Known limitations
~~~~~~~~~~~~~~~~~

The current SR-IOV implementation for the OVN Neutron driver has a few
known limitations that should be addressed in the future:

#. Routing on VLAN tenant network will not work with SR-IOV. This
   is because the external ports are not being co-located with
   the logical router's gateway ports, for more information take a look at
   `bug #1875852 <https://bugs.launchpad.net/neutron/+bug/1875852>`_.
