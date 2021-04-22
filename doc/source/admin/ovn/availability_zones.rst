.. _ovn_availability_zones:

================================
Availability Zones guide for OVN
================================

The purpose of this page is to describe how the availability zones works
with OVN. Prior to reading this document, it is recommended to first
read :ref:`ML2/OVS driver Availability Zones guide<config-az>`.

There are two types of availability zones available in Neutron: Router
and Network. For ML2/OVS, this is related to the scheduling of the L3
agent and DHCP agent respectively. For ML2/OVN, it's about the scheduling
of logical router ports and "external" ports respectively.

More details about each type of availability zones can be found later
in this document but first let's go over the common parts between them:

How to configure it
-------------------

Different from the ML2/OVS driver for Neutron the availability zones for
the OVN driver is not configured via a configuration file. Since ML2/OVN
does not rely on an external agent such as the L3 agent, certain nodes
(e.g gateway/networker node) won't have any Neutron configuration file
present. For this reason, OVN uses the local OVSDB for configuring the
availability zones that instance of ``ovn-controller`` running on that
hypervisor belongs to.

The configuration is done via the ``ovn-cms-options`` entry in
*external_ids* column of the local *Open_vSwitch* table:

.. code-block:: bash

   $ ovs-vsctl set Open_vSwitch . external-ids:ovn-cms-options="enable-chassis-as-gw,availability-zones=az-0:az-1:az-2"

.. end

The above command is adding two configurations to the ``ovn-cms-options``
option, the ``enable-chassis-as-gw`` option which tells the OVN driver
that this is a gateway/networker node and the ``availability-zones``
option specifying three availability zones: **az-0**, **az-1** and
**az-2**.

.. note::

   Specifying the "enable-chassis-as-gw" option is not required for the
   Availability Zones **however** ML2/OVN will only consider nodes that
   are gateway (the ones with the "enable-chassis-as-gw" option) when
   scheduling both ``router`` and ``external`` ports. So, even tho the
   "availability-zones" option can be set own their own, the ML2/OVN
   driver does not have a use case for it at the moment.

.. end

Note that, the syntax used to specify the availability zones is the
``availability-zones`` word, followed by an equal sign (=) and a
**colon** separated list of the availability zones that this local
``ovn-controller`` instance belongs to.

To confirm the specific ``ovn-controller`` availability zones, check the
**Availability Zone** column in the output of the command below:

.. code-block:: bash

   $ openstack network agent list
   +--------------------------------------+------------------------------+----------------+-------------------+-------+-------+----------------+
   | ID                                   | Agent Type                   | Host           | Availability Zone | Alive | State | Binary         |
   +--------------------------------------+------------------------------+----------------+-------------------+-------+-------+----------------+
   | 2d1924b2-99a4-4c6c-a4f2-0be64c0cec8c | OVN Controller Gateway agent | gateway-host-0 | az0, az1, az2     | :-)   | UP    | ovn-controller |
   +--------------------------------------+------------------------------+----------------+-------------------+-------+-------+----------------+

.. end

.. note::

   If you know the UUID of the agent the "**openstack network agent show
   <UUID>**" command can also be used.

.. end

To confirm the availability zones defined in the system as a whole:

.. code-block:: bash

   $ openstack availability zone list --network
   +-----------+-------------+
   | Zone Name | Zone Status |
   +-----------+-------------+
   | az0       | available   |
   | az1       | available   |
   | az2       | available   |
   +-----------+-------------+

.. end

Router Availability Zones
-------------------------

In order to create a router with availability zones the
``--availability-zone-hint`` should be passed to the create command,
note that this parameter can be specified multiple times in case the
router belongs to more than one availability zone. For example:

.. code-block:: bash

   $ openstack router create --availability-zone-hint az-0 --availability-zone-hint az-1 router-0
   +-------------------------+--------------------------------------+
   | Field                   | Value                                |
   +-------------------------+--------------------------------------+
   | admin_state_up          | UP                                   |
   | availability_zone_hints | az-0, az-1                           |
   | availability_zones      |                                      |
   | created_at              | 2020-06-04T08:29:33Z                 |
   | description             |                                      |
   | external_gateway_info   | null                                 |
   | flavor_id               | None                                 |
   | id                      | 8fd6d01a-57ad-4e91-a788-ebe48742d000 |
   | name                    | router-0                             |
   | project_id              | 2a364ced6c084888be0919450629de1c     |
   | revision_number         | 1                                    |
   | routes                  |                                      |
   | status                  | ACTIVE                               |
   | tags                    |                                      |
   | updated_at              | 2020-06-04T08:29:33Z                 |
   +-------------------------+--------------------------------------+

.. end

It's also possible to set the default availability zones via the
*/etc/neutron/neutron.conf* configuration file:

.. code-block:: ini

   [DEFAULT]
   default_availability_zones = az-0,az-2
   ...

.. end

When scheduling the gateway ports of a router, the OVN driver will take
into consideration the router availability zones and make sure that the
ports are scheduled on the nodes belonging to those availability zones.

Note that in the router object we have two attributes
related to availability zones: ``availability_zones`` and
``availability_zone_hints``:

.. code-block:: bash

   | availability_zone_hints | az-0, az-1                           |
   | availability_zones      |                                      |

.. end

This distinction makes more sense in the **ML2/OVS** driver which
relies on the L3 agent for its router placement (see the :ref:`ML2/OVS
driver Availability Zones guide<config-az>` for more information). In
**ML2/OVN** the ``ovn-controller`` service will be running on all nodes
of the cluster so the ``availability_zone_hints`` will always match the
``availability_zones`` attribute, as below:

.. code-block:: bash

   | availability_zone_hints | az-0, az-1                           |
   | availability_zones      | az-0, az-1                           |

.. end

OVN Database information
************************

In order to check the availability zones of a router
via the OVN Northbound database, one can look for the
``neutron:availability_zone_hints`` key in the ``external_ids``
column for its entry in the ``Logical_Router`` table:

.. code-block:: bash

   $ ovn-nbctl list Logical_Router
   _uuid               : 4df68f1e-17dd-4b9a-848d-b6152ae19203
   external_ids        : {"neutron:availability_zone_hints"="az-0,az-1", "neutron:gw_port_id"="", "neutron:revision_number"="1", "neutron:router_name"=router-0}
   name                : neutron-8fd6d01a-57ad-4e91-a788-ebe48742d000
   ...

.. end


To check the availability zones of the Chassis, look at the
``ovn-cms-options`` key in the ``other_config`` column (or
``external_ids`` for an older version of OVN) of the ``Chassis`` table
in the OVN Southbound database:

.. code-block:: bash

   $ ovn-sbctl list Chassis
   _uuid               : abaa9f07-9988-40c0-bd1a-8d8326af08b0
   name                : "2d1924b2-99a4-4c6c-a4f2-0be64c0cec8c"
   other_config        : {..., ovn-cms-options="enable-chassis-as-gw,availability-zones=az-0:az-1:az-2"}
   ...

.. end

As mentioned in the `Router availability zones`_ section, the
scheduling of the gateway router ports will take into consideration
the availability zones that the router belongs to. We can confirm
this behavior by looking in the ``Gateway_Chassis`` table from the OVN
Northbound database:

.. code-block:: bash

   $ ovn-nbctl list Gateway_Chassis
   _uuid               : ac61b70f-ff51-43d9-830b-f9bc6d74090a
   chassis_name        : "2d1924b2-99a4-4c6c-a4f2-0be64c0cec8c"
   external_ids        : {}
   name                : lrp-5a40eeca-5233-4029-a470-9018aa8b3de9_2d1924b2-99a4-4c6c-a4f2-0be64c0cec8c
   options             : {}
   priority            : 2

   _uuid               : c1b7763b-1784-4e5a-a948-853662faeddc
   chassis_name        : "1cde2542-69f9-4598-b20b-d4f68304deb0"
   external_ids        : {}
   name                : lrp-5a40eeca-5233-4029-a470-9018aa8b3de9_1cde2542-69f9-4598-b20b-d4f68304deb0
   options             : {}
   priority            : 1

.. end

Each entry on this table represents an instance of the gateway port
(L3 HA, for more information see :ref:`Routing in OVN<ovn_routing>`),
the ``chassis_name`` column indicates which Chassis that port instance
is scheduled onto. If we co-relate each entry and their ``chassis_name``
we will see that this port has been only scheduled to Chassis matching
with the router's availability zones.

Network Availability Zones
--------------------------

Since OVN has a distributed DHCP server model (see the
`ovn-architecture <http://www.openvswitch.org/support/dist-docs-2.5/ovn-architecture.7.html>`_
document for more information), one may think that there's no need
for Ml2/OVN to support Network Availability Zones as there's no need
to co-locate a DHCP agent within the same zones to serve the VMs but,
in ML2/OVN there's a special case which are the ``external`` ports and
those need to be aware of the Availability Zones for its scheduling.

These ``external`` ports are ports that are located on a different
node than the one that the VM is running. At the moment, ML2/OVN only
supports one case that makes use of these ports which is the :ref:`SR-IOV
support<ovn_sriov>`.

In order to create a network with availability zones the
``--availability-zone-hint`` should be passed to the create command,
note that this parameter can be specified multiple times in case the
network belongs to more than one availability zone. For example:

.. code-block:: bash

   $ openstack network create --availability-zone-hint az-0 --availability-zone-hint az-1 network-0
   +---------------------------+--------------------------------------+
   | Field                     | Value                                |
   +---------------------------+--------------------------------------+
   | admin_state_up            | UP                                   |
   | availability_zone_hints   | az-0, az-1                           |
   | availability_zones        |                                      |
   | created_at                | 2021-04-26T14:04:51Z                 |
   | description               |                                      |
   | dns_domain                |                                      |
   | id                        | ba584cdb-b866-4744-85d3-6e38718055cc |
   | ipv4_address_scope        | None                                 |
   | ipv6_address_scope        | None                                 |
   | is_default                | False                                |
   | is_vlan_transparent       | None                                 |
   | mtu                       | 1442                                 |
   | name                      | network-0                            |
   | port_security_enabled     | True                                 |
   | project_id                | ffd9e4a60af34b0599f1d50aed20dde0     |
   | provider:network_type     | None                                 |
   | provider:physical_network | None                                 |
   | provider:segmentation_id  | None                                 |
   | qos_policy_id             | None                                 |
   | revision_number           | 1                                    |
   | router:external           | Internal                             |
   | segments                  | None                                 |
   | shared                    | False                                |
   | status                    | ACTIVE                               |
   | subnets                   |                                      |
   | tags                      |                                      |
   | updated_at                | 2021-04-26T14:04:52Z                 |
   +---------------------------+--------------------------------------+

.. end

OVN Database information
************************

Upon creating the first ``external`` port to a network with Availability
Zones set a HA Chassis Group correspondent to that network will also be
created in the OVN Northbound Database:

.. code-block:: bash

   $ openstack port create --network network-0 --vnic-type direct port-0
   +-------------------------+--------------------------------------+
   | Field                   | Value                                |
   +-------------------------+--------------------------------------+
   | id                      | 2523d7f5-c7ca-40b8-83c5-ac37e5b126ea |
   | name                    | port-0                               |
   | network_id              | ba584cdb-b866-4744-85d3-6e38718055cc |
   ...
   +-------------------------+--------------------------------------+
.. end

To find the corresponding HA Chassis Group we need to look for a group
named as *neutron-<Neutron Network UUID>*, for example:

.. code-block:: bash

   $ ovn-nbctl list HA_Chassis_Group neutron-ba584cdb-b866-4744-85d3-6e38718055cc
   _uuid               : f6a49abb-dc97-4e2a-955a-6f8e8be4865e
   external_ids        : {"neutron:availability_zone_hints"="az-0,az-1"}
   ha_chassis          : [46850075-7383-4da9-b0b2-5ded2858f681, ce1da6a5-77d3-4945-b218-c0ae35403b80]
   name                : neutron-ba584cdb-b866-4744-85d3-6e38718055cc

.. end

In the output above is possible to see that the HA Chassis Group for
the Neutron network ``ba584cdb-b866-4744-85d3-6e38718055cc`` includes
two Chassis (the ``ha_chassis`` column) that are part of the Availability
Zones that this network is also part of.

We can inspect these members to see which one has the **highest**
priority, which means that when the ``external`` port is bound it
will first bound to the HA Chassis with the **highest** priority in
the Group. In case that Chassis goes down the port will move on to the
next Chassis with the **highest** priority and so on. To check these HA
Chassis do:

.. code-block:: bash

   $ ovn-nbctl list HA_Chassis 46850075-7383-4da9-b0b2-5ded2858f681
   _uuid               : 46850075-7383-4da9-b0b2-5ded2858f681
   chassis_name        : "2c5c4479-0e2b-4742-a1d7-df10be020143"
   external_ids        : {}
   priority            : 32766

   $ ovn-nbctl list HA_Chassis ce1da6a5-77d3-4945-b218-c0ae35403b8
   _uuid               : ce1da6a5-77d3-4945-b218-c0ae35403b80
   chassis_name        : "159970f0-71f7-4d3d-9a9e-92e37c5f03c5"
   external_ids        : {}
   priority            : 32767

.. end

In this case, the **active** Chassis is the
``159970f0-71f7-4d3d-9a9e-92e37c5f03c5``.

And lastly, to find which HA Chassis Group an external
port belongs to by looking into the OVN Northbound Database do:

.. code-block:: bash

   $ sudo ovn-nbctl list Logical_Switch_Port 2523d7f5-c7ca-40b8-83c5-ac37e5b126ea
   _uuid               : 382d8cd8-575f-4a3f-93ba-a01cb9c2c265
   ha_chassis_group    : f6a49abb-dc97-4e2a-955a-6f8e8be4865e
   name                : "2523d7f5-c7ca-40b8-83c5-ac37e5b126ea"
   type                : external
   ...

.. end

The ``ha_chassis_group`` column will point to the UUID (in the OVN
database) of the HA Chassis Group it belongs to.
