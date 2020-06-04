.. _ovn_router_availability_zones:

=======================================
Router Availability Zones guide for OVN
=======================================

The purpose of this page is to describe how the router availability zones
works with OVN. Prior to reading this document, it is recommended to first
read :ref:`ML2/OVS driver Availability Zones guide<config-az>`.

How to configure it
~~~~~~~~~~~~~~~~~~~

Different from the ML2/OVS driver for Neutron the availability zones for
the OVN driver is not configured via a configuration file. Since ML2/OVN
does not rely on an external agent such as the L3 agent, certain nodes
(e.g gateway/networker node) won't have any Neutron configuration file present. For
this reason, OVN uses the local OVSDB for configuring the availability
zones that instance of ``ovn-controller`` running on that hypervisor
belongs to.

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

   $ openstack availability zone list
   +-----------+-------------+
   | Zone Name | Zone Status |
   +-----------+-------------+
   | az0       | available   |
   | az1       | available   |
   | az2       | available   |
   +-----------+-------------+

.. end

Using router availability zones
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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
``availability_zones`` attribute.

OVN Database information
~~~~~~~~~~~~~~~~~~~~~~~~

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

As mentioned in the `Using router availability zones`_ section, the
scheduling of the gateway router ports will take into consideration
the availability zones that the router belongs to. We can confirm
this behavior by looking in the ``Gateway_Chassis`` table from the OVN
Southbound database:

.. code-block:: bash

   $ ovn-sbctl list Gateway_Chassis
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
