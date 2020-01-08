.. _acl_optimizations:

========================================
ACL Handling optimizations in ovn driver
========================================

This document presents the current problem with ACLs and the design changes
proposed to core OVN as well as the necessary modifications to be made to
ovn driver to improve their usage.

Problem description
===================

There is basically two problems being addressed in this spec:

1. While in Neutron, a ``Security Group Rule`` is tied to a
``Security Group``, in OVN ``ACLs`` are created per port. Therefore,
we'll typically have *many* more ACLs than Security Group Rules, resulting
in a performance hit as the number of ports grows.

2. An ACL in OVN is applied to a ``Logical Switch``. As a result,
``ovn driver`` has to figure out which Logical Switches to apply the
generated ACLs per each Security Rule.

Let's highlight both problems with an example:

- Neutron Networks: NA, NB, NC
- Neutron Security Group: SG1
- Number of Neutron Security Group Rules in SG1: 10
- Neutron Ports in NA: 100
- Neutron Ports in NB: 100
- Neutron Ports in NC: 100
- All ports belong to SG1

When we implement the above scenario in OVN, this is what we'll get:

- OVN Logical Switches: NA, NB, NC
- Number of ACL rows in Northbound DB ACL table: 3000 (10 rules * 100 ports *
  3 networks)
- Number of elements in acl column on each Logical_Switch row: 1000 (10 rules
  * 100 ports).

And this is how, for example, the ACL match fields for the default Neutron
Security Group would look like::

 outport == <port1_uuid> && ip4 && ip4.src == $as_ip4_<sg1_uuid>
 outport == <port2_uuid> && ip4 && ip4.src == $as_ip4_<sg1_uuid>
 outport == <port3_uuid> && ip4 && ip4.src == $as_ip4_<sg1_uuid>
 ...
 outport == <port300_uuid> && ip4 && ip4.src == $as_ip4_<sg1_uuid>

As you can see, all of them look the same except for the outport field which
is clearly redundant and makes the NB database grow a lot at scale.
Also, ``ovn driver`` had to figure out for each rule in SG1 which Logical
Switches it had to apply the ACLs on (NA, NB and NC). This can be really costly
when the number of networks and port grows.


Proposed optimization
=====================

In the OpenStack context, we'll be facing this scenario most of the time
where the majority of the ACLs will look the same except for the
outport/inport fields in the match column. It would make sense to be able to
substitute all those ACLs by a single one which references all the ports
affected by that SG rule::

 outport == @port_group1 && ip4 && ip4.src == $port_group1_ip4


Implementation Details
======================

Core OVN
--------

There's a series of patches in Core OVN that will enable us to achieve this
optimization:

https://github.com/openvswitch/ovs/commit/3d2848bafa93a2b483a4504c5de801454671dccf
https://github.com/openvswitch/ovs/commit/1beb60afd25a64f1779903b22b37ed3d9956d47c
https://github.com/openvswitch/ovs/commit/689829d53612a573f810271a01561f7b0948c8c8


In summary, these patches are:

- Adding a new entity called Port_Group which will hold a list of weak
  references to the Logical Switch ports that belong to it.
- Automatically creating/updating two Address Sets (_ip4 and _ip6) in
  Southbound database every time a new port is added to the group.
- Support adding a list of ACLs to a Port Group. As the SG rules may
  span across different Logical Switches, we used to insert the ACLs in
  all the Logical Switches where we have ports in within a SG. Figuring this
  out is expensive and this new feature is a huge gain in terms of
  performance when creating/deleting ports.


ovn driver
----------

In the OpenStack integration driver, the following changes are required to
accomplish this optimization:

- When a Neutron Security Group is created, create the equivalent Port Group
  in OVN (pg-<security_group_id>), instead of creating a pair of Adress Sets
  for IPv4 and IPv6. This Port Group will reference Neutron SG id in its
  ``external_ids`` column.

- When a Neutron Port is created, the equivalent Logical Port in OVN will be
  added to those Port Groups associated to the Neutron Security Groups this
  port belongs to.

- When a Neutron Port is deleted, we'll delete the associated Logical Port in
  OVN. Since the schema includes a weak reference to the port, when the LSP
  gets deleted, it will also be automatically deleted from any Port Group
  entry where it was previously present.

- Instead of handling SG rules per port, we now need to handle them per SG
  referencing the associated Port Group in the outport/inport fields. This
  will be the biggest gain in terms of processing since we don't need to
  iterate through all the ports anymore. For example:

.. code-block:: python

    -def acl_direction(r, port):
    +def acl_direction(r):
        if r['direction'] == 'ingress':
            portdir = 'outport'
        else:
            portdir = 'inport'
    -   return '%s == "%s"' % (portdir, port['id'])
    +   return '%s == "@%s"' % (portdir, utils.ovn_name(r['security_group_id'])

- Every time a SG rule is created, instead of figuring out the ports affected
  by its SG and inserting an ACL row which will be referrenced by different
  Logical Switches, we will just reference it from the associated Port Group.

- For Neutron remote security groups, we just need to reference the
  automatically created Address_Set for that Port Group.

As a bonus, we are tackling the race conditions that could happen in
Address_Sets right now when we're deleting and creating a port at the same
time. This is thanks to the fact that the Address_Sets in the SB table are
generated automatically by ovn-northd from the Port_Group contents and
Port Group is referencing actual Logical Switch Ports. More info at:
https://bugs.launchpad.net/networking-ovn/+bug/1611852


Backwards compatibility considerations
--------------------------------------

- If the schema doesn't include the ``Port_Group`` table, keep the old
  behavior(Address Sets) for backwards compatibility.

- If the schema supports Port Groups, then a migration task will be performed
  from an OvnWorker. This way we'll ensure that it'll happen only once across
  the cloud thanks the OVSDB lock. This will be done right at the beginning of
  the ovn_db_sync process to make sure that when neutron-server starts,
  everything is in place to work with Port Groups. This migration process will
  perform the following steps:

  * Create the default drop Port Group and add all ports with port
    security enabled to it.
  * Create a Port Group for every existing Neutron Security Group and
    add all its Security Group Rules as ACLs to that Port Group.
  * Delete all existing Address Sets in NorthBound database which correspond to
    a Neutron Security Group.
  * Delete all the ACLs in every Logical Switch (Neutron network).

We should eventually remove the backwards compatibility and migration path. At
that point we should require OVS >= 2.10 from neutron ovn driver.

Special cases
-------------

Ports with no security groups
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When a port doesn't belong to any Security Group and port security is enabled,
we, by default, drop all the traffic to/from that port. In order to implement
this through Port Groups, we'll create a special Port Group with a fixed name
(``neutron_pg_drop``) which holds the ACLs to drop all the traffic.

This PG will be created automatically when we first need it, avoiding the need
to create it beforehand or during deployment.

