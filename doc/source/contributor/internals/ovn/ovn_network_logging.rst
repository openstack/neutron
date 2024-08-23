.. _ovn_network_logging:

ML2/OVN Network Logging
=======================

ML2/OVN supports network logging, based on security groups. Unlike ML2/OVS,
the driver for this functionality leverages the Northbound database to
manage affected security group rules. Thus, there is no need for an agent.

It is good to keep in mind that Openstack Security Groups (SG) and their rules
(SGR) map 1:1 into OVN's Port Groups (PG) and Access Control Lists (ACL):

.. code-block::

   Openstack Security Group <=> OVN Port Group
   Openstack Security Group Rule <=> OVN ACL

Just like SGs have a list of SGRs, PGs have a list of ACLs. PGs also have
a list of logical ports, but that is not really relevant in this context.
With regards to Neutron ports, network logging entries (NLE) can filter
on Neutron ports, also known as "targets". When that is the case, the
underlying implementation finds the corresponding SGs out of the
Neutron port. So it is all back to SGs and affected SGRs. Or PGs and ACLs
as far as OVN is concerned.

For more info on port groups, see:
https://docs.openstack.org/networking-ovn/latest/contributor/design/acl_optimizations.html

In order to enable network logging, the Neutron OVN driver relies on 2
tables of the Northbound database: Meter and ACL.

Meter Table
-----------

Meters are how network logging events get throttled, so they do not negatively
affect the control plane. Logged events are sent to the ovn-controller that
runs locally on each compute node. Thus, the throttle keeps ovn-controller
from getting overwhelmed. Note that the meters used for network logging do
not rate-limit the datapath; they only affect the logs themselves.
With the addition of 'fair meters', multiple ACLs can refer to the same
meter without competing with each other for what logs get rate limited.
This attribute is a pre-requisite for this feature, as the design aspires
to keep the complexity associated with the management of meters outside
Openstack. The benefit of ACLs sharing a 'fair' meter is that a noisy
neighbor (ACL) will not consume all the available capacity set for the meter.

For more info on fair meters, see:
https://github.com/ovn-org/ovn/commit/880dca99eaf73db7e783999c29386d03c82093bf

Below is an example of a meter configuration in OVN. You can locate the fair,
unit, burst_size, and rate attributes:

.. code-block:: bash

   $ ovn-nbctl list meter
   _uuid               : 70c76ba9-f303-471b-9d49-25dee299827f
   bands               : [f114c205-a170-4425-8ca6-4e71099d1955]
   external_ids        : {"neutron:device_owner"=logging-plugin}
   fair                : true
   name                : acl_log_meter
   unit                : pktps

   $ ovn-nbctl list meter-band
   _uuid               : f114c205-a170-4425-8ca6-4e71099d1955
   action              : drop
   burst_size          : 25
   external_ids        : {}
   rate                : 100

The burst_size and rate attributes are configurable through
neutron.conf.services.logging.log_driver_opts. That is not new.

ACL Table
---------

As mentioned before, ACLs are the OVN's counterpart to Openstack's SGRs.
Moreover, there are a few attributes in each ACL that makes it able to
provide the networking logging feature. Let's use the example below
to point out the relevant fields:

.. code-block:: bash

   $ openstack network log create --resource-type security_group \
     --resource ${SG} --event ACCEPT logme -f value -c ID
   2e456c7f-154e-40a8-bb10-f88ba51b90b5

   $ openstack security group show ${SG} -f json -c rules | jq '.rules | .[2]' | grep -v 'null'
   {
    "id": "de4ea1e4-c946-40ed-b5b6-53c59418dc0b",
    "tenant_id": "2600067ea3a446dba332d20a30ed44fa",
    "security_group_id": "c604e984-0789-4c9a-a297-3e7f62fa73fd",
    "ethertype": "IPv4",
    "direction": "egress",
    "standard_attr_id": 48,
    "tags": [],
    "created_at": "2021-02-06T22:17:44Z",
    "updated_at": "2021-02-06T22:17:44Z",
    "revision_number": 0,
    "project_id": "2600067ea3a446dba332d20a30ed44fa"
  }

  $ ovn-nbctl find acl \
    "external_ids:\"neutron:security_group_rule_id\""="de4ea1e4-c946-40ed-b5b6-53c59418dc0b"
  _uuid               : 791679e9-237d-4732-a31e-aa634496e02b
  action              : allow-related
  direction           : from-lport
  external_ids        : {"neutron:security_group_rule_id"="de4ea1e4-c946-40ed-b5b6-53c59418dc0b"}
  log                 : true
  match               : "inport == @pg_c604e984_0789_4c9a_a297_3e7f62fa73fd && ip4"
  meter               : acl_log_meter
  name                : neutron-2e456c7f-154e-40a8-bb10-f88ba51b90b5
  priority            : 1002
  severity            : info

The first command creates a networking-log for a given SG. The second shows an
SGR from that SG. The third shell command is where we can see how the ACL with
the meter information gets populated.
These are the attributes pertinent to network logging:

* log: a boolean that dictates whether a log will be generated. Even if the
  NLE applies to the SGR via its associated SG, this may be 'false' if the
  action is not a match. That would be the case if the NLE specified
  "--event DROP", in this example.
* meter: this is the name of the fair meter. It is the same for all ACLs.
* name: This is a string composed of the prefix "neutron-" and the id of the
  NLE. It will be part of the generated logs.
* severity: this is the log severity that will be used by the ovn-controller.
  It is currently hard coded in Neutron, but can be made configurable in
  future releases.

If we poked the SGR with packets that match its criteria, the ovn-controller
local to where the ACLs is enforced will log something that looks like this:

.. code-block:: bash

   2021-02-16T11:59:00.640Z|00045|acl_log(ovn_pinctrl0)|INFO|
   name="neutron-2e456c7f-154e-40a8-bb10-f88ba51b90b5",
   verdict=allow, severity=info: icmp,vlan_tci=0x0000,dl_src=fa:16:3e:24:dc:88,
   dl_dst=fa:16:3e:15:6d:e0,
   nw_src=10.0.0.12,nw_dst=10.0.0.11,nw_tos=0,nw_ecn=0,nw_ttl=64,icmp_type=8,
   icmp_code=0

It is beyond the scope of this document to talk about what happens after the
logs are generated by ovn-controllers. The harvesting of files across compute
nodes is something a project like `Monasca`_ may be a good fit.

.. _`Monasca`: https://wiki.openstack.org/wiki/Monasca
