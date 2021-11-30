..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.


      Convention for heading levels in Neutron devref:
      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4
      (Avoid deeper levels because they do not render well.)


Composite Object Status via Provisioning Blocks
===============================================

We use the STATUS field on objects to indicate when a resource is ready
by setting it to ACTIVE so external systems know when it's safe to use
that resource. Knowing when to set the status to ACTIVE is simple when
there is only one entity responsible for provisioning a given object.
When that entity has finishing provisioning, we just update the STATUS
directly to active. However, there are resources in Neutron that require
provisioning by multiple asynchronous entities before they are ready to
be used so managing the transition to the ACTIVE status becomes more
complex. To handle these cases, Neutron has `the provisioning_blocks
module
<http://opendev.org/openstack/neutron/src/neutron/db/provisioning_blocks.py>`_
to track the entities that are still provisioning a resource.

The main example of this is with ML2, the L2 agents and the DHCP agents.
When a port is created and bound to a host, it's placed in the DOWN
status. The L2 agent now has to setup flows, security group rules, etc
for the port and the DHCP agent has to setup a DHCP reservation for
the port's IP and MAC. Before the transition to ACTIVE, both agents
must complete their work or the port user (e.g. Nova) may attempt to
use the port and not have connectivity. To solve this, the
provisioning_blocks module is used to track the provisioning state
of each agent and the status is only updated when both complete.


High Level View
---------------

To make use of the provisioning_blocks module, provisioning components
should be added whenever there is work to be done by another entity
before an object's status can transition to ACTIVE. This is
accomplished by calling the add_provisioning_component method for
each entity. Then as each entity finishes provisioning the object,
the provisioning_complete must be called to lift the provisioning
block.

When the last provisioning block is removed, the provisioning_blocks
module will trigger a callback notification containing the object ID
for the object's resource type with the event PROVISIONING_COMPLETE.
A subscriber to this event can now update the status of this object
to ACTIVE or perform any other necessary actions.

A normal state transition will look something like the following:

1. Request comes in to create an object
2. Logic on the Neutron server determines which entities are required
   to provision the object and adds a provisioning component for each
   entity for that object.
3. A notification is emitted to the entities so they start their work.
4. Object is returned to the API caller in the DOWN (or BUILD) state.
5. Each entity tells the server when it has finished provisioning the
   object. The server calls provisioning_complete for each entity that
   finishes.
6. When provisioning_complete is called on the last remaining entity,
   the provisioning_blocks module will emit an event indicating that
   provisioning has completed for that object.
7. A subscriber to this event on the server will then update the status
   of the object to ACTIVE to indicate that it is fully provisioned.

For a more concrete example, see the section below.


ML2, L2 agents, and DHCP agents
-------------------------------

ML2 makes use of the provisioning_blocks module to prevent the status
of ports from being transitioned to ACTIVE until both the L2 agent and
the DHCP agent have finished wiring a port.

When a port is created or updated, the following happens to register
the DHCP agent's provisioning blocks:

1. The subnet_ids are extracted from the fixed_ips field of the port
   and then ML2 checks to see if DHCP is enabled on any of the subnets.
2. The configuration for the DHCP agents hosting the network are looked
   up to ensure that at least one of them is new enough to report back
   that it has finished setting up the port reservation.
3. If either of the preconditions above fail, a provisioning block for
   the DHCP agent is not added and any existing DHCP agent blocks for
   that port are cleared to ensure the port isn't blocked waiting for an
   event that will never happen.
4. If the preconditions pass, a provisioning block is added for the port
   under the 'DHCP' entity.

When a port is created or updated, the following happens to register the
L2 agent's provisioning blocks:

1. If the port is not bound, nothing happens because we don't know yet
   if an L2 agent is involved so we have to wait until a port update that
   binds it.
2. Once the port is bound, the agent based mechanism drivers will check
   if they have an agent on the bound host and if the VNIC type belongs
   to the mechanism driver, a provisioning block is added for the port
   under the 'L2 Agent' entity.


Once the DHCP agent has finished setting up the reservation, it calls
dhcp_ready_on_ports via the RPC API with the port ID. The DHCP RPC
handler receives this and calls 'provisioning_complete' in the
provisioning module with the port ID and the 'DHCP' entity to remove
the provisioning block.

Once the L2 agent has finished setting up the reservation, it calls
the normal update_device_list (or update_device_up) via the RPC API.
The RPC callbacks handler calls 'provisioning_complete' with the
port ID and the 'L2 Agent' entity to remove the provisioning block.

On the 'provisioning_complete' call that removes the last record,
the provisioning_blocks module emits a callback PROVISIONING_COMPLETE
event with the port ID. A function subscribed to this in ML2 then calls
update_port_status to set the port to ACTIVE.

At this point the normal notification is emitted to Nova allowing the
VM to be unpaused.

In the event that the DHCP or L2 agent is down, the port will not
transition to the ACTIVE status (as is the case now if the L2 agent
is down). Agents must account for this by telling the server that
wiring has been completed after configuring everything during
startup. This ensures that ports created on offline agents (or agents
that crash and restart) eventually become active.

To account for server instability, the notifications about port wiring
be complete must use RPC calls so the agent gets a positive
acknowledgement from the server and it must keep retrying until either
the port is deleted or it is successful.

If an ML2 driver immediately places a bound port in the ACTIVE state
(e.g. after calling a backend in update_port_postcommit), this patch
will not have any impact on that process.
