.. _port_forwarding:

ML2/OVN Port forwarding
=======================

ML2/OVN supports Port Forwarding (PF) across the North/South data plane.
Specific L4 Ports of the Floating IP (FIP) can be directed to a specific
FixedIP:PortNumber of a VM, so that different services running in a VM
can be isolated, and can communicate with external networks easily.

OVN's native load balancing (LB) feature is used for providing this
functionality. An OVN load balancer is expressed in the OVN northbound
load_balancer table for all mappings for a given FIP+protocol. All PFs
for the same FIP+protocol are kept as Virtual IP (VIP) mappings inside a
LB entry. See the diagram below for an example of how that looks like:

.. code-block:: none

   VIP:PORT = MEMBER1:MPORT1, MEMBER2:MPORT2

   The same is extended for port forwarding as:

   FIP:PORT = PRIVATE_IP:PRIV_PORT

         Neutron DB                              OVN Northbound DB

   +---------------------+              +---------------------------------+
   | Floating IP AA      |              | Load Balancer AA UDP            |
   |                     |              |                                 |
   | +-----------------+ |              |                                 |
   | | Port Forwarding | |   +----------->AA:portA => internal IP1:portX  |
   | |                 | |   |          |                                 |
   | | External PortA  +-----+   +------->AA:portB => internal IP2:portX  |
   | | Fixed IP1 PortX | |       |      |                                 |
   | | Protocol: UDP   | |       |      +---------------------------------+
   | +-----------------+ |       |
   |                     |       |      +---------------------------------+
   | +-----------------+ |       |      | Load Balancer AA TCP            |
   | | Port Forwarding | |       |      |                                 |
   | |                 | |       |      |                                 |
   | | External PortB  +---------+   +--->AA:portC => internal IP3:portX  |
   | | Fixed IP2 PortX | |           |  |                                 |
   | | Protocol: UDP   | |           |  +---------------------------------+
   | +-----------------+ |           |
   |                     |           |
   | +-----------------+ |           |
   | | Port Forwarding | |           |
   | |                 | |           |  +---------------------------------+
   | | External PortC  | |           |  | Load Balancer BB TCP            |
   | | Fixed IP3 PortX +-------------+  |                                 |
   | | Protocol: TCP   | |              |                                 |
   | +-----------------+ |    +---------->BB:portD => internal IP4:portX  |
   |                     |    |         |                                 |
   +---------------------+    |         +---------------------------------+
                              |
                              |         +-------------------+
                              |         | Logical Router X1 |
   +---------------------+    |         |                   |
   | Floating IP BB      |    |         | Load Balancers:   |
   |                     |    |         | AA UDP, AA TCP    |
   | +-----------------+ |    |         +-------------------+
   | | Port Forwarding | |    |
   | |                 | |    |         +-------------------+
   | | External PortD  | |    |         | Logical Router Z1 |
   | | Fixed IP4 PortX +------+         |                   |
   | | Protocol: TCP   | |              | Load Balancers:   |
   | +-----------------+ |              | BB TCP            |
   +---------------------+              +-------------------+

The OVN LB entries have names that include the id of the FIP and a protocol
suffix. That protocol portion is needed because a single FIP can have multiple
UDP and TCP port forwarding entries while a given LB entry can either be one
or the other protocol (not both). Based on that, the format used to specify an
LB entry is:

.. code-block:: ini

   pf-floatingip-<NEUTRON_FIP_ID>-<PROTOCOL>

A revision value is present in external_ids of each OVN load balancer entry.
That number is synchronized with floating IP entries (NOT the port
forwarding!) of the Neutron database.

In order to differentiate a load balancer entry that was created by port
forwarding vs load balancer entries maintained by ovn-octavia-provider, the
external_ids field also has an owner value:

.. code-block:: python

   external_ids = {
      ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY: PORT_FORWARDING_PLUGIN,
      ovn_const.OVN_FIP_EXT_ID_KEY: pf_obj.floatingip_id,
      ovn_const.OVN_ROUTER_NAME_EXT_ID_KEY: rtr_name,
      neutron:revision_number: fip_obj.revision_number,
   }

The following registry (API) neutron events trigger the OVN backend to map port
forwarding into LB:

.. code-block:: python

   @registry.receives(PORT_FORWARDING_PLUGIN, [events.AFTER_INIT])
   def register(self, resource, event, trigger, payload=None):
      registry.subscribe(self._handle_notification, PORT_FORWARDING, events.AFTER_CREATE)
      registry.subscribe(self._handle_notification, PORT_FORWARDING, events.AFTER_UPDATE)
      registry.subscribe(self._handle_notification, PORT_FORWARDING, events.AFTER_DELETE)
