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


Local IP
========

Local IP is a virtual IP that can be shared across multiple ports/VMs
(similar to anycast IP) and is guaranteed to only be reachable within the same
physical server/node boundaries. The feature is primarily focused on high
efficiency and performance of the networking data plane for very large scale
clouds and/or clouds with high network throughput demands.
Technically it is Neutron API/DB extension + openvswitch agent extension.

Usage
-----

Usage is similar to Floating IP usage. If you want to assign a virtual Local IP
to one of your VMs:

- first create Local IP object using network (name or ID) or
  local-port (name or ID) input parameter: it will be used
  to allocate/take IP address

  .. code-block:: console

    $ openstack local ip create --network <network>
    +------------------+--------------------------------------+
    | Field            | Value                                |
    +------------------+--------------------------------------+
    | created_at       | 2021-12-01T13:50:24Z                 |
    | description      |                                      |
    | id               | b4425e9d-f1d0-4493-a2a8-1d3c7fbe049b |
    | ip_mode          | translate                            |
    | local_ip_address | 172.24.4.10                          |
    | local_port_id    | 13181907-f258-4381-9516-ca07648ea239 |
    | name             |                                      |
    | network_id       | be0ec407-e341-4efa-a33a-3e0160afeedc |
    | project_id       | b8462a1eba47462ea8c3e4e6adc22e63     |
    | revision_number  | 0                                    |
    | updated_at       | 2021-12-01T13:50:24Z                 |
    +------------------+--------------------------------------+

- then create Local IP association object using local-ip (name or ID) and
  fixed-port-id input parameters, thus assigning Local IP to the needed VM

  .. code-block:: console

    $ openstack local ip association create <local-ip> <fixed-port-id>
    +------------------+--------------------------------------+
    | Field            | Value                                |
    +------------------+--------------------------------------+
    | fixed_ip         | 10.0.0.194                           |
    | fixed_port_id    | 8cd37bb6-f7c3-4013-8d97-5c97676678a0 |
    | host             |                                      |
    | id               | None                                 |
    | local_ip_address | 172.24.4.10                          |
    | name             | None                                 |
    +------------------+--------------------------------------+

- Unlike Floating IP you can have many Local IP associations: to VMs on
  different nodes.

  .. warning::
     Assigning two or more fixed ports to the same Local IP on the same node
     is currently not supported. NAT could go either way or not work at all.

All node's VMs` egress traffic targeting IP address of Local IP object will be
DNATed to local VM.

Note: if no Local IP is assigned on a node packets will be redirected to an
underlying Neutron port IP address.

Note: in Yoga release only ``translate`` ip_mode is supported (default) -
it means DNAT will be used for packet redirection. Support for ``passthrough``
mode (no modifications to IP packets) will be added in next releases.

OpenVSwitch Agent Impact
------------------------

Unconditional changes
~~~~~~~~~~~~~~~~~~~~~

- 2 new OF tables are added for br-int:

  - LOCAL_EGRESS_TABLE - to save VLANs of local ports
  - LOCAL_IP_TABLE - for Local IP handling rules

- both tables has default rule to resubmit packets to TRANSIENT_TABLE;
- the only modification to packets flow is that egress packets will first
  go through empty LOCAL_EGRESS_TABLE before entering TRANSIENT_TABLE.
  This should be optimized by OVS to have no impact on performance.

If local_ip agent extension is enabled
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- LOCAL_EGRESS_TABLE will have a rule to save port's local VLAN to req6.
  This is needed in order to distinguish Local IPs from different nets.
  Then packets will be resubmitted to LOCAL_IP_TABLE which just has one
  default rule unless some local Port is associated with any Local IP.

If user creates Local IP Association with one of the ports owned by agent
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Following rules will be added to LOCAL_SWITCHING table:

- local gARP blocker rule to prevent undesired Local IP ARP updates
  from other nodes (including real IP address owner)

Following rules will be added to LOCAL_IP_TABLE:

- local arp responder rule to answer local ARP requests for Local IP address
- Local IP translation flows to do actual DNAT (Local IP -> fixed IP)

  - via conntrack using ``ct`` with ``nat`` action if ``static_nat`` config
    option is `False` (default)
  - via static NAT rules with source/destination (ETH + IP + TCP/UDP ports)
    tuples used for learning back flows - if  ``static_nat`` config is `True`

Yoga release limitations
------------------------

- Only IPv4 is supported. IPv6 support will be considered in future releases

- Only 'openvswitch' ML2 mechanism driver/agent supports the feature

- No deterministic handling of packets if a node contains multiple local ports
  from same L2 segment associated with the same Local IP
