===========================
Networking service overview
===========================

OpenStack Networking (neutron) allows you to create and attach interface
devices managed by other OpenStack services to networks. Plug-ins can be
implemented to accommodate different networking equipment and software,
providing flexibility to OpenStack architecture and deployment.

It includes the following components:

neutron-server
  Accepts and routes API requests to the appropriate OpenStack
  Networking plug-in for action.

OpenStack Networking plug-ins and agents
  Plug and unplug ports, create networks or subnets, and provide
  IP addressing. These plug-ins and agents differ depending on the
  vendor and technologies used in the particular cloud. OpenStack
  Networking ships with plug-ins and agents for Cisco virtual and
  physical switches, NEC OpenFlow products, Open vSwitch, Linux
  bridging, and the VMware NSX product.

  The common agents are L3 (layer 3), DHCP (dynamic host IP
  addressing), and a plug-in agent.

Messaging queue
  Used by most OpenStack Networking installations to route information
  between the neutron-server and various agents. Also acts as a database
  to store networking state for particular plug-ins.

OpenStack Networking mainly interacts with OpenStack Compute to provide
networks and connectivity for its instances.
