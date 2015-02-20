Advanced Services
=================

Historically, Neutron supported the following advanced services:

#. **FWaaS** (*Firewall-as-a-Service*): runs as part of the L3 agent.
#. **LBaaS** (*Load-Balancer-as-a-Service*): implemented purely inside
   neutron-server, does not interact directly with agents.
#. **VPNaaS** (*VPN-as-a-Service*): derives from L3 agent to add
   VPNaaS functionality.

Starting with the Kilo release, these services are split into separate
repositories managed by extended reviewer teams.

#. http://git.openstack.org/cgit/openstack/neutron-fwaas/
#. http://git.openstack.org/cgit/openstack/neutron-lbaas/
#. http://git.openstack.org/cgit/openstack/neutron-vpnaas/
