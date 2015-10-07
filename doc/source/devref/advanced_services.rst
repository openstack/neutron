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
