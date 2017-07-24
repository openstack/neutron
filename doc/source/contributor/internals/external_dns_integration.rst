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


Integration with external DNS services
======================================

Since the Mitaka release, neutron has an interface defined to interact with an
external DNS service. This interface is based on an abstract driver that can be
used as the base class to implement concrete drivers to interact with various
DNS services. The reference implementation of such a driver integrates neutron
with
`OpenStack Designate <https://docs.openstack.org/designate/latest/index.html>`_.

This integration allows users to publish *dns_name* and *dns_domain*
attributes associated with floating IP addresses, ports, and networks in an
external DNS service.


Changes to the neutron API
--------------------------

To support integration with an external DNS service, the *dns_name* and
*dns_domain* attributes were added to floating ips, ports and networks. The
*dns_name* specifies the name to be associated with a corresponding IP address,
both of which will be published to an existing domain with the name
*dns_domain* in the external DNS service.

Specifically, floating ips, ports and networks are extended as follows:

* Floating ips have a *dns_name* and a *dns_domain* attribute.
* Ports have a *dns_name* attribute.
* Networks have a *dns_domain* attributes.
