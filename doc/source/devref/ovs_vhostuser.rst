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

Neutron Open vSwitch vhost-user support
=======================================

Neutron supports using Open vSwitch + DPDK vhost-user interfaces directly in
the OVS ML2 driver and agent. The current implementation relies on a multiple
configuration values and includes runtime verification of Open vSwitch's
capability to provide these interfaces.

The OVS agent detects the capability of the underlying Open vSwitch
installation and passes that information over RPC via the agent
'configurations' dictionary. The ML2 driver uses this information to select
the proper VIF type and binding details.

Platform requirements
---------------------

* OVS 2.4.0+
* DPDK 2.0+

Configuration
-------------

.. code-block:: ini

    [OVS]
    datapath_type=netdev
    vhostuser_socket_dir=/var/run/openvswitch

When OVS is running with DPDK support enabled, and the ``datapath_type`` is
set to ``netdev``, then the OVS ML2 driver will use the ``vhost-user`` VIF
type and pass the necessary binding details to use OVS+DPDK and vhost-user
sockets. This includes the ``vhostuser_socket_dir`` setting, which must match
the directory passed to ``ovs-vswitchd`` on startup.

What about the networking-ovs-dpdk repo?
----------------------------------------

The networking-ovs-dpdk repo will continue to exist and undergo active
development. This feature just removes the necessity for a separate ML2 driver
and OVS agent in the networking-ovs-dpdk repo. The networking-ovs-dpdk project
also provides a devstack plugin which also allows automated CI, a Puppet
module, and an OpenFlow-based security group implementation.
