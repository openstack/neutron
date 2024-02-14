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


DNS Nameserver Order Consistency
================================

In Neutron subnets, DNS nameservers are given priority when created or updated.
This means if you create a subnet with multiple DNS servers, the order will
be retained and guests will receive the DNS servers in the order you
created them in when the subnet was created. The same thing applies for update
operations on subnets to add, remove, or update DNS servers.

Get Subnet Details Info
-----------------------
::

    $ openstack subnet list
    +--------------------------------------+---------+--------------------------------------+-------------+
    | ID                                   | Name    | Network                              | Subnet      |
    +--------------------------------------+---------+--------------------------------------+-------------+
    | 1a2d261b-b233-3ab9-902e-88576a82afa6 | private | a404518c-800d-2353-9193-57dbb42ac5ee | 10.0.0.0/24 |
    +--------------------------------------+---------+--------------------------------------+-------------+

    $ openstack subnet show 1a2d261b-b233-3ab9-902e-88576a82afa6
    +----------------------+--------------------------------------+
    | Field                | Value                                |
    +----------------------+--------------------------------------+
    | allocation_pools     | 10.0.0.2-10.0.0.254                  |
    | cidr                 | 10.0.0.0/24                          |
    | created_at           | 2024-02-13T21:42:34Z                 |
    | description          |                                      |
    | dns_nameservers      | 8.8.4.4, 8.8.8.8                     |
    | dns_publish_fixed_ip | None                                 |
    | enable_dhcp          | True                                 |
    | gateway_ip           | 10.0.0.1                             |
    | host_routes          |                                      |
    | id                   | 1a2d26fb-b733-4ab3-992e-88554a87afa6 |
    | ip_version           | 4                                    |
    | ipv6_address_mode    | None                                 |
    | ipv6_ra_mode         | None                                 |
    | name                 | private                              |
    | network_id           | a404518c-800d-2353-9193-57dbb42ac5ee |
    | project_id           | 3868290ab10f417390acbb754160dbb2     |
    | revision_number      | 0                                    |
    | segment_id           | None                                 |
    | service_types        |                                      |
    | subnetpool_id        |                                      |
    | tags                 |                                      |
    | updated_at           | 2024-02-13T21:42:34Z                 |
    +----------------------+--------------------------------------+

Update Subnet DNS Nameservers
-----------------------------

.. note::

   ``--no-dns-nameserver`` must be passed to clear the current list,
   otherwise a conflict will be raised if there are duplicates.

::

    $ openstack subnet set --no-dns-nameserver --dns-nameserver 8.8.8.8 \
      --dns-nameserver 8.8.4.4 1a2d261b-b233-3ab9-902e-88576a82afa6

    $ openstack subnet show 1a2d261b-b233-3ab9-902e-88576a82afa6
    +----------------------+--------------------------------------+
    | Field                | Value                                |
    +----------------------+--------------------------------------+
    | allocation_pools     | 10.0.0.2-10.0.0.254                  |
    | cidr                 | 10.0.0.0/24                          |
    | created_at           | 2024-02-13T21:42:34Z                 |
    | description          |                                      |
    | dns_nameservers      | 8.8.8.8, 8.8.4.4                     |
    | dns_publish_fixed_ip | None                                 |
    | enable_dhcp          | True                                 |
    | gateway_ip           | 10.0.0.1                             |
    | host_routes          |                                      |
    | id                   | 1a2d26fb-b733-4ab3-992e-88554a87afa6 |
    | ip_version           | 4                                    |
    | ipv6_address_mode    | None                                 |
    | ipv6_ra_mode         | None                                 |
    | name                 | private                              |
    | network_id           | a404518c-800d-2353-9193-57dbb42ac5ee |
    | project_id           | 3868290ab10f417390acbb754160dbb2     |
    | revision_number      | 1                                    |
    | segment_id           | None                                 |
    | service_types        |                                      |
    | subnetpool_id        |                                      |
    | tags                 |                                      |
    | updated_at           | 2024-02-13T21:42:34Z                 |
    +----------------------+--------------------------------------+

As shown in above output, the order of the DNS nameservers has been updated.
New virtual machines deployed to this subnet will receive the DNS nameservers
in this new priority order. Existing virtual machines that have already been
deployed will not be immediately affected by changing the DNS nameserver order
on the neutron subnet. Virtual machines that are configured to get their IP
address via DHCP will detect the DNS nameserver order change
when their DHCP lease expires or when the virtual machine is restarted.
Existing virtual machines configured with a static IP address will never
detect the updated DNS nameserver order.
