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


Keep DNS Nameserver Order Consistency In Neutron
================================================

In Neutron subnets, DNS nameservers are given priority when created or updated.
This means if you create a subnet with multiple DNS servers, the order will
be retained and guests will receive the DNS servers in the order you
created them in when the subnet was created. The same thing applies for update
operations on subnets to add, remove, or update DNS servers.

Get Subnet Details Info
-----------------------
::

        changzhi@stack:~/devstack$ neutron subnet-list
        +--------------------------------------+------+-------------+--------------------------------------------+
        | id                                   | name | cidr        | allocation_pools                           |
        +--------------------------------------+------+-------------+--------------------------------------------+
        | 1a2d261b-b233-3ab9-902e-88576a82afa6 |      | 10.0.0.0/24 | {"start": "10.0.0.2", "end": "10.0.0.254"} |
        +--------------------------------------+------+-------------+--------------------------------------------+

        changzhi@stack:~/devstack$ neutron subnet-show 1a2d261b-b233-3ab9-902e-88576a82afa6
        +------------------+--------------------------------------------+
        | Field            | Value                                      |
        +------------------+--------------------------------------------+
        | allocation_pools | {"start": "10.0.0.2", "end": "10.0.0.254"} |
        | cidr             | 10.0.0.0/24                                |
        | dns_nameservers  | 1.1.1.1                                    |
        |                  | 2.2.2.2                                    |
        |                  | 3.3.3.3                                    |
        | enable_dhcp      | True                                       |
        | gateway_ip       | 10.0.0.1                                   |
        | host_routes      |                                            |
        | id               | 1a2d26fb-b733-4ab3-992e-88554a87afa6       |
        | ip_version       | 4                                          |
        | name             |                                            |
        | network_id       | a404518c-800d-2353-9193-57dbb42ac5ee       |
        | tenant_id        | 3868290ab10f417390acbb754160dbb2           |
        +------------------+--------------------------------------------+

Update Subnet DNS Nameservers
-----------------------------
::

    neutron subnet-update 1a2d261b-b233-3ab9-902e-88576a82afa6 \
    --dns_nameservers list=true 3.3.3.3 2.2.2.2 1.1.1.1

    changzhi@stack:~/devstack$ neutron subnet-show 1a2d261b-b233-3ab9-902e-88576a82afa6
    +------------------+--------------------------------------------+
    | Field            | Value                                      |
    +------------------+--------------------------------------------+
    | allocation_pools | {"start": "10.0.0.2", "end": "10.0.0.254"} |
    | cidr             | 10.0.0.0/24                                |
    | dns_nameservers  | 3.3.3.3                                    |
    |                  | 2.2.2.2                                    |
    |                  | 1.1.1.1                                    |
    | enable_dhcp      | True                                       |
    | gateway_ip       | 10.0.0.1                                   |
    | host_routes      |                                            |
    | id               | 1a2d26fb-b733-4ab3-992e-88554a87afa6       |
    | ip_version       | 4                                          |
    | name             |                                            |
    | network_id       | a404518c-800d-2353-9193-57dbb42ac5ee       |
    | tenant_id        | 3868290ab10f417390acbb754160dbb2           |
    +------------------+--------------------------------------------+

As shown in above output, the order of the DNS nameservers has been updated.
New virtual machines deployed to this subnet will receive the DNS nameservers
in this new priority order. Existing virtual machines that have already been
deployed will not be immediately affected by changing the DNS nameserver order
on the neutron subnet. Virtual machines that are configured to get their IP
address via DHCP will detect the DNS nameserver order change
when their DHCP lease expires or when the virtual machine is restarted.
Existing virtual machines configured with a static IP address will never
detect the updated DNS nameserver order.
