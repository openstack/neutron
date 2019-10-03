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


Pre-configured domains for projects and users
---------------------------------------------

ML2 plugin extension ``dns_domain_keywords`` provides same dns integration as
``dns_domain_ports`` and ``subnet_dns_publish_fixed_ip`` and it also allows to
configure network's dns_domain with some specific keywords: ``<project_id>``,
``<project_name>``, ``<user_id>``, ``<user_name>``. Please see example below for
more details.

* Create DNS zone. ``0511951bd56e4a0aac27ac65e00bddd0`` is ID of the project
  used in the example

  .. code-block:: console

    $ openstack zone create 0511951bd56e4a0aac27ac65e00bddd0.example.com. --email admin@0511951bd56e4a0aac27ac65e00bddd0.example.com
    +----------------+----------------------------------------------------+
    | Field          | Value                                              |
    +----------------+----------------------------------------------------+
    | action         | CREATE                                             |
    | attributes     |                                                    |
    | created_at     | 2021-02-19T14:48:06.000000                         |
    | description    | None                                               |
    | email          | admin@0511951bd56e4a0aac27ac65e00bddd0.example.com |
    | id             | c14a8edc-d0b9-4cdd-93f1-1ab5a5f5ff9d               |
    | masters        |                                                    |
    | name           | 0511951bd56e4a0aac27ac65e00bddd0.example.com.      |
    | pool_id        | 794ccc2c-d751-44fe-b57f-8894c9f5c842               |
    | project_id     | 0511951bd56e4a0aac27ac65e00bddd0                   |
    | serial         | 1613746085                                         |
    | status         | PENDING                                            |
    | transferred_at | None                                               |
    | ttl            | 3600                                               |
    | type           | PRIMARY                                            |
    | updated_at     | None                                               |
    | version        | 1                                                  |
    +----------------+----------------------------------------------------+

* Create network with dns_domain

  .. code-block:: console

    $ openstack network create dns-test-network --dns-domain "<project_id>.demo.net."
    +---------------------------+--------------------------------------+
    | Field                     | Value                                |
    +---------------------------+--------------------------------------+
    | admin_state_up            | UP                                   |
    | availability_zone_hints   |                                      |
    | availability_zones        |                                      |
    | created_at                | 2021-02-19T15:16:36Z                 |
    | description               |                                      |
    | dns_domain                | <project_id>.demo.net.               |
    | id                        | fb247287-43aa-4a83-b768-a3b34dc6735a |
    | ipv4_address_scope        | None                                 |
    | ipv6_address_scope        | None                                 |
    | is_default                | False                                |
    | is_vlan_transparent       | None                                 |
    | mtu                       | 1450                                 |
    | name                      | dns-test-network                     |
    | port_security_enabled     | True                                 |
    | project_id                | 0511951bd56e4a0aac27ac65e00bddd0     |
    | provider:network_type     | vxlan                                |
    | provider:physical_network | None                                 |
    | provider:segmentation_id  | 1003                                 |
    | qos_policy_id             | None                                 |
    | revision_number           | 1                                    |
    | router:external           | Internal                             |
    | segments                  | None                                 |
    | shared                    | False                                |
    | status                    | ACTIVE                               |
    | subnets                   |                                      |
    | tags                      |                                      |
    | updated_at                | 2021-02-19T15:16:37Z                 |
    +---------------------------+--------------------------------------+

    $ openstack subnet create --network dns-test-network --subnet-range 192.168.100.0/24 --dns-publish-fixed-ip dns-test-subnet
    +----------------------+--------------------------------------+
    | Field                | Value                                |
    +----------------------+--------------------------------------+
    | allocation_pools     | 192.168.100.2-192.168.100.254        |
    | cidr                 | 192.168.100.0/24                     |
    | created_at           | 2021-02-19T15:21:50Z                 |
    | description          |                                      |
    | dns_nameservers      |                                      |
    | dns_publish_fixed_ip | True                                 |
    | enable_dhcp          | True                                 |
    | gateway_ip           | 192.168.100.1                        |
    | host_routes          |                                      |
    | id                   | 2547a3f2-374f-4262-aed5-3a69af73e732 |
    | ip_version           | 4                                    |
    | ipv6_address_mode    | None                                 |
    | ipv6_ra_mode         | None                                 |
    | name                 | dns-test-subnet                      |
    | network_id           | fb247287-43aa-4a83-b768-a3b34dc6735a |
    | prefix_length        | None                                 |
    | project_id           | 0511951bd56e4a0aac27ac65e00bddd0     |
    | revision_number      | 0                                    |
    | segment_id           | None                                 |
    | service_types        |                                      |
    | subnetpool_id        | None                                 |
    | tags                 |                                      |
    | updated_at           | 2021-02-19T15:21:50Z                 |
    +----------------------+--------------------------------------+

* Create port in that network

  .. code-block:: console

    $ openstack port create --network dns-test-network --dns-name dns-test-port test-port
    +-------------------------+---------------------------------------------------------------------------------------------------------------------------+
    | Field                   | Value                                                                                                                     |
    +-------------------------+---------------------------------------------------------------------------------------------------------------------------+
    | admin_state_up          | UP                                                                                                                        |
    | allowed_address_pairs   |                                                                                                                           |
    | binding_host_id         |                                                                                                                           |
    | binding_profile         |                                                                                                                           |
    | binding_vif_details     |                                                                                                                           |
    | binding_vif_type        | unbound                                                                                                                   |
    | binding_vnic_type       | normal                                                                                                                    |
    | created_at              | 2021-02-19T15:22:51Z                                                                                                      |
    | data_plane_status       | None                                                                                                                      |
    | description             |                                                                                                                           |
    | device_id               |                                                                                                                           |
    | device_owner            |                                                                                                                           |
    | device_profile          | None                                                                                                                      |
    | dns_assignment          | fqdn='dns-test-port.0511951bd56e4a0aac27ac65e00bddd0.example.com.', hostname='dns-test-port', ip_address='192.168.100.17' |
    | dns_domain              |                                                                                                                           |
    | dns_name                | dns-test-port                                                                                                             |
    | extra_dhcp_opts         |                                                                                                                           |
    | fixed_ips               | ip_address='192.168.100.17', subnet_id='2547a3f2-374f-4262-aed5-3a69af73e732'                                             |
    | id                      | f30908a1-6ef5-4137-bff4-c1205c6660ee                                                                                      |
    | ip_allocation           | None                                                                                                                      |
    | mac_address             | fa:16:3e:e8:33:b8                                                                                                         |
    | name                    | test-port                                                                                                                 |
    | network_id              | fb247287-43aa-4a83-b768-a3b34dc6735a                                                                                      |
    | numa_affinity_policy    | None                                                                                                                      |
    | port_security_enabled   | True                                                                                                                      |
    | project_id              | 0511951bd56e4a0aac27ac65e00bddd0                                                                                          |
    | propagate_uplink_status | None                                                                                                                      |
    | qos_network_policy_id   | None                                                                                                                      |
    | qos_policy_id           | None                                                                                                                      |
    | resource_request        | None                                                                                                                      |
    | revision_number         | 1                                                                                                                         |
    | security_group_ids      | 4425c3fd-6705-4134-9878-07b333d81314                                                                                      |
    | status                  | DOWN                                                                                                                      |
    | tags                    |                                                                                                                           |
    | trunk_details           | None                                                                                                                      |
    | updated_at              | 2021-02-19T15:22:51Z                                                                                                      |
    +-------------------------+---------------------------------------------------------------------------------------------------------------------------+

* Test if recordset was created properly in the DNS zone

  .. code-block:: console

    $ openstack recordset list c14a8edc-d0b9-4cdd-93f1-1ab5a5f5ff9d
    +--------------------------------------+-------------------------------------------------------------+------+------------------------------------------------------------------------------------------------------+--------+--------+
    | id                                   | name                                                        | type | records                                                                                              | status | action |
    +--------------------------------------+-------------------------------------------------------------+------+------------------------------------------------------------------------------------------------------+--------+--------+
    | 1c302468-4e30-466e-9330-e4cd9191ff99 | 0511951bd56e4a0aac27ac65e00bddd0.example.com.               | SOA  | ns1.devstack.org. admin.0511951bd56e4a0aac27ac65e00bddd0.example.com. 1613748171 3549 600 86400 3600 | ACTIVE | NONE   |
    | 99ce92d1-8c7a-4193-aeb2-44835048a6fa | 0511951bd56e4a0aac27ac65e00bddd0.example.com.               | NS   | ns1.devstack.org.                                                                                    | ACTIVE | NONE   |
    | 01f0569d-ce81-4424-915f-c6fe6229256e | dns-test-port.0511951bd56e4a0aac27ac65e00bddd0.example.com. | A    | 192.168.100.17                                                                                       | ACTIVE | NONE   |
    +--------------------------------------+-------------------------------------------------------------+------+------------------------------------------------------------------------------------------------------+--------+--------+
