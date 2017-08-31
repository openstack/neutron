.. _config-service-subnets:

===============
Service subnets
===============

Service subnets enable operators to define valid port types for each
subnet on a network without limiting networks to one subnet or manually
creating ports with a specific subnet ID. Using this feature, operators
can ensure that ports for instances and router interfaces, for example,
always use different subnets.

Operation
~~~~~~~~~

Define one or more service types for one or more subnets on a particular
network. Each service type must correspond to a valid device owner within
the port model in order for it to be used.

During IP allocation, the :ref:`IPAM <config-ipam>` driver returns an
address from a subnet with a service type matching the port device
owner. If no subnets match, or all matching subnets lack available IP
addresses, the IPAM driver attempts to use a subnet without any service
types to preserve compatibility. If all subnets on a network have a
service type, the IPAM driver cannot preserve compatibility. However, this
feature enables strict IP allocation from subnets with a matching device
owner. If multiple subnets contain the same service type, or a subnet
without a service type exists, the IPAM driver selects the first subnet
with a matching service type. For example, a floating IP agent gateway port
uses the following selection process:

* ``network:floatingip_agent_gateway``
* ``None``

.. note::

   Ports with the device owner ``network:dhcp`` are exempt from the above IPAM
   logic for subnets with ``dhcp_enabled`` set to ``True``. This preserves the
   existing automatic DHCP port creation behaviour for DHCP-enabled subnets.

Creating or updating a port with a specific subnet skips this selection
process and explicitly uses the given subnet.

Usage
~~~~~

.. note::

   Creating a subnet with a service type requires administrative
   privileges.

Example 1 - Proof-of-concept
----------------------------

This following example is not typical of an actual deployment. It is shown
to allow users to experiment with configuring service subnets.

#. Create a network.

   .. code-block:: console

      $ openstack network create demo-net1
      +---------------------------+--------------------------------------+
      | Field                     | Value                                |
      +---------------------------+--------------------------------------+
      | admin_state_up            | UP                                   |
      | availability_zone_hints   |                                      |
      | availability_zones        |                                      |
      | description               |                                      |
      | headers                   |                                      |
      | id                        | b5b729d8-31cc-4d2c-8284-72b3291fec02 |
      | ipv4_address_scope        | None                                 |
      | ipv6_address_scope        | None                                 |
      | mtu                       | 1450                                 |
      | name                      | demo-net1                            |
      | port_security_enabled     | True                                 |
      | project_id                | a3db43cd0f224242a847ab84d091217d     |
      | provider:network_type     | vxlan                                |
      | provider:physical_network | None                                 |
      | provider:segmentation_id  | 110                                  |
      | revision_number           | 1                                    |
      | router:external           | Internal                             |
      | shared                    | False                                |
      | status                    | ACTIVE                               |
      | subnets                   |                                      |
      | tags                      | []                                   |
      +---------------------------+--------------------------------------+

#. Create a subnet on the network with one or more service types. For
   example, the ``compute:nova`` service type enables instances to use
   this subnet.

   .. code-block:: console

      $ openstack subnet create demo-subnet1 --subnet-range 192.0.2.0/24 \
        --service-type 'compute:nova' --network demo-net1
      +-------------------+--------------------------------------+
      | Field             | Value                                |
      +-------------------+--------------------------------------+
      | id                | 6e38b23f-0b27-4e3c-8e69-fd23a3df1935 |
      | ip_version        | 4                                    |
      | cidr              | 192.0.2.0/24                         |
      | name              | demo-subnet1                         |
      | network_id        | b5b729d8-31cc-4d2c-8284-72b3291fec02 |
      | revision_number   | 1                                    |
      | service_types     | ['compute:nova']                     |
      | tags              | []                                   |
      | tenant_id         | a8b3054cc1214f18b1186b291525650f     |
      +-------------------+--------------------------------------+

#. Optionally, create another subnet on the network with a different service
   type. For example, the ``compute:foo`` arbitrary service type.

   .. code-block:: console

      $ openstack subnet create demo-subnet2 --subnet-range 198.51.100.0/24 \
        --service-type 'compute:foo' --network demo-net1
      +-------------------+--------------------------------------+
      | Field             | Value                                |
      +-------------------+--------------------------------------+
      | id                | ea139dcd-17a3-4f0a-8cca-dff8b4e03f8a |
      | ip_version        | 4                                    |
      | cidr              | 198.51.100.0/24                      |
      | name              | demo-subnet2                         |
      | network_id        | b5b729d8-31cc-4d2c-8284-72b3291fec02 |
      | revision_number   | 1                                    |
      | service_types     | ['compute:foo']                      |
      | tags              | []                                   |
      | tenant_id         | a8b3054cc1214f18b1186b291525650f     |
      +-------------------+--------------------------------------+

#. Launch an instance using the network. For example, using the ``cirros``
   image and ``m1.tiny`` flavor.

   .. code-block:: console

      $ openstack server create demo-instance1 --flavor m1.tiny \
        --image cirros --nic net-id=b5b729d8-31cc-4d2c-8284-72b3291fec02
      +--------------------------------------+-----------------------------------------------+
      | Field                                | Value                                         |
      +--------------------------------------+-----------------------------------------------+
      | OS-DCF:diskConfig                    | MANUAL                                        |
      | OS-EXT-AZ:availability_zone          |                                               |
      | OS-EXT-SRV-ATTR:host                 | None                                          |
      | OS-EXT-SRV-ATTR:hypervisor_hostname  | None                                          |
      | OS-EXT-SRV-ATTR:instance_name        | instance-00000009                             |
      | OS-EXT-STS:power_state               | 0                                             |
      | OS-EXT-STS:task_state                | scheduling                                    |
      | OS-EXT-STS:vm_state                  | building                                      |
      | OS-SRV-USG:launched_at               | None                                          |
      | OS-SRV-USG:terminated_at             | None                                          |
      | accessIPv4                           |                                               |
      | accessIPv6                           |                                               |
      | addresses                            |                                               |
      | adminPass                            | Fn85skabdxBL                                  |
      | config_drive                         |                                               |
      | created                              | 2016-09-19T15:07:42Z                          |
      | flavor                               | m1.tiny (1)                                   |
      | hostId                               |                                               |
      | id                                   | 04222b73-1a6e-4c2a-9af4-ef3d17d521ff          |
      | image                                | cirros (4aaec87d-c655-4856-8618-b2dada3a2b11) |
      | key_name                             | None                                          |
      | name                                 | demo-instance1                                |
      | os-extended-volumes:volumes_attached | []                                            |
      | progress                             | 0                                             |
      | project_id                           | d44c19e056674381b86430575184b167              |
      | properties                           |                                               |
      | security_groups                      | [{u'name': u'default'}]                       |
      | status                               | BUILD                                         |
      | updated                              | 2016-09-19T15:07:42Z                          |
      | user_id                              | 331afbeb322d4c559a181e19051ae362              |
      +--------------------------------------+-----------------------------------------------+

#. Check the instance status. The ``Networks`` field contains an IP address
   from the subnet having the ``compute:nova`` service type.

   .. code-block:: console

      $ openstack server list
      +--------------------------------------+-----------------+---------+---------------------+
      | ID                                   | Name            | Status  | Networks            |
      +--------------------------------------+-----------------+---------+---------------------+
      | 20181f46-5cd2-4af8-9af0-f4cf5c983008 | demo-instance1  | ACTIVE  | demo-net1=192.0.2.3 |
      +--------------------------------------+-----------------+---------+---------------------+

Example 2 - DVR configuration
-----------------------------

The following example outlines how you can configure service subnets in
a DVR-enabled deployment, with the goal of minimizing public IP
address consumption. This example uses three subnets on the same external
network:

* 192.0.2.0/24 for instance floating IP addresses
* 198.51.100.0/24 for floating IP agent gateway IPs configured on compute nodes
* 203.0.113.0/25 for all other IP allocations on the external network

This example uses again the private network, ``demo-net1``
(b5b729d8-31cc-4d2c-8284-72b3291fec02) which was created in
`Example 1 - Proof-of-concept`_.

.. note:

   The output of the commands is not always shown since it
   is very similar to the above.

#. Create an external network:

   .. code-block:: console

      $ openstack network create --external demo-ext-net

#. Create a subnet on the external network for the instance floating IP
   addresses. This uses the ``network:floatingip`` service type.

   .. code-block:: console

      $ openstack subnet create demo-floating-ip-subnet \
        --subnet-range 192.0.2.0/24 --no-dhcp \
        --service-type 'network:floatingip' --network demo-ext-net

#. Create a subnet on the external network for the floating IP agent
   gateway IP addresses, which are configured by DVR on compute nodes.
   This will use the ``network:floatingip_agent_gateway`` service type.

   .. code-block:: console

      $ openstack subnet create demo-floating-ip-agent-gateway-subnet \
        --subnet-range 198.51.100.0/24 --no-dhcp \
        --service-type 'network:floatingip_agent_gateway' \
        --network demo-ext-net

#. Create a subnet on the external network for all other IP addresses
   allocated on the external network. This will not use any service
   type. It acts as a fall back for allocations that do not match
   either of the above two service subnets.

   .. code-block:: console

      $ openstack subnet create demo-other-subnet \
        --subnet-range 203.0.113.0/25 --no-dhcp \
        --network demo-ext-net

#. Create a router:

   .. code-block:: console

      $ openstack router create demo-router

#. Add an interface to the router on demo-subnet1:

   .. code-block:: console

      $ openstack router add subnet demo-router demo-subnet1

#. Set the external gateway for the router, which will create an
   interface and allocate an IP address on demo-ext-net:

   .. code-block:: console

      $ neutron router-gateway-set demo-router demo-ext-net

#. Launch an instance on a private network and retrieve the neutron
   port ID that was allocated. As above, use the ``cirros``
   image and ``m1.tiny`` flavor:

   .. code-block:: console

      $ openstack server create demo-instance1 --flavor m1.tiny \
        --image cirros --nic net-id=b5b729d8-31cc-4d2c-8284-72b3291fec02
      $ openstack port list --server demo-instance1
      +--------------------------------------+------+-------------------+--------------------------------------------------+--------+
      | ID                                   | Name | MAC Address       | Fixed IP Addresses                               | Status |
      +--------------------------------------+------+-------------------+--------------------------------------------------+--------+
      | a752bb24-9bf2-4d37-b9d6-07da69c86f19 |      | fa:16:3e:99:54:32 | ip_address='203.0.113.130',                      | ACTIVE |
      |                                      |      |                   | subnet_id='6e38b23f-0b27-4e3c-8e69-fd23a3df1935' |        |
      +--------------------------------------+------+-------------------+--------------------------------------------------+--------+

#. Associate a floating IP with the instance port and verify it was
   allocated an IP address from the correct subnet:

   .. code-block:: console

      $ openstack floating ip create --port \
        a752bb24-9bf2-4d37-b9d6-07da69c86f19 demo-ext-net
      +---------------------+--------------------------------------+
      | Field               | Value                                |
      +---------------------+--------------------------------------+
      | fixed_ip_address    | 203.0.113.130                        |
      | floating_ip_address | 192.0.2.12                           |
      | floating_network_id | 02d236d5-dad9-4082-bb6b-5245f9f84d13 |
      | id                  | f15cae7f-5e05-4b19-bd25-4bb71edcf3de |
      | port_id             | a752bb24-9bf2-4d37-b9d6-07da69c86f19 |
      | project_id          | d44c19e056674381b86430575184b167     |
      | revision_number     | 1                                    |
      | router_id           | 5a8ca19f-3703-4f81-bc29-db6bc2f528d6 |
      | status              | ACTIVE                               |
      | tags                | []                                   |
      +---------------------+--------------------------------------+

#. As the `admin` user, verify the neutron routers are allocated IP
   addresses from their correct subnets. Use ``openstack port list``
   to find ports associated with the routers.

   First, the router gateway external port:

   .. code-block:: console

      $ neutron port-show f148ffeb-3c26-4067-bc5f-5c3dfddae2f5
      +-----------------------+--------------------------------------------------------------------------+
      | Field                 | Value                                                                    |
      +-----------------------+--------------------------------------------------------------------------+
      | admin_state_up        | UP                                                                       |
      | device_id             | 5a8ca19f-3703-4f81-bc29-db6bc2f528d6                                     |
      | device_owner          | network:router_gateway                                                   |
      | extra_dhcp_opts       |                                                                          |
      | fixed_ips             | ip_address='203.0.113.11',                                               |
      |                       | subnet_id='67c251d9-2b7a-4200-99f6-e13785b0334d'                         |
      | id                    | f148ffeb-3c26-4067-bc5f-5c3dfddae2f5                                     |
      | mac_address           | fa:16:3e:2c:0f:69                                                        |
      | network_id            | 02d236d5-dad9-4082-bb6b-5245f9f84d13                                     |
      | revision_number       | 1                                                                        |
      | project_id            |                                                                          |
      | status                | ACTIVE                                                                   |
      | tags                  | []                                                                       |
      +-----------------------+--------------------------------------------------------------------------+

   Second, the router floating IP agent gateway external port:

   .. code-block:: console

      $ neutron port-show a2d1e756-8ae1-4f96-9aa1-e7ea16a6a68a
      +-----------------------+--------------------------------------------------------------------------+
      | Field                 | Value                                                                    |
      +-----------------------+--------------------------------------------------------------------------+
      | admin_state_up        | UP                                                                       |
      | device_id             | 3d0c98eb-bca3-45cc-8aa4-90ae3deb0844                                     |
      | device_owner          | network:floatingip_agent_gateway                                         |
      | extra_dhcp_opts       |                                                                          |
      | fixed_ips             | ip_address='198.51.100.10',                                              |
      |                       | subnet_id='67c251d9-2b7a-4200-99f6-e13785b0334d'                         |
      | id                    | a2d1e756-8ae1-4f96-9aa1-e7ea16a6a68a                                     |
      | mac_address           | fa:16:3e:f4:5d:fa                                                        |
      | network_id            | 02d236d5-dad9-4082-bb6b-5245f9f84d13                                     |
      | project_id            |                                                                          |
      | revision_number       | 1                                                                        |
      | status                | ACTIVE                                                                   |
      | tags                  | []                                                                       |
      +-----------------------+--------------------------------------------------------------------------+
