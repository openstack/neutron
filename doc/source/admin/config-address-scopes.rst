.. _config-address-scopes:

==============
Address scopes
==============

Address scopes build from subnet pools. While subnet pools provide a mechanism
for controlling the allocation of addresses to subnets, address scopes show
where addresses can be routed between networks, preventing the use of
overlapping addresses in any two subnets. Because all addresses allocated in
the address scope do not overlap, neutron routers do not NAT between your
projects' network and your external network. As long as the addresses within
an address scope match, the Networking service performs simple routing
between networks.

Accessing address scopes
~~~~~~~~~~~~~~~~~~~~~~~~

Anyone with access to the Networking service can create their own address
scopes. However, network administrators can create shared address scopes,
allowing other projects to create networks within that address scope.

Access to addresses in a scope are managed through subnet pools.
Subnet pools can either be created in an address scope, or updated to belong
to an address scope.

With subnet pools, all addresses in use within the address
scope are unique from the point of view of the address scope owner. Therefore,
add more than one subnet pool to an address scope if the
pools have different owners, allowing for delegation of parts of the
address scope. Delegation prevents address overlap across the
whole scope. Otherwise, you receive an error if two pools have the same
address ranges.

Each router interface is associated with an address scope by looking at
subnets connected to the network. When a router connects
to an external network with matching address scopes, network traffic routes
between without Network address translation (NAT).
The router marks all traffic connections originating from each interface
with its corresponding address scope. If traffic leaves an interface in the
wrong scope, the router blocks the traffic.

Backwards compatibility
~~~~~~~~~~~~~~~~~~~~~~~

Networks created before the Mitaka release do not
contain explicitly named address scopes, unless the network contains
subnets from a subnet pool that belongs to a created or updated
address scope. The Networking service preserves backwards compatibility with
pre-Mitaka networks through special address scope properties so that
these networks can perform advanced routing:

#. Unlimited address overlap is allowed.
#. Neutron routers, by default, will NAT traffic from internal networks
   to external networks.
#. Pre-Mitaka address scopes are not visible through the API. You cannot
   list address scopes or show details. Scopes exist
   implicitly as a catch-all for addresses that are not explicitly scoped.

Create shared address scopes as an administrative user
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This section shows how to set up shared address scopes to
allow simple routing for project networks with the same subnet pools.

.. note:: Irrelevant fields have been trimmed from the output of
    these commands for brevity.

#. Create IPv6 and IPv4 address scopes:

   .. code-block:: console

      $ openstack address scope create --share --ip-version 6 address-scope-ip6

      +------------+--------------------------------------+
      | Field      | Value                                |
      +------------+--------------------------------------+
      | headers    |                                      |
      | id         | 28424dfc-9abd-481b-afa3-1da97a8fead7 |
      | ip_version | 6                                    |
      | name       | address-scope-ip6                    |
      | project_id | 098429d072d34d3596c88b7dbf7e91b6     |
      | shared     | True                                 |
      +------------+--------------------------------------+

   .. code-block:: console

      $ openstack address scope create --share --ip-version 4 address-scope-ip4

      +------------+--------------------------------------+
      | Field      | Value                                |
      +------------+--------------------------------------+
      | headers    |                                      |
      | id         | 3193bd62-11b5-44dc-acf8-53180f21e9f2 |
      | ip_version | 4                                    |
      | name       | address-scope-ip4                    |
      | project_id | 098429d072d34d3596c88b7dbf7e91b6     |
      | shared     | True                                 |
      +------------+--------------------------------------+


#. Create subnet pools specifying the name (or UUID) of the address
   scope that the subnet pool belongs to. If you have existing
   subnet pools, use the :command:`openstack subnet pool set` command to put
   them in a new address scope:

   .. code-block:: console

      $ openstack subnet pool create --address-scope address-scope-ip6 \
      --share --pool-prefix 2001:db8:a583::/48 --default-prefix-length 64 \
      subnet-pool-ip6
      +-------------------+--------------------------------------+
      | Field             | Value                                |
      +-------------------+--------------------------------------+
      | address_scope_id  | 28424dfc-9abd-481b-afa3-1da97a8fead7 |
      | created_at        | 2016-12-13T22:53:30Z                 |
      | default_prefixlen | 64                                   |
      | default_quota     | None                                 |
      | description       |                                      |
      | id                | a59ff52b-0367-41ff-9781-6318b927dd0e |
      | ip_version        | 6                                    |
      | is_default        | False                                |
      | max_prefixlen     | 128                                  |
      | min_prefixlen     | 64                                   |
      | name              | subnet-pool-ip6                      |
      | prefixes          | 2001:db8:a583::/48                   |
      | project_id        | 098429d072d34d3596c88b7dbf7e91b6     |
      | revision_number   | 1                                    |
      | shared            | True                                 |
      | tags              | []                                   |
      | updated_at        | 2016-12-13T22:53:30Z                 |
      +-------------------+--------------------------------------+


   .. code-block:: console

      $ openstack subnet pool create --address-scope address-scope-ip4 \
      --share --pool-prefix 203.0.113.0/24 --default-prefix-length 26 \
      subnet-pool-ip4
      +-------------------+--------------------------------------+
      | Field             | Value                                |
      +-------------------+--------------------------------------+
      | address_scope_id  | 3193bd62-11b5-44dc-acf8-53180f21e9f2 |
      | created_at        | 2016-12-13T22:55:09Z                 |
      | default_prefixlen | 26                                   |
      | default_quota     | None                                 |
      | description       |                                      |
      | id                | d02af70b-d622-426f-8e60-ed9df2a8301f |
      | ip_version        | 4                                    |
      | is_default        | False                                |
      | max_prefixlen     | 32                                   |
      | min_prefixlen     | 8                                    |
      | name              | subnet-pool-ip4                      |
      | prefixes          | 203.0.113.0/24                       |
      | project_id        | 098429d072d34d3596c88b7dbf7e91b6     |
      | revision_number   | 1                                    |
      | shared            | True                                 |
      | tags              | []                                   |
      | updated_at        | 2016-12-13T22:55:09Z                 |
      +-------------------+--------------------------------------+


#. Make sure that subnets on an external network are created
   from the subnet pools created above:

   .. code-block:: console

      $ openstack subnet show ipv6-public-subnet
      +-------------------+------------------------------------------+
      | Field             | Value                                    |
      +-------------------+------------------------------------------+
      | allocation_pools  | 2001:db8:a583::2-2001:db8:a583:0:ffff:ff |
      |                   | ff:ffff:ffff                             |
      | cidr              | 2001:db8:a583::/64                       |
      | created_at        | 2016-12-10T21:36:04Z                     |
      | description       |                                          |
      | dns_nameservers   |                                          |
      | enable_dhcp       | False                                    |
      | gateway_ip        | 2001:db8:a583::1                         |
      | host_routes       |                                          |
      | id                | b333bf5a-758c-4b3f-97ec-5f12d9bfceb7     |
      | ip_version        | 6                                        |
      | ipv6_address_mode | None                                     |
      | ipv6_ra_mode      | None                                     |
      | name              | ipv6-public-subnet                       |
      | network_id        | 05a8d31e-330b-4d96-a3fa-884b04abfa4c     |
      | project_id        | 098429d072d34d3596c88b7dbf7e91b6         |
      | revision_number   | 2                                        |
      | segment_id        | None                                     |
      | service_types     |                                          |
      | subnetpool_id     | a59ff52b-0367-41ff-9781-6318b927dd0e     |
      | tags              | []                                       |
      | updated_at        | 2016-12-10T21:36:04Z                     |
      +-------------------+------------------------------------------+


   .. code-block:: console

      $ openstack subnet show public-subnet
      +-------------------+--------------------------------------+
      | Field             | Value                                |
      +-------------------+--------------------------------------+
      | allocation_pools  | 203.0.113.2-203.0.113.62             |
      | cidr              | 203.0.113.0/26                       |
      | created_at        | 2016-12-10T21:35:52Z                 |
      | description       |                                      |
      | dns_nameservers   |                                      |
      | enable_dhcp       | False                                |
      | gateway_ip        | 203.0.113.1                          |
      | host_routes       |                                      |
      | id                | 7fd48240-3acc-4724-bc82-16c62857edec |
      | ip_version        | 4                                    |
      | ipv6_address_mode | None                                 |
      | ipv6_ra_mode      | None                                 |
      | name              | public-subnet                        |
      | network_id        | 05a8d31e-330b-4d96-a3fa-884b04abfa4c |
      | project_id        | 098429d072d34d3596c88b7dbf7e91b6     |
      | revision_number   | 2                                    |
      | segment_id        | None                                 |
      | service_types     |                                      |
      | subnetpool_id     | d02af70b-d622-426f-8e60-ed9df2a8301f |
      | tags              | []                                   |
      | updated_at        | 2016-12-10T21:35:52Z                 |
      +-------------------+--------------------------------------+

Routing with address scopes for non-privileged users
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This section shows how non-privileged users can use address scopes to
route straight to an external network without NAT.

#. Create a couple of networks to host subnets:

   .. code-block:: console

    $ openstack network create network1
    +---------------------------+--------------------------------------+
    | Field                     | Value                                |
    +---------------------------+--------------------------------------+
    | admin_state_up            | UP                                   |
    | availability_zone_hints   |                                      |
    | availability_zones        |                                      |
    | created_at                | 2016-12-13T23:21:01Z                 |
    | description               |                                      |
    | headers                   |                                      |
    | id                        | 1bcf3fe9-a0cb-4d88-a067-a4d7f8e635f0 |
    | ipv4_address_scope        | None                                 |
    | ipv6_address_scope        | None                                 |
    | mtu                       | 1450                                 |
    | name                      | network1                             |
    | port_security_enabled     | True                                 |
    | project_id                | 098429d072d34d3596c88b7dbf7e91b6     |
    | provider:network_type     | vxlan                                |
    | provider:physical_network | None                                 |
    | provider:segmentation_id  | 94                                   |
    | revision_number           | 3                                    |
    | router:external           | Internal                             |
    | shared                    | False                                |
    | status                    | ACTIVE                               |
    | subnets                   |                                      |
    | tags                      | []                                   |
    | updated_at                | 2016-12-13T23:21:01Z                 |
    +---------------------------+--------------------------------------+


   .. code-block:: console

      $ openstack network create network2
      +---------------------------+--------------------------------------+
      | Field                     | Value                                |
      +---------------------------+--------------------------------------+
      | admin_state_up            | UP                                   |
      | availability_zone_hints   |                                      |
      | availability_zones        |                                      |
      | created_at                | 2016-12-13T23:21:45Z                 |
      | description               |                                      |
      | headers                   |                                      |
      | id                        | 6c583603-c097-4141-9c5c-288b0e49c59f |
      | ipv4_address_scope        | None                                 |
      | ipv6_address_scope        | None                                 |
      | mtu                       | 1450                                 |
      | name                      | network2                             |
      | port_security_enabled     | True                                 |
      | project_id                | 098429d072d34d3596c88b7dbf7e91b6     |
      | provider:network_type     | vxlan                                |
      | provider:physical_network | None                                 |
      | provider:segmentation_id  | 81                                   |
      | revision_number           | 3                                    |
      | router:external           | Internal                             |
      | shared                    | False                                |
      | status                    | ACTIVE                               |
      | subnets                   |                                      |
      | tags                      | []                                   |
      | updated_at                | 2016-12-13T23:21:45Z                 |
      +---------------------------+--------------------------------------+

#. Create a subnet not associated with a subnet pool or
   an address scope:

   .. code-block:: console

      $ openstack subnet create --network network1 --subnet-range \
      198.51.100.0/26 subnet-ip4-1
      +-------------------+--------------------------------------+
      | Field             | Value                                |
      +-------------------+--------------------------------------+
      | allocation_pools  | 198.51.100.2-198.51.100.62           |
      | cidr              | 198.51.100.0/26                      |
      | created_at        | 2016-12-13T23:24:16Z                 |
      | description       |                                      |
      | dns_nameservers   |                                      |
      | enable_dhcp       | True                                 |
      | gateway_ip        | 198.51.100.1                         |
      | headers           |                                      |
      | host_routes       |                                      |
      | id                | 66874039-d31b-4a27-85d7-14c89341bbb7 |
      | ip_version        | 4                                    |
      | ipv6_address_mode | None                                 |
      | ipv6_ra_mode      | None                                 |
      | name              | subnet-ip4-1                         |
      | network_id        | 1bcf3fe9-a0cb-4d88-a067-a4d7f8e635f0 |
      | project_id        | 098429d072d34d3596c88b7dbf7e91b6     |
      | revision_number   | 2                                    |
      | service_types     |                                      |
      | subnetpool_id     | None                                 |
      | tags              | []                                   |
      | updated_at        | 2016-12-13T23:24:16Z                 |
      +-------------------+--------------------------------------+


   .. code-block:: console

      $ openstack subnet create --network network1 --ipv6-ra-mode slaac \
      --ipv6-address-mode slaac --ip-version 6 --subnet-range \
      2001:db8:80d2:c4d3::/64 subnet-ip6-1
      +-------------------+-----------------------------------------+
      | Field             | Value                                   |
      +-------------------+-----------------------------------------+
      | allocation_pools  | 2001:db8:80d2:c4d3::2-2001:db8:80d2:c4d |
      |                   | 3:ffff:ffff:ffff:ffff                   |
      | cidr              | 2001:db8:80d2:c4d3::/64                 |
      | created_at        | 2016-12-13T23:28:28Z                    |
      | description       |                                         |
      | dns_nameservers   |                                         |
      | enable_dhcp       | True                                    |
      | gateway_ip        | 2001:db8:80d2:c4d3::1                   |
      | headers           |                                         |
      | host_routes       |                                         |
      | id                | a7551b23-2271-4a88-9c41-c84b048e0722    |
      | ip_version        | 6                                       |
      | ipv6_address_mode | slaac                                   |
      | ipv6_ra_mode      | slaac                                   |
      | name              | subnet-ip6-1                            |
      | network_id        | 1bcf3fe9-a0cb-4d88-a067-a4d7f8e635f0    |
      | project_id        | 098429d072d34d3596c88b7dbf7e91b6        |
      | revision_number   | 2                                       |
      | service_types     |                                         |
      | subnetpool_id     | None                                    |
      | tags              | []                                      |
      | updated_at        | 2016-12-13T23:28:28Z                    |
      +-------------------+-----------------------------------------+


#. Create a subnet using a subnet pool associated with an address scope
   from an external network:

   .. code-block:: console

      $ openstack subnet create --subnet-pool subnet-pool-ip4 \
      --network network2 subnet-ip4-2
      +-------------------+--------------------------------------+
      | Field             | Value                                |
      +-------------------+--------------------------------------+
      | allocation_pools  | 203.0.113.2-203.0.113.62             |
      | cidr              | 203.0.113.0/26                       |
      | created_at        | 2016-12-13T23:32:12Z                 |
      | description       |                                      |
      | dns_nameservers   |                                      |
      | enable_dhcp       | True                                 |
      | gateway_ip        | 203.0.113.1                          |
      | headers           |                                      |
      | host_routes       |                                      |
      | id                | 12be8e8f-5871-4091-9e9e-4e0651b9677e |
      | ip_version        | 4                                    |
      | ipv6_address_mode | None                                 |
      | ipv6_ra_mode      | None                                 |
      | name              | subnet-ip4-2                         |
      | network_id        | 6c583603-c097-4141-9c5c-288b0e49c59f |
      | project_id        | 098429d072d34d3596c88b7dbf7e91b6     |
      | revision_number   | 2                                    |
      | service_types     |                                      |
      | subnetpool_id     | d02af70b-d622-426f-8e60-ed9df2a8301f |
      | tags              | []                                   |
      | updated_at        | 2016-12-13T23:32:12Z                 |
      +-------------------+--------------------------------------+

   .. code-block:: console

      $ openstack subnet create --ip-version 6 --ipv6-ra-mode slaac \
      --ipv6-address-mode slaac --subnet-pool subnet-pool-ip6 \
      --network network2 subnet-ip6-2
      +-------------------+--------------------------------------+
      | Field             | Value                                |
      +-------------------+--------------------------------------+
      | allocation_pools  | 2001:db8:a583::2-2001:db8:a583:0:fff |
      |                   | f:ffff:ffff:ffff                     |
      | cidr              | 2001:db8:a583::/64                   |
      | created_at        | 2016-12-13T23:31:17Z                 |
      | description       |                                      |
      | dns_nameservers   |                                      |
      | enable_dhcp       | True                                 |
      | gateway_ip        | 2001:db8:a583::1                     |
      | headers           |                                      |
      | host_routes       |                                      |
      | id                | b599c2be-e3cd-449c-ba39-3cfcc744c4be |
      | ip_version        | 6                                    |
      | ipv6_address_mode | slaac                                |
      | ipv6_ra_mode      | slaac                                |
      | name              | subnet-ip6-2                         |
      | network_id        | 6c583603-c097-4141-9c5c-288b0e49c59f |
      | project_id        | 098429d072d34d3596c88b7dbf7e91b6     |
      | revision_number   | 2                                    |
      | service_types     |                                      |
      | subnetpool_id     | a59ff52b-0367-41ff-9781-6318b927dd0e |
      | tags              | []                                   |
      | updated_at        | 2016-12-13T23:31:17Z                 |
      +-------------------+--------------------------------------+

   By creating subnets from scoped subnet pools, the network is
   associated with the address scope.

   .. code-block:: console

      $ openstack network show network2
      +---------------------------+------------------------------+
      | Field                     | Value                        |
      +---------------------------+------------------------------+
      | admin_state_up            | UP                           |
      | availability_zone_hints   |                              |
      | availability_zones        | nova                         |
      | created_at                | 2016-12-13T23:21:45Z         |
      | description               |                              |
      | id                        | 6c583603-c097-4141-9c5c-     |
      |                           | 288b0e49c59f                 |
      | ipv4_address_scope        | 3193bd62-11b5-44dc-          |
      |                           | acf8-53180f21e9f2            |
      | ipv6_address_scope        | 28424dfc-9abd-481b-          |
      |                           | afa3-1da97a8fead7            |
      | mtu                       | 1450                         |
      | name                      | network2                     |
      | port_security_enabled     | True                         |
      | project_id                | 098429d072d34d3596c88b7dbf7e |
      |                           | 91b6                         |
      | provider:network_type     | vxlan                        |
      | provider:physical_network | None                         |
      | provider:segmentation_id  | 81                           |
      | revision_number           | 10                           |
      | router:external           | Internal                     |
      | shared                    | False                        |
      | status                    | ACTIVE                       |
      | subnets                   | 12be8e8f-5871-4091-9e9e-     |
      |                           | 4e0651b9677e, b599c2be-e3cd- |
      |                           | 449c-ba39-3cfcc744c4be       |
      | tags                      | []                           |
      | updated_at                | 2016-12-13T23:32:12Z         |
      +---------------------------+------------------------------+

#. Connect a router to each of the project subnets that have been created, for
   example, using a router called ``router1``:

   .. code-block:: console

      $ openstack router add subnet router1 subnet-ip4-1
      $ openstack router add subnet router1 subnet-ip4-2
      $ openstack router add subnet router1 subnet-ip6-1
      $ openstack router add subnet router1 subnet-ip6-2

Checking connectivity
---------------------

This example shows how to check the connectivity between networks
with address scopes.

#. Launch two instances, ``instance1`` on ``network1`` and
   ``instance2`` on ``network2``. Associate a floating IP address to both
   instances.

#. Adjust security groups to allow pings and SSH (both IPv4 and IPv6):

   .. code-block:: console

      $ openstack server list
      +--------------+-----------+---------------------------------------------------------------------------+------------+
      | ID           | Name      | Networks                                                                  | Image Name |
      +--------------+-----------+---------------------------------------------------------------------------+------------+
      | 97e49c8e-... | instance1 | network1=2001:db8:80d2:c4d3:f816:3eff:fe52:b69f, 198.51.100.3, 203.0.113.3| cirros     |
      | ceba9638-... | instance2 | network2=203.0.113.3, 2001:db8:a583:0:f816:3eff:fe42:1eeb, 203.0.113.4    | centos     |
      +--------------+-----------+---------------------------------------------------------------------------+------------+

Regardless of address scopes, the floating IPs can be pinged from the
external network:

.. code-block:: console

    $ ping -c 1 203.0.113.3
    1 packets transmitted, 1 received, 0% packet loss, time 0ms
    $ ping -c 1 203.0.113.4
    1 packets transmitted, 1 received, 0% packet loss, time 0ms

You can now ping ``instance2`` directly because ``instance2`` shares the
same address scope as the external network:

.. note:: BGP routing can be used to automatically set up a static
   route for your instances.

.. code-block:: console

    # ip route add 203.0.113.0/26 via 203.0.113.2
    $ ping -c 1 203.0.113.3
    1 packets transmitted, 1 received, 0% packet loss, time 0ms

.. code-block:: console

    # ip route add 2001:db8:a583::/64 via 2001:db8::1
    $ ping6 -c 1 2001:db8:a583:0:f816:3eff:fe42:1eeb
    1 packets transmitted, 1 received, 0% packet loss, time 0ms

You cannot ping ``instance1`` directly because the address scopes do not
match:

.. code-block:: console

    # ip route add 198.51.100.0/26 via 203.0.113.2
    $ ping -c 1 198.51.100.3
    1 packets transmitted, 0 received, 100% packet loss, time 0ms

.. code-block:: console

    # ip route add 2001:db8:80d2:c4d3::/64 via 2001:db8::1
    $ ping6 -c 1 2001:db8:80d2:c4d3:f816:3eff:fe52:b69f
    1 packets transmitted, 0 received, 100% packet loss, time 0ms

If the address scopes match between
networks then pings and other traffic route directly through. If the
scopes do not match between networks, the router either drops the
traffic or applies NAT to cross scope boundaries.
