.. _config-subnet-onboard:

==============
Subnet onboard
==============

The subnet onboard feature allows you to take existing subnets that have been
created outside of a subnet pool and move them into an existing subnet pool.
This enables you to begin using subnet pools and address scopes if you haven't
allocated existing subnets from subnet pools. It also allows you to move
individual subnets between subnet pools, and by extension, move them between
address scopes.

How it works
~~~~~~~~~~~~

One of the fundamental constraints of subnet pools is that all subnets of
the same address family (IPv4, IPv6) on a network must be allocated from
the same subnet pool. Because of this constraint, subnets must be moved,
or "onboarded", into a subnet pool as a group at the network level rather than
being handled individually. As such, the onboarding of subnets requires users
to supply the UUID of the network the subnet(s) to onboard are associated with,
and the UUID of the target subnet pool to perform the operation.

Does my environment support subnet onboard?
-------------------------------------------

To test that subnet onboard is supported in your environment, execute
the following command:

.. code-block:: console

    $ openstack extension list --network -c Alias -c Description | grep subnet_onboard
    | subnet_onboard | Provides support for onboarding subnets into subnet pools

Support for subnet onboard exists in the ML2 plugin as of the Stein release. If
you require subnet onboard but your current environment does not support it,
consider upgrading to a release that supports subnet onboard. When using
third-party plugins with neutron, check with the supplier of the plugin
regarding support for subnet onboard.

Demo
----

Suppose an administrator has an existing provider network in their environment
that was created without allocating its subnets from a subnet pool.

.. code-block:: console

    $ openstack network list
    +--------------------------------------+----------------+--------------------------------------+
    | ID                                   | Name           | Subnets                              |
    +--------------------------------------+----------------+--------------------------------------+
    | f643a4f5-f8d3-4325-b1fe-6061a9af0f07 | provider-net-1 | 5153cab7-7ab6-4956-8466-39aa85dccc9a |
    +--------------------------------------+----------------+--------------------------------------+

    $ openstack subnet show 5153cab7-7ab6-4956-8466-39aa85dccc9a
    +-------------------+--------------------------------------+
    | Field             | Value                                |
    +-------------------+--------------------------------------+
    | allocation_pools  | 192.168.0.2-192.168.7.254            |
    | cidr              | 192.168.0.0/21                       |
    | description       |                                      |
    | dns_nameservers   |                                      |
    | enable_dhcp       | True                                 |
    | gateway_ip        | 192.168.0.1                          |
    | host_routes       |                                      |
    | id                | 5153cab7-7ab6-4956-8466-39aa85dccc9a |
    | ip_version        | 4                                    |
    | ipv6_address_mode | None                                 |
    | ipv6_ra_mode      | None                                 |
    | network_id        | f643a4f5-f8d3-4325-b1fe-6061a9af0f07 |
    | prefix_length     | None                                 |
    | project_id        | 7b80998e5e044cee91c1cdb2e9c63afd     |
    | revision_number   | 0                                    |
    | segment_id        | None                                 |
    | service_types     |                                      |
    | subnetpool_id     | None                                 |
    | tags              |                                      |
    | updated_at        | 2019-03-13T18:24:37Z                 |
    +-------------------+--------------------------------------+

The administrator has created a subnet pool named ``routable-prefixes`` and
wants to onboard the subnets associated with network ``provider-net-1``. The
administrator now wants to manage the address space for provider networks using
a subnet pool, but doesn't have the prefixes used by these provider networks
under the management of a subnet pool or address scope.

.. code-block:: console

    $ openstack subnet pool list
    +--------------------------------------+-------------------+--------------+
    | ID                                   | Name              | Prefixes     |
    +--------------------------------------+-------------------+--------------+
    | d05e9f61-248c-43f2-98f4-5142570127e1 | routable-prefixes | 10.10.0.0/16 |
    +--------------------------------------+-------------------+--------------+

.. code-block:: console

    $ openstack subnet pool show routable-prefixes
    +-------------------+--------------------------------+
    | Field             | Value                          |
    +-------------------+--------------------------------+
    | address_scope_id  | None                           |
    | created_at        | 2019-03-102T05:45:01Z          |
    | default_prefixlen | 26                             |
    | default_quota     | None                           |
    | description       | Routable prefixes for projects |
    | headers           |                                |
    | id                | d3aefb76-2527-43d4-bc21-0ec253 |
    |                   | 908545                         |
    | ip_version        | 4                              |
    | is_default        | False                          |
    | max_prefixlen     | 32                             |
    | min_prefixlen     | 8                              |
    | name              | routable-prefixes              |
    | prefixes          | 10.10.0.0/16                   |
    | project_id        | cfd1889ac7d64ad891d4f20aef9f8d |
    |                   | 7c                             |
    | revision_number   | 1                              |
    | shared            | True                           |
    | tags              | []                             |
    | updated_at        | 2019-03-10T05:45:01Z           |
    +-------------------+--------------------------------+

The administrator can use the following command to bring these subnets under
the management of a subnet pool:

.. code-block:: console

    $ openstack network onboard subnets provider-net-1 routable-prefixes

The subnets on ``provider-net-1`` should now all have their subnetpool_id
updated to match the UUID of the ``routable-prefixes`` subnet pool:

.. code-block:: console

    $ openstack subnet show 5153cab7-7ab6-4956-8466-39aa85dccc9a
    +-------------------+--------------------------------------+
    | Field             | Value                                |
    +-------------------+--------------------------------------+
    | allocation_pools  | 192.168.0.2-192.168.7.254            |
    | cidr              | 192.168.0.0/21                       |
    | description       |                                      |
    | dns_nameservers   |                                      |
    | enable_dhcp       | True                                 |
    | gateway_ip        | 192.168.0.1                          |
    | host_routes       |                                      |
    | id                | 5153cab7-7ab6-4956-8466-39aa85dccc9a |
    | ip_version        | 4                                    |
    | ipv6_address_mode | None                                 |
    | ipv6_ra_mode      | None                                 |
    | network_id        | f643a4f5-f8d3-4325-b1fe-6061a9af0f07 |
    | prefix_length     | None                                 |
    | project_id        | 7b80998e5e044cee91c1cdb2e9c63afd     |
    | revision_number   | 0                                    |
    | segment_id        | None                                 |
    | service_types     |                                      |
    | subnetpool_id     | d3aefb76-2527-43d4-bc21-0ec253908545 |
    | updated_at        | 2019-03-13T18:24:37Z                 |
    +-------------------+--------------------------------------+

The subnet pool will also now show the onboarded prefix(es) in its prefix list:

.. code-block:: console

    $ openstack subnet pool show routable-prefixes
    +-------------------+--------------------------------+
    | Field             | Value                          |
    +-------------------+--------------------------------+
    | address_scope_id  | None                           |
    | created_at        | 2019-03-102T05:45:01Z          |
    | default_prefixlen | 26                             |
    | default_quota     | None                           |
    | description       | Routable prefixes for projects |
    | headers           |                                |
    | id                | d3aefb76-2527-43d4-bc21-0ec253 |
    |                   | 908545                         |
    | ip_version        | 4                              |
    | is_default        | False                          |
    | max_prefixlen     | 32                             |
    | min_prefixlen     | 8                              |
    | name              | routable-prefixes              |
    | prefixes          | 10.10.0.0/16, 192.168.0.0/21   |
    | project_id        | cfd1889ac7d64ad891d4f20aef9f8d |
    |                   | 7c                             |
    | revision_number   | 1                              |
    | shared            | True                           |
    | tags              | []                             |
    | updated_at        | 2019-03-12T13:11:037Z          |
    +-------------------+--------------------------------+
