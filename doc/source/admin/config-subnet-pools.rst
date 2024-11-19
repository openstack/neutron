.. _config-subnet-pools:

============
Subnet Pools
============

Subnet pools have been made available since the Kilo release. It is a simple
feature that has the potential to improve your workflow considerably. It also
provides a building block from which other new features will be built in to
OpenStack Networking.

To see if your cloud has this feature available, you can check that it is
listed in the supported aliases. You can do this with the OpenStack client.

.. code-block:: console

    $ openstack extension list | grep subnet_allocation
    | Subnet Allocation | subnet_allocation | Enables allocation of subnets
    from a subnet pool                                                                                                         |

Why you need them
~~~~~~~~~~~~~~~~~

Before Kilo, Networking had no automation around the addresses used to create a
subnet. To create one, you had to come up with the addresses on your own
without any help from the system. There are valid use cases for this but if you
are interested in the following capabilities, then subnet pools might be for
you.

First, would not it be nice if you could turn your pool of addresses over to
Neutron to take care of?  When you need to create a subnet, you just ask for
addresses to be allocated from the pool. You do not have to worry about what
you have already used and what addresses are in your pool. Subnet pools can do
this.

Second, subnet pools can manage addresses across projects. The addresses are
guaranteed not to overlap. If the addresses come from an externally routable
pool then you know that all of the projects have addresses which are *routable*
and unique. This can be useful in the following scenarios.

#. IPv6 since OpenStack Networking has no IPv6 floating IPs.
#. Routing directly to a project network from an external network.

How they work
~~~~~~~~~~~~~

A subnet pool manages a pool of addresses from which subnets can be allocated.
It ensures that there is no overlap between any two subnets allocated from the
same pool.

As a regular project in an OpenStack cloud, you can create a subnet pool of
your own and use it to manage your own pool of addresses. This does not require
any admin privileges. Your pool will not be visible to any other project.

If you are an admin, you can create a pool which can be accessed by any regular
project. Being a shared resource, there is a quota mechanism to arbitrate
access.

Quotas
~~~~~~

Subnet pools have a quota system which is a little bit different than
other quotas in Neutron. Other quotas in Neutron count discrete
instances of an object against a quota. Each time you create something
like a router, network, or a port, it uses one from your total quota.

With subnets, the resource is the IP address space. Some subnets take
more of it than others. For example, 203.0.113.0/24 uses 256 addresses
in one subnet but 198.51.100.224/28 uses only 16. If address space is
limited, the quota system can encourage efficient use of the space.

With IPv4, the default_quota can be set to the number of absolute
addresses any given project is allowed to consume from the pool. For
example, with a quota of 128, I might get 203.0.113.128/26,
203.0.113.224/28, and still have room to allocate 48 more addresses in
the future.

With IPv6 it is a little different. It is not practical to count
individual addresses. To avoid ridiculously large numbers, the quota is
expressed in the number of /64 subnets which can be allocated. For
example, with a default_quota of 3, I might get 2001:db8:c18e:c05a::/64,
2001:db8:221c:8ef3::/64, and still have room to allocate one more prefix
in the future.

Default subnet pools
~~~~~~~~~~~~~~~~~~~~

Beginning with Mitaka, a subnet pool can be marked as the default. This
is handled with a new extension.

.. code-block:: console

    $ openstack extension list | grep default-subnetpools
    | Default Subnetpools | default-subnetpools | Provides ability to mark
    and use a subnetpool as the default                                                                                             |


An administrator can mark a pool as default. Only one pool from each
address family can be marked default.

.. code-block:: console

    $ openstack subnet pool set --default 74348864-f8bf-4fc0-ab03-81229d189467

If there is a default, it can be requested by passing
``--use-default-subnet-pool`` instead of
``--subnet-pool SUBNETPOOL`` when creating a subnet.

Demo
----

If you have access to an OpenStack Kilo or later based neutron, you can play
with this feature now. Give it a try. All of the following commands work
equally as well with IPv6 addresses.

First, as admin, create a shared subnet pool:

.. code-block:: console

    $ openstack subnet pool create --share --pool-prefix 203.0.113.0/24 \
    --default-prefix-length 26 demo-subnetpool4
    +-------------------+--------------------------------+
    | Field             | Value                          |
    +-------------------+--------------------------------+
    | address_scope_id  | None                           |
    | created_at        | 2016-12-14T07:21:26Z           |
    | default_prefixlen | 26                             |
    | default_quota     | None                           |
    | description       |                                |
    | headers           |                                |
    | id                | d3aefb76-2527-43d4-bc21-0ec253 |
    |                   | 908545                         |
    | ip_version        | 4                              |
    | is_default        | False                          |
    | max_prefixlen     | 32                             |
    | min_prefixlen     | 8                              |
    | name              | demo-subnetpool4               |
    | prefixes          | 203.0.113.0/24                 |
    | project_id        | cfd1889ac7d64ad891d4f20aef9f8d |
    |                   | 7c                             |
    | revision_number   | 1                              |
    | shared            | True                           |
    | tags              | []                             |
    | updated_at        | 2016-12-14T07:21:26Z           |
    +-------------------+--------------------------------+

The ``default_prefix_length`` defines the subnet size you will get
if you do not specify ``--prefix-length`` when creating a subnet.

Do essentially the same thing for IPv6 and there are now two subnet
pools. Regular projects can see them. (the output is trimmed a bit
for display)

.. code-block:: console

    $ openstack subnet pool list
    +------------------+------------------+--------------------+
    | ID               | Name             | Prefixes           |
    +------------------+------------------+--------------------+
    | 2b7cc19f-0114-4e | demo-subnetpool  | 2001:db8:a583::/48 |
    | f4-ad86-c1bb91fc |                  |                    |
    | d1f9             |                  |                    |
    | d3aefb76-2527-43 | demo-subnetpool4 | 203.0.113.0/24     |
    | d4-bc21-0ec25390 |                  |                    |
    | 8545             |                  |                    |
    +------------------+------------------+--------------------+

Now, use them. It is easy to create a subnet from a pool:

.. code-block:: console

    $ openstack subnet create --ip-version 4 --subnet-pool \
    demo-subnetpool4 --network demo-network1 demo-subnet1
    +-------------------+--------------------------------------+
    | Field             | Value                                |
    +-------------------+--------------------------------------+
    | allocation_pools  | 203.0.113.194-203.0.113.254          |
    | cidr              | 203.0.113.192/26                     |
    | created_at        | 2016-12-14T07:33:13Z                 |
    | description       |                                      |
    | dns_nameservers   |                                      |
    | enable_dhcp       | True                                 |
    | gateway_ip        | 203.0.113.193                        |
    | headers           |                                      |
    | host_routes       |                                      |
    | id                | 8d4fbae3-076c-4c08-b2dd-2d6175115a5e |
    | ip_version        | 4                                    |
    | ipv6_address_mode | None                                 |
    | ipv6_ra_mode      | None                                 |
    | name              | demo-subnet1                         |
    | network_id        | 6b377f77-ce00-4ff6-8676-82343817470d |
    | project_id        | cfd1889ac7d64ad891d4f20aef9f8d7c     |
    | revision_number   | 2                                    |
    | service_types     |                                      |
    | subnetpool_id     | d3aefb76-2527-43d4-bc21-0ec253908545 |
    | tags              | []                                   |
    | updated_at        | 2016-12-14T07:33:13Z                 |
    +-------------------+--------------------------------------+


You can request a specific subnet from the pool. You need to specify a subnet
that falls within the pool's prefixes. If the subnet is not already allocated,
the request succeeds. You can leave off the IP version because it is deduced
from the subnet pool.

.. code-block:: console

    $ openstack subnet create --subnet-pool demo-subnetpool4 \
    --network demo-network1 --subnet-range 203.0.113.128/26 subnet2
    +-------------------+--------------------------------------+
    | Field             | Value                                |
    +-------------------+--------------------------------------+
    | allocation_pools  | 203.0.113.130-203.0.113.190          |
    | cidr              | 203.0.113.128/26                     |
    | created_at        | 2016-12-14T07:27:40Z                 |
    | description       |                                      |
    | dns_nameservers   |                                      |
    | enable_dhcp       | True                                 |
    | gateway_ip        | 203.0.113.129                        |
    | headers           |                                      |
    | host_routes       |                                      |
    | id                | d32814e3-cf46-4371-80dd-498a80badfba |
    | ip_version        | 4                                    |
    | ipv6_address_mode | None                                 |
    | ipv6_ra_mode      | None                                 |
    | name              | subnet2                              |
    | network_id        | 6b377f77-ce00-4ff6-8676-82343817470d |
    | project_id        | cfd1889ac7d64ad891d4f20aef9f8d7c     |
    | revision_number   | 2                                    |
    | service_types     |                                      |
    | subnetpool_id     | d3aefb76-2527-43d4-bc21-0ec253908545 |
    | tags              | []                                   |
    | updated_at        | 2016-12-14T07:27:40Z                 |
    +-------------------+--------------------------------------+


If the pool becomes exhausted, load some more prefixes:

.. code-block:: console

    $ openstack subnet pool set --pool-prefix \
    198.51.100.0/24 demo-subnetpool4
    $ openstack subnet pool show demo-subnetpool4
    +-------------------+--------------------------------------+
    | Field             | Value                                |
    +-------------------+--------------------------------------+
    | address_scope_id  | None                                 |
    | created_at        | 2016-12-14T07:21:26Z                 |
    | default_prefixlen | 26                                   |
    | default_quota     | None                                 |
    | description       |                                      |
    | id                | d3aefb76-2527-43d4-bc21-0ec253908545 |
    | ip_version        | 4                                    |
    | is_default        | False                                |
    | max_prefixlen     | 32                                   |
    | min_prefixlen     | 8                                    |
    | name              | demo-subnetpool4                     |
    | prefixes          | 198.51.100.0/24, 203.0.113.0/24      |
    | project_id        | cfd1889ac7d64ad891d4f20aef9f8d7c     |
    | revision_number   | 2                                    |
    | shared            | True                                 |
    | tags              | []                                   |
    | updated_at        | 2016-12-14T07:30:32Z                 |
    +-------------------+--------------------------------------+

