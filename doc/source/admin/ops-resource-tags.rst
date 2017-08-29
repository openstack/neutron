.. _ops-resource-tags:

=============
Resource tags
=============

Various virtual networking resources support tags for use by external
systems or any other clients of the Networking service API.

All resources that support standard attributes are applicable for tagging.
This includes:

* networks
* subnets
* subnetpools
* ports
* routers
* floatingips
* logs
* security-groups
* security-group-rules
* segments
* policies
* trunks

Use cases
~~~~~~~~~

The following use cases refer to adding tags to networks, but the same
can be applicable to any other supported Networking service resource:

#. Ability to map different networks in different OpenStack locations
   to one logically same network (for multi-site OpenStack).

#. Ability to map IDs from different management/orchestration systems to
   OpenStack networks in mixed environments. For example, in the Kuryr project,
   the Docker network ID is mapped to the Neutron network ID.

#. Ability to leverage tags by deployment tools.

#. Ability to tag information about provider networks
   (for example, high-bandwidth, low-latency, and so on).

Filtering with tags
~~~~~~~~~~~~~~~~~~~

The API allows searching/filtering of the ``GET /v2.0/networks`` API. The
following query parameters are supported:

* ``tags``
* ``tags-any``
* ``not-tags``
* ``not-tags-any``

To request the list of networks that have a single tag, ``tags`` argument
should be set to the desired tag name. Example::

    GET /v2.0/networks?tags=red

To request the list of networks that have two or more tags, the ``tags``
argument should be set to the list of tags, separated by commas. In this case,
the tags given must all be present for a network to be included in the query
result. Example that returns networks that have the "red" and "blue" tags::

    GET /v2.0/networks?tags=red,blue

To request the list of networks that have one or more of a list of given tags,
the ``tags-any`` argument should be set to the list of tags, separated by
commas. In this case, as long as one of the given tags is present, the network
will be included in the query result. Example that returns the networks that
have the "red" or the "blue" tag::

    GET /v2.0/networks?tags-any=red,blue

To request the list of networks that do not have one or more tags, the
``not-tags`` argument should be set to the list of tags, separated by commas.
In this case, only the networks that do not have any of the given tags will be
included in the query results. Example that returns the networks that do not
have either "red" or "blue" tag::

    GET /v2.0/networks?not-tags=red,blue

To request the list of networks that do not have at least one of a list of
tags, the ``not-tags-any`` argument should be set to the list of tags,
separated by commas. In this case, only the networks that do not have at least
one of the given tags will be included in the query result. Example that
returns the networks that do not have the "red" tag, or do not have the "blue"
tag::

    GET /v2.0/networks?not-tags-any=red,blue

The ``tags``, ``tags-any``, ``not-tags``, and ``not-tags-any`` arguments can be
combined to build more complex queries. Example::

    GET /v2.0/networks?tags=red,blue&tags-any=green,orange

The above example returns any networks that have the "red" and "blue" tags,
plus at least one of "green" and "orange".

Complex queries may have contradictory parameters. Example::

    GET /v2.0/networks?tags=blue&not-tags=blue

In this case, we should let the Networking service find these
networks. Obviously, there are no such networks and the service will return an
empty list.

User workflow
~~~~~~~~~~~~~

Add a tag to a resource:

.. code-block:: console

    $ neutron tag-add --resource-type network --resource ab442634-1cc9-49e5-bd49-0dac9c811f69 --tag red
    $ neutron net-show net
    +-------------------------+--------------------------------------+
    | Field                   | Value                                |
    +-------------------------+--------------------------------------+
    | admin_state_up          | True                                 |
    | availability_zone_hints |                                      |
    | availability_zones      |                                      |
    | id                      | ab442634-1cc9-49e5-bd49-0dac9c811f69 |
    | ipv4_address_scope      |                                      |
    | ipv6_address_scope      |                                      |
    | mtu                     | 1450                                 |
    | name                    | net                                  |
    | port_security_enabled   | True                                 |
    | router:external         | False                                |
    | shared                  | False                                |
    | status                  | ACTIVE                               |
    | subnets                 |                                      |
    | tags                    | red                                  |
    | tenant_id               | e6710680bfd14555891f265644e1dd5c     |
    +-------------------------+--------------------------------------+

Remove a tag from a resource:

.. code-block:: console

    $ neutron tag-remove --resource-type network --resource ab442634-1cc9-49e5-bd49-0dac9c811f69 --tag red
    $ neutron net-show net
    +-------------------------+--------------------------------------+
    | Field                   | Value                                |
    +-------------------------+--------------------------------------+
    | admin_state_up          | True                                 |
    | availability_zone_hints |                                      |
    | availability_zones      |                                      |
    | id                      | ab442634-1cc9-49e5-bd49-0dac9c811f69 |
    | ipv4_address_scope      |                                      |
    | ipv6_address_scope      |                                      |
    | mtu                     | 1450                                 |
    | name                    | net                                  |
    | port_security_enabled   | True                                 |
    | router:external         | False                                |
    | shared                  | False                                |
    | status                  | ACTIVE                               |
    | subnets                 |                                      |
    | tags                    |                                      |
    | tenant_id               | e6710680bfd14555891f265644e1dd5c     |
    +-------------------------+--------------------------------------+

Replace all tags on the resource:

.. code-block:: console

    $ neutron tag-replace --resource-type network --resource ab442634-1cc9-49e5-bd49-0dac9c811f69 --tag red --tag blue
    $ neutron net-show net
    +-------------------------+--------------------------------------+
    | Field                   | Value                                |
    +-------------------------+--------------------------------------+
    | admin_state_up          | True                                 |
    | availability_zone_hints |                                      |
    | availability_zones      |                                      |
    | id                      | ab442634-1cc9-49e5-bd49-0dac9c811f69 |
    | ipv4_address_scope      |                                      |
    | ipv6_address_scope      |                                      |
    | mtu                     | 1450                                 |
    | name                    | net                                  |
    | port_security_enabled   | True                                 |
    | router:external         | False                                |
    | shared                  | False                                |
    | status                  | ACTIVE                               |
    | subnets                 |                                      |
    | tags                    | red                                  |
    |                         | blue                                 |
    | tenant_id               | e6710680bfd14555891f265644e1dd5c     |
    +-------------------------+--------------------------------------+

Clear tags from a resource:

.. code-block:: console

    $ neutron tag-remove --resource-type network --resource ab442634-1cc9-49e5-bd49-0dac9c811f69 --all
    $ neutron net-show net
    +-------------------------+--------------------------------------+
    | Field                   | Value                                |
    +-------------------------+--------------------------------------+
    | admin_state_up          | True                                 |
    | availability_zone_hints |                                      |
    | availability_zones      |                                      |
    | id                      | ab442634-1cc9-49e5-bd49-0dac9c811f69 |
    | ipv4_address_scope      |                                      |
    | ipv6_address_scope      |                                      |
    | mtu                     | 1450                                 |
    | name                    | net                                  |
    | port_security_enabled   | True                                 |
    | router:external         | False                                |
    | shared                  | False                                |
    | status                  | ACTIVE                               |
    | subnets                 |                                      |
    | tags                    |                                      |
    | tenant_id               | e6710680bfd14555891f265644e1dd5c     |
    +-------------------------+--------------------------------------+

Get list of resources with tag filters from networks. The networks are:
test-net1 with "red" tag, test-net2 with "red" and "blue" tags, test-net3 with
"red", "blue", and "green" tags, and test-net4 with "green" tag.

Get list of resources with ``tags`` filter:

.. code-block:: console

    $ neutron net-list --tags red,blue
    +--------------------------------------+-----------+---------+
    | id                                   | name      | subnets |
    +--------------------------------------+-----------+---------+
    | 8ca3b9ed-f578-45fa-8c44-c53f13aec05a | test-net3 |         |
    | e736e63d-42e4-4f4c-836c-6ad286ffd68a | test-net2 |         |
    +--------------------------------------+-----------+---------+

Get list of resources with ``tags-any`` filter:

.. code-block:: console

    $ neutron net-list --tags-any red,blue
    +--------------------------------------+-----------+---------+
    | id                                   | name      | subnets |
    +--------------------------------------+-----------+---------+
    | 30491224-3855-431f-a688-fb29df004d82 | test-net1 |         |
    | 8ca3b9ed-f578-45fa-8c44-c53f13aec05a | test-net3 |         |
    | e736e63d-42e4-4f4c-836c-6ad286ffd68a | test-net2 |         |
    +--------------------------------------+-----------+---------+

Get list of resources with ``not-tags`` filter:

.. code-block:: console

    $ neutron net-list --not-tags red,blue
    +--------------------------------------+-----------+---------+
    | id                                   | name      | subnets |
    +--------------------------------------+-----------+---------+
    | 30491224-3855-431f-a688-fb29df004d82 | test-net1 |         |
    | cdb3ed08-ca63-4090-ba12-30b366372993 | test-net4 |         |
    +--------------------------------------+-----------+---------+

Get list of resources with ``not-tags-any`` filter:

.. code-block:: console

    $ neutron net-list --not-tags-any red,blue
    +--------------------------------------+-----------+---------+
    | id                                   | name      | subnets |
    +--------------------------------------+-----------+---------+
    | cdb3ed08-ca63-4090-ba12-30b366372993 | test-net4 |         |
    +--------------------------------------+-----------+---------+

Limitations
~~~~~~~~~~~

Filtering resources with a tag whose name contains a comma is not
supported. Thus, do not put such a tag name to resources.

Future support
~~~~~~~~~~~~~~

In future releases, the Networking service may support setting tags for
additional resources.
