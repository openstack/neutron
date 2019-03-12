.. _config-network-segment-ranges:

======================
Network segment ranges
======================

The network segment range service exposes the segment range management to be
administered via the Neutron API. In addition, it introduces the ability for
the administrator to control the segment ranges globally or on a per-tenant
basis.

Why you need it
~~~~~~~~~~~~~~~

Before Stein, network segment ranges were configured as an entry in ML2
config file ``ml2_conf.ini`` that was statically defined for tenant network
allocation and therefore had to be managed as part of the host deployment and
management. When a regular tenant user creates a network, Neutron assigns the
next free segmentation ID (VLAN ID, VNI etc.) from the configured segment
ranges. Only an administrator can assign a specific segment ID via the
provider extension.

The network segment range management service provides the following
capabilities that the administrator may be interested in:

#. To check out the network segment ranges defined by the operators in the
   ML2 config file so that the admin can use this information to make segment
   range allocation.

#. To dynamically create and assign network segment ranges, which can help
   with the distribution of the underlying network connection mapping for
   privacy or dedicated business connection needs. This includes:

   * global shared network segment ranges
   * tenant-specific network segment ranges

#. To dynamically update a network segment range to offer the ability to adapt
   to the connection mapping changes.

#. To dynamically manage a network segment range when there are no segment
   ranges defined within the ML2 config file ``ml2_conf.ini`` and no restart
   of the Neutron server is required in this situation.

#. To check the availability and usage statistics of network segment ranges.

How it works
~~~~~~~~~~~~

A network segment range manages a set of segments from which self-service
networks can be allocated. The network segment range management service is
admin-only.

As a regular project in an OpenStack cloud, you can not create a network
segment range of your own and you just create networks in regular way.

If you are an admin, you can create a network segment range which can be
shared (i.e. used by any regular project) or tenant-specific (i.e.
assignment on a per-tenant basis). Your network segment ranges will not be
visible to any other regular projects. Other CRUD operations are also
supported.

When a tenant allocates a segment, it will first be allocated from an available
segment range assigned to the tenant, and then a shared range if no tenant
specific allocation is possible.

Default network segment ranges
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A set of ``default`` network segment ranges are created out of the values
defined in the ML2 config file: ``network_vlan_ranges`` for ml2_type_vlan,
``vni_ranges`` for ml2_type_vxlan, ``tunnel_id_ranges`` for ml2_type_gre and
``vni_ranges`` for ml2_type_geneve. They will be reloaded when Neutron
server starts or restarts. The ``default`` network segment ranges are
``read-only``, but will be treated as any other ``shared`` ranges on segment
allocation.

The administrator can use the default network segment range information to
make shared and/or per-tenant range creation and assignment.

Example configuration
~~~~~~~~~~~~~~~~~~~~~

Controller node
---------------

#. Enable the network segment range service plugin by appending
   ``network_segment_range`` to the list of ``service_plugins`` in the
   ``neutron.conf`` file on all nodes running the ``neutron-server`` service:

   .. code-block:: ini

      [DEFAULT]
      # ...
      service_plugins = ...,network_segment_range,...

#. Restart the ``neutron-server`` service.

Verify service operation
------------------------

#. Source the administrative project credentials and list the enabled
   extensions.

#. Use the command :command:`openstack extension list --network` to verify
   that the ``Neutron Network Segment Range`` extension with Alias
   ``network-segment-range`` is enabled.

.. code-block:: console

    $ openstack extension list --network
    +-------------------------------+-----------------------+-----------------------------------------------------------+
    | Name                          | Alias                 | Description                                               |
    +-------------------------------+-----------------------+-----------------------------------------------------------+
    | ......                        | ......                | ......                                                    |
    +-------------------------------+-----------------------+-----------------------------------------------------------+
    | Neutron Network Segment Range | network-segment-range | Provides support for the network segment range management |
    +-------------------------------+-----------------------+-----------------------------------------------------------+
    | ......                        | ......                | ......                                                    |
    +-------------------------------+-----------------------+-----------------------------------------------------------+

Workflow
~~~~~~~~

At a high level, the basic workflow for a network segment range creation is
the following:

#. The Cloud administrator:

   * Lists the existing network segment ranges.
   * Creates a shared or a tenant-specific network segment range based on the
     requirement.

#. A regular tenant creates a network in regular way. The network created
   will automatically allocate a segment from the segment ranges assigned to
   the tenant or shared if no tenant specific range available.

At a high level, the basic workflow for a network segment range update is
the following:

#. The Cloud administrator:

   * Lists the existing network segment ranges and identifies the one that
     needs to be updated.
   * Updates the network segment range based on the requirement.

#. A regular tenant creates a network in regular way. The network created
   will automatically allocate a segment from the updated network segment
   ranges available.

List the network segment ranges or show a network segment range
---------------------------------------------------------------

As admin, list the existing network segment ranges:

.. code-block:: console

    $ openstack network segment range list
    +--------------------------------------+-------------------+---------+--------+----------------------------------+--------------+------------------+------------+------------+
    | ID                                   | Name              | Default | Shared | Project ID                       | Network Type | Physical Network | Minimum ID | Maximum ID |
    +--------------------------------------+-------------------+---------+--------+----------------------------------+--------------+------------------+------------+------------+
    | 20ce94e1-4e51-4aa0-a5f1-26bdfb5bd90e |                   | True    | True   | None                             | vxlan        | None             |          1 |        200 |
    | 4b7af684-ec97-422d-ba38-8b9c2919ae67 | test_range_3      | False   | False  | 7011dc7fccac4efda89dc3b7f0d0975a | gre          | None             |        100 |        120 |
    | a021e582-6b0f-49f5-90cb-79a670c61973 |                   | True    | True   | None                             | vlan         | default          |          1 |        100 |
    | a3373630-969b-4ce9-bae7-dff0f8fa2f92 | test_range_2      | False   | True   | None                             | vxlan        | None             |        501 |        505 |
    | a5707a8f-76f0-4f90-9aa7-c42bf54e94b5 |                   | True    | True   | None                             | gre          | None             |          1 |        150 |
    | aad1b55b-43f1-46f9-8c35-85f270863ed6 |                   | True    | True   | None                             | geneve       | None             |          1 |        120 |
    | e3233178-2866-4f40-b794-7c6fecdc8655 | test_range_1      | False   | False  | 7011dc7fccac4efda89dc3b7f0d0975a | vlan         | group0-data0     |         11 |         11 |
    +--------------------------------------+-------------------+---------+--------+----------------------------------+--------------+------------------+------------+------------+

The network segment ranges with ``Default`` as ``True`` are the ranges
specified by the operators in the ML2 config file. Besides, there
are also shared and tenant specific network segment ranges created by the
admin previously.

The admin is also able to check/show the detailed information (e.g.
availability and usage statistics) of a network segment range:

.. code-block:: console

    $ openstack network segment range show test_range_1
    +------------------+-----------------------------------------------+
    | Field            | Value                                         |
    +------------------+-----------------------------------------------+
    | available        | []                                            |
    | default          | False                                         |
    | id               | e3233178-2866-4f40-b794-7c6fecdc8655          |
    | location         | None                                          |
    | maximum          | 11                                            |
    | minimum          | 11                                            |
    | name             | test_range_1                                  |
    | network_type     | vlan                                          |
    | physical_network | group0-data0                                  |
    | project_id       | 7011dc7fccac4efda89dc3b7f0d0975a              |
    | shared           | False                                         |
    | used             | {u'7011dc7fccac4efda89dc3b7f0d0975a': ['11']} |
    +------------------+-----------------------------------------------+

Create or update the network segment range
------------------------------------------

As admin, create a network segment range based on your requirement:

.. code-block:: console

    $ openstack network segment range create --private --project demo \
    --network-type vxlan --minimum 120 --maximum 140 test_range_4
    +------------------+--------------------------------------+
    | Field            | Value                                |
    +------------------+--------------------------------------+
    | available        | ['120-140']                          |
    | default          | False                                |
    | id               | c016dcda-5bc3-4e98-b41f-6773e92fcd2d |
    | location         | None                                 |
    | maximum          | 140                                  |
    | minimum          | 120                                  |
    | name             | test_range_4                         |
    | network_type     | vxlan                                |
    | physical_network | None                                 |
    | project_id       | 7011dc7fccac4efda89dc3b7f0d0975a     |
    | shared           | False                                |
    | used             | {}                                   |
    +------------------+--------------------------------------+

Update a network segment range based on your requirement:

.. code-block:: console

    $ openstack network segment range set --minimum 100 --maximum 150 \
    test_range_4

Create a tenant network
-----------------------

Now, as project ``demo`` (to source the client environment script
``demo-openrc`` for ``demo`` project according to
https://docs.openstack.org/keystone/latest/install/keystone-openrc-rdo.html),
create a network in a regular way.

.. code-block:: console

    $ source demo-openrc
    $ openstack network create test_net
    +---------------------------+--------------------------------------+
    | Field                     | Value                                |
    +---------------------------+--------------------------------------+
    | admin_state_up            | UP                                   |
    | availability_zone_hints   |                                      |
    | availability_zones        |                                      |
    | created_at                | 2019-02-25T23:20:36Z                 |
    | description               |                                      |
    | dns_domain                |                                      |
    | id                        | 39e5b95c-ad7a-40b5-9ec1-a4b4a8a43f14 |
    | ipv4_address_scope        | None                                 |
    | ipv6_address_scope        | None                                 |
    | is_default                | False                                |
    | is_vlan_transparent       | None                                 |
    | location                  | None                                 |
    | mtu                       | 1450                                 |
    | name                      | test_net                             |
    | port_security_enabled     | True                                 |
    | project_id                | 7011dc7fccac4efda89dc3b7f0d0975a     |
    | provider:network_type     | vxlan                                |
    | provider:physical_network | None                                 |
    | provider:segmentation_id  | None                                  |
    | qos_policy_id             | None                                 |
    | revision_number           | 2                                    |
    | router:external           | Internal                             |
    | segments                  | None                                 |
    | shared                    | False                                |
    | status                    | ACTIVE                               |
    | subnets                   |                                      |
    | tags                      |                                      |
    | updated_at                | 2019-02-25T23:20:36Z                 |
    +---------------------------+--------------------------------------+


Then, switch back to the admin to check the segmentation ID of the tenant
network created.

.. code-block:: console

    $ source admin-openrc
    $ openstack network show test_net
    +---------------------------+--------------------------------------+
    | Field                     | Value                                |
    +---------------------------+--------------------------------------+
    | admin_state_up            | UP                                   |
    | availability_zone_hints   |                                      |
    | availability_zones        |                                      |
    | created_at                | 2019-02-25T23:20:36Z                 |
    | description               |                                      |
    | dns_domain                |                                      |
    | id                        | 39e5b95c-ad7a-40b5-9ec1-a4b4a8a43f14 |
    | ipv4_address_scope        | None                                 |
    | ipv6_address_scope        | None                                 |
    | is_default                | False                                |
    | is_vlan_transparent       | None                                 |
    | location                  | None                                 |
    | mtu                       | 1450                                 |
    | name                      | test_net                             |
    | port_security_enabled     | True                                 |
    | project_id                | 7011dc7fccac4efda89dc3b7f0d0975a     |
    | provider:network_type     | vxlan                                |
    | provider:physical_network | None                                 |
    | provider:segmentation_id  | 137                                  |
    | qos_policy_id             | None                                 |
    | revision_number           | 2                                    |
    | router:external           | Internal                             |
    | segments                  | None                                 |
    | shared                    | False                                |
    | status                    | ACTIVE                               |
    | subnets                   |                                      |
    | tags                      |                                      |
    | updated_at                | 2019-02-25T23:20:36Z                 |
    +---------------------------+--------------------------------------+

The tenant network created automatically allocates a segment with
segmentation ID ``137`` from the network segment range with segmentation
ID range ``120-140`` that is assigned to the tenant.

If no more available segment in the network segment range assigned to this
tenant, then the segment allocation would refer to the ``shared`` segment
ranges to check whether there's one segment available. If still there is no
segment available, the allocation will fail as follows:

.. code-block:: console

    $ openstack network create test_net
    $ Unable to create the network. No tenant network is available for
      allocation.

In this case, the admin is advised to check the availability and usage
statistics of the related network segment ranges in order to take further
actions (e.g. enlarging a segment range etc.).

Known limitations
~~~~~~~~~~~~~~~~~

* This service plugin is only compatible with ML2 core plugin for now.
  However, it is possible for other core plugins to support this feature
  with a follow-on effort.
