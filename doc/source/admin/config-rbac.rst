.. _config-rbac:

================================
Role-Based Access Control (RBAC)
================================

The Role-Based Access Control (RBAC) policy framework enables both operators
and users to grant access to resources for specific projects.


Supported objects for sharing with specific projects
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Currently, the access that can be granted using this feature
is supported by:

* Regular port creation permissions on networks (since Liberty).
* Binding QoS policies permissions to networks or ports (since Mitaka).
* Attaching router gateways to networks (since Mitaka).
* Binding security groups to ports (since Stein).
* Assigning address scopes to subnet pools (since Ussuri).
* Assigning subnet pools to subnets (since Ussuri).
* Assigning address groups to security group rules (since Wallaby).


Sharing an object with specific projects
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Sharing an object with a specific project is accomplished by creating
a policy entry that permits the target project the ``access_as_shared``
action on that object.


Sharing a network with specific projects
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Create a network to share:

.. code-block:: console

   $ openstack network create secret_network
   +---------------------------+--------------------------------------+
   | Field                     | Value                                |
   +---------------------------+--------------------------------------+
   | admin_state_up            | UP                                   |
   | availability_zone_hints   |                                      |
   | availability_zones        |                                      |
   | created_at                | 2017-01-25T20:16:40Z                 |
   | description               |                                      |
   | dns_domain                | None                                 |
   | id                        | f55961b9-3eb8-42eb-ac96-b97038b568de |
   | ipv4_address_scope        | None                                 |
   | ipv6_address_scope        | None                                 |
   | is_default                | None                                 |
   | mtu                       | 1450                                 |
   | name                      | secret_network                       |
   | port_security_enabled     | True                                 |
   | project_id                | 61b7eba037fd41f29cfba757c010faff     |
   | provider:network_type     | vxlan                                |
   | provider:physical_network | None                                 |
   | provider:segmentation_id  | 9                                    |
   | qos_policy_id             | None                                 |
   | revision_number           | 3                                    |
   | router:external           | Internal                             |
   | segments                  | None                                 |
   | shared                    | False                                |
   | status                    | ACTIVE                               |
   | subnets                   |                                      |
   | tags                      | []                                   |
   | updated_at                | 2017-01-25T20:16:40Z                 |
   +---------------------------+--------------------------------------+


Create the policy entry using the :command:`openstack network rbac create`
command (in this example, the ID of the project we want to share with is
``b87b2fc13e0248a4a031d38e06dc191d``):

.. code-block:: console

   $ openstack network rbac create --target-project \
   b87b2fc13e0248a4a031d38e06dc191d --action access_as_shared \
   --type network f55961b9-3eb8-42eb-ac96-b97038b568de
   +-------------------+--------------------------------------+
   | Field             | Value                                |
   +-------------------+--------------------------------------+
   | action            | access_as_shared                     |
   | id                | f93efdbf-f1e0-41d2-b093-8328959d469e |
   | name              | None                                 |
   | object_id         | f55961b9-3eb8-42eb-ac96-b97038b568de |
   | object_type       | network                              |
   | project_id        | 61b7eba037fd41f29cfba757c010faff     |
   | target_project_id | b87b2fc13e0248a4a031d38e06dc191d     |
   +-------------------+--------------------------------------+


The ``target-project`` parameter specifies the project that requires
access to the network. The ``action`` parameter specifies what
the project is allowed to do. The ``type`` parameter says
that the target object is a network. The final parameter is the ID of
the network we are granting access to.

Project ``b87b2fc13e0248a4a031d38e06dc191d`` will now be able to see
the network when running :command:`openstack network list` and
:command:`openstack network show` and will also be able to create ports
on that network. No other users (other than admins and the owner)
will be able to see the network.

.. note::
   Subnets inherit the RBAC policy entries of their network.

To remove access for that project, delete the policy that allows
it using the :command:`openstack network rbac delete` command:

.. code-block:: console

   $ openstack network rbac delete f93efdbf-f1e0-41d2-b093-8328959d469e

If that project has ports on the network, the server will prevent the
policy from being deleted until the ports have been deleted:

.. code-block:: console

   $ openstack network rbac delete f93efdbf-f1e0-41d2-b093-8328959d469e
   RBAC policy on object f93efdbf-f1e0-41d2-b093-8328959d469e
   cannot be removed because other objects depend on it.

This process can be repeated any number of times to share a network
with an arbitrary number of projects.


Sharing a QoS policy with specific projects
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Create a QoS policy to share:

.. code-block:: console

   $ openstack network qos policy create secret_policy
   +-------------------+--------------------------------------+
   | Field             | Value                                |
   +-------------------+--------------------------------------+
   | description       |                                      |
   | id                | 1f730d69-1c45-4ade-a8f2-89070ac4f046 |
   | name              | secret_policy                        |
   | project_id        | 61b7eba037fd41f29cfba757c010faff     |
   | revision_number   | 1                                    |
   | rules             | []                                   |
   | shared            | False                                |
   | tags              | []                                   |
   +-------------------+--------------------------------------+


Create the RBAC policy entry using the :command:`openstack network rbac create`
command (in this example, the ID of the project we want to share with is
``be98b82f8fdf46b696e9e01cebc33fd9``):

.. code-block:: console

   $ openstack network rbac create --target-project \
   be98b82f8fdf46b696e9e01cebc33fd9 --action access_as_shared \
   --type qos_policy 1f730d69-1c45-4ade-a8f2-89070ac4f046
   +-------------------+--------------------------------------+
   | Field             | Value                                |
   +-------------------+--------------------------------------+
   | action            | access_as_shared                     |
   | id                | 8828e38d-a0df-4c78-963b-e5f215d3d550 |
   | name              | None                                 |
   | object_id         | 1f730d69-1c45-4ade-a8f2-89070ac4f046 |
   | object_type       | qos_policy                           |
   | project_id        | 61b7eba037fd41f29cfba757c010faff     |
   | target_project_id | be98b82f8fdf46b696e9e01cebc33fd9     |
   +-------------------+--------------------------------------+


The ``target-project`` parameter specifies the project that requires
access to the QoS policy. The ``action`` parameter specifies what
the project is allowed to do. The ``type`` parameter says
that the target object is a QoS policy. The final parameter is the ID of
the QoS policy we are granting access to.

Project ``be98b82f8fdf46b696e9e01cebc33fd9`` will now be able to see
the QoS policy when running :command:`openstack network qos policy list` and
:command:`openstack network qos policy show` and will also be able to bind
it to its ports or networks. No other users (other than admins and the owner)
will be able to see the QoS policy.

To remove access for that project, delete the RBAC policy that allows
it using the :command:`openstack network rbac delete` command:

.. code-block:: console

   $ openstack network rbac delete 8828e38d-a0df-4c78-963b-e5f215d3d550

If that project has ports or networks with the QoS policy applied to them,
the server will not delete the RBAC policy until
the QoS policy is no longer in use:

.. code-block:: console

   $ openstack network rbac delete 8828e38d-a0df-4c78-963b-e5f215d3d550
   RBAC policy on object 8828e38d-a0df-4c78-963b-e5f215d3d550
   cannot be removed because other objects depend on it.

This process can be repeated any number of times to share a qos-policy
with an arbitrary number of projects.


Sharing a security group with specific projects
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Create a security group to share:

.. code-block:: console

   $ openstack security group create my_security_group
   +-------------------+--------------------------------------+
   | Field             | Value                                |
   +-------------------+--------------------------------------+
   | created_at        | 2019-02-07T06:09:59Z                 |
   | description       | my_security_group                    |
   | id                | 5ba835b7-22b0-4be6-bdbe-e0722d1b5f24 |
   | location          | None                                 |
   | name              | my_security_group                    |
   | project_id        | 077e8f39d3db4c9e998d842b0503283a     |
   | revision_number   | 1                                    |
   | rules             | ...                                  |
   | tags              | []                                   |
   | updated_at        | 2019-02-07T06:09:59Z                 |
   +-------------------+--------------------------------------+


Create the RBAC policy entry using the :command:`openstack network rbac create`
command (in this example, the ID of the project we want to share with is
``32016615de5d43bb88de99e7f2e26a1e``):

.. code-block:: console

   $ openstack network rbac create --target-project \
   32016615de5d43bb88de99e7f2e26a1e --action access_as_shared \
   --type security_group 5ba835b7-22b0-4be6-bdbe-e0722d1b5f24
   +-------------------+--------------------------------------+
   | Field             | Value                                |
   +-------------------+--------------------------------------+
   | action            | access_as_shared                     |
   | id                | 8828e38d-a0df-4c78-963b-e5f215d3d550 |
   | name              | None                                 |
   | object_id         | 5ba835b7-22b0-4be6-bdbe-e0722d1b5f24 |
   | object_type       | security_group                       |
   | project_id        | 077e8f39d3db4c9e998d842b0503283a     |
   | target_project_id | 32016615de5d43bb88de99e7f2e26a1e     |
   +-------------------+--------------------------------------+


The ``target-project`` parameter specifies the project that requires
access to the security group. The ``action`` parameter specifies what
the project is allowed to do. The ``type`` parameter says
that the target object is a security group. The final parameter is the ID of
the security group we are granting access to.

Project ``32016615de5d43bb88de99e7f2e26a1e`` will now be able to see
the security group when running :command:`openstack security group list` and
:command:`openstack security group show` and will also be able to bind
it to its ports. No other users (other than admins and the owner)
will be able to see the security group.

To remove access for that project, delete the RBAC policy that allows
it using the :command:`openstack network rbac delete` command:

.. code-block:: console

   $ openstack network rbac delete 8828e38d-a0df-4c78-963b-e5f215d3d550

If that project has ports with the security group applied to them,
the server will not delete the RBAC policy until
the security group is no longer in use:

.. code-block:: console

   $ openstack network rbac delete 8828e38d-a0df-4c78-963b-e5f215d3d550
   RBAC policy on object 8828e38d-a0df-4c78-963b-e5f215d3d550
   cannot be removed because other objects depend on it.

This process can be repeated any number of times to share a security-group
with an arbitrary number of projects.


Creating an instance which uses a security group shared through RBAC, but only
specifying the network ID when calling Nova will not work currently. In such
cases Nova will check if the given security group exists in Neutron before it
creates a port in the given network. The problem with that is that Nova asks
only for the security groups filtered by the project_id thus it will not get
the shared security group back from the Neutron API. See `bug 1942615
<https://bugs.launchpad.net/neutron/+bug/1942615>`__ for details.
To workaround the issue, the user needs to create a port in Neutron first, and
then pass that port to Nova:

.. code-block:: console

   $ openstack port create --network net1 --security-group
   5ba835b7-22b0-4be6-bdbe-e0722d1b5f24 shared-sg-port

   $ openstack server create --image cirros-0.5.1-x86_64-disk --flavor m1.tiny
   --port shared-sg-port vm-with-shared-sg



Sharing an address scope with specific projects
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Create an address scope to share:

.. code-block:: console

   $ openstack address scope create my_address_scope
   +-------------------+--------------------------------------+
   | Field             | Value                                |
   +-------------------+--------------------------------------+
   | id                | c19cb654-3489-4160-9c82-8a3015483643 |
   | ip_version        | 4                                    |
   | location          | ...                                  |
   | name              | my_address_scope                     |
   | project_id        | 34304bc4f233470fa4a2448d153b6324     |
   | shared            | False                                |
   +-------------------+--------------------------------------+


Create the RBAC policy entry using the :command:`openstack network rbac create`
command (in this example, the ID of the project we want to share with is
``32016615de5d43bb88de99e7f2e26a1e``):

.. code-block:: console

   $ openstack network rbac create --target-project \
   32016615de5d43bb88de99e7f2e26a1e --action access_as_shared \
   --type address_scope c19cb654-3489-4160-9c82-8a3015483643
   +-------------------+--------------------------------------+
   | Field             | Value                                |
   +-------------------+--------------------------------------+
   | action            | access_as_shared                     |
   | id                | d54b1482-98c4-44aa-9115-ede80387ffe0 |
   | location          | ...                                  |
   | name              | None                                 |
   | object_id         | c19cb654-3489-4160-9c82-8a3015483643 |
   | object_type       | address_scope                        |
   | project_id        | 34304bc4f233470fa4a2448d153b6324     |
   | target_project_id | 32016615de5d43bb88de99e7f2e26a1e     |
   +-------------------+--------------------------------------+


The ``target-project`` parameter specifies the project that requires
access to the address scope. The ``action`` parameter specifies what
the project is allowed to do. The ``type`` parameter says
that the target object is an address scope. The final parameter is the ID of
the address scope we are granting access to.

Project ``32016615de5d43bb88de99e7f2e26a1e`` will now be able to see
the address scope when running :command:`openstack address scope list` and
:command:`openstack address scope show` and will also be able to assign
it to its subnet pools. No other users (other than admins and the owner)
will be able to see the address scope.

To remove access for that project, delete the RBAC policy that allows
it using the :command:`openstack network rbac delete` command:

.. code-block:: console

   $ openstack network rbac delete d54b1482-98c4-44aa-9115-ede80387ffe0

If that project has subnet pools with the address scope applied to them,
the server will not delete the RBAC policy until
the address scope is no longer in use:

.. code-block:: console

   $ openstack network rbac delete d54b1482-98c4-44aa-9115-ede80387ffe0
   RBAC policy on object c19cb654-3489-4160-9c82-8a3015483643
   cannot be removed because other objects depend on it.

This process can be repeated any number of times to share an address scope
with an arbitrary number of projects.

Sharing a subnet pool with specific projects
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Create a subnet pool to share:

.. code-block:: console

   $ openstack subnet pool create my_subnetpool --pool-prefix 203.0.113.0/24
   +-------------------+--------------------------------------+
   | Field             | Value                                |
   +-------------------+--------------------------------------+
   | address_scope_id  | None                                 |
   | created_at        | 2020-03-16T14:23:01Z                 |
   | default_prefixlen | 8                                    |
   | default_quota     | None                                 |
   | description       |                                      |
   | id                | 11f79287-bc17-46b2-bfd0-2562471eb631 |
   | ip_version        | 4                                    |
   | is_default        | False                                |
   | location          | ...                                  |
   | max_prefixlen     | 32                                   |
   | min_prefixlen     | 8                                    |
   | name              | my_subnetpool                        |
   | project_id        | 290ccedbcf594ecc8e76eff06f964f7e     |
   | revision_number   | 0                                    |
   | shared            | False                                |
   | tags              |                                      |
   | updated_at        | 2020-03-16T14:23:01Z                 |
   +-------------------+--------------------------------------+


Create the RBAC policy entry using the :command:`openstack network rbac create`
command (in this example, the ID of the project we want to share with is
``32016615de5d43bb88de99e7f2e26a1e``):

.. code-block:: console

   $ openstack network rbac create --target-project \
   32016615de5d43bb88de99e7f2e26a1e --action access_as_shared \
   --type subnetpool 11f79287-bc17-46b2-bfd0-2562471eb631
   +-------------------+--------------------------------------+
   | Field             | Value                                |
   +-------------------+--------------------------------------+
   | action            | access_as_shared                     |
   | id                | d54b1482-98c4-44aa-9115-ede80387ffe0 |
   | location          | ...                                  |
   | name              | None                                 |
   | object_id         | 11f79287-bc17-46b2-bfd0-2562471eb631 |
   | object_type       | subnetpool                           |
   | project_id        | 290ccedbcf594ecc8e76eff06f964f7e     |
   | target_project_id | 32016615de5d43bb88de99e7f2e26a1e     |
   +-------------------+--------------------------------------+


The ``target-project`` parameter specifies the project that requires
access to the subnet pool. The ``action`` parameter specifies what
the project is allowed to do. The ``type`` parameter says
that the target object is a subnet pool. The final parameter is the ID of
the subnet pool we are granting access to.

Project ``32016615de5d43bb88de99e7f2e26a1e`` will now be able to see
the subnet pool when running :command:`openstack subnet pool list` and
:command:`openstack subnet pool show` and will also be able to assign
it to its subnets. No other users (other than admins and the owner)
will be able to see the subnet pool.

To remove access for that project, delete the RBAC policy that allows
it using the :command:`openstack network rbac delete` command:

.. code-block:: console

   $ openstack network rbac delete d54b1482-98c4-44aa-9115-ede80387ffe0

If that project has subnets with the subnet pool applied to them,
the server will not delete the RBAC policy until
the subnet pool is no longer in use:

.. code-block:: console

   $ openstack network rbac delete d54b1482-98c4-44aa-9115-ede80387ffe0
   RBAC policy on object 11f79287-bc17-46b2-bfd0-2562471eb631
   cannot be removed because other objects depend on it.

This process can be repeated any number of times to share a subnet pool
with an arbitrary number of projects.

Sharing an address group with specific projects
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Create an address group to share:

.. code-block:: console

   $ openstack address group create test-ag --address 10.1.1.1
   +-------------+--------------------------------------+
   | Field       | Value                                |
   +-------------+--------------------------------------+
   | addresses   | ['10.1.1.1/32']                      |
   | description |                                      |
   | id          | cdb6eb3e-f9a0-4d52-8478-358eaa2c4737 |
   | name        | test-ag                              |
   | project_id  | 66c77cf262454777a8f455cce48c12c0     |
   +-------------+--------------------------------------+


Create the RBAC policy entry using the :command:`openstack network rbac create`
command (in this example, the ID of the project we want to share with is
``bbd82892525d4372911390b984ed3265``):

.. code-block:: console

   $ openstack network rbac create --target-project \
   bbd82892525d4372911390b984ed3265 --action access_as_shared \
   --type address_group cdb6eb3e-f9a0-4d52-8478-358eaa2c4737
   +-------------------+--------------------------------------+
   | Field             | Value                                |
   +-------------------+--------------------------------------+
   | action            | access_as_shared                     |
   | id                | c7414ac2-9a6b-420b-84c5-4158a6cca4f9 |
   | name              | None                                 |
   | object_id         | cdb6eb3e-f9a0-4d52-8478-358eaa2c4737 |
   | object_type       | address_group                        |
   | project_id        | 66c77cf262454777a8f455cce48c12c0     |
   | target_project_id | bbd82892525d4372911390b984ed3265     |
   +-------------------+--------------------------------------+


The ``target-project`` parameter specifies the project that requires
access to the address group. The ``action`` parameter specifies what
the project is allowed to do. The ``type`` parameter says
that the target object is an address group. The final parameter is the ID of
the address group we are granting access to.

Project ``bbd82892525d4372911390b984ed3265`` will now be able to see
the address group when running :command:`openstack address group list` and
:command:`openstack address group show` and will also be able to assign
it to its security group rules. No other users (other than admins and the
owner) will be able to see the address group.

To remove access for that project, delete the RBAC policy that allows
it using the :command:`openstack network rbac delete` command:

.. code-block:: console

   $ openstack network rbac delete c7414ac2-9a6b-420b-84c5-4158a6cca4f9

If that project has security group rules with the address group applied to
them, the server will not delete the RBAC policy until the address group is no
longer in use:

.. code-block:: console

   $ openstack network rbac delete c7414ac2-9a6b-420b-84c5-4158a6cca4f9
   RBAC policy on object cdb6eb3e-f9a0-4d52-8478-358eaa2c4737
   cannot be removed because other objects depend on it

This process can be repeated any number of times to share an address group
with an arbitrary number of projects.


How the 'shared' flag relates to these entries
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

As introduced in other guide entries, neutron provides a means of
making an object (``address-scope``, ``network``, ``qos-policy``,
``security-group``, ``subnetpool``) available to every project.
This is accomplished using the ``shared`` flag on the supported object:

.. code-block:: console

   $ openstack network create global_network --share
   +---------------------------+--------------------------------------+
   | Field                     | Value                                |
   +---------------------------+--------------------------------------+
   | admin_state_up            | UP                                   |
   | availability_zone_hints   |                                      |
   | availability_zones        |                                      |
   | created_at                | 2017-01-25T20:32:06Z                 |
   | description               |                                      |
   | dns_domain                | None                                 |
   | id                        | 84a7e627-573b-49da-af66-c9a65244f3ce |
   | ipv4_address_scope        | None                                 |
   | ipv6_address_scope        | None                                 |
   | is_default                | None                                 |
   | mtu                       | 1450                                 |
   | name                      | global_network                       |
   | port_security_enabled     | True                                 |
   | project_id                | 61b7eba037fd41f29cfba757c010faff     |
   | provider:network_type     | vxlan                                |
   | provider:physical_network | None                                 |
   | provider:segmentation_id  | 7                                    |
   | qos_policy_id             | None                                 |
   | revision_number           | 3                                    |
   | router:external           | Internal                             |
   | segments                  | None                                 |
   | shared                    | True                                 |
   | status                    | ACTIVE                               |
   | subnets                   |                                      |
   | tags                      | []                                   |
   | updated_at                | 2017-01-25T20:32:07Z                 |
   +---------------------------+--------------------------------------+


This is the equivalent of creating a policy on the network that permits
every project to perform the action ``access_as_shared`` on that network.
Neutron treats them as the same thing, so the policy entry for that
network should be visible using the :command:`openstack network rbac list`
command:

.. code-block:: console

   $ openstack network rbac list
   +-------------------------------+-------------+--------------------------------+
   | ID                            | Object Type | Object ID                      |
   +-------------------------------+-------------+--------------------------------+
   | 58a5ee31-2ad6-467d-           | qos_policy  | 1f730d69-1c45-4ade-            |
   | 8bb8-8c2ae3dd1382             |             | a8f2-89070ac4f046              |
   | 27efbd79-f384-4d89-9dfc-      | network     | 84a7e627-573b-49da-            |
   | 6c4a606ceec6                  |             | af66-c9a65244f3ce              |
   +-------------------------------+-------------+--------------------------------+


Use the :command:`openstack network rbac show` command to see the details:

.. code-block:: console

   $ openstack network rbac show 27efbd79-f384-4d89-9dfc-6c4a606ceec6
   +-------------------+--------------------------------------+
   | Field             | Value                                |
   +-------------------+--------------------------------------+
   | action            | access_as_shared                     |
   | id                | 27efbd79-f384-4d89-9dfc-6c4a606ceec6 |
   | name              | None                                 |
   | object_id         | 84a7e627-573b-49da-af66-c9a65244f3ce |
   | object_type       | network                              |
   | project_id        | 61b7eba037fd41f29cfba757c010faff     |
   | target_project_id | *                                    |
   +-------------------+--------------------------------------+


The output shows that the entry allows the action ``access_as_shared``
on object ``84a7e627-573b-49da-af66-c9a65244f3ce`` of type ``network``
to target_project ``*``, which is a wildcard that represents all projects.

Currently, the ``shared`` flag is just a mapping to the underlying
RBAC policies for a network. Setting the flag to ``True`` on a network
creates a wildcard RBAC entry. Setting it to ``False`` removes the
wildcard entry.

When you run :command:`openstack network list` or
:command:`openstack network show`, the ``shared`` flag is calculated by the
server based on the calling project and the RBAC entries for each network.
For QoS objects use :command:`openstack network qos policy list` or
:command:`openstack network qos policy show` respectively.
If there is a wildcard entry, the ``shared`` flag is always set to ``True``.
If there are only entries that share with specific projects, only
the projects the object is shared to will see the flag as ``True``
and the rest will see the flag as ``False``.


Allowing a network to be used as an external network
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To make a network available as an external network for specific projects
rather than all projects, use the ``access_as_external`` action.

#. Create a network that you want to be available as an external network:

   .. code-block:: console

      $ openstack network create secret_external_network
      +---------------------------+--------------------------------------+
      | Field                     | Value                                |
      +---------------------------+--------------------------------------+
      | admin_state_up            | UP                                   |
      | availability_zone_hints   |                                      |
      | availability_zones        |                                      |
      | created_at                | 2017-01-25T20:36:59Z                 |
      | description               |                                      |
      | dns_domain                | None                                 |
      | id                        | 802d4e9e-4649-43e6-9ee2-8d052a880cfb |
      | ipv4_address_scope        | None                                 |
      | ipv6_address_scope        | None                                 |
      | is_default                | None                                 |
      | mtu                       | 1450                                 |
      | name                      | secret_external_network              |
      | port_security_enabled     | True                                 |
      | project_id                | 61b7eba037fd41f29cfba757c010faff     |
      | proider:network_type      | vxlan                                |
      | provider:physical_network | None                                 |
      | provider:segmentation_id  | 21                                   |
      | qos_policy_id             | None                                 |
      | revision_number           | 3                                    |
      | router:external           | Internal                             |
      | segments                  | None                                 |
      | shared                    | False                                |
      | status                    | ACTIVE                               |
      | subnets                   |                                      |
      | tags                      | []                                   |
      | updated_at                | 2017-01-25T20:36:59Z                 |
      +---------------------------+--------------------------------------+


#. Create a policy entry using the :command:`openstack network rbac create`
   command (in this example, the ID of the project we want to share with is
   ``838030a7bf3c4d04b4b054c0f0b2b17c``):

   .. code-block:: console

      $ openstack network rbac create --target-project \
      838030a7bf3c4d04b4b054c0f0b2b17c --action access_as_external \
      --type network 802d4e9e-4649-43e6-9ee2-8d052a880cfb
      +-------------------+--------------------------------------+
      | Field             | Value                                |
      +-------------------+--------------------------------------+
      | action            | access_as_external                   |
      | id                | afdd5b8d-b6f5-4a15-9817-5231434057be |
      | name              | None                                 |
      | object_id         | 802d4e9e-4649-43e6-9ee2-8d052a880cfb |
      | object_type       | network                              |
      | project_id        | 61b7eba037fd41f29cfba757c010faff     |
      | target_project_id | 838030a7bf3c4d04b4b054c0f0b2b17c     |
      +-------------------+--------------------------------------+


The ``target-project`` parameter specifies the project that requires
access to the network. The ``action`` parameter specifies what
the project is allowed to do. The ``type`` parameter indicates
that the target object is a network. The final parameter is the ID of
the network we are granting external access to.

Now project ``838030a7bf3c4d04b4b054c0f0b2b17c`` is able to see
the network when running :command:`openstack network list`
and :command:`openstack network show` and can attach router gateway
ports to that network. No other users (other than admins
and the owner) are able to see the network.

To remove access for that project, delete the policy that allows
it using the :command:`openstack network rbac delete` command:

.. code-block:: console

   $ openstack network rbac delete afdd5b8d-b6f5-4a15-9817-5231434057be

If that project has router gateway ports attached to that network,
the server prevents the policy from being deleted until the
ports have been deleted:

.. code-block:: console

   $ openstack network rbac delete afdd5b8d-b6f5-4a15-9817-5231434057be
   RBAC policy on object afdd5b8d-b6f5-4a15-9817-5231434057be
   cannot be removed because other objects depend on it.

This process can be repeated any number of times to make a network
available as external to an arbitrary number of projects.

If a network is marked as external during creation, it now implicitly
creates a wildcard RBAC policy granting everyone access to preserve
previous behavior before this feature was added.

.. code-block:: console

   $ openstack network create global_external_network --external
   +---------------------------+--------------------------------------+
   | Field                     | Value                                |
   +---------------------------+--------------------------------------+
   | admin_state_up            | UP                                   |
   | availability_zone_hints   |                                      |
   | availability_zones        |                                      |
   | created_at                | 2017-01-25T20:41:44Z                 |
   | description               |                                      |
   | dns_domain                | None                                 |
   | id                        | 72a257a2-a56e-4ac7-880f-94a4233abec6 |
   | ipv4_address_scope        | None                                 |
   | ipv6_address_scope        | None                                 |
   | is_default                | None                                 |
   | mtu                       | 1450                                 |
   | name                      | global_external_network              |
   | port_security_enabled     | True                                 |
   | project_id                | 61b7eba037fd41f29cfba757c010faff     |
   | provider:network_type     | vxlan                                |
   | provider:physical_network | None                                 |
   | provider:segmentation_id  | 69                                   |
   | qos_policy_id             | None                                 |
   | revision_number           | 4                                    |
   | router:external           | External                             |
   | segments                  | None                                 |
   | shared                    | False                                |
   | status                    | ACTIVE                               |
   | subnets                   |                                      |
   | tags                      | []                                   |
   | updated_at                | 2017-01-25T20:41:44Z                 |
   +---------------------------+--------------------------------------+


In the output above the standard ``router:external`` attribute is
``External`` as expected. Now a wildcard policy is visible in the
RBAC policy listings:

.. code-block:: console

   $ openstack network rbac list --long -c ID -c Action
   +--------------------------------------+--------------------+
   | ID                                   | Action             |
   +--------------------------------------+--------------------+
   | b694e541-bdca-480d-94ec-eda59ab7d71a | access_as_external |
   +--------------------------------------+--------------------+


You can modify or delete this policy with the same constraints
as any other RBAC ``access_as_external`` policy.


Preventing regular users from sharing objects with each other
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The default ``policy.yaml`` file will not allow regular
users to share objects with every other project using a wildcard;
however, it will allow them to share objects with specific project
IDs.

If an operator wants to prevent normal users from doing this, the
``"create_rbac_policy":`` entry in ``policy.yaml`` can be adjusted
from ``""`` to ``"rule:admin_only"``.


Improve database RBAC query operations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Since [1]_, present in Yoga version, Neutron has indexes for
"target_tenant" (now "target_project") and "action" columns in all
RBAC related tables. That improves the SQL queries involving the
RBAC tables [2]_. Any system before Yoga won't have these indexes
but the system administrator can manually add them to the Neutron
database following the next steps:

* Find the RBAC tables:

.. code-block:: console

    $ tables=`mysql -e "use ovs_neutron; show tables;" | grep rbac`


* Insert the indexes for the "target_tenant" and "action" columns:

    $ for table in $tables do; mysql -e \
        "alter table $table add key (action); alter table $table add key (target_tenant);"; done


In order to prevent errors during a system upgrade, [3]_ was
implemented and backported up to Yoga. This patch checks if any index
is already present in the Neutron tables and avoids executing the
index creation command again.


.. [1] https://review.opendev.org/c/openstack/neutron/+/810072
.. [2] https://github.com/openstack/neutron-lib/blob/890d62a3df3f35bb18bf1a11e79a9e97e7dd2d2c/neutron_lib/db/model_query.py#L123-L131
.. [3] https://review.opendev.org/c/openstack/neutron/+/884617
