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


How the 'shared' flag relates to these entries
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

As introduced in other guide entries, neutron provides a means of
making an object (``network``, ``qos-policy``, ``security-group``) available
to every project.
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
to target_tenant ``*``, which is a wildcard that represents all projects.

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

The default ``policy.json`` file will not allow regular
users to share objects with every other project using a wildcard;
however, it will allow them to share objects with specific project
IDs.

If an operator wants to prevent normal users from doing this, the
``"create_rbac_policy":`` entry in ``policy.json`` can be adjusted
from ``""`` to ``"rule:admin_only"``.
