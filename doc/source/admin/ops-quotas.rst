================================
Manage Networking service quotas
================================

A quota limits the number of available resources. A default
quota might be enforced for all projects. When you try to create
more resources than the quota allows, an error occurs:

.. code-block:: console

   $ openstack network create test_net
    Error while executing command: ConflictException: 409, Quota exceeded for resources: ['network'].

Per-project quota configuration is also supported by the quota
extension API. See :ref:`cfg_quotas_per_project` for details.

Basic quota configuration
~~~~~~~~~~~~~~~~~~~~~~~~~

In the Networking default quota mechanism, all projects have
the same quota values, such as the number of resources that a
project can create.

The quota value is defined in the OpenStack Networking
``/etc/neutron/neutron.conf`` configuration file. This example shows the
default quota values:

.. code-block:: ini

   [quotas]
   # Default number of resources allowed per project. A negative value means
   # unlimited. (integer value)
   #default_quota = -1

   # Number of networks allowed per project. A negative value means unlimited.
   # (integer value)
   quota_network = 100

   # Number of subnets allowed per project, A negative value means unlimited.
   # (integer value)
   quota_subnet = 100

   # Number of ports allowed per project. A negative value means unlimited.
   # (integer value)
   quota_port = 500

   # default driver to use for quota checks
   quota_driver = neutron.db.quota.driver_nolock.DbQuotaNoLockDriver

   # When set to True, quota usage will be tracked in the Neutron database
   # for each resource, by directly mapping to a data model class, for
   # example, networks, subnets, ports, etc. When set to False, quota usage
   # will be tracked by the quota engine as a count of the object type
   # directly. For more information, see the Quota Management and
   # Enforcement guide.
   # (boolean value)
   track_quota_usage = true

   #
   # From neutron.extensions
   #

   # Number of routers allowed per project. A negative value means unlimited.
   # (integer value)
   quota_router = 10

   # Number of floating IPs allowed per project. A negative value means
   # unlimited.
   # (integer value)
   quota_floatingip = 50

   # Number of security groups allowed per project. A negative value means
   # unlimited.
   # (integer value)
   quota_security_group = 10

   # Number of security group rules allowed per project. A negative value means
   # unlimited.
   # (integer value)
   quota_security_group_rule = 100

.. _cfg_quotas_per_project:

Configure per-project quotas
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
OpenStack Networking also supports per-project quota limit by
quota extension API.

Use these commands to manage per-project quotas:

openstack quota delete
    Delete defined quotas for a specified project

openstack quota list
    Lists defined quotas for all projects with non-default quota values

openstack quota show
    Shows defined quotas for all projects

openstack quota show <project>
    Shows quotas for a specified project

openstack quota show --default <project>
    Show default quotas for a specified project

openstack quota set --<resource> <value> <project>
    Updates quotas for a specified project

Only users with the ``admin`` role can change a quota value. By default,
the default set of quotas are enforced for all projects, so no
:command:`opentack quota create` command exists.

#. Configure Networking to show per-project quotas

   Set the ``quota_driver`` option in the ``/etc/neutron/neutron.conf`` file.

   .. code-block:: ini

      quota_driver = neutron.db.quota.driver.DbQuotaDriver

   When you set this option, the output for Networking commands shows ``quotas``.

#. List Networking extensions.

   To list the Networking extensions, run this command:

   .. code-block:: console

      $ openstack extension list --network

   The command shows the ``quotas`` extension, which provides
   per-project quota management support.

   .. code-block:: console

      +------------------------+------------------------+--------------------------+
      | Name                   | Alias                  | Description              |
      +------------------------+------------------------+--------------------------+
      | ...                    | ...                    | ...                      |
      | Quota management       | quotas                 | Expose functions for     |
      | support                |                        | quotas management per    |
      |                        |                        | project                  |
      | ...                    | ...                    | ...                      |
      +------------------------+------------------------+--------------------------+

#. Show information for the quotas extension.

   To show information for the ``quotas`` extension, run this command:

   .. code-block:: console

      $ openstack extension show quotas
      +-------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
      | Field       | Value                                                                                                                                                                                     |
      +-------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
      | alias       | quotas                                                                                                                                                                                    |
      | description | Expose functions for quotas management per project                                                                                                                                        |
      | id          | quotas                                                                                                                                                                                    |
      | links       | []                                                                                                                                                                                        |
      | location    | Munch({'cloud': '', 'region_name': 'RegionOne', 'zone': None, 'project': Munch({'id': 'afc55714081b4ef29f99ec128cb1fa30', 'name': 'demo', 'domain_id': 'default', 'domain_name': None})}) |
      | name        | Quota management support                                                                                                                                                                  |
      | updated     | 2012-07-29T10:00:00-00:00                                                                                                                                                                 |
      +-------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

   .. note::

      Only some plug-ins support per-project quotas. Specifically, OVN and Open
      vSwitch support them, but new versions of other plug-ins might bring
      additional functionality. See the documentation for each plug-in.

#. List projects who have per-project quota support.

   The :command:`openstack quota list` command lists projects for which the
   per-project quota is enabled. The command does not list projects with
   default quota support. You must be an administrative user to run this
   command:

   .. code-block:: console

      $ openstack quota list --network
      +----------------------------------+--------------+----------+-------+---------------+---------+-----------------+----------------------+---------+--------------+
      | Project ID                       | Floating IPs | Networks | Ports | RBAC Policies | Routers | Security Groups | Security Group Rules | Subnets | Subnet Pools |
      +----------------------------------+--------------+----------+-------+---------------+---------+-----------------+----------------------+---------+--------------+
      | 6f88036c45344d9999a1f971e4882723 |           50 |      100 |   500 |            10 |      20 |              10 |                  100 |     100 |           -1 |
      | bff5c9455ee24231b5bc713c1b96d422 |          100 |      100 |   500 |            10 |      10 |              10 |                  100 |     100 |           -1 |
      +----------------------------------+--------------+----------+-------+---------------+---------+-----------------+----------------------+---------+--------------+

#. Show per-project quota values.

   The :command:`openstack quota show` command reports the current
   set of quota limits for the specified project.
   Non-administrative users can run this command without the
   ``<project>`` argument. If per-project quota limits are
   not enabled for the project, the command shows the default
   set of quotas.

   .. code-block:: console

      $ openstack quota show 6f88036c45344d9999a1f971e4882723
      +----------------+-------+
      | Resource       | Limit |
      +----------------+-------+
      | networks       |   100 |
      | ports          |   500 |
      | rbac_policies  |    10 |
      | routers        |    20 |
      | subnets        |   100 |
      | subnet_pools   |    -1 |
      | floating-ips   |    50 |
      | secgroup-rules |   100 |
      | secgroups      |    10 |
      +----------------+-------+

   The following command shows the command output for a
   non-administrative user.

   .. code-block:: console

      $ openstack quota show
      +----------------+-------+
      | Resource       | Limit |
      +----------------+-------+
      | networks       |   100 |
      | ports          |   500 |
      | rbac_policies  |    10 |
      | routers        |    20 |
      | subnets        |   100 |
      | subnet_pools   |    -1 |
      | floating-ips   |    50 |
      | secgroup-rules |   100 |
      | secgroups      |    10 |
      +----------------+-------+

#. Update quota values for a specified project.

   Use the :command:`openstack quota set` command to
   update a quota for a specified project.

   .. code-block:: console

      $ openstack quota set --routers 20 6f88036c45344d9999a1f971e4882723

   You can update quotas for multiple resources through one
   command.

   .. code-block:: console

      $ openstack quota set --subnets 50 --ports 100 6f88036c45344d9999a1f971e4882723

   You can update the limits of multiple resources through
   one command:

   .. code-block:: console

      $ openstack quota set --networks 50 --subnets 50 --ports 100 \
        --floating-ips 20 --routers 5 6f88036c45344d9999a1f971e4882723

#. Delete per-project quota values.

   To clear per-project quota limits, use the
   :command:`openstack quota delete` command.

   .. code-block:: console

      $ openstack quota delete 6f88036c45344d9999a1f971e4882723

   After you run this command, you can see that quota
   values for the project are reset to the default values.

   .. code-block:: console

      $ openstack quota show --network 6f88036c45344d9999a1f971e4882723
      +----------------+-------+
      | Resource       | Limit |
      +----------------+-------+
      | networks       |   100 |
      | ports          |   500 |
      | rbac_policies  |    10 |
      | routers        |    20 |
      | subnets        |   100 |
      | subnet_pools   |    -1 |
      | floating-ips   |    50 |
      | secgroup-rules |   100 |
      | secgroups      |    10 |
      +----------------+-------+

.. note::

   Listing default quotas with the OpenStack command line client will
   provide all quotas for networking and other services.
