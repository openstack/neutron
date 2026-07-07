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

Supported quota resources
~~~~~~~~~~~~~~~~~~~~~~~~~

The following table lists all resources subject to quota enforcement in
Neutron, along with their configuration option name and default limit:

.. list-table::
   :header-rows: 1
   :widths: 20 25 10 40

   * - Resource
     - Configuration option
     - Default
     - Description
   * - firewall_group
     - ``quota_firewall_group``
     - 10
     - Number of firewall groups allowed per project (``neutron-fwaas``).
   * - firewall_policy
     - ``quota_firewall_policy``
     - 10
     - Number of firewall policies allowed per project (``neutron-fwaas``).
   * - firewall_rule
     - ``quota_firewall_rule``
     - 100
     - Number of firewall rules allowed per project (``neutron-fwaas``).
   * - floating_ips
     - ``quota_floatingip``
     - 50
     - Number of floating IPs allowed per project.
   * - networks
     - ``quota_network``
     - 100
     - Number of networks allowed per project.
   * - ports
     - ``quota_port``
     - 500
     - Number of ports allowed per project.
   * - rbac_policies
     - ``quota_rbac_policy``
     - 10
     - Number of RBAC policy entries allowed per project.
   * - router_routes
     - ``quota_router_route``
     - 30
     - Number of router routes (extra routes) allowed **per router**.
   * - routers
     - ``quota_router``
     - 10
     - Number of routers allowed per project.
   * - security_group_rules
     - ``quota_security_group_rule``
     - 100
     - Number of security group rules allowed per project (across
       all security groups).
   * - security_groups
     - ``quota_security_group``
     - 10
     - Number of security groups allowed per project.
   * - subnet_pools
     - ``default_quota``
     - -1 (unlimited)
     - Number of subnet pools allowed per project. Uses the global
       ``default_quota`` since no specific option exists.
   * - subnets
     - ``quota_subnet``
     - 100
     - Number of subnets allowed per project.
   * - trunks
     - ``default_quota``
     - -1 (unlimited)
     - Number of trunk ports allowed per project. Uses the global
       ``default_quota`` since no specific option exists.

All quota options are set in the ``[quotas]`` section of
``/etc/neutron/neutron.conf``. A negative value means unlimited (no quota
enforcement for that resource). The ``default_quota`` option provides a
fallback limit for any resource that does not have its own dedicated
configuration option.

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

      quota_driver = neutron.db.quota.driver_nolock.DbQuotaNoLockDriver

   When you set this option, the output for Networking commands shows ``quotas``.
   The ``driver_nolock.DbQuotaNoLockDriver`` is the default quota driver,
   defined in the configuration option ``quota_driver``.

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
      +-------------+----------------------------------------------------+
      | Field       | Value                                              |
      +-------------+----------------------------------------------------+
      | alias       | quotas                                             |
      | description | Expose functions for quotas management per project |
      | name        | Quota management support                           |
      | updated_at  | 2012-07-29T10:00:00-00:00                          |
      +-------------+----------------------------------------------------+

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

   .. note::

      This command will show the quotas for the projects with customized
      quotas. if a project has no customized quotas, the command won't show
      the project.

#. Show per-project quota values and usage.

   The :command:`openstack quota show` command reports the current
   set of quota limits for the specified project.
   Non-administrative users can run this command without the
   ``<project>`` argument. If per-project quota limits are
   not enabled for the project, the command shows the default
   set of quotas. Using the ``--network`` argument, the command will
   show only the network quotas.

   .. code-block:: console

      $ openstack quota show --network 6f88036c45344d9999a1f971e4882723
      +----------------------+-------+
      | Resource             | Limit |
      +----------------------+-------+
      | firewall_rule        |   100 |
      | firewall_group       |    10 |
      | firewall_policy      |    10 |
      | floating_ips         |    50 |
      | networks             |   100 |
      | ports                |   500 |
      | rbac_policies        |    10 |
      | routers              |     5 |
      | router_routes        |    30 |
      | subnets              |   100 |
      | subnet_pools         |    -1 |
      | security_group_rules |   100 |
      | security_groups      |    10 |
      | trunk                |    -1 |
      +----------------------+-------+

   With the ``--usage`` argument, the command will show the usage of the
   quotas. Some resources, like ``router_routes``, are counted per parent
   resource (router). The usage field for these resources will be always zero.

   .. code-block:: console

      $ openstack quota show --network --usage
      +----------------------+-------+--------+----------+
      | Resource             | Limit | In Use | Reserved |
      +----------------------+-------+--------+----------+
      | firewall_rule        |   100 |      0 |        0 |
      | firewall_group       |    10 |      0 |        0 |
      | firewall_policy      |    10 |      0 |        0 |
      | floating_ips         |    50 |      0 |        0 |
      | networks             |   100 |      1 |        0 |
      | ports                |   500 |      2 |        0 |
      | rbac_policies        |     4 |      1 |        0 |
      | routers              |    10 |      1 |        0 |
      | router_routes        |    30 |      0 |        0 |
      | subnets              |   100 |      1 |        0 |
      | subnet_pools         |    -1 |      0 |        0 |
      | security_group_rules |   100 |      6 |        0 |
      | security_groups      |    10 |      2 |        0 |
      | trunk                |    -1 |      0 |        0 |
      +----------------------+-------+--------+----------+

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
      +----------------------+-------+
      | Resource             | Limit |
      +----------------------+-------+
      | firewall_rule        |   100 |
      | firewall_group       |    10 |
      | firewall_policy      |    10 |
      | floating_ips         |    50 |
      | networks             |   100 |
      | ports                |   500 |
      | rbac_policies        |    10 |
      | routers              |    10 |
      | router_routes        |    30 |
      | subnets              |   100 |
      | subnet_pools         |    -1 |
      | security_group_rules |   100 |
      | security_groups      |    10 |
      | trunk                |    -1 |
      +----------------------+-------+

.. note::

   Listing default quotas with the OpenStack command line client will
   provide all quotas for networking and other services.
