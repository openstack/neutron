================================
Manage Networking service quotas
================================

A quota limits the number of available resources. A default
quota might be enforced for all projects. When you try to create
more resources than the quota allows, an error occurs:

.. code-block:: console

   $ openstack network create test_net
    Quota exceeded for resources: ['network']

Per-project quota configuration is also supported by the quota
extension API. See :ref:`cfg_quotas_per_tenant` for details.

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
   # number of networks allowed per tenant, and minus means unlimited
   quota_network = 10

   # number of subnets allowed per tenant, and minus means unlimited
   quota_subnet = 10

   # number of ports allowed per tenant, and minus means unlimited
   quota_port = 50

   # default driver to use for quota checks
   quota_driver = neutron.quota.DbQuotaNoLockDriver

OpenStack Networking also supports quotas for L3 resources:
router and floating IP. Add these lines to the
``quotas`` section in the ``/etc/neutron/neutron.conf`` file:

.. code-block:: ini

   [quotas]
   # number of routers allowed per tenant, and minus means unlimited
   quota_router = 10

   # number of floating IPs allowed per tenant, and minus means unlimited
   quota_floatingip = 50

OpenStack Networking also supports quotas for security group
resources: number of security groups and number of rules.
Add these lines to the ``quotas`` section in the
``/etc/neutron/neutron.conf`` file:

.. code-block:: ini

   [quotas]
   # number of security groups per tenant, and minus means unlimited
   quota_security_group = 10

   # number of security rules allowed per tenant, and minus means unlimited
   quota_security_group_rule = 100

.. _cfg_quotas_per_tenant:

Configure per-project quotas
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
OpenStack Networking also supports per-project quota limit by
quota extension API.

.. todo:: This document needs to be migrated to using ``openstack`` commands
          rather than the deprecated ``neutron`` commands.

Use these commands to manage per-project quotas:

neutron quota-delete
    Delete defined quotas for a specified project

neutron quota-list
    Lists defined quotas for all projects

neutron quota-show
    Shows quotas for a specified project

neutron quota-default-show
    Show default quotas for a specified tenant

neutron quota-update
    Updates quotas for a specified project

Only users with the ``admin`` role can change a quota value. By default,
the default set of quotas are enforced for all projects, so no
:command:`quota-create` command exists.

#. Configure Networking to show per-project quotas

   Set the ``quota_driver`` option in the ``/etc/neutron/neutron.conf`` file.

   .. code-block:: ini

      quota_driver = neutron.db.quota_db.DbQuotaDriver

   When you set this option, the output for Networking commands shows ``quotas``.

#. List Networking extensions.

   To list the Networking extensions, run this command:

   .. code-block:: console

      $ openstack extension list --network

   The command shows the ``quotas`` extension, which provides
   per-project quota management support.

   .. note::

      Many of the extensions shown below are supported in the Mitaka release and later.

   .. code-block:: console

      +------------------------+------------------------+--------------------------+
      | Name                   | Alias                  | Description              |
      +------------------------+------------------------+--------------------------+
      | ...                    | ...                    | ...                      |
      | Quota management       | quotas                 | Expose functions for     |
      | support                |                        | quotas management per    |
      |                        |                        | tenant                   |
      | ...                    | ...                    | ...                      |
      +------------------------+------------------------+--------------------------+

#. Show information for the quotas extension.

   To show information for the ``quotas`` extension, run this command:

   .. code-block:: console

      $ neutron ext-show quotas
      +-------------+------------------------------------------------------------+
      | Field       | Value                                                      |
      +-------------+------------------------------------------------------------+
      | alias       | quotas                                                     |
      | description | Expose functions for quotas management per tenant          |
      | links       |                                                            |
      | name        | Quota management support                                   |
      | namespace   | https://docs.openstack.org/network/ext/quotas-sets/api/v2.0 |
      | updated     | 2012-07-29T10:00:00-00:00                                  |
      +-------------+------------------------------------------------------------+

   .. note::

      Only some plug-ins support per-project quotas.
      Specifically, Open vSwitch, Linux Bridge, and VMware NSX
      support them, but new versions of other plug-ins might
      bring additional functionality. See the documentation for
      each plug-in.

#. List projects who have per-project quota support.

   The :command:`neutron quota-list` command lists projects for which the
   per-project quota is enabled. The command does not list projects with
   default quota support. You must be an administrative user to run this
   command:

   .. code-block:: console

      $ neutron quota-list
      +------------+---------+------+--------+--------+----------------------------------+
      | floatingip | network | port | router | subnet | tenant_id                        |
      +------------+---------+------+--------+--------+----------------------------------+
      |         20 |       5 |   20 |     10 |      5 | 6f88036c45344d9999a1f971e4882723 |
      |         25 |      10 |   30 |     10 |     10 | bff5c9455ee24231b5bc713c1b96d422 |
      +------------+---------+------+--------+--------+----------------------------------+

#. Show per-project quota values.

   The :command:`neutron quota-show` command reports the current
   set of quota limits for the specified project.
   Non-administrative users can run this command without the
   ``--tenant_id`` parameter. If per-project quota limits are
   not enabled for the project, the command shows the default
   set of quotas.

   .. note::

      Additional quotas added in the Mitaka release include ``security_group``,
      ``security_group_rule``, ``subnet``, and ``subnetpool``.

   .. code-block:: console

      $ neutron quota-show --tenant_id 6f88036c45344d9999a1f971e4882723
      +---------------------+-------+
      | Field               | Value |
      +---------------------+-------+
      | floatingip          | 50    |
      | network             | 10    |
      | port                | 50    |
      | rbac_policy         | 10    |
      | router              | 10    |
      | security_group      | 10    |
      | security_group_rule | 100   |
      | subnet              | 10    |
      | subnetpool          | -1    |
      +---------------------+-------+

   The following command shows the command output for a
   non-administrative user.

   .. code-block:: console

      $ neutron quota-show
      +---------------------+-------+
      | Field               | Value |
      +---------------------+-------+
      | floatingip          | 50    |
      | network             | 10    |
      | port                | 50    |
      | rbac_policy         | 10    |
      | router              | 10    |
      | security_group      | 10    |
      | security_group_rule | 100   |
      | subnet              | 10    |
      | subnetpool          | -1    |
      +---------------------+-------+

#. Update quota values for a specified project.

   Use the :command:`neutron quota-update` command to
   update a quota for a specified project.

   .. code-block:: console

      $ neutron quota-update --tenant_id 6f88036c45344d9999a1f971e4882723 --network 5
      +---------------------+-------+
      | Field               | Value |
      +---------------------+-------+
      | floatingip          | 50    |
      | network             | 5     |
      | port                | 50    |
      | rbac_policy         | 10    |
      | router              | 10    |
      | security_group      | 10    |
      | security_group_rule | 100   |
      | subnet              | 10    |
      | subnetpool          | -1    |
      +---------------------+-------+

   You can update quotas for multiple resources through one
   command.

   .. code-block:: console

      $ neutron quota-update --tenant_id 6f88036c45344d9999a1f971e4882723 --subnet 5 --port 20
      +---------------------+-------+
      | Field               | Value |
      +---------------------+-------+
      | floatingip          | 50    |
      | network             | 5     |
      | port                | 20    |
      | rbac_policy         | 10    |
      | router              | 10    |
      | security_group      | 10    |
      | security_group_rule | 100   |
      | subnet              | 5     |
      | subnetpool          | -1    |
      +---------------------+-------+

   To update the limits for an L3 resource such as, router
   or floating IP, you must define new values for the quotas
   after the ``--`` directive.

   This example updates the limit of the number of floating
   IPs for the specified project.

   .. code-block:: console

      $ neutron quota-update --tenant_id 6f88036c45344d9999a1f971e4882723 --floatingip 20
      +---------------------+-------+
      | Field               | Value |
      +---------------------+-------+
      | floatingip          | 20    |
      | network             | 5     |
      | port                | 20    |
      | rbac_policy         | 10    |
      | router              | 10    |
      | security_group      | 10    |
      | security_group_rule | 100   |
      | subnet              | 5     |
      | subnetpool          | -1    |
      +---------------------+-------+

   You can update the limits of multiple resources by
   including L2 resources and L3 resource through one
   command:

   .. code-block:: console

      $ neutron quota-update --tenant_id 6f88036c45344d9999a1f971e4882723 \
        --network 3 --subnet 3 --port 3 --floatingip 3 --router 3
      +---------------------+-------+
      | Field               | Value |
      +---------------------+-------+
      | floatingip          | 3     |
      | network             | 3     |
      | port                | 3     |
      | rbac_policy         | 10    |
      | router              | 3     |
      | security_group      | 10    |
      | security_group_rule | 100   |
      | subnet              | 3     |
      | subnetpool          | -1    |
      +---------------------+-------+

#. Delete per-project quota values.

   To clear per-project quota limits, use the
   :command:`neutron quota-delete` command.

   .. code-block:: console

      $ neutron quota-delete --tenant_id 6f88036c45344d9999a1f971e4882723
       Deleted quota: 6f88036c45344d9999a1f971e4882723

   After you run this command, you can see that quota
   values for the project are reset to the default values.

   .. code-block:: console

      $ openstack quota show 6f88036c45344d9999a1f971e4882723
      +---------------------+-------+
      | Field               | Value |
      +---------------------+-------+
      | floatingip          | 50    |
      | network             | 10    |
      | port                | 50    |
      | rbac_policy         | 10    |
      | router              | 10    |
      | security_group      | 10    |
      | security_group_rule | 100   |
      | subnet              | 10    |
      | subnetpool          | -1    |
      +---------------------+-------+

.. note::

   Listing default quotas with the OpenStack command line client will
   provide all quotas for networking and other services. Previously,
   the :command:`neutron quota-show --tenant_id` would list only networking
   quotas.
