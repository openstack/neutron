=========================================
Configure Identity service for Networking
=========================================

**To configure the Identity service for use with Networking**

#. Create the ``get_id()`` function

   The ``get_id()`` function stores the ID of created objects, and removes
   the need to copy and paste object IDs in later steps:

   a. Add the following function to your ``.bashrc`` file:

      .. code-block:: bash

         function get_id () {
         echo `"$@" | awk '/ id / { print $4 }'`
         }

   b. Source the ``.bashrc`` file:

      .. code-block:: console

         $ source .bashrc

#. Create the Networking service entry

   Networking must be available in the Compute service catalog. Create the
   service:

   .. code-block:: console

      $ NEUTRON_SERVICE_ID=$(get_id openstack service create network \
        --name neutron --description 'OpenStack Networking Service')

#. Create the Networking service endpoint entry

   The way that you create a Networking endpoint entry depends on whether
   you are using the SQL or the template catalog driver:

   -  If you are using the ``SQL driver``, run the following command with the
      specified region (``$REGION``), IP address of the Networking server
      (``$IP``), and service ID (``$NEUTRON_SERVICE_ID``, obtained in the
      previous step).

      .. code-block:: console

         $ openstack endpoint create $NEUTRON_SERVICE_ID --region $REGION \
           --publicurl 'http://$IP:9696/' --adminurl 'http://$IP:9696/' \
           --internalurl 'http://$IP:9696/'

      For example:

      .. code-block:: console

         $ openstack endpoint create $NEUTRON_SERVICE_ID --region myregion \
           --publicurl "http://10.211.55.17:9696/" \
           --adminurl "http://10.211.55.17:9696/" \
           --internalurl "http://10.211.55.17:9696/"

   -  If you are using the ``template driver``, specify the following
      parameters in your Compute catalog template file
      (``default_catalog.templates``), along with the region (``$REGION``)
      and IP address of the Networking server (``$IP``).

      .. code-block:: bash

         catalog.$REGION.network.publicURL = http://$IP:9696
         catalog.$REGION.network.adminURL = http://$IP:9696
         catalog.$REGION.network.internalURL = http://$IP:9696
         catalog.$REGION.network.name = Network Service

      For example:

      .. code-block:: bash

         catalog.$Region.network.publicURL = http://10.211.55.17:9696
         catalog.$Region.network.adminURL = http://10.211.55.17:9696
         catalog.$Region.network.internalURL = http://10.211.55.17:9696
         catalog.$Region.network.name = Network Service

#. Create the Networking service user

   You must provide admin user credentials that Compute and some internal
   Networking components can use to access the Networking API. Create a
   special ``service`` project and a ``neutron`` user within this project,
   and assign an ``admin`` role to this role.

   a. Create the ``admin`` role:

      .. code-block:: console

         $ ADMIN_ROLE=$(get_id openstack role create admin)

   b. Create the ``neutron`` user:

      .. code-block:: console

         $ NEUTRON_USER=$(get_id openstack user create neutron \
           --password "$NEUTRON_PASSWORD" --email demo@example.com \
           --project service)

   c. Create the ``service`` project:

      .. code-block:: console

         $ SERVICE_TENANT=$(get_id openstack project create service \
           --description "Services project" --domain default)

   d. Establish the relationship among the project, user, and role:

      .. code-block:: console

         $ openstack role add $ADMIN_ROLE --user $NEUTRON_USER \
           --project $SERVICE_TENANT

For information about how to create service entries and users, see the `Ocata Installation
Tutorials and Guides <https://docs.openstack.org/project-install-guide/ocata/>`_
for your distribution.

Compute
~~~~~~~

If you use Networking, do not run the Compute ``nova-network`` service (like
you do in traditional Compute deployments). Instead, Compute delegates
most network-related decisions to Networking.

.. note::

   Uninstall ``nova-network`` and reboot any physical nodes that have been
   running ``nova-network`` before using them to run Networking.
   Inadvertently running the ``nova-network`` process while using
   Networking can cause problems, as can stale iptables rules pushed
   down by previously running ``nova-network``.

Compute proxies project-facing API calls to manage security groups and
floating IPs to Networking APIs. However, operator-facing tools such
as ``nova-manage``, are not proxied and should not be used.

.. warning::

   When you configure networking, you must use this guide. Do not rely
   on Compute networking documentation or past experience with Compute.
   If a :command:`nova` command or configuration option related to networking
   is not mentioned in this guide, the command is probably not
   supported for use with Networking. In particular, you cannot use CLI
   tools like ``nova-manage`` and ``nova`` to manage networks or IP
   addressing, including both fixed and floating IPs, with Networking.

To ensure that Compute works properly with Networking (rather than the
legacy ``nova-network`` mechanism), you must adjust settings in the
``nova.conf`` configuration file.

Networking API and credential configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Each time you provision or de-provision a VM in Compute, ``nova-\*``
services communicate with Networking using the standard API. For this to
happen, you must configure the following items in the ``nova.conf`` file
(used by each ``nova-compute`` and ``nova-api`` instance).

.. list-table:: **nova.conf API and credential settings prior to Mitaka**
   :widths: 20 50
   :header-rows: 1

   * - Attribute name
     - Required
   * - ``[DEFAULT] use_neutron``
     - Modify from the default to ``True`` to
       indicate that Networking should be used rather than the traditional
       nova-network networking model.
   * - ``[neutron] url``
     - Update to the host name/IP and port of the neutron-server instance
       for this deployment.
   * - ``[neutron] auth_strategy``
     - Keep the default ``keystone`` value for all production deployments.
   * - ``[neutron] admin_project_name``
     - Update to the name of the service tenant created in the above section on
       Identity configuration.
   * - ``[neutron] admin_username``
     - Update to the name of the user created in the above section on Identity
       configuration.
   * - ``[neutron] admin_password``
     - Update to the password of the user created in the above section on
       Identity configuration.
   * - ``[neutron] admin_auth_url``
     - Update to the Identity server IP and port. This is the Identity
       (keystone) admin API server IP and port value, and not the Identity
       service API IP and port.

.. list-table:: **nova.conf API and credential settings in Newton**
   :widths: 20 50
   :header-rows: 1

   * - Attribute name
     - Required
   * - ``[DEFAULT] use_neutron``
     - Modify from the default to ``True`` to
       indicate that Networking should be used rather than the traditional
       nova-network networking model.
   * - ``[neutron] url``
     - Update to the host name/IP and port of the neutron-server instance
       for this deployment.
   * - ``[neutron] auth_strategy``
     - Keep the default ``keystone`` value for all production deployments.
   * - ``[neutron] project_name``
     - Update to the name of the service tenant created in the above section on
       Identity configuration.
   * - ``[neutron] username``
     - Update to the name of the user created in the above section on Identity
       configuration.
   * - ``[neutron] password``
     - Update to the password of the user created in the above section on
       Identity configuration.
   * - ``[neutron] auth_url``
     - Update to the Identity server IP and port. This is the Identity
       (keystone) admin API server IP and port value, and not the Identity
       service API IP and port.

Configure security groups
~~~~~~~~~~~~~~~~~~~~~~~~~

The Networking service provides security group functionality using a
mechanism that is more flexible and powerful than the security group
capabilities built into Compute. Therefore, if you use Networking, you
should always disable built-in security groups and proxy all security
group calls to the Networking API. If you do not, security policies
will conflict by being simultaneously applied by both services.

To proxy security groups to Networking, use the following configuration
values in the ``nova.conf`` file:

**nova.conf security group settings**

+-----------------------+-----------------------------------------------------+
| Item                  | Configuration                                       |
+=======================+=====================================================+
| ``firewall_driver``   | Update to ``nova.virt.firewall.NoopFirewallDriver``,|
|                       | so that nova-compute does not perform               |
|                       | iptables-based filtering itself.                    |
+-----------------------+-----------------------------------------------------+

Configure metadata
~~~~~~~~~~~~~~~~~~

The Compute service allows VMs to query metadata associated with a VM by
making a web request to a special 169.254.169.254 address. Networking
supports proxying those requests to nova-api, even when the requests are
made from isolated networks, or from multiple networks that use
overlapping IP addresses.

To enable proxying the requests, you must update the following fields in
``[neutron]`` section in the ``nova.conf``.

**nova.conf metadata settings**

+---------------------------------+------------------------------------------+
| Item                            | Configuration                            |
+=================================+==========================================+
| ``service_metadata_proxy``      | Update to ``true``, otherwise nova-api   |
|                                 | will not properly respond to requests    |
|                                 | from the neutron-metadata-agent.         |
+---------------------------------+------------------------------------------+
| ``metadata_proxy_shared_secret``| Update to a string "password" value.     |
|                                 | You must also configure the same value in|
|                                 | the ``metadata_agent.ini`` file, to      |
|                                 | authenticate requests made for metadata. |
|                                 |                                          |
|                                 | The default value of an empty string in  |
|                                 | both files will allow metadata to        |
|                                 | function, but will not be secure if any  |
|                                 | non-trusted entities have access to the  |
|                                 | metadata APIs exposed by nova-api.       |
+---------------------------------+------------------------------------------+

.. note::

   As a precaution, even when using ``metadata_proxy_shared_secret``,
   we recommend that you do not expose metadata using the same
   nova-api instances that are used for projects. Instead, you should
   run a dedicated set of nova-api instances for metadata that are
   available only on your management network. Whether a given nova-api
   instance exposes metadata APIs is determined by the value of
   ``enabled_apis`` in its ``nova.conf``.

Example nova.conf (for nova-compute and nova-api)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Example values for the above settings, assuming a cloud controller node
running Compute and Networking with an IP address of 192.168.1.2:

.. code-block:: ini

   [DEFAULT]
   use_neutron = True
   firewall_driver=nova.virt.firewall.NoopFirewallDriver

   [neutron]
   url=http://192.168.1.2:9696
   auth_strategy=keystone
   admin_tenant_name=service
   admin_username=neutron
   admin_password=password
   admin_auth_url=http://192.168.1.2:35357/v2.0
   service_metadata_proxy=true
   metadata_proxy_shared_secret=foo
