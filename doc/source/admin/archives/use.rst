==============
Use Networking
==============

You can manage OpenStack Networking services by using the service
command. For example:

.. code-block:: console

   # service neutron-server stop
   # service neutron-server status
   # service neutron-server start
   # service neutron-server restart

Log files are in the ``/var/log/neutron`` directory.

Configuration files are in the ``/etc/neutron`` directory.

Administrators and projects can use OpenStack Networking to build
rich network topologies. Administrators can create network
connectivity on behalf of projects.

Core Networking API features
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

After installing and configuring Networking (neutron), projects and
administrators can perform create-read-update-delete (CRUD) API networking
operations. This is performed using the Networking API directly with either
the :command:`neutron` command-line interface (CLI) or the :command:`openstack`
CLI. The :command:`neutron` CLI is a wrapper around the Networking API. Every
Networking API call has a corresponding :command:`neutron` command.

The :command:`openstack` CLI is a common interface for all OpenStack
projects, however, not every API operation has been implemented. For the
list of available commands, see `Command List
<https://docs.openstack.org/python-openstackclient/latest/cli/command-list.html>`__.

The :command:`neutron` CLI includes a number of options. For details, see
`Create and manage networks <https://docs.openstack.org/user-guide/cli-create-and-manage-networks.html>`__.

Basic Networking operations
---------------------------

To learn about advanced capabilities available through the :command:`neutron`
command-line interface (CLI), read the networking section `Create and manage
networks <https://docs.openstack.org/user-guide/cli-create-and-manage-networks.html>`__
in the OpenStack End User Guide.

This table shows example :command:`openstack` commands that enable you to
complete basic network operations:

+-------------------------+-------------------------------------------------+
| Operation               | Command                                         |
+=========================+=================================================+
|Creates a network.       |                                                 |
|                         |                                                 |
|                         |     ``$ openstack network create net1``         |
+-------------------------+-------------------------------------------------+
|Creates a subnet that is |                                                 |
|associated with net1.    |                                                 |
|                         |                                                 |
|                         |     ``$ openstack subnet create subnet1``       |
|                         |     ``--subnet-range 10.0.0.0/24``              |
|                         |     ``--network net1``                          |
+-------------------------+-------------------------------------------------+
|Lists ports for a        |                                                 |
|specified project.       |                                                 |
|                         |                                                 |
|                         |     ``$ openstack port list``                   |
+-------------------------+-------------------------------------------------+
|Lists ports for a        |                                                 |
|specified project        |                                                 |
|and displays the ``ID``, |                                                 |
|``Fixed IP Addresses``   |                                                 |
|                         |                                                 |
|                         |     ``$ openstack port list -c ID``             |
|                         |     ``-c "Fixed IP Addresses``                  |
+-------------------------+-------------------------------------------------+
|Shows information for a  |                                                 |
|specified port.          |                                                 |
|                         |     ``$ openstack port show PORT_ID``           |
+-------------------------+-------------------------------------------------+

**Basic Networking operations**

.. note::

   The ``device_owner`` field describes who owns the port. A port whose
   ``device_owner`` begins with:

   -  ``network`` is created by Networking.

   -  ``compute`` is created by Compute.

Administrative operations
-------------------------

The administrator can run any :command:`openstack` command on behalf of
projects by specifying an Identity ``project`` in the command, as
follows:

.. code-block:: console

   $ openstack network create --project PROJECT_ID NETWORK_NAME

For example:

.. code-block:: console

   $ openstack network create --project 5e4bbe24b67a4410bc4d9fae29ec394e net1

.. note::

   To view all project IDs in Identity, run the following command as an
   Identity service admin user:

   .. code-block:: console

      $ openstack project list

Advanced Networking operations
------------------------------

This table shows example CLI commands that enable you to complete
advanced network operations:

+-------------------------------+--------------------------------------------+
| Operation                     | Command                                    |
+===============================+============================================+
|Creates a network that         |                                            |
|all projects can use.          |                                            |
|                               |                                            |
|                               |     ``$ openstack network create``         |
|                               |     ``--share public-net``                 |
+-------------------------------+--------------------------------------------+
|Creates a subnet with a        |                                            |
|specified gateway IP address.  |                                            |
|                               |                                            |
|                               |   ``$ openstack subnet create subnet1``    |
|                               |   ``--gateway 10.0.0.254 --network net1``  |
+-------------------------------+--------------------------------------------+
|Creates a subnet that has      |                                            |
|no gateway IP address.         |                                            |
|                               |                                            |
|                               |     ``$ openstack subnet create subnet1``  |
|                               |     ``--no-gateway --network net1``        |
+-------------------------------+--------------------------------------------+
|Creates a subnet with DHCP     |                                            |
|disabled.                      |                                            |
|                               |                                            |
|                               |   ``$ openstack subnet create subnet1``    |
|                               |   ``--network net1 --no-dhcp``             |
+-------------------------------+--------------------------------------------+
|Specifies a set of host routes |                                            |
|                               |                                            |
|                               |     ``$ openstack subnet create subnet1``  |
|                               |     ``--network net1 --host-route``        |
|                               |     ``destination=40.0.1.0/24,``           |
|                               |     ``gateway=40.0.0.2``                   |
+-------------------------------+--------------------------------------------+
|Creates a subnet with a        |                                            |
|specified set of dns name      |                                            |
|servers.                       |                                            |
|                               |                                            |
|                               |     ``$ openstack subnet create subnet1``  |
|                               |     ``--network net1 --dns-nameserver``    |
|                               |     ``8.8.4.4``                            |
+-------------------------------+--------------------------------------------+
|Displays all ports and         |                                            |
|IPs allocated on a network.    |                                            |
|                               |                                            |
|                               | ``$ openstack port list --network NET_ID`` |
+-------------------------------+--------------------------------------------+

**Advanced Networking operations**

.. note::

   During port creation and update, specific extra-dhcp-options can be left blank.
   For example, ``router`` and ``classless-static-route``. This causes dnsmasq
   to have an empty option in the ``opts`` file related to the network.
   For example:

   .. code-block:: console

      tag:tag0,option:classless-static-route,
      tag:tag0,option:router,

Use Compute with Networking
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Basic Compute and Networking operations
---------------------------------------

This table shows example :command:`openstack` commands that enable you to
complete basic VM networking operations:

+----------------------------------+-----------------------------------------+
| Action                           | Command                                 |
+==================================+=========================================+
|Checks available networks.        |                                         |
|                                  |                                         |
|                                  |    ``$ openstack network list``         |
+----------------------------------+-----------------------------------------+
|Boots a VM with a single NIC on   |                                         |
|a selected Networking network.    |                                         |
|                                  |                                         |
|                                  |  ``$ openstack server create --image``  |
|                                  |  ``IMAGE --flavor FLAVOR --nic``        |
|                                  |  ``net-id=NET_ID VM_NAME``              |
+----------------------------------+-----------------------------------------+
|Searches for ports with a         |                                         |
|``device_id`` that matches the    |                                         |
|Compute instance UUID. See :ref:  |                                         |
|`Create and delete VMs`           |                                         |
|                                  |                                         |
|                                  |``$ openstack port list --server VM_ID`` |
+----------------------------------+-----------------------------------------+
|Searches for ports, but shows     |                                         |
|only the ``mac_address`` of       |                                         |
|the port.                         |                                         |
|                                  |                                         |
|                                  |    ``$ openstack port list -c``         |
|                                  |    ``"MAC Address" --server VM_ID``     |
+----------------------------------+-----------------------------------------+
|Temporarily disables a port from  |                                         |
|sending traffic.                  |                                         |
|                                  |                                         |
|                                  |  ``$ openstack port set PORT_ID``       |
|                                  |  ``--disable``                          |
+----------------------------------+-----------------------------------------+

**Basic Compute and Networking operations**

.. note::

   The ``device_id`` can also be a logical router ID.

.. note::

   -  When you boot a Compute VM, a port on the network that
      corresponds to the VM NIC is automatically created and associated
      with the default security group. You can configure `security
      group rules <#enable-ping-and-ssh-on-vms-security-groups>`__ to enable
      users to access the VM.

.. _Create and delete VMs:
    -  When you delete a Compute VM, the underlying Networking port is
       automatically deleted.

Advanced VM creation operations
-------------------------------

This table shows example :command:`openstack` commands that enable you to
complete advanced VM creation operations:

+-------------------------------------+--------------------------------------+
| Operation                           | Command                              |
+=====================================+======================================+
|Boots a VM with multiple             |                                      |
|NICs.                                |                                      |
|                                     | ``$ openstack server create --image``|
|                                     | ``IMAGE --flavor FLAVOR --nic``      |
|                                     | ``net-id=NET_ID VM_NAME``            |
|                                     | ``net-id=NET2-ID VM_NAME``           |
+-------------------------------------+--------------------------------------+
|Boots a VM with a specific IP        |                                      |
|address. Note that you cannot        |                                      |
|use the ``--max`` or ``--min``       |                                      |
|parameters in this case.             |                                      |
|                                     |                                      |
|                                     | ``$ openstack server create --image``|
|                                     | ``IMAGE --flavor FLAVOR --nic``      |
|                                     | ``net-id=NET_ID VM_NAME``            |
|                                     | ``v4-fixed-ip=IP-ADDR VM_NAME``      |
+-------------------------------------+--------------------------------------+
|Boots a VM that connects to all      |                                      |
|networks that are accessible to the  |                                      |
|project who submits the request      |                                      |
|(without the ``--nic`` option).      |                                      |
|                                     |                                      |
|                                     | ``$ openstack server create --image``|
|                                     | ``IMAGE --flavor FLAVOR``            |
+-------------------------------------+--------------------------------------+

**Advanced VM creation operations**

.. note::

   Cloud images that distribution vendors offer usually have only one
   active NIC configured. When you boot with multiple NICs, you must
   configure additional interfaces on the image or the NICs are not
   reachable.

   The following Debian/Ubuntu-based example shows how to set up the
   interfaces within the instance in the ``/etc/network/interfaces``
   file. You must apply this configuration to the image.

   .. code-block:: bash

      # The loopback network interface
      auto lo
      iface lo inet loopback

      auto eth0
      iface eth0 inet dhcp

      auto eth1
      iface eth1 inet dhcp

Enable ping and SSH on VMs (security groups)
--------------------------------------------

You must configure security group rules depending on the type of plug-in
you are using. If you are using a plug-in that:

-  Implements Networking security groups, you can configure security
   group rules directly by using the :command:`openstack security group rule create`
   command. This example enables ``ping`` and ``ssh`` access to your VMs.

   .. code-block:: console

      $ openstack security group rule create --protocol icmp \
        --ingress SECURITY_GROUP

   .. code-block:: console

      $ openstack security group rule create --protocol tcp \
        --egress --description "Sample Security Group" SECURITY_GROUP

-  Does not implement Networking security groups, you can configure
   security group rules by using the :command:`openstack security group rule
   create` or :command:`euca-authorize` command. These :command:`openstack`
   commands enable ``ping`` and ``ssh`` access to your VMs.

   .. code-block:: console

      $ openstack security group rule create --protocol icmp default
      $ openstack security group rule create --protocol tcp --dst-port 22:22 default

.. note::

    If your plug-in implements Networking security groups, you can also
    leverage Compute security groups by setting
    ``security_group_api = neutron`` in the ``nova.conf`` file. After
    you set this option, all Compute security group commands are proxied
    to Networking.
