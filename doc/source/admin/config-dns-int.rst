.. _config-dns-int:

===============
DNS integration
===============

This page serves as a guide for how to use the DNS integration functionality of
the Networking service. The functionality described covers DNS from two points
of view:

* The internal DNS functionality offered by the Networking service and its
  interaction with the Compute service.
* Integration of the Compute service and the Networking service with an
  external DNSaaS (DNS-as-a-Service).

Users can control the behavior of the Networking service in regards to DNS
using two attributes associated with ports, networks, and floating IPs. The
following table shows the attributes available for each one of these resources:

.. list-table::
   :header-rows: 1
   :widths: 30 30 30

   * - Resource
     - dns_name
     - dns_domain
   * - Ports
     - Yes
     - Yes
   * - Networks
     - No
     - Yes
   * - Floating IPs
     - Yes
     - Yes

.. note::
   The ``DNS Integration`` extension enables all the attribute and resource
   combinations shown in the previous table, except for ``dns_domain`` for
   ports, which requires the ``dns_domain for ports`` extension.

.. note::
   Since the ``DNS Integration`` extension is a subset of
   ``dns_domain for ports``, if ``dns_domain`` functionality for ports is
   required, only the latter extension has to be configured.

.. note::
   When the ``dns_domain for ports`` extension is configured, ``DNS
   Integration`` is also included when the Neutron server responds to a request
   to list the active API extensions. This preserves backwards API
   compatibility.

.. _config-dns-int-dns-resolution:

The Networking service internal DNS resolution
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The Networking service enables users to control the name assigned to ports by
the internal DNS. To enable this functionality, do the following:

1. Edit the ``/etc/neutron/neutron.conf`` file and assign a value different to
   ``openstacklocal`` (its default value) to the ``dns_domain`` parameter in
   the ``[default]`` section. As an example:

   .. code-block:: ini

      dns_domain = example.org.

2. Add ``dns`` (for the ``DNS Integration`` extension) or ``dns_domain_ports``
   (for the ``dns_domain for ports`` extension) to ``extension_drivers`` in the
   ``[ml2]`` section of ``/etc/neutron/plugins/ml2/ml2_conf.ini``. The
   following is an example:

   .. code-block:: console

      [ml2]
      extension_drivers = port_security,dns_domain_ports

After re-starting the ``neutron-server``, users will be able to assign a
``dns_name`` attribute to their ports.

.. note::
   The enablement of this functionality is prerequisite for the enablement of
   the Networking service integration with an external DNS service, which is
   described in detail in :ref:`config-dns-int-ext-serv`.

The following illustrates the creation of a port with ``my-port``
in its ``dns_name`` attribute.

.. note::
   The name assigned to the port by the Networking service internal DNS is now
   visible in the response in the ``dns_assignment`` attribute.

.. code-block:: console

   $ neutron port-create my-net --dns-name my-port
   Created a new port:
   +-----------------------+-------------------------------------------------------------------------------------+
   | Field                 | Value                                                                               |
   +-----------------------+-------------------------------------------------------------------------------------+
   | admin_state_up        | True                                                                                |
   | allowed_address_pairs |                                                                                     |
   | binding:vnic_type     | normal                                                                              |
   | device_id             |                                                                                     |
   | device_owner          |                                                                                     |
   | dns_assignment        | {"hostname": "my-port", "ip_address": "192.0.2.67", "fqdn": "my-port.example.org."} |
   | dns_name              | my-port                                                                             |
   | fixed_ips             | {"subnet_id":"6141b474-56cd-430f-b731-71660bb79b79", "ip_address": "192.0.2.67"}    |
   | id                    | fb3c10f4-017e-420c-9be1-8f8c557ae21f                                                |
   | mac_address           | fa:16:3e:aa:9b:e1                                                                   |
   | name                  |                                                                                     |
   | network_id            | bf2802a0-99a0-4e8c-91e4-107d03f158ea                                                |
   | port_security_enabled | True                                                                                |
   | revision_number       | 1                                                                                   |
   | security_groups       | 1f0ddd73-7e3c-48bd-a64c-7ded4fe0e635                                                |
   | status                | DOWN                                                                                |
   | tenant_id             | d5660cb1e6934612a01b4fb2fb630725                                                    |
   +-----------------------+-------------------------------------------------------------------------------------+

When this functionality is enabled, it is leveraged by the Compute service when
creating instances. When allocating ports for an instance during boot, the
Compute service populates the ``dns_name`` attributes of these ports with
the ``hostname`` attribute of the instance, which is a DNS sanitized version of
its display name. As a consequence, at the end of the boot process, the
allocated ports will be known in the dnsmasq associated to their networks by
their instance ``hostname``.

The following is an example of an instance creation, showing how its
``hostname`` populates the ``dns_name`` attribute of the allocated port:

.. code-block:: console

   $ openstack server create --image cirros --flavor 42 \
     --nic net-id=37aaff3a-6047-45ac-bf4f-a825e56fd2b3 my_vm
   +--------------------------------------+----------------------------------------------------------------+
   | Field                                | Value                                                          |
   +--------------------------------------+----------------------------------------------------------------+
   | OS-DCF:diskConfig                    | MANUAL                                                         |
   | OS-EXT-AZ:availability_zone          |                                                                |
   | OS-EXT-STS:power_state               | 0                                                              |
   | OS-EXT-STS:task_state                | scheduling                                                     |
   | OS-EXT-STS:vm_state                  | building                                                       |
   | OS-SRV-USG:launched_at               | -                                                              |
   | OS-SRV-USG:terminated_at             | -                                                              |
   | accessIPv4                           |                                                                |
   | accessIPv6                           |                                                                |
   | adminPass                            | dB45Zvo8Jpfe                                                   |
   | config_drive                         |                                                                |
   | created                              | 2016-02-05T21:35:04Z                                           |
   | flavor                               | m1.nano (42)                                                   |
   | hostId                               |                                                                |
   | id                                   | 66c13cb4-3002-4ab3-8400-7efc2659c363                           |
   | image                                | cirros-0.3.5-x86_64-uec(b9d981eb-d21c-4ce2-9dbc-dd38f3d9015f)  |
   | key_name                             | -                                                              |
   | locked                               | False                                                          |
   | metadata                             | {}                                                             |
   | name                                 | my_vm                                                          |
   | os-extended-volumes:volumes_attached | []                                                             |
   | progress                             | 0                                                              |
   | security_groups                      | default                                                        |
   | status                               | BUILD                                                          |
   | tenant_id                            | d5660cb1e6934612a01b4fb2fb630725                               |
   | updated                              | 2016-02-05T21:35:04Z                                           |
   | user_id                              | 8bb6e578cba24e7db9d3810633124525                               |
   +--------------------------------------+----------------------------------------------------------------+

   $ neutron port-list --device_id 66c13cb4-3002-4ab3-8400-7efc2659c363
   +--------------------------------------+------+-------------------+---------------------------------------------------------------------------------------+
   | id                                   | name | mac_address       | fixed_ips                                                                             |
   +--------------------------------------+------+-------------------+---------------------------------------------------------------------------------------+
   | b3ecc464-1263-44a7-8c38-2d8a52751773 |      | fa:16:3e:a8:ce:b8 | {"subnet_id": "277eca5d-9869-474b-960e-6da5951d09f7", "ip_address": "203.0.113.8"}    |
   |                                      |      |                   | {"subnet_id": "eab47748-3f0a-4775-a09f-b0c24bb64bc4", "ip_address":"2001:db8:10::8"}  |
   +--------------------------------------+------+-------------------+---------------------------------------------------------------------------------------+

   $ neutron port-show b3ecc464-1263-44a7-8c38-2d8a52751773
   +-----------------------+---------------------------------------------------------------------------------------+
   | Field                 | Value                                                                                 |
   +-----------------------+---------------------------------------------------------------------------------------+
   | admin_state_up        | True                                                                                  |
   | allowed_address_pairs |                                                                                       |
   | binding:vnic_type     | normal                                                                                |
   | device_id             | 66c13cb4-3002-4ab3-8400-7efc2659c363                                                  |
   | device_owner          | compute:None                                                                          |
   | dns_assignment        | {"hostname": "my-vm", "ip_address": "203.0.113.8", "fqdn": "my-vm.example.org."}      |
   |                       | {"hostname": "my-vm", "ip_address": "2001:db8:10::8", "fqdn": "my-vm.example.org."}   |
   | dns_name              | my-vm                                                                                 |
   | extra_dhcp_opts       |                                                                                       |
   | fixed_ips             | {"subnet_id": "277eca5d-9869-474b-960e-6da5951d09f7", "ip_address": "203.0.113.8"}    |
   |                       | {"subnet_id": "eab47748-3f0a-4775-a09f-b0c24bb64bc4", "ip_address": "2001:db8:10::8"} |
   | id                    | b3ecc464-1263-44a7-8c38-2d8a52751773                                                  |
   | mac_address           | fa:16:3e:a8:ce:b8                                                                     |
   | name                  |                                                                                       |
   | network_id            | 37aaff3a-6047-45ac-bf4f-a825e56fd2b3                                                  |
   | port_security_enabled | True                                                                                  |
   | revision_number       | 1                                                                                     |
   | security_groups       | 1f0ddd73-7e3c-48bd-a64c-7ded4fe0e635                                                  |
   | status                | ACTIVE                                                                                |
   | tags                  | []                                                                                    |
   | tenant_id             | d5660cb1e6934612a01b4fb2fb630725                                                      |
   +-----------------------+---------------------------------------------------------------------------------------+

In the above example notice that:

* The name given to the instance by the user, ``my_vm``, is sanitized by the
  Compute service and becomes ``my-vm`` as the port's ``dns_name``.
* The port's ``dns_assignment`` attribute shows that its FQDN is
  ``my-vm.example.org.`` in the Networking service internal DNS, which is
  the result of concatenating the port's ``dns_name`` with the value configured
  in the ``dns_domain`` parameter in ``neutron.conf``, as explained previously.
* The ``dns_assignment`` attribute also shows that the port's ``hostname`` in
  the Networking service internal DNS is ``my-vm``.
* Instead of having the Compute service create the port for the instance, the
  user might have created it and assigned a value to its ``dns_name``
  attribute. In this case, the value assigned to the ``dns_name`` attribute
  must be equal to the value that Compute service will assign to the instance's
  ``hostname``, in this example ``my-vm``. Otherwise, the instance boot will
  fail.
