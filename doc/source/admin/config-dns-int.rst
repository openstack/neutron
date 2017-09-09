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
   | security_groups       | 1f0ddd73-7e3c-48bd-a64c-7ded4fe0e635                                                  |
   | status                | ACTIVE                                                                                |
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

Integration with an external DNS service
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Users can also integrate the Networking and Compute services with an external
DNS. To accomplish this, the users have to:

#. Enable the functionality described in
   :ref:`config-dns-int-dns-resolution`.
#. Configure an external DNS driver. The Networking service provides a driver
   reference implementation based on the OpenStack DNS service. It is expected
   that third party vendors will provide other implementations in the future.
   For detailed configuration instructions, see
   :ref:`config-dns-int-ext-serv`.

Once the ``neutron-server`` has been configured and restarted, users will have
functionality that covers three use cases, described in the following sections.
In each of the use cases described below:

* The examples assume the OpenStack DNS service as the external DNS.
* A, AAAA and PTR records will be created in the DNS service.
* Before executing any of the use cases, the user must create in the DNS
  service under his project a DNS zone where the A and AAAA records will be
  created. For the description of the use cases below, it is assumed the zone
  ``example.org.`` was created previously.
* The PTR records will be created in zones owned by a project with admin
  privileges. See :ref:`config-dns-int-ext-serv` for more details.

.. _config-dns-use-case-1:

Use case 1: Ports are published directly in the external DNS service
--------------------------------------------------------------------

In this case, the user is creating ports or booting instances on a network
that is accessible externally. If the user wants to publish a port in the
external DNS service in a zone specified by the ``dns_domain`` attribute of the
network, these are the steps to be taken:

#. Assign a valid domain name to the network's ``dns_domain`` attribute. This
   name must end with a period (``.``).
#. Boot an instance specifying the externally accessible network.
   Alternatively, create a port on the externally accessible network specifying
   a valid value to its ``dns_name`` attribute. If the port is going to be used
   for an instance boot, the value assigned to ``dns_name`` must be equal to
   the ``hostname`` that the Compute service will assign to the instance.
   Otherwise, the boot will fail.

Once these steps are executed, the port's DNS data will be published in the
external DNS service. This is an example:

.. code-block:: console

   $ neutron net-list
   +--------------------------------------+----------+----------------------------------------------------------+
   | id                                   | name     | subnets                                                  |
   +--------------------------------------+----------+----------------------------------------------------------+
   | 41fa3995-9e4a-4cd9-bb51-3e5424f2ff2a | public   | a67cfdf7-9d5d-406f-8a19-3f38e4fc3e74                     |
   |                                      |          | cbd8c6dc-ca81-457e-9c5d-f8ece7ef67f8                     |
   | 37aaff3a-6047-45ac-bf4f-a825e56fd2b3 | external | 277eca5d-9869-474b-960e-6da5951d09f7 203.0.113.0/24      |
   |                                      |          | eab47748-3f0a-4775-a09f-b0c24bb64bc4 2001:db8:10::/64    |
   | bf2802a0-99a0-4e8c-91e4-107d03f158ea | my-net   | 6141b474-56cd-430f-b731-71660bb79b79 192.0.2.64/26       |
   | 38c5e950-b450-4c30-83d4-ee181c28aad3 | private  | 43414c53-62ae-49bc-aa6c-c9dd7705818a fda4:653e:71b0::/64 |
   |                                      |          | 5b9282a1-0be1-4ade-b478-7868ad2a16ff 192.0.2.0/26        |
   +--------------------------------------+----------+----------------------------------------------------------+

   $ neutron net-update 37aaff3a-6047-45ac-bf4f-a825e56fd2b3 --dns_domain example.org.
   Updated network: 37aaff3a-6047-45ac-bf4f-a825e56fd2b3

   $ neutron net-show 37aaff3a-6047-45ac-bf4f-a825e56fd2b3
   +---------------------------+--------------------------------------+
   | Field                     | Value                                |
   +---------------------------+--------------------------------------+
   | admin_state_up            | True                                 |
   | availability_zone_hints   |                                      |
   | availability_zones        | nova                                 |
   | dns_domain                | example.org.                         |
   | id                        | 37aaff3a-6047-45ac-bf4f-a825e56fd2b3 |
   | mtu                       | 1450                                 |
   | name                      | external                             |
   | port_security_enabled     | True                                 |
   | provider:network_type     | vlan                                 |
   | provider:physical_network |                                      |
   | provider:segmentation_id  | 2016                                 |
   | router:external           | False                                |
   | shared                    | True                                 |
   | status                    | ACTIVE                               |
   | subnets                   | eab47748-3f0a-4775-a09f-b0c24bb64bc4 |
   |                           | 277eca5d-9869-474b-960e-6da5951d09f7 |
   | tenant_id                 | 04fc2f83966245dba907efb783f8eab9     |
   +---------------------------+--------------------------------------+

   $ designate record-list example.org.
   +--------------------------------------+------+--------------+-----------------------------------------------------------------------+
   | id                                   | type | name         | data                                                                  |
   +--------------------------------------+------+--------------+-----------------------------------------------------------------------+
   | 10a36008-6ecf-47c3-b321-05652a929b04 | SOA  | example.org. | ns1.devstack.org. malavall.us.ibm.com. 1454729414 3600 600 86400 3600 |
   | 56ca0b88-e343-4c98-8faa-19746e169baf | NS   | example.org. | ns1.devstack.org.                                                     |
   +--------------------------------------+------+--------------+-----------------------------------------------------------------------+

   $ neutron port-create 37aaff3a-6047-45ac-bf4f-a825e56fd2b3 --dns_name my-vm
   Created a new port:
   +-----------------------+---------------------------------------------------------------------------------------+
   | Field                 | Value                                                                                 |
   +-----------------------+---------------------------------------------------------------------------------------+
   | admin_state_up        | True                                                                                  |
   | allowed_address_pairs |                                                                                       |
   | binding:vnic_type     | normal                                                                                |
   | device_id             |                                                                                       |
   | device_owner          |                                                                                       |
   | dns_assignment        | {"hostname": "my-vm", "ip_address": "203.0.113.9", "fqdn": "my-vm.example.org."}      |
   |                       | {"hostname": "my-vm", "ip_address": "2001:db8:10::9", "fqdn": "my-vm.example.org."}   |
   | dns_name              | my-vm                                                                                 |
   | fixed_ips             | {"subnet_id": "277eca5d-9869-474b-960e-6da5951d09f7", "ip_address": "203.0.113.9"}    |
   |                       | {"subnet_id": "eab47748-3f0a-4775-a09f-b0c24bb64bc4", "ip_address": "2001:db8:10::9"} |
   | id                    | 04be331b-dc5e-410a-9103-9c8983aeb186                                                  |
   | mac_address           | fa:16:3e:0f:4b:e4                                                                     |
   | name                  |                                                                                       |
   | network_id            | 37aaff3a-6047-45ac-bf4f-a825e56fd2b3                                                  |
   | port_security_enabled | True                                                                                  |
   | security_groups       | 1f0ddd73-7e3c-48bd-a64c-7ded4fe0e635                                                  |
   | status                | DOWN                                                                                  |
   | tenant_id             | d5660cb1e6934612a01b4fb2fb630725                                                      |
   +-----------------------+---------------------------------------------------------------------------------------+

   $ designate record-list example.org.
   +--------------------------------------+------+--------------------+-----------------------------------------------------------------------+
   | id                                   | type | name               | data                                                                  |
   +--------------------------------------+------+--------------------+-----------------------------------------------------------------------+
   | 10a36008-6ecf-47c3-b321-05652a929b04 | SOA  | example.org.       | ns1.devstack.org. malavall.us.ibm.com. 1455563035 3600 600 86400 3600 |
   | 56ca0b88-e343-4c98-8faa-19746e169baf | NS   | example.org.       | ns1.devstack.org.                                                     |
   | 3593591b-181f-4beb-9ab7-67fad7413b37 | A    | my-vm.example.org. | 203.0.113.9                                                           |
   | 5649c68f-7a88-48f5-9f87-ccb1f6ae67ca | AAAA | my-vm.example.org. | 2001:db8:10::9                                                        |
   +--------------------------------------+------+--------------------+-----------------------------------------------------------------------+

   $ openstack server create --image cirros --flavor 42 \
     --nic port-id=04be331b-dc5e-410a-9103-9c8983aeb186 my_vm
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
   | adminPass                            | TDc9EpBT3B9W                                                   |
   | config_drive                         |                                                                |
   | created                              | 2016-02-15T19:10:43Z                                           |
   | flavor                               | m1.nano (42)                                                   |
   | hostId                               |                                                                |
   | id                                   | 62c19691-d1c7-4d7b-a88e-9cc4d95d4f41                           |
   | image                                | cirros-0.3.5-x86_64-uec (b9d981eb-d21c-4ce2-9dbc-dd38f3d9015f) |
   | key_name                             | -                                                              |
   | locked                               | False                                                          |
   | metadata                             | {}                                                             |
   | name                                 | my_vm                                                          |
   | os-extended-volumes:volumes_attached | []                                                             |
   | progress                             | 0                                                              |
   | security_groups                      | default                                                        |
   | status                               | BUILD                                                          |
   | tenant_id                            | d5660cb1e6934612a01b4fb2fb630725                               |
   | updated                              | 2016-02-15T19:10:43Z                                           |
   | user_id                              | 8bb6e578cba24e7db9d3810633124525                               |
   +--------------------------------------+----------------------------------------------------------------+

   $ openstack server list
   +--------------------------------------+-------+--------+------------+-------------+--------------------------------------+------------+
   | ID                                   | Name  | Status | Task State | Power State | Networks                             | Image Name |
   +--------------------------------------+-------+--------+------------+-------------+--------------------------------------+------------+
   | 62c19691-d1c7-4d7b-a88e-9cc4d95d4f41 | my_vm | ACTIVE | -          | Running     | external=203.0.113.9, 2001:db8:10::9 | cirros     |
   +--------------------------------------+-------+--------+------------+-------------+--------------------------------------+------------+

In this example the port is created manually by the user and then used to boot
an instance. Notice that:

* The port's data was visible in the DNS service as soon as it was created.
* See :ref:`config-dns-performance-considerations` for an explanation of
  the potential performance impact associated with this use case.

Following are the PTR records created for this example. Note that for
IPv4, the value of ipv4_ptr_zone_prefix_size is 24. In the case of IPv6, the
value of ipv6_ptr_zone_prefix_size is 116. For more details, see
:ref:`config-dns-int-ext-serv`:

.. code-block:: console

   $ designate record-list 113.0.203.in-addr.arpa.
   +--------------------------------------+------+---------------------------+---------------------------------------------------------------------+
   | id                                   | type | name                      | data                                                                |
   +--------------------------------------+------+---------------------------+---------------------------------------------------------------------+
   | ab7ada72-7e64-4bed-913e-04718a80fafc | NS   | 113.0.203.in-addr.arpa.   | ns1.devstack.org.                                                   |
   | 28346a94-790c-4ae1-9f7b-069d98d9efbd | SOA  | 113.0.203.in-addr.arpa.   | ns1.devstack.org. admin.example.org. 1455563035 3600 600 86400 3600 |
   | cfcaf537-844a-4c1b-9b5f-464ff07dca33 | PTR  | 9.113.0.203.in-addr.arpa. | my-vm.example.org.                                                  |
   +--------------------------------------+------+---------------------------+---------------------------------------------------------------------+

   $ designate record-list 0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.8.b.d.0.1.0.0.2.ip6.arpa.
   +--------------------------------------+------+---------------------------------------------------------------------------+---------------------------------------------------------------------+
   | id                                   | type | name                                                                      | data                                                                |
   +--------------------------------------+------+---------------------------------------------------------------------------+---------------------------------------------------------------------+
   | d8923354-13eb-4bd9-914a-0a2ae5f95989 | SOA  | 0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.8.b.d.0.1.0.0.2.ip6.arpa.       | ns1.devstack.org. admin.example.org. 1455563036 3600 600 86400 3600 |
   | 72e60acd-098d-41ea-9771-5b6546c9c06f | NS   | 0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.8.b.d.0.1.0.0.2.ip6.arpa.       | ns1.devstack.org.                                                   |
   | 877e0215-2ddf-4d01-a7da-47f1092dfd56 | PTR  | 9.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.8.b.d.0.1.0.0.2.ip6.arpa. | my-vm.example.org.                                                  |
   +--------------------------------------+------+---------------------------------------------------------------------------+---------------------------------------------------------------------+

See :ref:`config-dns-int-ext-serv` for detailed instructions on how
to create the externally accessible network.

Alternatively, if the ``dns_domain for ports`` extension has been configured,
the user can create a port specifying a non-blank value in its
``dns_domain`` attribute, as shown here:

.. code-block:: console

   $ neutron port-create 37aaff3a-6047-45ac-bf4f-a825e56fd2b3 \
     --dns-name my-vm --dns_domain port-domain.org.
   Created a new port:
   +-----------------------+---------------------------------------------------------------------------------------+
   | Field                 | Value                                                                                 |
   +-----------------------+---------------------------------------------------------------------------------------+
   | admin_state_up        | True                                                                                  |
   | allowed_address_pairs |                                                                                       |
   | binding:vnic_type     | normal                                                                                |
   | created_at            | 2017-08-16T22:05:57Z                                                                  |
   | description           |                                                                                       |
   | device_id             |                                                                                       |
   | device_owner          |                                                                                       |
   | dns_assignment        | {"hostname": "my-vm", "ip_address": "203.0.113.9", "fqdn": "my-vm.example.org."}      |
   |                       | {"hostname": "my-vm", "ip_address": "2001:db8:10::9", "fqdn": "my-vm.example.org."}   |
   | dns_domain            | port-domain.org.                                                                      |
   | dns_name              | my-vm                                                                                 |
   | extra_dhcp_opts       |                                                                                       |
   | fixed_ips             | {"subnet_id": "277eca5d-9869-474b-960e-6da5951d09f7", "ip_address": "203.0.113.9"}    |
   |                       | {"subnet_id": "eab47748-3f0a-4775-a09f-b0c24bb64bc4", "ip_address": "2001:db8:10::9"} |
   | id                    | 422134a8-1088-458d-adbd-880863d8c07c                                                  |
   | ip_allocation         | immediate                                                                             |
   | mac_address           | fa:16:3e:fb:d6:24                                                                     |
   | name                  |                                                                                       |
   | network_id            | 37aaff3a-6047-45ac-bf4f-a825e56fd2b3                                                  |
   | port_security_enabled | True                                                                                  |
   | project_id            | d5660cb1e6934612a01b4fb2fb630725                                                      |
   | revision_number       | 5                                                                                     |
   | security_groups       | 07b21ad4-edb6-420b-bd76-9bb4aab0d135                                                  |
   | status                | DOWN                                                                                  |
   | tags                  |                                                                                       |
   | tenant_id             | d5660cb1e6934612a01b4fb2fb630725                                                      |
   | updated_at            | 2017-08-16T22:05:58Z                                                                  |
   +-----------------------+---------------------------------------------------------------------------------------+

In this case, the port's ``dns_name`` (``my-vm``) will be published in the
``port-domain.org.`` zone, as shown here:

.. code-block:: console

   $ designate record-list port-domain.org.
   +--------------------------------------+------+-------------------------+-----------------------------------------------------------------------+
   | id                                   | type | name                    | data                                                                  |
   +--------------------------------------+------+-------------------------+-----------------------------------------------------------------------+
   | 03e5a35b-d984-4d10-942a-2de8ccb9b941 | SOA  | port-domain.org.        | ns1.devstack.org. malavall.us.ibm.com. 1503272259 3549 600 86400 3600 |
   | d2dd1dfe-531d-4fea-8c0e-f5b559942ac5 | NS   | port-domain.org.        | ns1.devstack.org.                                                     |
   | 67a8e83d-7e3c-4fb1-9261-0481318bb7b5 | A    | my-vm.port-domain.org.  | 203.0.113.9                                                           |
   | 5a4f671c-9969-47aa-82e1-e05754021852 | AAAA | my-vm.port-domain.org.  | 2001:db8:10::9                                                        |
   +--------------------------------------+------+-------------------------+-----------------------------------------------------------------------+

.. note::
   If both the port and its network have a valid non-blank string assigned to
   their ``dns_domain`` attributes, the port's ``dns_domain`` takes precedence
   over the network's.

.. note::
   The name assigned to the port's ``dns_domain`` attribute must end with a
   period (``.``).

.. note::
   In the above example, the ``port-domain.org.`` zone must be created before
   Neutron can publish any port data to it.

Use case 2: Floating IPs are published with associated port DNS attributes
--------------------------------------------------------------------------

In this use case, the address of a floating IP is published in the external
DNS service in conjunction with the ``dns_name`` of its associated port and the
``dns_domain`` of the port's network. The steps to execute in this use case are
the following:

#. Assign a valid domain name to the network's ``dns_domain`` attribute. This
   name must end with a period (``.``).
#. Boot an instance or alternatively, create a port specifying a valid value to
   its ``dns_name`` attribute. If the port is going to be used for an instance
   boot, the value assigned to ``dns_name`` must be equal to the ``hostname``
   that the Compute service will assign to the instance. Otherwise, the boot
   will fail.
#. Create a floating IP and associate it to the port.

Following is an example of these steps:

.. code-block:: console

   $ neutron net-update 38c5e950-b450-4c30-83d4-ee181c28aad3 --dns_domain example.org.
   Updated network: 38c5e950-b450-4c30-83d4-ee181c28aad3

   $ neutron net-show 38c5e950-b450-4c30-83d4-ee181c28aad3
   +-------------------------+--------------------------------------+
   | Field                   | Value                                |
   +-------------------------+--------------------------------------+
   | admin_state_up          | True                                 |
   | availability_zone_hints |                                      |
   | availability_zones      | nova                                 |
   | dns_domain              | example.org.                         |
   | id                      | 38c5e950-b450-4c30-83d4-ee181c28aad3 |
   | mtu                     | 1450                                 |
   | name                    | private                              |
   | port_security_enabled   | True                                 |
   | router:external         | False                                |
   | shared                  | False                                |
   | status                  | ACTIVE                               |
   | subnets                 | 43414c53-62ae-49bc-aa6c-c9dd7705818a |
   |                         | 5b9282a1-0be1-4ade-b478-7868ad2a16ff |
   | tenant_id               | d5660cb1e6934612a01b4fb2fb630725     |
   +-------------------------+--------------------------------------+

   $ openstack server create --image cirros --flavor 42 \
     --nic net-id=38c5e950-b450-4c30-83d4-ee181c28aad3 my_vm
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
   | adminPass                            | oTLQLR3Kezmt                                                   |
   | config_drive                         |                                                                |
   | created                              | 2016-02-15T19:27:34Z                                           |
   | flavor                               | m1.nano (42)                                                   |
   | hostId                               |                                                                |
   | id                                   | 43f328bb-b2d1-4cf1-a36f-3b2593397cb1                           |
   | image                                | cirros-0.3.5-x86_64-uec (b9d981eb-d21c-4ce2-9dbc-dd38f3d9015f) |
   | key_name                             | -                                                              |
   | locked                               | False                                                          |
   | metadata                             | {}                                                             |
   | name                                 | my_vm                                                          |
   | os-extended-volumes:volumes_attached | []                                                             |
   | progress                             | 0                                                              |
   | security_groups                      | default                                                        |
   | status                               | BUILD                                                          |
   | tenant_id                            | d5660cb1e6934612a01b4fb2fb630725                               |
   | updated                              | 2016-02-15T19:27:34Z                                           |
   | user_id                              | 8bb6e578cba24e7db9d3810633124525                               |
   +--------------------------------------+----------------------------------------------------------------+

   $ openstack server list
   +--------------------------------------+-------+--------+------------+-------------+----------------------------------------------------------+------------+
   | ID                                   | Name  | Status | Task State | Power State | Networks                                                 | Image Name |
   +--------------------------------------+-------+--------+------------+-------------+----------------------------------------------------------+------------+
   | 43f328bb-b2d1-4cf1-a36f-3b2593397cb1 | my_vm | ACTIVE | -          | Running     | private=fda4:653e:71b0:0:f816:3eff:fe16:b5f2, 192.0.2.15 | cirros     |
   +--------------------------------------+-------+--------+------------+-------------+----------------------------------------------------------+------------+

   $ neutron port-list --device_id 43f328bb-b2d1-4cf1-a36f-3b2593397cb1
   +--------------------------------------+------+-------------------+-------------------------------------------------------------------------------------------------------------+
   | id                                   | name | mac_address       | fixed_ips                                                                                                   |
   +--------------------------------------+------+-------------------+-------------------------------------------------------------------------------------------------------------+
   | da0b1f75-c895-460f-9fc1-4d6ec84cf85f |      | fa:16:3e:16:b5:f2 | {"subnet_id": "5b9282a1-0be1-4ade-b478-7868ad2a16ff", "ip_address": "192.0.2.15"}                           |
   |                                      |      |                   | {"subnet_id": "43414c53-62ae-49bc-aa6c-c9dd7705818a", "ip_address": "fda4:653e:71b0:0:f816:3eff:fe16:b5f2"} |
   +--------------------------------------+------+-------------------+-------------------------------------------------------------------------------------------------------------+

   $ neutron port-show da0b1f75-c895-460f-9fc1-4d6ec84cf85f
   +-----------------------+-------------------------------------------------------------------------------------------------------------+
   | Field                 | Value                                                                                                       |
   +-----------------------+-------------------------------------------------------------------------------------------------------------+
   | admin_state_up        | True                                                                                                        |
   | allowed_address_pairs |                                                                                                             |
   | binding:vnic_type     | normal                                                                                                      |
   | device_id             | 43f328bb-b2d1-4cf1-a36f-3b2593397cb1                                                                        |
   | device_owner          | compute:None                                                                                                |
   | dns_assignment        | {"hostname": "my-vm", "ip_address": "192.0.2.15", "fqdn": "my-vm.example.org."}                             |
   |                       | {"hostname": "my-vm", "ip_address": "fda4:653e:71b0:0:f816:3eff:fe16:b5f2", "fqdn": "my-vm.example.org."}   |
   | dns_name              | my-vm                                                                                                       |
   | extra_dhcp_opts       |                                                                                                             |
   | fixed_ips             | {"subnet_id": "5b9282a1-0be1-4ade-b478-7868ad2a16ff", "ip_address": "192.0.2.15"}                           |
   |                       | {"subnet_id": "43414c53-62ae-49bc-aa6c-c9dd7705818a", "ip_address": "fda4:653e:71b0:0:f816:3eff:fe16:b5f2"} |
   | id                    | da0b1f75-c895-460f-9fc1-4d6ec84cf85f                                                                        |
   | mac_address           | fa:16:3e:16:b5:f2                                                                                           |
   | name                  |                                                                                                             |
   | network_id            | 38c5e950-b450-4c30-83d4-ee181c28aad3                                                                        |
   | port_security_enabled | True                                                                                                        |
   | security_groups       | 1f0ddd73-7e3c-48bd-a64c-7ded4fe0e635                                                                        |
   | status                | ACTIVE                                                                                                      |
   | tenant_id             | d5660cb1e6934612a01b4fb2fb630725                                                                            |
   +-----------------------+-------------------------------------------------------------------------------------------------------------+

   $ designate record-list example.org.
   +--------------------------------------+------+--------------+-----------------------------------------------------------------------+
   | id                                   | type | name         | data                                                                  |
   +--------------------------------------+------+--------------+-----------------------------------------------------------------------+
   | 10a36008-6ecf-47c3-b321-05652a929b04 | SOA  | example.org. | ns1.devstack.org. malavall.us.ibm.com. 1455563783 3600 600 86400 3600 |
   | 56ca0b88-e343-4c98-8faa-19746e169baf | NS   | example.org. | ns1.devstack.org.                                                     |
   +--------------------------------------+------+--------------+-----------------------------------------------------------------------+

   $ neutron floatingip-create 41fa3995-9e4a-4cd9-bb51-3e5424f2ff2a \
     --port_id da0b1f75-c895-460f-9fc1-4d6ec84cf85f
   Created a new floatingip:
   +---------------------+--------------------------------------+
   | Field               | Value                                |
   +---------------------+--------------------------------------+
   | dns_domain          |                                      |
   | dns_name            |                                      |
   | fixed_ip_address    | 192.0.2.15                           |
   | floating_ip_address | 198.51.100.4                         |
   | floating_network_id | 41fa3995-9e4a-4cd9-bb51-3e5424f2ff2a |
   | id                  | e78f6eb1-a35f-4a90-941d-87c888d5fcc7 |
   | port_id             | da0b1f75-c895-460f-9fc1-4d6ec84cf85f |
   | router_id           | 970ebe83-c4a3-4642-810e-43ab7b0c2b5f |
   | status              | DOWN                                 |
   | tenant_id           | d5660cb1e6934612a01b4fb2fb630725     |
   +---------------------+--------------------------------------+

   $ designate record-list example.org.
   +--------------------------------------+------+--------------------+-----------------------------------------------------------------------+
   | id                                   | type | name               | data                                                                  |
   +--------------------------------------+------+--------------------+-----------------------------------------------------------------------+
   | 10a36008-6ecf-47c3-b321-05652a929b04 | SOA  | example.org.       | ns1.devstack.org. malavall.us.ibm.com. 1455564861 3600 600 86400 3600 |
   | 56ca0b88-e343-4c98-8faa-19746e169baf | NS   | example.org.       | ns1.devstack.org.                                                     |
   | 5ff53fd0-3746-48da-b9c9-77ed3004ec67 | A    | my-vm.example.org. | 198.51.100.4                                                          |
   +--------------------------------------+------+--------------------+-----------------------------------------------------------------------+

In this example, notice that the data is published in the DNS service when the
floating IP is associated to the port.

Following are the PTR records created for this example. Note that for
IPv4, the value of ``ipv4_ptr_zone_prefix_size`` is 24. For more details, see
:ref:`config-dns-int-ext-serv`:

.. code-block:: console

   $ designate record-list 100.51.198.in-addr.arpa.
   +--------------------------------------+------+----------------------------+---------------------------------------------------------------------+
   | id                                   | type | name                       | data                                                                |
   +--------------------------------------+------+----------------------------+---------------------------------------------------------------------+
   | 2dd0b894-25fa-4563-9d32-9f13bd67f329 | NS   | 100.51.198.in-addr.arpa.   | ns1.devstack.org.                                                   |
   | 47b920f1-5eff-4dfa-9616-7cb5b7cb7ca6 | SOA  | 100.51.198.in-addr.arpa.   | ns1.devstack.org. admin.example.org. 1455564862 3600 600 86400 3600 |
   | fb1edf42-abba-410c-8397-831f45fd0cd7 | PTR  | 4.100.51.198.in-addr.arpa. | my-vm.example.org.                                                  |
   +--------------------------------------+------+----------------------------+---------------------------------------------------------------------+


Use case 3: Floating IPs are published in the external DNS service
------------------------------------------------------------------

In this use case, the user assigns ``dns_name`` and ``dns_domain`` attributes
to a floating IP when it is created. The floating IP data becomes visible in
the external DNS service as soon as it is created. The floating IP can be
associated with a port on creation or later on. The following example shows a
user booting an instance and then creating a floating IP associated to the port
allocated for the instance:

.. code-block:: console

   $ neutron net-show 38c5e950-b450-4c30-83d4-ee181c28aad3
   +-------------------------+--------------------------------------+
   | Field                   | Value                                |
   +-------------------------+--------------------------------------+
   | admin_state_up          | True                                 |
   | availability_zone_hints |                                      |
   | availability_zones      | nova                                 |
   | dns_domain              | example.org.                         |
   | id                      | 38c5e950-b450-4c30-83d4-ee181c28aad3 |
   | mtu                     | 1450                                 |
   | name                    | private                              |
   | port_security_enabled   | True                                 |
   | router:external         | False                                |
   | shared                  | False                                |
   | status                  | ACTIVE                               |
   | subnets                 | 43414c53-62ae-49bc-aa6c-c9dd7705818a |
   |                         | 5b9282a1-0be1-4ade-b478-7868ad2a16ff |
   | tenant_id               | d5660cb1e6934612a01b4fb2fb630725     |
   +-------------------------+--------------------------------------+

   $ openstack server create --image cirros --flavor 42 \
     --nic net-id=38c5e950-b450-4c30-83d4-ee181c28aad3 my_vm
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
   | adminPass                            | HLXGznYqXM4J                                                   |
   | config_drive                         |                                                                |
   | created                              | 2016-02-15T19:42:44Z                                           |
   | flavor                               | m1.nano (42)                                                   |
   | hostId                               |                                                                |
   | id                                   | 71fb4ac8-eed8-4644-8113-0641962bb125                           |
   | image                                | cirros-0.3.5-x86_64-uec (b9d981eb-d21c-4ce2-9dbc-dd38f3d9015f) |
   | key_name                             | -                                                              |
   | locked                               | False                                                          |
   | metadata                             | {}                                                             |
   | name                                 | my_vm                                                          |
   | os-extended-volumes:volumes_attached | []                                                             |
   | progress                             | 0                                                              |
   | security_groups                      | default                                                        |
   | status                               | BUILD                                                          |
   | tenant_id                            | d5660cb1e6934612a01b4fb2fb630725                               |
   | updated                              | 2016-02-15T19:42:44Z                                           |
   | user_id                              | 8bb6e578cba24e7db9d3810633124525                               |
   +--------------------------------------+----------------------------------------------------------------+

   $ openstack server list
   +--------------------------------------+-------+--------+------------+-------------+----------------------------------------------------------+------------+
   | ID                                   | Name  | Status | Task State | Power State | Networks                                                 | Image Name |
   +--------------------------------------+-------+--------+------------+-------------+----------------------------------------------------------+------------+
   | 71fb4ac8-eed8-4644-8113-0641962bb125 | my_vm | ACTIVE | -          | Running     | private=fda4:653e:71b0:0:f816:3eff:fe24:8614, 192.0.2.16 | cirros     |
   +--------------------------------------+-------+--------+------------+-------------+----------------------------------------------------------+------------+

   $ neutron port-list --device_id 71fb4ac8-eed8-4644-8113-0641962bb125
   +--------------------------------------+------+-------------------+-------------------------------------------------------------------------------------------------------------+
   | id                                   | name | mac_address       | fixed_ips                                                                                                   |
   +--------------------------------------+------+-------------------+-------------------------------------------------------------------------------------------------------------+
   | 1e7033fb-8e9d-458b-89ed-8312cafcfdcb |      | fa:16:3e:24:86:14 | {"subnet_id": "5b9282a1-0be1-4ade-b478-7868ad2a16ff", "ip_address": "192.0.2.16"}                           |
   |                                      |      |                   | {"subnet_id": "43414c53-62ae-49bc-aa6c-c9dd7705818a", "ip_address": "fda4:653e:71b0:0:f816:3eff:fe24:8614"} |
   +--------------------------------------+------+-------------------+-------------------------------------------------------------------------------------------------------------+

   $ neutron port-show 1e7033fb-8e9d-458b-89ed-8312cafcfdcb
   +-----------------------+-------------------------------------------------------------------------------------------------------------+
   | Field                 | Value                                                                                                       |
   +-----------------------+-------------------------------------------------------------------------------------------------------------+
   | admin_state_up        | True                                                                                                        |
   | allowed_address_pairs |                                                                                                             |
   | binding:vnic_type     | normal                                                                                                      |
   | device_id             | 71fb4ac8-eed8-4644-8113-0641962bb125                                                                        |
   | device_owner          | compute:None                                                                                                |
   | dns_assignment        | {"hostname": "my-vm", "ip_address": "192.0.2.16", "fqdn": "my-vm.example.org."}                             |
   |                       | {"hostname": "my-vm", "ip_address": "fda4:653e:71b0:0:f816:3eff:fe24:8614", "fqdn": "my-vm.example.org."}   |
   | dns_name              | my-vm                                                                                                       |
   | extra_dhcp_opts       |                                                                                                             |
   | fixed_ips             | {"subnet_id": "5b9282a1-0be1-4ade-b478-7868ad2a16ff", "ip_address": "192.0.2.16"}                           |
   |                       | {"subnet_id": "43414c53-62ae-49bc-aa6c-c9dd7705818a", "ip_address": "fda4:653e:71b0:0:f816:3eff:fe24:8614"} |
   | id                    | 1e7033fb-8e9d-458b-89ed-8312cafcfdcb                                                                        |
   | mac_address           | fa:16:3e:24:86:14                                                                                           |
   | name                  |                                                                                                             |
   | network_id            | 38c5e950-b450-4c30-83d4-ee181c28aad3                                                                        |
   | port_security_enabled | True                                                                                                        |
   | security_groups       | 1f0ddd73-7e3c-48bd-a64c-7ded4fe0e635                                                                        |
   | status                | ACTIVE                                                                                                      |
   | tenant_id             | d5660cb1e6934612a01b4fb2fb630725                                                                            |
   +-----------------------+-------------------------------------------------------------------------------------------------------------+

   $ designate record-list example.org.
   +--------------------------------------+------+--------------+-----------------------------------------------------------------------+
   | id                                   | type | name         | data                                                                  |
   +--------------------------------------+------+--------------+-----------------------------------------------------------------------+
   | 10a36008-6ecf-47c3-b321-05652a929b04 | SOA  | example.org. | ns1.devstack.org. malavall.us.ibm.com. 1455565110 3600 600 86400 3600 |
   | 56ca0b88-e343-4c98-8faa-19746e169baf | NS   | example.org. | ns1.devstack.org.                                                     |
   +--------------------------------------+------+--------------+-----------------------------------------------------------------------+

   $ neutron floatingip-create 41fa3995-9e4a-4cd9-bb51-3e5424f2ff2a \
     --dns_domain example.org. --dns_name my-floatingip
   Created a new floatingip:
   +---------------------+--------------------------------------+
   | Field               | Value                                |
   +---------------------+--------------------------------------+
   | dns_domain          | example.org.                         |
   | dns_name            | my-floatingip                        |
   | fixed_ip_address    |                                      |
   | floating_ip_address | 198.51.100.5                         |
   | floating_network_id | 41fa3995-9e4a-4cd9-bb51-3e5424f2ff2a |
   | id                  | 9f23a9c6-eceb-42eb-9f45-beb58c473728 |
   | port_id             |                                      |
   | router_id           |                                      |
   | status              | DOWN                                 |
   | tenant_id           | d5660cb1e6934612a01b4fb2fb630725     |
   +---------------------+--------------------------------------+

   $ designate record-list example.org.
   +--------------------------------------+------+----------------------------+-----------------------------------------------------------------------+
   | id                                   | type | name                       | data                                                                  |
   +--------------------------------------+------+----------------------------+-----------------------------------------------------------------------+
   | 10a36008-6ecf-47c3-b321-05652a929b04 | SOA  | example.org.               | ns1.devstack.org. malavall.us.ibm.com. 1455566486 3600 600 86400 3600 |
   | 56ca0b88-e343-4c98-8faa-19746e169baf | NS   | example.org.               | ns1.devstack.org.                                                     |
   | 8884c56f-3ef5-446e-ae4d-8053cc8bc2b4 | A    | my-floatingip.example.org. | 198.51.100.53                                                         |
   +--------------------------------------+------+----------------------------+-----------------------------------------------------------------------+

Note that in this use case:

* The ``dns_name`` and ``dns_domain`` attributes of a floating IP must be
  specified together on creation. They cannot be assigned to the floating IP
  separately.
* The ``dns_name`` and ``dns_domain`` of a floating IP have precedence, for
  purposes of being published in the external DNS service, over the
  ``dns_name`` of its associated port and the ``dns_domain`` of the port's
  network, whether they are specified or not. Only the ``dns_name`` and the
  ``dns_domain`` of the floating IP are published in the external DNS service.

Following are the PTR records created for this example. Note that for
IPv4, the value of ipv4_ptr_zone_prefix_size is 24. For more details, see
:ref:`config-dns-int-ext-serv`:

.. code-block:: console

   $ designate record-list 100.51.198.in-addr.arpa.
   +--------------------------------------+------+----------------------------+---------------------------------------------------------------------+
   | id                                   | type | name                       | data                                                                |
   +--------------------------------------+------+----------------------------+---------------------------------------------------------------------+
   | 2dd0b894-25fa-4563-9d32-9f13bd67f329 | NS   | 100.51.198.in-addr.arpa.   | ns1.devstack.org.                                                   |
   | 47b920f1-5eff-4dfa-9616-7cb5b7cb7ca6 | SOA  | 100.51.198.in-addr.arpa.   | ns1.devstack.org. admin.example.org. 1455566487 3600 600 86400 3600 |
   | 589a0171-e77a-4ab6-ba6e-23114f2b9366 | PTR  | 5.100.51.198.in-addr.arpa. | my-floatingip.example.org.                                          |
   +--------------------------------------+------+----------------------------+---------------------------------------------------------------------+

.. _config-dns-performance-considerations:

Performance considerations
--------------------------

Only for :ref:`config-dns-use-case-1`, if the port binding extension is
enabled in the Networking service, the Compute service will execute one
additional port update operation when allocating the port for the instance
during the boot process. This may have a noticeable adverse effect in the
performance of the boot process that must be evaluated before adoption of this
use case.

.. _config-dns-int-ext-serv:

Configuring OpenStack Networking for integration with an external DNS service
-----------------------------------------------------------------------------

The first step to configure the integration with an external DNS service is to
enable the functionality described in :ref:`config-dns-int-dns-resolution`.
Once this is done, the user has to take the following steps and restart
``neutron-server``.

#. Edit the ``[default]`` section of ``/etc/neutron/neutron.conf`` and specify
   the external DNS service driver to be used in parameter
   ``external_dns_driver``. The valid options are defined in namespace
   ``neutron.services.external_dns_drivers``. The following example shows how
   to set up the driver for the OpenStack DNS service:

   .. code-block:: console

      external_dns_driver = designate

#. If the OpenStack DNS service is the target external DNS, the ``[designate]``
   section of ``/etc/neutron/neutron.conf`` must define the following
   parameters:

   * ``url``: the OpenStack DNS service public endpoint URL.
   * ``allow_reverse_dns_lookup``: a boolean value specifying whether to enable
     or not the creation of reverse lookup (PTR) records.
   * ``admin_auth_url``: the Identity service admin authorization endpoint url.
     This endpoint will be used by the Networking service to authenticate as an
     admin user to create and update reverse lookup (PTR) zones.
   * ``admin_username``: the admin user to be used by the Networking service to
     create and update reverse lookup (PTR) zones.
   * ``admin_password``: the password of the admin user to be used by
     Networking service to create and update reverse lookup (PTR) zones.
   * ``admin_tenant_name``: the project of the admin user to be used by the
     Networking service to create and update reverse lookup (PTR) zones.
   * ``ipv4_ptr_zone_prefix_size``: the size in bits of the prefix for the IPv4
     reverse lookup (PTR) zones.
   * ``ipv6_ptr_zone_prefix_size``: the size in bits of the prefix for the IPv6
     reverse lookup (PTR) zones.
   * ``insecure``: Disable SSL certificate validation. By default, certificates
     are validated.
   * ``cafile``: Path to a valid Certificate Authority (CA) certificate.
   * ``auth_uri``: the unversioned public endpoint of the Identity service.
   * ``project_domain_id``: the domain ID of the admin user's project.
   * ``user_domain_id``: the domain ID of the admin user to be used by the
     Networking service.
   * ``project_name``: the project of the admin user to be used by the
     Networking service.
   * ``username``: the admin user to be used by the Networking service to
     create and update reverse lookup (PTR) zones.
   * ``password``: the password of the admin user to be used by
     Networking service.

   The following is an example:

   .. code-block:: console

      [designate]
      url = http://192.0.2.240:9001/v2
      auth_uri = http://192.0.2.240:5000
      admin_auth_url = http://192.0.2.240:35357
      admin_username = neutron
      admin_password = PASSWORD
      admin_tenant_name = service
      project_domain_id = default
      user_domain_id = default
      project_name = service
      username = neutron
      password = PASSWORD
      allow_reverse_dns_lookup = True
      ipv4_ptr_zone_prefix_size = 24
      ipv6_ptr_zone_prefix_size = 116
      cafile = /etc/ssl/certs/my_ca_cert

Configuration of the externally accessible network for use case 1
-----------------------------------------------------------------

In :ref:`config-dns-use-case-1`, the externally accessible network must
meet the following requirements:

* The network cannot have attribute ``router:external`` set to ``True``.
* The network type can be FLAT, VLAN, GRE, VXLAN or GENEVE.
* For network types VLAN, GRE, VXLAN or GENEVE, the segmentation ID must be
  outside the ranges assigned to project networks.
