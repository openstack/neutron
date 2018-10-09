.. _config-dns-int-ext-serv:

========================================
DNS integration with an external service
========================================

This page serves as a guide for how to use the DNS integration functionality of
the Networking service with an external DNSaaS (DNS-as-a-Service).

As a prerequisite this needs the internal DNS functionality offered by the
Networking service to be enabled, see :ref:`config-dns-int`.

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

   * ``url``: the OpenStack DNS service public endpoint URL. Note that
     this must always be the versioned endpoint currently.
   * ``auth_type``: the authorization plugin to use.
     Usually this should be ``password``, see
     https://docs.openstack.org/keystoneauth/latest/authentication-plugins.html
     for other options.
   * ``auth_url``: the Identity service authorization endpoint url.
     This endpoint will be used by the Networking service to authenticate as an
     user to create and update reverse lookup (PTR) zones.
   * ``username``: the username to be used by the Networking service to
     create and update reverse lookup (PTR) zones.
   * ``password``: the password of the user to be used by the
     Networking service to create and update reverse lookup (PTR) zones.
   * ``project_name``: the name of the project to be used by the
     Networking service to create and update reverse lookup (PTR) zones.
   * ``project_domain_name``: the name of the domain for the project to be used by the
     Networking service to create and update reverse lookup (PTR) zones.
   * ``user_domain_name``: the name of the domain for the user to be used by the
     Networking service to create and update reverse lookup (PTR) zones.
   * ``region_name``: the name of the region to be used by the
     Networking service to create and update reverse lookup (PTR) zones.
   * ``allow_reverse_dns_lookup``: a boolean value specifying whether to enable
     or not the creation of reverse lookup (PTR) records.
   * ``ipv4_ptr_zone_prefix_size``: the size in bits of the prefix for the IPv4
     reverse lookup (PTR) zones.
   * ``ipv6_ptr_zone_prefix_size``: the size in bits of the prefix for the IPv6
     reverse lookup (PTR) zones.
   * ``ptr_zone_email``: the email address to use when creating new reverse
     lookup (PTR) zones. The default is ``admin@<dns_domain>`` where ``<dns_domain>``
     is the domain for the first record being created in that zone.
   * ``insecure``: whether to disable SSL certificate validation. By default, certificates
     are validated.
   * ``cafile``: Path to a valid Certificate Authority (CA) certificate.
     Optional, the system CAs are used as default.

   The following is an example:

   .. code-block:: console

      [designate]
      url = http://192.0.2.240:9001/v2
      auth_type = password
      auth_url = http://192.0.2.240:5000
      username = neutron
      password = PASSWORD
      project_name = service
      project_domain_name = Default
      user_domain_name = Default
      allow_reverse_dns_lookup = True
      ipv4_ptr_zone_prefix_size = 24
      ipv6_ptr_zone_prefix_size = 116
      ptr_zone_email = admin@example.org
      cafile = /etc/ssl/certs/my_ca_cert


Once the ``neutron-server`` has been configured and restarted, users will have
functionality that covers three use cases, described in the following sections.
In each of the use cases described below:

* The examples assume the OpenStack DNS service as the external DNS.
* A, AAAA and PTR records will be created in the DNS service.
* Before executing any of the use cases, the user must create in the DNS
  service under his project a DNS zone where the A and AAAA records will be
  created. For the description of the use cases below, it is assumed the zone
  ``example.org.`` was created previously.
* The PTR records will be created in zones owned by the project specified
  for ``project_name`` above.
* Despite officially being deprecated, using the neutron CLI is still necessary
  for some of the tasks, as the corresponding features are not yet implemented
  for the openstack client.

Use case 1: Floating IPs are published with associated port DNS attributes
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

   $ openstack network show 38c5e950-b450-4c30-83d4-ee181c28aad3
   +---------------------------+--------------------------------------+
   | Field                     | Value                                |
   +---------------------------+--------------------------------------+
   | admin_state_up            | UP                                   |
   | availability_zone_hints   |                                      |
   | availability_zones        | nova                                 |
   | created_at                | 2016-05-04T19:27:34Z                 |
   | description               |                                      |
   | dns_domain                | example.org.                         |
   | id                        | 38c5e950-b450-4c30-83d4-ee181c28aad3 |
   | ipv4_address_scope        | None                                 |
   | ipv6_address_scope        | None                                 |
   | is_default                | None                                 |
   | is_vlan_transparent       | None                                 |
   | mtu                       | 1450                                 |
   | name                      | private                              |
   | port_security_enabled     | True                                 |
   | project_id                | d5660cb1e6934612a01b4fb2fb630725     |
   | provider:network_type     | vlan                                 |
   | provider:physical_network | None                                 |
   | provider:segmentation_id  | 24                                   |
   | qos_policy_id             | None                                 |
   | revision_number           | 1                                    |
   | router:external           | Internal                             |
   | segments                  | None                                 |
   | shared                    | False                                |
   | status                    | ACTIVE                               |
   | subnets                   | 43414c53-62ae-49bc-aa6c-c9dd7705818a |
   |                           | 5b9282a1-0be1-4ade-b478-7868ad2a16ff |
   | tags                      |                                      |
   | updated_at                | 2016-05-04T19:27:34Z                 |
   +---------------------------+--------------------------------------+

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
   +--------------------------------------+-------+--------+----------------------------------------------------------+--------+---------+
   | ID                                   | Name  | Status | Networks                                                 | Image  | Flavor  |
   +--------------------------------------+-------+--------+----------------------------------------------------------+--------+---------+
   | 43f328bb-b2d1-4cf1-a36f-3b2593397cb1 | my_vm | ACTIVE | private=fda4:653e:71b0:0:f816:3eff:fe16:b5f2, 192.0.2.15 | cirros | m1.nano |
   +--------------------------------------+-------+--------+----------------------------------------------------------+--------+---------+

   $ openstack port list --device-id 43f328bb-b2d1-4cf1-a36f-3b2593397cb1
   +--------------------------------------+------+-------------------+-------------------------------------------------------------------------------------------------------------+--------+
   | ID                                   | Name | MAC Address       | Fixed IP Addresses                                                                                          | Status |
   +--------------------------------------+------+-------------------+-------------------------------------------------------------------------------------------------------------+--------+
   | da0b1f75-c895-460f-9fc1-4d6ec84cf85f |      | fa:16:3e:16:b5:f2 | ip_address='192.0.2.15', subnet_id='5b9282a1-0be1-4ade-b478-7868ad2a16ff'                                   | ACTIVE |
   |                                      |      |                   | ip_address='fda4:653e:71b0:0:f816:3eff:fe16:b5f2', subnet_id='43414c53-62ae-49bc-aa6c-c9dd7705818a'         |        |
   +--------------------------------------+------+-------------------+-------------------------------------------------------------------------------------------------------------+--------+

   $ openstack port show da0b1f75-c895-460f-9fc1-4d6ec84cf85f
   +-----------------------+------------------------------------------------------------------------------------------------------------+
   | Field                 | Value                                                                                                      |
   +-----------------------+------------------------------------------------------------------------------------------------------------+
   | admin_state_up        | UP                                                                                                         |
   | allowed_address_pairs |                                                                                                            |
   | binding_host_id       | vultr.guest                                                                                                |
   | binding_profile       |                                                                                                            |
   | binding_vif_details   | datapath_type='system', ovs_hybrid_plug='True', port_filter='True'                                         |
   | binding_vif_type      | ovs                                                                                                        |
   | binding_vnic_type     | normal                                                                                                     |
   | created_at            | 2016-02-15T19:27:34Z                                                                                       |
   | data_plane_status     | None                                                                                                       |
   | description           |                                                                                                            |
   | device_id             | 43f328bb-b2d1-4cf1-a36f-3b2593397cb1                                                                       |
   | device_owner          | compute:None                                                                                               |
   | dns_assignment        | fqdn='my-vm.example.org.', hostname='my-vm', ip_address='192.0.2.15'                                       |
   |                       | fqdn='my-vm.example.org.', hostname='my-vm', ip_address='fda4:653e:71b0:0:f816:3eff:fe16:b5f2'             |
   | dns_domain            | example.org.                                                                                               |
   | dns_name              | my-vm                                                                                                      |
   | extra_dhcp_opts       |                                                                                                            |
   | fixed_ips             | ip_address='192.0.2.15', subnet_id='5b9282a1-0be1-4ade-b478-7868ad2a16ff'                                  |
   |                       | ip_address='fda4:653e:71b0:0:f816:3eff:fe16:b5f2', subnet_id='43414c53-62ae-49bc-aa6c-c9dd7705818a'        |
   | id                    | da0b1f75-c895-460f-9fc1-4d6ec84cf85f                                                                       |
   | mac_address           | fa:16:3e:16:b5:f2                                                                                          |
   | name                  |                                                                                                            |
   | network_id            | 38c5e950-b450-4c30-83d4-ee181c28aad3                                                                       |
   | port_security_enabled | True                                                                                                       |
   | project_id            | d5660cb1e6934612a01b4fb2fb630725                                                                           |
   | qos_policy_id         | None                                                                                                       |
   | revision_number       | 1                                                                                                          |
   | security_group_ids    | 1f0ddd73-7e3c-48bd-a64c-7ded4fe0e635                                                                       |
   | status                | ACTIVE                                                                                                     |
   | tags                  |                                                                                                            |
   | trunk_details         | None                                                                                                       |
   | updated_at            | 2016-02-15T19:27:34Z                                                                                       |
   +-----------------------+------------------------------------------------------------------------------------------------------------+

   $ openstack recordset list example.org.
   +--------------------------------------+--------------------+------+-----------------------------------------------------------------------+--------+--------+
   | id                                   | name               | type | records                                                               | status | action |
   +--------------------------------------+--------------------+------+-----------------------------------------------------------------------+--------+--------+
   | a5fe696d-203f-4018-b0d8-590221adb513 | example.org.       | NS   | ns1.devstack.org.                                                     | ACTIVE | NONE   |
   | e7c05a5d-83a0-4fe5-8bd5-ab058a3326aa | example.org.       | SOA  | ns1.devstack.org. malavall.us.ibm.com. 1513767794 3532 600 86400 3600 | ACTIVE | NONE   |
   +--------------------------------------+--------------------+------+-----------------------------------------------------------------------+--------+--------+

   $ openstack floating ip create 41fa3995-9e4a-4cd9-bb51-3e5424f2ff2a \
     --port da0b1f75-c895-460f-9fc1-4d6ec84cf85f
   +---------------------+--------------------------------------+
   | Field               | Value                                |
   +---------------------+--------------------------------------+
   | created_at          | 2016-02-15T20:27:34Z                 |
   | description         |                                      |
   | dns_domain          |                                      |
   | dns_name            |                                      |
   | fixed_ip_address    | 192.0.2.15                           |
   | floating_ip_address | 198.51.100.4                         |
   | floating_network_id | 41fa3995-9e4a-4cd9-bb51-3e5424f2ff2a |
   | id                  | e78f6eb1-a35f-4a90-941d-87c888d5fcc7 |
   | name                | 198.51.100.4                         |
   | port_id             | da0b1f75-c895-460f-9fc1-4d6ec84cf85f |
   | project_id          | d5660cb1e6934612a01b4fb2fb630725     |
   | qos_policy_id       | None                                 |
   | revision_number     | 1                                    |
   | router_id           | 970ebe83-c4a3-4642-810e-43ab7b0c2b5f |
   | status              | DOWN                                 |
   | subnet_id           | None                                 |
   | tags                | []                                   |
   | updated_at          | 2016-02-15T20:27:34Z                 |
   +---------------------+--------------------------------------+

   $ openstack recordset list example.org.
   +--------------------------------------+--------------------+------+-----------------------------------------------------------------------+--------+--------+
   | id                                   | name               | type | records                                                               | status | action |
   +--------------------------------------+--------------------+------+-----------------------------------------------------------------------+--------+--------+
   | a5fe696d-203f-4018-b0d8-590221adb513 | example.org.       | NS   | ns1.devstack.org.                                                     | ACTIVE | NONE   |
   | e7c05a5d-83a0-4fe5-8bd5-ab058a3326aa | example.org.       | SOA  | ns1.devstack.org. malavall.us.ibm.com. 1513768814 3532 600 86400 3600 | ACTIVE | NONE   |
   | 5ff53fd0-3746-48da-b9c9-77ed3004ec67 | my-vm.example.org. | A    | 198.51.100.4                                                          | ACTIVE | NONE   |
   +--------------------------------------+--------------------+------+-----------------------------------------------------------------------+--------+--------+

In this example, notice that the data is published in the DNS service when the
floating IP is associated to the port.

Following are the PTR records created for this example. Note that for
IPv4, the value of ``ipv4_ptr_zone_prefix_size`` is 24. Also, since the zone
for the PTR records is created in the ``service`` project, you need to use
admin credentials in order to be able to view it.


.. code-block:: console

   $ openstack recordset list --all-projects 100.51.198.in-addr.arpa.
   +--------------------------------------+----------------------------------+----------------------------+------+---------------------------------------------------------------------+--------+--------+
   | id                                   | project_id                       | name                       | type | data                                                                | status | action |
   +--------------------------------------+----------------------------------+-----------------------------------+---------------------------------------------------------------------+--------+--------+
   | 2dd0b894-25fa-4563-9d32-9f13bd67f329 | 07224d17d76d42499a38f00ba4339710 | 100.51.198.in-addr.arpa.   | NS   | ns1.devstack.org.                                                   | ACTIVE | NONE   |
   | 47b920f1-5eff-4dfa-9616-7cb5b7cb7ca6 | 07224d17d76d42499a38f00ba4339710 | 100.51.198.in-addr.arpa.   | SOA  | ns1.devstack.org. admin.example.org. 1455564862 3600 600 86400 3600 | ACTIVE | NONE   |
   | fb1edf42-abba-410c-8397-831f45fd0cd7 | 07224d17d76d42499a38f00ba4339710 | 4.100.51.198.in-addr.arpa. | PTR  | my-vm.example.org.                                                  | ACTIVE | NONE   |
   +--------------------------------------+----------------------------------+----------------------------+------+---------------------------------------------------------------------+--------+--------+


Use case 2: Floating IPs are published in the external DNS service
------------------------------------------------------------------

In this use case, the user assigns ``dns_name`` and ``dns_domain`` attributes
to a floating IP when it is created. The floating IP data becomes visible in
the external DNS service as soon as it is created. The floating IP can be
associated with a port on creation or later on. The following example shows a
user booting an instance and then creating a floating IP associated to the port
allocated for the instance:

.. code-block:: console

   $ openstack network show 38c5e950-b450-4c30-83d4-ee181c28aad3
   +---------------------------+----------------------------------------------------------------------------+
   | Field                     | Value                                                                      |
   +---------------------------+----------------------------------------------------------------------------+
   | admin_state_up            | UP                                                                         |
   | availability_zone_hints   |                                                                            |
   | availability_zones        | nova                                                                       |
   | created_at                | 2016-05-04T19:27:34Z                                                       |
   | description               |                                                                            |
   | dns_domain                | example.org.                                                               |
   | id                        | 38c5e950-b450-4c30-83d4-ee181c28aad3                                       |
   | ipv4_address_scope        | None                                                                       |
   | ipv6_address_scope        | None                                                                       |
   | is_default                | None                                                                       |
   | is_vlan_transparent       | None                                                                       |
   | mtu                       | 1450                                                                       |
   | name                      | private                                                                    |
   | port_security_enabled     | True                                                                       |
   | project_id                | d5660cb1e6934612a01b4fb2fb630725                                           |
   | provider:network_type     | vlan                                                                       |
   | provider:physical_network | None                                                                       |
   | provider:segmentation_id  | 24                                                                         |
   | qos_policy_id             | None                                                                       |
   | revision_number           | 1                                                                          |
   | router:external           | Internal                                                                   |
   | segments                  | None                                                                       |
   | shared                    | False                                                                      |
   | status                    | ACTIVE                                                                     |
   | subnets                   | 43414c53-62ae-49bc-aa6c-c9dd7705818a, 5b9282a1-0be1-4ade-b478-7868ad2a16ff |
   | tags                      |                                                                            |
   | updated_at                | 2016-05-04T19:27:34Z                                                       |
   +---------------------------+----------------------------------------------------------------------------+

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
   +--------------------------------------+-------+--------+----------------------------------------------------------+--------+---------+
   | ID                                   | Name  | Status | Networks                                                 | Image  | Flavor  |
   +--------------------------------------+-------+--------+----------------------------------------------------------+--------+---------+
   | 71fb4ac8-eed8-4644-8113-0641962bb125 | my_vm | ACTIVE | private=fda4:653e:71b0:0:f816:3eff:fe24:8614, 192.0.2.16 | cirros | m1.nano |
   +--------------------------------------+-------+--------+----------------------------------------------------------+--------+---------+

   $ openstack port list --device-id 71fb4ac8-eed8-4644-8113-0641962bb125
   +--------------------------------------+------+-------------------+-----------------------------------------------------------------------------------------------------+--------+
   | ID                                   | Name | MAC Address       | Fixed IP Addresses                                                                                  | Status |
   +--------------------------------------+------+-------------------+-----------------------------------------------------------------------------------------------------+--------+
   | 1e7033fb-8e9d-458b-89ed-8312cafcfdcb |      | fa:16:3e:24:86:14 | ip_address='192.0.2.16', subnet_id='5b9282a1-0be1-4ade-b478-7868ad2a16ff'                           | ACTIVE |
   |                                      |      |                   | ip_address='fda4:653e:71b0:0:f816:3eff:fe24:8614', subnet_id='43414c53-62ae-49bc-aa6c-c9dd7705818a' |        |
   +--------------------------------------+------+-------------------+-----------------------------------------------------------------------------------------------------+--------+

   $ openstack port show 1e7033fb-8e9d-458b-89ed-8312cafcfdcb
   +-----------------------+------------------------------------------------------------------------------------------------------------+
   | Field                 | Value                                                                                                      |
   +-----------------------+------------------------------------------------------------------------------------------------------------+
   | admin_state_up        | UP                                                                                                         |
   | allowed_address_pairs |                                                                                                            |
   | binding_host_id       | vultr.guest                                                                                                |
   | binding_profile       |                                                                                                            |
   | binding_vif_details   | datapath_type='system', ovs_hybrid_plug='True', port_filter='True'                                         |
   | binding_vif_type      | ovs                                                                                                        |
   | binding_vnic_type     | normal                                                                                                     |
   | created_at            | 2016-02-15T19:42:44Z                                                                                       |
   | data_plane_status     | None                                                                                                       |
   | description           |                                                                                                            |
   | device_id             | 71fb4ac8-eed8-4644-8113-0641962bb125                                                                       |
   | device_owner          | compute:None                                                                                               |
   | dns_assignment        | fqdn='my-vm.example.org.', hostname='my-vm', ip_address='192.0.2.16'                                       |
   |                       | fqdn='my-vm.example.org.', hostname='my-vm', ip_address='fda4:653e:71b0:0:f816:3eff:fe24:8614'             |
   | dns_domain            | example.org.                                                                                               |
   | dns_name              | my-vm                                                                                                      |
   | extra_dhcp_opts       |                                                                                                            |
   | fixed_ips             | ip_address='192.0.2.16', subnet_id='5b9282a1-0be1-4ade-b478-7868ad2a16ff'                                  |
   |                       | ip_address='fda4:653e:71b0:0:f816:3eff:fe24:8614', subnet_id='43414c53-62ae-49bc-aa6c-c9dd7705818a'        |
   | id                    | 1e7033fb-8e9d-458b-89ed-8312cafcfdcb                                                                       |
   | mac_address           | fa:16:3e:24:86:14                                                                                          |
   | name                  |                                                                                                            |
   | network_id            | 38c5e950-b450-4c30-83d4-ee181c28aad3                                                                       |
   | port_security_enabled | True                                                                                                       |
   | project_id            | d5660cb1e6934612a01b4fb2fb630725                                                                           |
   | qos_policy_id         | None                                                                                                       |
   | revision_number       | 1                                                                                                          |
   | security_group_ids    | 1f0ddd73-7e3c-48bd-a64c-7ded4fe0e635                                                                       |
   | status                | ACTIVE                                                                                                     |
   | tags                  |                                                                                                            |
   | trunk_details         | None                                                                                                       |
   | updated_at            | 2016-02-15T19:42:44Z                                                                                       |
   +-----------------------+------------------------------------------------------------------------------------------------------------+

   $ openstack recordset list example.org.
   +--------------------------------------+--------------------+------+-----------------------------------------------------------------------+--------+--------+
   | id                                   | name               | type | records                                                               | status | action |
   +--------------------------------------+--------------------+------+-----------------------------------------------------------------------+--------+--------+
   | 56ca0b88-e343-4c98-8faa-19746e169baf | example.org.       | NS   | ns1.devstack.org.                                                     | ACTIVE | NONE   |
   | 10a36008-6ecf-47c3-b321-05652a929b04 | example.org.       | SOA  | ns1.devstack.org. malavall.us.ibm.com. 1455565110 3532 600 86400 3600 | ACTIVE | NONE   |
   +--------------------------------------+--------------------+------+-----------------------------------------------------------------------+--------+--------+

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
   | revision_number     | 1                                    |
   | router_id           |                                      |
   | status              | DOWN                                 |
   | tags                | []                                   |
   | tenant_id           | d5660cb1e6934612a01b4fb2fb630725     |
   +---------------------+--------------------------------------+

   $ openstack recordset list example.org.
   +--------------------------------------+----------------------------+------+-----------------------------------------------------------------------+--------+--------+
   | id                                   | name                       | type | records                                                               | status | action |
   +--------------------------------------+----------------------------+------+-----------------------------------------------------------------------+--------+--------+
   | 56ca0b88-e343-4c98-8faa-19746e169baf | example.org.               | NS   | ns1.devstack.org.                                                     | ACTIVE | NONE   |
   | 10a36008-6ecf-47c3-b321-05652a929b04 | example.org.               | SOA  | ns1.devstack.org. malavall.us.ibm.com. 1455565110 3532 600 86400 3600 | ACTIVE | NONE   |
   | 8884c56f-3ef5-446e-ae4d-8053cc8bc2b4 | my-floatingip.example.org. | A    | 198.51.100.53                                                         | ACTIVE | NONE   |
   +--------------------------------------+----------------------------+------+-----------------------------------------------------------------------+--------+--------+

Note that in this use case:

* The ``dns_name`` and ``dns_domain`` attributes of a floating IP must be
  specified together on creation. They cannot be assigned to the floating IP
  separately and they cannot be changed after the floating IP has been
  created.
* The ``dns_name`` and ``dns_domain`` of a floating IP have precedence, for
  purposes of being published in the external DNS service, over the
  ``dns_name`` of its associated port and the ``dns_domain`` of the port's
  network, whether they are specified or not. Only the ``dns_name`` and the
  ``dns_domain`` of the floating IP are published in the external DNS service.

Following are the PTR records created for this example. Note that for
IPv4, the value of ``ipv4_ptr_zone_prefix_size`` is 24. Also, since the zone
for the PTR records is created in the ``service`` project, you need to use
admin credentials in order to be able to view it.


.. code-block:: console

   $ openstack recordset list --all-projects 100.51.198.in-addr.arpa.
   +--------------------------------------+----------------------------------+----------------------------+------+---------------------------------------------------------------------+--------+--------+
   | id                                   | project_id                       | name                       | type | data                                                                | status | action |
   +--------------------------------------+----------------------------------+-----------------------------------+---------------------------------------------------------------------+--------+--------+
   | 2dd0b894-25fa-4563-9d32-9f13bd67f329 | 07224d17d76d42499a38f00ba4339710 | 100.51.198.in-addr.arpa.   | NS   | ns1.devstack.org.                                                   | ACTIVE | NONE   |
   | 47b920f1-5eff-4dfa-9616-7cb5b7cb7ca6 | 07224d17d76d42499a38f00ba4339710 | 100.51.198.in-addr.arpa.   | SOA  | ns1.devstack.org. admin.example.org. 1455564862 3600 600 86400 3600 | ACTIVE | NONE   |
   | 589a0171-e77a-4ab6-ba6e-23114f2b9366 | 07224d17d76d42499a38f00ba4339710 | 5.100.51.198.in-addr.arpa. | PTR  | my-floatingip.example.org.                                          | ACTIVE | NONE   |
   +--------------------------------------+----------------------------------+----------------------------+------+---------------------------------------------------------------------+--------+--------+

.. _config-dns-use-case-3:

Use case 3: Ports are published directly in the external DNS service
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

   $ openstack network list
   +--------------------------------------+----------+-----------------------------------------------------------------------------+
   | ID                                   | Name     | Subnets                                                                     |
   +--------------------------------------+----------+-----------------------------------------------------------------------------+
   | 41fa3995-9e4a-4cd9-bb51-3e5424f2ff2a | public   | a67cfdf7-9d5d-406f-8a19-3f38e4fc3e74, cbd8c6dc-ca81-457e-9c5d-f8ece7ef67f8  |
   | 37aaff3a-6047-45ac-bf4f-a825e56fd2b3 | external | 277eca5d-9869-474b-960e-6da5951d09f7, eab47748-3f0a-4775-a09f-b0c24bb64bc4  |
   | bf2802a0-99a0-4e8c-91e4-107d03f158ea | my-net   | 6141b474-56cd-430f-b731-71660bb79b79                                        |
   | 38c5e950-b450-4c30-83d4-ee181c28aad3 | private  | 43414c53-62ae-49bc-aa6c-c9dd7705818a, 5b9282a1-0be1-4ade-b478-7868ad2a16ff  |
   +--------------------------------------+----------+-----------------------------------------------------------------------------+

   $ neutron net-update 37aaff3a-6047-45ac-bf4f-a825e56fd2b3 --dns_domain example.org.
   Updated network: 37aaff3a-6047-45ac-bf4f-a825e56fd2b3

   $ openstack network show 37aaff3a-6047-45ac-bf4f-a825e56fd2b3
   +---------------------------+----------------------------------------------------------------------------+
   | Field                     | Value                                                                      |
   +---------------------------+----------------------------------------------------------------------------+
   | admin_state_up            | UP                                                                         |
   | availability_zone_hints   |                                                                            |
   | availability_zones        | nova                                                                       |
   | created_at                | 2016-02-14T19:42:44Z                                                       |
   | description               |                                                                            |
   | dns_domain                | example.org.                                                               |
   | id                        | 37aaff3a-6047-45ac-bf4f-a825e56fd2b3                                       |
   | ipv4_address_scope        | None                                                                       |
   | ipv6_address_scope        | None                                                                       |
   | is_default                | None                                                                       |
   | is_vlan_transparent       | None                                                                       |
   | mtu                       | 1450                                                                       |
   | name                      | external                                                                   |
   | port_security_enabled     | True                                                                       |
   | project_id                | 04fc2f83966245dba907efb783f8eab9                                           |
   | provider:network_type     | vlan                                                                       |
   | provider:physical_network | None                                                                       |
   | provider:segmentation_id  | 2016                                                                       |
   | qos_policy_id             | None                                                                       |
   | revision_number           | 4                                                                          |
   | router:external           | Internal                                                                   |
   | segments                  | None                                                                       |
   | shared                    | True                                                                       |
   | status                    | ACTIVE                                                                     |
   | subnets                   | eab47748-3f0a-4775-a09f-b0c24bb64bc4, 277eca5d-9869-474b-960e-6da5951d09f7 |
   | tags                      |                                                                            |
   | updated_at                | 2016-02-15T13:42:44Z                                                       |
   +---------------------------+----------------------------------------------------------------------------+

   $ openstack recordset list example.org.
   +--------------------------------------+--------------+------+-----------------------------------------------------------------------+--------+--------+
   | id                                   | name         | type | records                                                               | status | action |
   +--------------------------------------+--------------+------+-----------------------------------------------------------------------+--------+--------+
   | a5fe696d-203f-4018-b0d8-590221adb513 | example.org. | NS   | ns1.devstack.org.                                                     | ACTIVE | NONE   |
   | e7c05a5d-83a0-4fe5-8bd5-ab058a3326aa | example.org. | SOA  | ns1.devstack.org. malavall.us.ibm.com. 1513767619 3532 600 86400 3600 | ACTIVE | NONE   |
   +--------------------------------------+--------------+------+-----------------------------------------------------------------------+--------+--------+

   $ openstack port create --network 37aaff3a-6047-45ac-bf4f-a825e56fd2b3 --dns-name my-vm test
   +-----------------------+-------------------------------------------------------------------------------+
   | Field                 | Value                                                                         |
   +-----------------------+-------------------------------------------------------------------------------+
   | admin_state_up        | UP                                                                            |
   | allowed_address_pairs |                                                                               |
   | binding_host_id       |                                                                               |
   | binding_profile       |                                                                               |
   | binding_vif_details   |                                                                               |
   | binding_vif_type      | unbound                                                                       |
   | binding_vnic_type     | normal                                                                        |
   | created_at            | 2016-02-15T16:42:44Z                                                          |
   | data_plane_status     | None                                                                          |
   | description           |                                                                               |
   | device_id             |                                                                               |
   | device_owner          |                                                                               |
   | dns_assignment        | fqdn='my-vm.example.org.', hostname='my-vm', ip_address='203.0.113.9'         |
   |                       | fqdn='my-vm.example.org.', hostname='my-vm', ip_address='2001:db8:10::9'      |
   | dns_domain            | None                                                                          |
   | dns_name              | my-vm                                                                         |
   | extra_dhcp_opts       |                                                                               |
   | fixed_ips             | ip_address='203.0.113.9', subnet_id='277eca5d-9869-474b-960e-6da5951d09f7'    |
   |                       | ip_address='2001:db8:10::9', subnet_id=‘eab47748-3f0a-4775-a09f-b0c24bb64bc4’ |
   | id                    | 04be331b-dc5e-410a-9103-9c8983aeb186                                          |
   | mac_address           | fa:16:3e:0f:4b:e4                                                             |
   | name                  | test                                                                          |
   | network_id            | 37aaff3a-6047-45ac-bf4f-a825e56fd2b3                                          |
   | port_security_enabled | True                                                                          |
   | project_id            | d5660cb1e6934612a01b4fb2fb630725                                              |
   | qos_policy_id         | None                                                                          |
   | revision_number       | 1                                                                             |
   | security_group_ids    | 1f0ddd73-7e3c-48bd-a64c-7ded4fe0e635                                          |
   | status                | DOWN                                                                          |
   | tags                  |                                                                               |
   | trunk_details         | None                                                                          |
   | updated_at            | 2016-02-15T16:42:44Z                                                          |
   +-----------------------+-------------------------------------------------------------------------------+

   $ openstack recordset list example.org.
   +--------------------------------------+--------------------+------+-----------------------------------------------------------------------+--------+--------+
   | id                                   | name               | type | records                                                               | status | action |
   +--------------------------------------+--------------------+------+-----------------------------------------------------------------------+--------+--------+
   | a5fe696d-203f-4018-b0d8-590221adb513 | example.org.       | NS   | ns1.devstack.org.                                                     | ACTIVE | NONE   |
   | e7c05a5d-83a0-4fe5-8bd5-ab058a3326aa | example.org.       | SOA  | ns1.devstack.org. malavall.us.ibm.com. 1513767794 3532 600 86400 3600 | ACTIVE | NONE   |
   | fa753ab8-bffa-400d-9ef8-d4a3b1a7ffbf | my-vm.example.org. | A    | 203.0.113.9                                                           | ACTIVE | NONE   |
   | 04abf9f8-c7a3-43f6-9a55-95cee9b144a9 | my-vm.example.org. | AAAA | 2001:db8:10::9                                                        | ACTIVE | NONE   |
   +--------------------------------------+--------------------+------+-----------------------------------------------------------------------+--------+--------+

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
   +--------------------------------------+-------+--------+--------------------------------------+--------+---------+
   | ID                                   | Name  | Status | Networks                             | Image  | Flavor  |
   +--------------------------------------+-------+--------+--------------------------------------+--------+---------+
   | 62c19691-d1c7-4d7b-a88e-9cc4d95d4f41 | my_vm | ACTIVE | external=203.0.113.9, 2001:db8:10::9 | cirros | m1.nano |
   +--------------------------------------+-------+--------+--------------------------------------+--------+---------+

In this example the port is created manually by the user and then used to boot
an instance. Notice that:

* The port's data was visible in the DNS service as soon as it was created.
* See :ref:`config-dns-performance-considerations` for an explanation of
  the potential performance impact associated with this use case.

Following are the PTR records created for this example. Note that for
IPv4, the value of ipv4_ptr_zone_prefix_size is 24. In the case of IPv6, the
value of ipv6_ptr_zone_prefix_size is 116.

.. code-block:: console

   $ openstack recordset list --all-projects 113.0.203.in-addr.arpa.
   +--------------------------------------+----------------------------------+---------------------------+------+---------------------------------------------------------------------+--------+--------+
   | id                                   | project_id                       | name                      | type | records                                                             | status | action |
   +--------------------------------------+----------------------------------+---------------------------+------+---------------------------------------------------------------------+--------+--------+
   | 32f1c05b-7c5d-4230-9088-961a0a462d28 | 07224d17d76d42499a38f00ba4339710 | 113.0.203.in-addr.arpa.   | SOA  | ns1.devstack.org. admin.example.org. 1455563035 3600 600 86400 3600 | ACTIVE | NONE   |
   | 3d402c43-b215-4a75-a730-51cbb8999cb8 | 07224d17d76d42499a38f00ba4339710 | 113.0.203.in-addr.arpa.   | NS   | ns1.devstack.org.                                                   | ACTIVE | NONE   |
   | 8e4e618c-24b0-43db-ab06-91b741a91c10 | 07224d17d76d42499a38f00ba4339710 | 9.113.0.203.in-addr.arpa. | PTR  | my-vm.example.org.                                                  | ACTIVE | NONE   |
   +--------------------------------------+----------------------------------+---------------------------+------+---------------------------------------------------------------------+--------+--------+

   $ openstack recordset list --all-projects  0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.8.b.d.0.1.0.0.2.ip6.arpa.
   +--------------------------------------+----------------------------------+---------------------------------------------------------------------------+------+---------------------------------------------------------------------+--------+--------+
   | id                                   | project_id                       | name                                                                      | type | records                                                             | status | action |
   +--------------------------------------+----------------------------------+---------------------------------------------------------------------------+------+---------------------------------------------------------------------+--------+--------+
   | d8923354-13eb-4bd9-914a-0a2ae5f95989 | 07224d17d76d42499a38f00ba4339710 | 0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.8.b.d.0.1.0.0.2.ip6.arpa.       | SOA  | ns1.devstack.org. admin.example.org. 1455563036 3600 600 86400 3600 | ACTIVE | NONE   |
   | 72e60acd-098d-41ea-9771-5b6546c9c06f | 07224d17d76d42499a38f00ba4339710 | 0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.8.b.d.0.1.0.0.2.ip6.arpa.       | NS   | ns1.devstack.org.                                                   | ACTIVE | NONE   |
   | 877e0215-2ddf-4d01-a7da-47f1092dfd56 | 07224d17d76d42499a38f00ba4339710 | 9.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.8.b.d.0.1.0.0.2.ip6.arpa. | PTR  | my-vm.example.org.                                                  | ACTIVE | NONE   |
   +--------------------------------------+----------------------------------+---------------------------------------------------------------------------+------+---------------------------------------------------------------------+--------+--------+

See :ref:`config-dns-int-ext-serv-net` for detailed instructions on how
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

   $ openstack recordset list port-domain.org.
   +--------------------------------------+-------------------------+------+-----------------------------------------------------------------------+--------+--------+
   | id                                   | name                    | type | records                                                               | status | action |
   +--------------------------------------+-------------------------+------+-----------------------------------------------------------------------+--------+--------+
   | 03e5a35b-d984-4d10-942a-2de8ccb9b941 | port-domain.org.        | SOA  | ns1.devstack.org. malavall.us.ibm.com. 1503272259 3549 600 86400 3600 | ACTIVE | NONE   |
   | d2dd1dfe-531d-4fea-8c0e-f5b559942ac5 | port-domain.org.        | NS   | ns1.devstack.org.                                                     | ACTIVE | NONE   |
   | 67a8e83d-7e3c-4fb1-9261-0481318bb7b5 | my-vm.port-domain.org.  | A    | 203.0.113.9                                                           | ACTIVE | NONE   |
   | 5a4f671c-9969-47aa-82e1-e05754021852 | my-vm.port-domain.org.  | AAAA | 2001:db8:10::9                                                        | ACTIVE | NONE   |
   +--------------------------------------+-------------------------+------+-----------------------------------------------------------------------+--------+--------+

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

.. _config-dns-performance-considerations:

Performance considerations
--------------------------

Only for :ref:`config-dns-use-case-3`, if the port binding extension is
enabled in the Networking service, the Compute service will execute one
additional port update operation when allocating the port for the instance
during the boot process. This may have a noticeable adverse effect in the
performance of the boot process that should be evaluated before adoption of this
use case.

.. _config-dns-int-ext-serv-net:

Configuration of the externally accessible network for use case 3
-----------------------------------------------------------------

In :ref:`config-dns-use-case-3`, the externally accessible network must
meet the following requirements:

* The network may not have attribute ``router:external`` set to ``True``.
* The network type can be FLAT, VLAN, GRE, VXLAN or GENEVE.
* For network types VLAN, GRE, VXLAN or GENEVE, the segmentation ID must be
  outside the ranges assigned to project networks.

This usually implies that this use case only works for networks specifically
created for this purpose by an admin, it does not work for networks
which tenants can create.
