.. _config-ndp-proxy:

=========
NDP proxy
=========

If NDP proxy is set on a router, it is used to publish IPv6 addresses to
external routers. Its purpose is similar to floating IP, but it forwards the
traffic directly by using route rules and has no NAT action. Read the related
`specification <https://specs.openstack.org/openstack/neutron-specs/specs/xena/l3-router-support-ndp-proxy.html>`_
for more details.


Configuration of NDP proxy
~~~~~~~~~~~~~~~~~~~~~~~~~~

To configure NDP proxy, take the following steps:

* On the controller nodes:

  Add the ``ndp_proxy`` service to the ``service_plugins`` setting in
  the ``[DEFAULT]`` section of ``/etc/neutron/neutron.conf``. For example:

  .. code-block:: ini

      [DEFAULT]
      service_plugins = router,ndp_proxy

  .. note::

    The ``router`` service plug-in has to be configured along with the
    ``ndp_proxy`` service plug-in.

* On the network nodes or the compute nodes (for the dvr mode router):

  Set the ``extensions`` option in the ``[agent]`` section of
  ``/etc/neutron/l3_agent.ini`` to include ``ndp_proxy``. This has to be
  done in each network and compute node where the L3 agent is running. For
  example:

  .. code-block:: ini

     extensions = ndp_proxy

.. note::

  After updating the options in the configuration files, the neutron-server
  and every neutron-l3-agent need to be restarted for the new values to take
  effect.

  After configuring NDP proxy, the ``ndp-proxy`` extension alias will be
  included in the output of the following command:

  For API extension:

  .. code-block:: console

     $ openstack extension list --network

  For agent extension:

  .. code-block:: console

     $ openstack network agent show <l3-agent-id>

.. note::

  We introduced a new command ``ndsend`` for the NDP proxy feature, the command can
  send Neighbor Advertisement about IPv6 to upstream router. With this command,
  we can make the upstream router rapidly perceive the change of internal IPv6
  address (such as, port migrated to other node). Read the
  `manual page <http://manpages.ubuntu.com/manpages/focal/man8/ndsend.8.html>`_
  for more details about this command.

  Currently, you need to install this command manually in every L3 agent node. For
  Ubuntu, the command is provided by the ``vzctl`` pkg, the install command:
  ``sudo apt install vzctl``.

* On the upstream router (the datacenter's physical router):

  Generally, the admin operator should plan one or more IPv6 subnetpools to use
  when NDP proxy is enabled, so that all internal subnets can be allocated from
  a single, integrated subnetpool. In order to make NDP proxy work correctly,
  the admin operator needs to set direct routes for these subnetpools.

  Such as, we have a IPv6 subnetpool, it's CIDR is 2001:db8::/96. The direct route
  like below should be set:

  .. code-block:: none

      2001:db8::/96 dev <ext-gw>

  The ``ext-gw`` is the gateway interface of the cloud's external network.


User workflow
~~~~~~~~~~~~~

Assume the admin operator already prepared an IPv6 subnetpool:
``test-subnetpool``, its CIDR is 2001:db8::/96.

The basic steps to publish an IPv6 address to an external
network (such as: public network) are the following:

#. Create a router:

   .. code-block:: console

      $ openstack router create test-router
      +-------------------------+--------------------------------------+
      | Field                   | Value                                |
      +-------------------------+--------------------------------------+
      | admin_state_up          | UP                                   |
      | availability_zone_hints |                                      |
      | availability_zones      |                                      |
      | created_at              | 2022-01-01T06:50:44Z                 |
      | description             |                                      |
      | distributed             | False                                |
      | enable_ndp_proxy        | False                                |
      | external_gateway_info   | null                                 |
      | flavor_id               | None                                 |
      | ha                      | False                                |
      | id                      | 3aab8554-e5c4-4262-ab95-b92857c641de |
      | name                    | test-router                          |
      | project_id              | bcb0c7a5338b4a46959e47971c58f0f1     |
      | revision_number         | 1                                    |
      | routes                  |                                      |
      | status                  | ACTIVE                               |
      | tags                    |                                      |
      | updated_at              | 2022-01-01T06:50:44Z                 |
      +-------------------------+--------------------------------------+

#. Set external gateway for the router:

   .. code-block:: console

      $ openstack router set test-router --external-gateway public


   .. note::

      If the external network has no IPv6 subnet and the ``ipv6_gateway`` is
      configured on the ``neutron-l3-agent``, you may want to set
      ``use_lla_address`` to True at ``/etc/neutron/neutron.conf``, otherwise
      the following command will raise a 403 error.

#. Enable NDP proxy support on the router:

   .. code-block:: console

      $ openstack router set test-router --enable-ndp-proxy

   .. warning::

      If you are using another method (such as:
      :ref:`BGP <config-bgp-dynamic-routing-for-ipv6>`,
      :ref:`prefix-delegation` etc.) to publish the internal IPv6 address, the
      command will break dataplane traffic.

#. Create an internal network and IPv6 subnet and add the subnet to the above router:

   .. code-block:: console

      $ openstack network create int-net
      +---------------------------+--------------------------------------+
      | Field                     | Value                                |
      +---------------------------+--------------------------------------+
      | admin_state_up            | UP                                   |
      | availability_zone_hints   |                                      |
      | availability_zones        |                                      |
      | created_at                | 2022-01-01T07:11:08Z                 |
      | description               |                                      |
      | dns_domain                | None                                 |
      | id                        | e527b38e-9e2a-439b-adf8-4ee1aa4f03b1 |
      | ipv4_address_scope        | None                                 |
      | ipv6_address_scope        | None                                 |
      | is_default                | False                                |
      | is_vlan_transparent       | None                                 |
      | mtu                       | 1450                                 |
      | name                      | int-net                              |
      | port_security_enabled     | True                                 |
      | project_id                | bcb0c7a5338b4a46959e47971c58f0f1     |
      | provider:network_type     | vxlan                                |
      | provider:physical_network | None                                 |
      | provider:segmentation_id  | 575                                  |
      | qos_policy_id             | None                                 |
      | revision_number           | 1                                    |
      | router:external           | Internal                             |
      | segments                  | None                                 |
      | shared                    | False                                |
      | status                    | ACTIVE                               |
      | subnets                   |                                      |
      | tags                      |                                      |
      | updated_at                | 2022-01-01T07:11:08Z                 |
      +---------------------------+--------------------------------------+
      $ openstack subnet create --network int-net --subnet-pool test-subnetpool \
        --prefix-length 112 --ip-version 6 \
        --ipv6-ra-mode dhcpv6-stateful \
        --ipv6-address-mode dhcpv6-stateful int-sub
      +----------------------+--------------------------------------+
      | Field                | Value                                |
      +----------------------+--------------------------------------+
      | allocation_pools     | 2001:db8::2-2001:db8::ffff           |
      | cidr                 | 2001:db8::/112                       |
      | created_at           | 2022-01-02T08:20:26Z                 |
      | description          |                                      |
      | dns_nameservers      |                                      |
      | dns_publish_fixed_ip | None                                 |
      | enable_dhcp          | True                                 |
      | gateway_ip           | 2001:db8::1                          |
      | host_routes          |                                      |
      | id                   | 9bcf194c-d44f-4e6f-90da-98510ddef283 |
      | ip_version           | 6                                    |
      | ipv6_address_mode    | dhcpv6-stateful                      |
      | ipv6_ra_mode         | dhcpv6-stateful                      |
      | name                 | int-sub                              |
      | network_id           | e527b38e-9e2a-439b-adf8-4ee1aa4f03b1 |
      | project_id           | bcb0c7a5338b4a46959e47971c58f0f1     |
      | revision_number      | 0                                    |
      | segment_id           | None                                 |
      | service_types        |                                      |
      | subnetpool_id        | 73c5311c-6750-43f5-9a69-b50c1c5694fd |
      | tags                 |                                      |
      | updated_at           | 2022-01-02T08:20:26Z                 |
      +----------------------+--------------------------------------+
      $ openstack router add subnet test-router int-sub

#. Launch an instance:

   .. code-block:: console

      $ openstack server create --flavor m1.tiny --image cirros-0.5.2-x86_64-disk --network int-net test-server
      +-------------------------------------+-----------------------------------------------------------------+
      | Field                               | Value                                                           |
      +-------------------------------------+-----------------------------------------------------------------+
      | OS-DCF:diskConfig                   | MANUAL                                                          |
      | OS-EXT-AZ:availability_zone         |                                                                 |
      | OS-EXT-SRV-ATTR:host                | None                                                            |
      | OS-EXT-SRV-ATTR:hypervisor_hostname | None                                                            |
      | OS-EXT-SRV-ATTR:instance_name       |                                                                 |
      | OS-EXT-STS:power_state              | NOSTATE                                                         |
      | OS-EXT-STS:task_state               | scheduling                                                      |
      | OS-EXT-STS:vm_state                 | building                                                        |
      | OS-SRV-USG:launched_at              | None                                                            |
      | OS-SRV-USG:terminated_at            | None                                                            |
      | accessIPv4                          |                                                                 |
      | accessIPv6                          |                                                                 |
      | addresses                           |                                                                 |
      | adminPass                           | 97UvRLgdFozR                                                    |
      | config_drive                        |                                                                 |
      | created                             | 2022-01-02T08:22:35Z                                            |
      | flavor                              | m1.tiny (1)                                                     |
      | hostId                              |                                                                 |
      | id                                  | 189a104c-36cd-479a-8702-8111eb34fdb6                            |
      | image                               | cirros-0.5.2-x86_64-disk (2b2d2975-7ffc-463b-8c0e-993122f38b77) |
      | key_name                            | None                                                            |
      | name                                | test-server                                                     |
      | progress                            | 0                                                               |
      | project_id                          | bcb0c7a5338b4a46959e47971c58f0f1                                |
      | properties                          |                                                                 |
      | security_groups                     | name='default'                                                  |
      | status                              | BUILD                                                           |
      | updated                             | 2022-01-02T08:22:34Z                                            |
      | user_id                             | 27e0947bb4fe47e4981da31d4a18ddf7                                |
      | volumes_attached                    |                                                                 |
      +-------------------------------------+-----------------------------------------------------------------+

#. Create NDP proxy for the instance's port:

   Query the port of the instance

   .. code-block:: console

      $ openstack port list --server test-server
      +--------------------------------------+------+-------------------+------------------------------------------------------------------------------+--------+
      | ID                                   | Name | MAC Address       | Fixed IP Addresses                                                           | Status |
      +--------------------------------------+------+-------------------+------------------------------------------------------------------------------+--------+
      | bdd64aa0-437a-4db6-bbca-99869426c908 |      | fa:16:3e:ac:15:b8 | ip_address='2001:db8::284', subnet_id='9bcf194c-d44f-4e6f-90da-98510ddef283' | ACTIVE |
      +--------------------------------------+------+-------------------+------------------------------------------------------------------------------+--------+

   Create NDP proxy for the port

   .. code-block:: console

      $ openstack network ndp proxy create --router test-router --port bdd64aa0-437a-4db6-bbca-99869426c908 test-np
      +-----------------+--------------------------------------+
      | Field           | Value                                |
      +-----------------+--------------------------------------+
      | created_at      | 2022-01-02T08:25:31Z                 |
      | description     |                                      |
      | id              | 73889fee-e322-443f-941e-142e4fc5f898 |
      | ip_address      | 2001:db8::284                        |
      | name            | test-np                              |
      | port_id         | bdd64aa0-437a-4db6-bbca-99869426c908 |
      | project_id      | bcb0c7a5338b4a46959e47971c58f0f1     |
      | revision_number | 0                                    |
      | router_id       | 3aab8554-e5c4-4262-ab95-b92857c641de |
      | updated_at      | 2022-01-02T08:25:31Z                 |
      +-----------------+--------------------------------------+

#. Then ping the port's address from the upstream router:

   .. code-block:: console

      $ ping 2001:db8::284
      PING 2001:db8::284(2001:db8::284) 56 data bytes
      64 bytes from 2001:db8::284: icmp_seq=1 ttl=64 time=0.365 ms
      64 bytes from 2001:db8::284: icmp_seq=2 ttl=64 time=0.385 ms

   .. note::

      You may also need to add a security group rule that allows ICMPv6
      traffic towards the instance.

Known limitations
~~~~~~~~~~~~~~~~~

- Using NDP proxies in combination with the OVN backend is not supported.
