.. _config-ndp-proxy:

=========
NDP Proxy
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

  Such as, we have a IPv6 subnetpool, it's CIDR is 2001:db8::/96. The direct
  route like below should be set:

  .. code-block:: console

      2001:db8::/96 dev <ext-gw>

  The ``ext-gw`` is the gateway interface of the cloud's external network.


User workflow
~~~~~~~~~~~~~

The basic steps to publish an IPv6 address to an external
network (such as: public network) are the following:

.. note::

   In order to prevent a potential
   `security risk <https://bugs.launchpad.net/neutron/+bug/1987410>`_,
   the NDP proxy feature requires that an IPv6 address scope be used to
   ensure the uniqueness of the IPv6 address which is published externally.

#. Create an IPv6 address scope

   .. code-block:: console

     $ openstack address scope create test-ipv6-as --ip-version 6
     +------------+--------------------------------------+
     | Field      | Value                                |
     +------------+--------------------------------------+
     | id         | 24761ec5-b659-4358-b9ab-495ead15fa7a |
     | ip_version | 6                                    |
     | name       | test-ipv6-as                         |
     | project_id | bcb0c7a5338b4a46959e47971c58f0f1     |
     | shared     | False                                |
     +------------+--------------------------------------+

#. Create an IPv6 subnet pool

   .. code-block:: console

     $ openstack subnet pool create test-subnetpool --address-scope test-ipv6-as \
             --pool-prefix 2001:db8::/96 --default-prefix-length 112
     +-------------------+--------------------------------------+
     | Field             | Value                                |
     +-------------------+--------------------------------------+
     | address_scope_id  | 24761ec5-b659-4358-b9ab-495ead15fa7a |
     | created_at        | 2022-09-05T06:16:31Z                 |
     | default_prefixlen | 112                                  |
     | default_quota     | None                                 |
     | description       |                                      |
     | id                | 4af07f59-45b8-424d-98c5-35d20ba61526 |
     | ip_version        | 6                                    |
     | is_default        | False                                |
     | max_prefixlen     | 128                                  |
     | min_prefixlen     | 64                                   |
     | name              | test-subnetpool                      |
     | prefixes          | 2001:db8::/96                        |
     | project_id        | bcb0c7a5338b4a46959e47971c58f0f1     |
     | revision_number   | 0                                    |
     | shared            | False                                |
     | tags              |                                      |
     | updated_at        | 2022-01-01T06:42:08Z                 |
     +-------------------+--------------------------------------+

#. Create an external network

   .. code-block:: console

     $ openstack network create --external --provider-network-type flat \
           --provider-physical-network public public
     +---------------------------+--------------------------------------+
     | Field                     | Value                                |
     +---------------------------+--------------------------------------+
     | admin_state_up            | UP                                   |
     | availability_zone_hints   |                                      |
     | availability_zones        |                                      |
     | created_at                | 2022-09-05T06:18:31Z                 |
     | description               |                                      |
     | dns_domain                | None                                 |
     | id                        | 98b0f468-7be0-4530-919d-c4d9417c3abf |
     | ipv4_address_scope        | None                                 |
     | ipv6_address_scope        | None                                 |
     | is_default                | False                                |
     | is_vlan_transparent       | None                                 |
     | mtu                       | 1500                                 |
     | name                      | public                               |
     | port_security_enabled     | True                                 |
     | project_id                | bcb0c7a5338b4a46959e47971c58f0f1     |
     | provider:network_type     | flat                                 |
     | provider:physical_network | public                               |
     | provider:segmentation_id  | None                                 |
     | qos_policy_id             | None                                 |
     | revision_number           | 1                                    |
     | router:external           | External                             |
     | segments                  | None                                 |
     | shared                    | False                                |
     | status                    | ACTIVE                               |
     | subnets                   |                                      |
     | tags                      |                                      |
     | updated_at                | 2022-01-01T06:45:08Z                 |
     +---------------------------+--------------------------------------+

#. Create an external subnet

   .. code-block:: console

      $ openstack subnet create --network public --subnet-pool test-subnetpool \
              --prefix-length 112 --ip-version 6 --no-dhcp ext-sub
       +----------------------+--------------------------------------+
      | Field                | Value                                |
      +----------------------+--------------------------------------+
      | allocation_pools     | 2001:db8::2-2001:db8::ffff           |
      | cidr                 | 2001:db8::/112                       |
      | created_at           | 2022-09-05T06:21:37Z                 |
      | description          |                                      |
      | dns_nameservers      |                                      |
      | dns_publish_fixed_ip | None                                 |
      | enable_dhcp          | False                                |
      | gateway_ip           | 2001:db8::1                          |
      | host_routes          |                                      |
      | id                   | ec11de28-9b84-4cee-b6a1-0ed56135bcd8 |
      | ip_version           | 6                                    |
      | ipv6_address_mode    | None                                 |
      | ipv6_ra_mode         | None                                 |
      | name                 | ext-sub                              |
      | network_id           | 98b0f468-7be0-4530-919d-c4d9417c3abf |
      | project_id           | bcb0c7a5338b4a46959e47971c58f0f1     |
      | revision_number      | 0                                    |
      | segment_id           | None                                 |
      | service_types        |                                      |
      | subnetpool_id        | 4af07f59-45b8-424d-98c5-35d20ba61526 |
      | tags                 |                                      |
      | updated_at           | 2022-01-01T06:47:08Z                 |
      +----------------------+--------------------------------------+

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

#. Create an internal network and IPv6 subnet and add the subnet to the above
   router:

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
      | allocation_pools     | 2001:db8::1:2-2001:db8::1:ffff       |
      | cidr                 | 2001:db8::1:0/112                    |
      | created_at           | 2022-09-05T06:24:13Z                 |
      | description          |                                      |
      | dns_nameservers      |                                      |
      | dns_publish_fixed_ip | None                                 |
      | enable_dhcp          | True                                 |
      | gateway_ip           | 2001:db8::1:1                        |
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
      | subnetpool_id        | 4af07f59-45b8-424d-98c5-35d20ba61526 |
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
      +--------------------------------------+------+-------------------+--------------------------------------------------------------------------------+--------+
      | ID                                   | Name | MAC Address       | Fixed IP Addresses                                                             | Status |
      +--------------------------------------+------+-------------------+--------------------------------------------------------------------------------+--------+
      | bdd64aa0-437a-4db6-bbca-99869426c908 |      | fa:16:3e:ac:15:b8 | ip_address='2001:db8::1:284', subnet_id='9bcf194c-d44f-4e6f-90da-98510ddef283' | ACTIVE |
      +--------------------------------------+------+-------------------+--------------------------------------------------------------------------------+--------+

   Create NDP proxy for the port

   .. code-block:: console

      $ openstack router ndp proxy create test-router --port bdd64aa0-437a-4db6-bbca-99869426c908 --name test-np
      +-----------------+--------------------------------------+
      | Field           | Value                                |
      +-----------------+--------------------------------------+
      | created_at      | 2022-01-02T08:25:31Z                 |
      | description     |                                      |
      | id              | 73889fee-e322-443f-941e-142e4fc5f898 |
      | ip_address      | 2001:db8::1:284                      |
      | name            | test-np                              |
      | port_id         | bdd64aa0-437a-4db6-bbca-99869426c908 |
      | project_id      | bcb0c7a5338b4a46959e47971c58f0f1     |
      | revision_number | 0                                    |
      | router_id       | 3aab8554-e5c4-4262-ab95-b92857c641de |
      | updated_at      | 2022-01-02T08:25:31Z                 |
      +-----------------+--------------------------------------+

#. Then ping the port's address from the upstream router:

   .. code-block:: console

      $ ping 2001:db8::1:284
      PING 2001:db8::1:284(2001:db8::1:284) 56 data bytes
      64 bytes from 2001:db8::1:284: icmp_seq=1 ttl=64 time=0.365 ms
      64 bytes from 2001:db8::1:284: icmp_seq=2 ttl=64 time=0.385 ms

   .. note::

      You may also need to add a security group rule that allows ICMPv6
      traffic towards the instance.

Known limitations
~~~~~~~~~~~~~~~~~

- Using NDP proxies in combination with the OVN backend is not supported.
