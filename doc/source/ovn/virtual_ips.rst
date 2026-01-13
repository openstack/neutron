.. _ovn_virtual_ips:

Virtual IPs
===========

It is common practice to create an unbound port in a Neutron network to
allocate (reserve) an IP address that will be used as a Virtual IP (VIP)
by other ports in the same network.  Such IP addresses are then added as
``allowed_address_pairs`` to the ports used by Virtual Machines.

Applications, such as keepalived, running inside these Virtual Machines can
then configure the VIP on one of the VMs and move it between VMs dynamically.

Implementation in OVN
~~~~~~~~~~~~~~~~~~~~~

For Virtual IP addresses to work properly in the OVN backend, Neutron needs to
mark the ``Logical Switch Port`` corresponding to the port with the Virtual IP
as ``virtual``.  Neutron does this for ports that are unbound and have a fixed
IP address that is also configured in the ``allowed_address_pairs`` of any
other port in the same network.

Limitations
~~~~~~~~~~~

* In the case when a Virtual IP address is going to be used in Virtual Machines
  and configured as ``allowed_address_pairs``, it is necessary to also create
  such an unbound port in Neutron in order to:

  * reserve that IP address for that use case so that it will not be later
    allocated for another port in the same network as the fixed IP,
  * let OVN know that this IP and ``Logical Switch Port`` is ``virtual`` so
    that OVN can configure it accordingly.

* A port created in Neutron in order to allocate virtual IP address has to be
  ``unbound``, it can not be attached directly to any Virtual Machine.

* Because of how Virtual IP addresses are implemented in the ML2/OVN backend,
  the Virtual IP address must be set in the ``allowed_address_pairs`` of the VM
  port as a single IP address (/32 for IPv4 or /128 for IPv6).
  Setting a larger CIDR as ``allowed_address_pairs``, even if it contains
  the Virtual IP address, will not mark the ``Logical Switch Port``
  corresponding to the port with that IP address as ``virtual``.

* Another limitation is that setting an IP address that belongs to the
  distributed metadata port in the same network as ``allowed_address_pairs`` is
  not allowed.


Usage example
~~~~~~~~~~~~~

To use a Virtual IP address in Neutron, you need to create an unbound port in a
Neutron network and add the Virtual IP address to the ``allowed_address_pairs``
of the port(s) that belong to the Virtual Machine(s).

* Create an unbound port in the Neutron network to allocate the Virtual IP
  address:

  .. code-block:: console

    $ openstack port create --network private virtual-ip-port
    +-------------------------+-----------------------------------------------------------------------------------------------------+
    | Field                   | Value                                                                                               |
    +-------------------------+-----------------------------------------------------------------------------------------------------+
    | admin_state_up          | UP                                                                                                  |
    | allowed_address_pairs   |                                                                                                     |
    | binding_host_id         |                                                                                                     |
    | binding_profile         |                                                                                                     |
    | binding_vif_details     |                                                                                                     |
    | binding_vif_type        | unbound                                                                                             |
    | binding_vnic_type       | normal                                                                                              |
    | created_at              | 2025-11-28T14:39:06Z                                                                                |
    | data_plane_status       | None                                                                                                |
    | description             |                                                                                                     |
    | device_id               |                                                                                                     |
    | device_owner            |                                                                                                     |
    | device_profile          | None                                                                                                |
    | dns_assignment          |                                                                                                     |
    | dns_domain              | None                                                                                                |
    | dns_name                | None                                                                                                |
    | extra_dhcp_opts         |                                                                                                     |
    | fixed_ips               | ip_address='10.0.0.20', subnet_id='866305cc-26db-48d7-8471-cbd267321b8b'                            |
    |                         | ip_address='fde7:7c8e:8883:0:f816:3eff:feb6:559f', subnet_id='b8b0a413-6229-4c64-9d6e-65906a33b056' |
    | hardware_offload_type   | None                                                                                                |
    | hints                   |                                                                                                     |
    | id                      | 3f078d1b-2f6e-41d8-99d7-70bc801f3979                                                                |
    | ip_allocation           | None                                                                                                |
    | mac_address             | fa:16:3e:b6:55:9f                                                                                   |
    | name                    | virtual-ip-port                                                                                     |
    | network_id              | c8e5e81c-d318-43f6-a45e-056f22a518e6                                                                |
    | numa_affinity_policy    | None                                                                                                |
    | port_security_enabled   | True                                                                                                |
    | project_id              | b7907ac4c9794e5787a8d6bac0e5b80b                                                                    |
    | propagate_uplink_status | None                                                                                                |
    | resource_request        | None                                                                                                |
    | revision_number         | 1                                                                                                   |
    | qos_network_policy_id   | None                                                                                                |
    | qos_policy_id           | None                                                                                                |
    | security_group_ids      | 876d4c44-e2fd-48fc-bbd4-4bd295676a0e                                                                |
    | status                  | DOWN                                                                                                |
    | tags                    |                                                                                                     |
    | trunk_details           | None                                                                                                |
    | trusted                 | None                                                                                                |
    | updated_at              | 2025-11-28T14:39:06Z                                                                                |
    +-------------------------+-----------------------------------------------------------------------------------------------------+

* Create a Virtual Machine

  .. code-block:: console

    openstack server create --flavor m1.micro --image cirros-0.5.1-x86_64-disk --network private virtual-machine
    +-------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    | Field                               | Value                                                                                                                                                |
    +-------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+
    | OS-DCF:diskConfig                   | MANUAL                                                                                                                                               |
    | OS-EXT-AZ:availability_zone         | None                                                                                                                                                 |
    | OS-EXT-SRV-ATTR:host                | None                                                                                                                                                 |
    | OS-EXT-SRV-ATTR:hostname            | virtual-machine                                                                                                                                      |
    | OS-EXT-SRV-ATTR:hypervisor_hostname | None                                                                                                                                                 |
    | OS-EXT-SRV-ATTR:instance_name       | None                                                                                                                                                 |
    | OS-EXT-SRV-ATTR:kernel_id           | None                                                                                                                                                 |
    | OS-EXT-SRV-ATTR:launch_index        | None                                                                                                                                                 |
    | OS-EXT-SRV-ATTR:ramdisk_id          | None                                                                                                                                                 |
    | OS-EXT-SRV-ATTR:reservation_id      | None                                                                                                                                                 |
    | OS-EXT-SRV-ATTR:root_device_name    | None                                                                                                                                                 |
    | OS-EXT-SRV-ATTR:user_data           | None                                                                                                                                                 |
    | OS-EXT-STS:power_state              | N/A                                                                                                                                                  |
    | OS-EXT-STS:task_state               | scheduling                                                                                                                                           |
    | OS-EXT-STS:vm_state                 | building                                                                                                                                             |
    | OS-SRV-USG:launched_at              | None                                                                                                                                                 |
    | OS-SRV-USG:terminated_at            | None                                                                                                                                                 |
    | accessIPv4                          | None                                                                                                                                                 |
    | accessIPv6                          | None                                                                                                                                                 |
    | addresses                           | N/A                                                                                                                                                  |
    | adminPass                           | QNkLbpeZ72LF                                                                                                                                         |
    | config_drive                        | None                                                                                                                                                 |
    | created                             | 2025-11-28T14:41:22Z                                                                                                                                 |
    | description                         | None                                                                                                                                                 |
    | flavor                              | description=, disk='1', ephemeral='0', extra_specs.hw_rng:allowed='True', id='m1.micro', is_disabled=, is_public='True', location=, name='m1.micro', |
    |                                     | original_name='m1.micro', ram='256', rxtx_factor=, swap='0', vcpus='1'                                                                               |
    | hostId                              | None                                                                                                                                                 |
    | host_status                         | None                                                                                                                                                 |
    | id                                  | d2573702-b79c-46a3-bd7a-d8aa50341082                                                                                                                 |
    | image                               | cirros-0.5.1-x86_64-disk (7b920c82-0879-4526-9ee8-7e3b77e7fe28)                                                                                      |
    | key_name                            | None                                                                                                                                                 |
    | locked                              | None                                                                                                                                                 |
    | locked_reason                       | None                                                                                                                                                 |
    | name                                | virtual-machine                                                                                                                                      |
    | pinned_availability_zone            | None                                                                                                                                                 |
    | progress                            | None                                                                                                                                                 |
    | project_id                          | b7907ac4c9794e5787a8d6bac0e5b80b                                                                                                                     |
    | properties                          | None                                                                                                                                                 |
    | scheduler_hints                     |                                                                                                                                                      |
    | security_groups                     | name='default'                                                                                                                                       |
    | server_groups                       | None                                                                                                                                                 |
    | status                              | BUILD                                                                                                                                                |
    | tags                                |                                                                                                                                                      |
    | trusted_image_certificates          | None                                                                                                                                                 |
    | updated                             | 2025-11-28T14:41:22Z                                                                                                                                 |
    | user_id                             | d46c7955bea644c9a45e5d95bb462e29                                                                                                                     |
    | volumes_attached                    |                                                                                                                                                      |
    +-------------------------------------+------------------------------------------------------------------------------------------------------------------------------------------------------+


* List ports of the Virtual Machine

  .. code-block:: console

    $ openstack port list --device-id d2573702-b79c-46a3-bd7a-d8aa50341082
    +--------------------------------------+------+-------------------+-----------------------------------------------------------------------------------------------------+--------+
    | ID                                   | Name | MAC Address       | Fixed IP Addresses                                                                                  | Status |
    +--------------------------------------+------+-------------------+-----------------------------------------------------------------------------------------------------+--------+
    | 692c7f41-0497-4d4c-9766-3d71ffd229df |      | fa:16:3e:b6:44:9a | ip_address='10.0.0.30', subnet_id='866305cc-26db-48d7-8471-cbd267321b8b'                            | ACTIVE |
    |                                      |      |                   | ip_address='fde7:7c8e:8883:0:f816:3eff:feb6:449a', subnet_id='b8b0a413-6229-4c64-9d6e-65906a33b056' |        |
    +--------------------------------------+------+-------------------+-----------------------------------------------------------------------------------------------------+--------+

* Set the Virtual IP address as an allowed address pair to the port of the
  Virtual Machine

  .. code-block:: console

    $ openstack port set --allowed-address ip-address=10.0.0.20 692c7f41-0497-4d4c-9766-3d71ffd229df


After these steps, the Virtual IP address will be available on the port of the
Virtual Machine.

If a CIDR such as ``10.0.0.0/24`` is set in the ``allowed_address_pairs``
instead of the IP address ``10.0.0.20``, then the ``Logical Switch Port``
related to the port with IP address ``10.0.0.20`` would
not be marked as a Virtual IP address due to the limitations mentioned above.

