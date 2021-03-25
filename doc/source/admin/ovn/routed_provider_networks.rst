.. _routed_provider_networks:

================================
Routed Provider Networks for OVN
================================

The Routed Provider Networks feature is used to present a multi-segmented
layer-3 network as a single entity in Neutron.

After creating a provider network with multiple segments as described
in the :ref:`Neutron documentation<config-routed-provider-networks>`,
each segment connects to a provider ``Local_Switch`` entry as
``Logical_Switch_Port`` entries with the ``localnet`` port type.

For example, in the OVN Northbound database, this is how a VLAN
Provider Network with two segments (VLAN: 100, 200) is related to their
``Logical_Switch`` counterpart:

  .. code-block:: bash

     $ ovn-nbctl list logical_switch public
     _uuid               : 983719e5-4f32-4fb0-926d-46291457ca41
     acls                : []
     dns_records         : []
     external_ids        : {"neutron:mtu"="1450", "neutron:network_name"=public, "neutron:revision_number"="3"}
     forwarding_groups   : []
     load_balancer       : []
     name                : neutron-6c8be12a-9ed0-4ac4-8130-cb8fad83cd46
     other_config        : {mcast_flood_unregistered="false", mcast_snoop="true"}
     ports               : [81bce1ab-87f8-4ed5-8163-f16701499dfe, b23d0c2e-773b-4ecb-8306-53d117006a7b]
     qos_rules           : []

     $ ovn-nbctl list logical_switch_port 81bce1ab-87f8-4ed5-8163-f16701499dfe
     _uuid               : 81bce1ab-87f8-4ed5-8163-f16701499dfe
     addresses           : [unknown]
     dhcpv4_options      : []
     dhcpv6_options      : []
     dynamic_addresses   : []
     enabled             : []
     external_ids        : {}
     ha_chassis_group    : []
     name                : provnet-96f663af-19fa-4c7e-a1b8-1dfdc9cd9e82
     options             : {network_name=phys-net-1}
     parent_name         : []
     port_security       : []
     tag                 : 100
     tag_request         : []
     type                : localnet
     up                  : false

     $ ovn-nbctl list logical_switch_port b23d0c2e-773b-4ecb-8306-53d117006a7b
     _uuid               : b23d0c2e-773b-4ecb-8306-53d117006a7b
     addresses           : [unknown]
     dhcpv4_options      : []
     dhcpv6_options      : []
     dynamic_addresses   : []
     enabled             : []
     external_ids        : {}
     ha_chassis_group    : []
     name                : provnet-469cbc3d-8e06-4a8f-be3a-3fcdadfd398a
     options             : {network_name=phys-net-2}
     parent_name         : []
     port_security       : []
     tag                 : 200
     tag_request         : []
     type                : localnet
     up                  : false


As you can see, the two ``localnet`` ports are configured with a
VLAN tag and are related to a single ``Logical_Switch`` entry. When
*ovn-controller* sees that a port in that network has been bound to the
node it's running on it will create a patch port to the provider bridge
accordingly to the bridge mappings configuration.

  .. code-block:: bash

     compute-1: bridge-mappings = segment-1:br-provider1
     compute-2: bridge-mappings = segment-2:br-provider2

For example, when a port in the multisegment network gets bound to
compute-1, ovn-controller will create a patch-port between br-int and
br-provider1.

An important note here is that, on a given hypervisor only ports belonging
to **the same segment** should be present. **It is not allowed to mix
ports from different segments on the same hypervisor for the same network
(Logical_Switch).**
