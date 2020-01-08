.. _data_model:

===========================================
Mapping between Neutron and OVN data models
===========================================

The primary job of the Neutron OVN ML2 driver is to translate requests for
resources into OVN's data model.  Resources are created in OVN by updating the
appropriate tables in the OVN northbound database (an ovsdb database).  This
document looks at the mappings between the data that exists in Neutron and what
the resulting entries in the OVN northbound DB would look like.


Network
-------

::

    Neutron Network:
        id
        name
        subnets
        admin_state_up
        status
        tenant_id

Once a network is created, we should create an entry in the Logical Switch
table.

::

    OVN northbound DB Logical Switch:
        external_ids: {
            'neutron:network_name': network.name
        }


Subnet
------

::

    Neutron Subnet:
        id
        name
        ip_version
        network_id
        cidr
        gateway_ip
        allocation_pools
        dns_nameservers
        host_routers
        tenant_id
        enable_dhcp
        ipv6_ra_mode
        ipv6_address_mode

Once a subnet is created, we should create an entry in the DHCP Options table
with the DHCPv4 or DHCPv6 options.

::

    OVN northbound DB DHCP_Options:
        cidr
        options
        external_ids: {
            'subnet_id': subnet.id
        }

Port
----

::

    Neutron Port:
        id
        name
        network_id
        admin_state_up
        mac_address
        fixed_ips
        device_id
        device_owner
        tenant_id
        status

When a port is created, we should create an entry in the Logical Switch Ports
table in the OVN northbound DB.

::

    OVN Northbound DB Logical Switch Port:
        switch: reference to OVN Logical Switch
        router_port: (empty)
        name: port.id
        up: (read-only)
        macs: [port.mac_address]
        port_security:
        external_ids: {'neutron:port_name': port.name}


If the port has extra DHCP options defined, we should create an entry
in the DHCP Options table in the OVN northbound DB.

::

    OVN northbound DB DHCP_Options:
        cidr
        options
        external_ids: {
            'subnet_id': subnet.id,
            'port_id':  port.id
        }

Router
------

::

    Neutron Router:
        id
        name
        admin_state_up
        status
        tenant_id
        external_gw_info:
            network_id
            external_fixed_ips: list of dicts
                ip_address
                subnet_id

::

    OVN Northbound DB Logical Router:
        ip:
        default_gw:
        external_ids:


Router Port
-----------

::

    OVN Northbound DB Logical Router Port:
        router: (reference to Logical Router)
        network: (reference to network this port is connected to)
        mac:
        external_ids:


Security Groups
---------------

::

   Neutron Port:
       id
       security_group: id
       network_id

   Neutron Security Group
       id
       name
       tenant_id
       security_group_rules

   Neutron Security Group Rule
       id
       tenant_id
       security_group_id
       direction
       remote_group_id
       ethertype
       protocol
       port_range_min
       port_range_max
       remote_ip_prefix

::

   OVN Northbound DB ACL Rule:
       lswitch:  (reference to Logical Switch - port.network_id)
       priority: (0..65535)
       match: boolean expressions according to security rule
              Translation map (sg_rule  ==> match expression)
              -----------------------------------------------
              sg_rule.direction="Ingress" => "inport=port.id"
              sg_rule.direction="Egress" => "outport=port.id"
              sg_rule.ethertype => "eth.type"
              sg_rule.protocol => "ip.proto"
              sg_rule.port_range_min/port_range_max  =>
                      "port_range_min &lt;= tcp.src &lt;= port_range_max"
                      "port_range_min &lt;= udp.src &lt;= port_range_max"

              sg_rule.remote_ip_prefix => "ip4.src/mask, ip4.dst/mask, ipv6.src/mask, ipv6.dst/mask"

              (all match options for ACL can be found here:
               http://openvswitch.org/support/dist-docs/ovn-nb.5.html)
       action: "allow-related"
       log: true/false
       external_ids: {'neutron:port_id': port.id}
                     {'neutron:security_rule_id': security_rule.id}

Security groups maps between three neutron objects to one OVN-NB object, this
enable us to do the mapping in various ways, depending on OVN capabilities

The current implementation will use the first option in this list for
simplicity, but all options are kept here for future reference

1) For every <neutron port, security rule> pair, define an ACL entry::

     Leads to many ACL entries.
     acl.match = sg_rule converted
     example: ((inport==port.id) && (ip.proto == "tcp") &&
              (1024 &lt;= tcp.src &lt;= 4095) && (ip.src==192.168.0.1/16))

     external_ids: {'neutron:port_id': port.id}
                   {'neutron:security_rule_id': security_rule.id}

2) For every <neutron port, security group> pair, define an ACL entry::

     Reduce the number of ACL entries.
     Means we have to manage the match field in case specific rule changes
     example: (((inport==port.id) && (ip.proto == "tcp") &&
              (1024 &lt;= tcp.src &lt;= 4095) && (ip.src==192.168.0.1/16)) ||
              ((outport==port.id) && (ip.proto == "udp") && (1024 &lt;= tcp.src &lt;= 4095)) ||
              ((inport==port.id) && (ip.proto == 6) ) ||
              ((inport==port.id) && (eth.type == 0x86dd)))

              (This example is a security group with four security rules)

     external_ids: {'neutron:port_id': port.id}
                   {'neutron:security_group_id': security_group.id}

3) For every <lswitch, security group> pair, define an ACL entry::

     Reduce even more the number of ACL entries.
     Manage complexity increase
     example: (((inport==port.id) && (ip.proto == "tcp") && (1024 &lt;= tcp.src &lt;= 4095)
               && (ip.src==192.168.0.1/16)) ||
              ((outport==port.id) && (ip.proto == "udp") && (1024 &lt;= tcp.src &lt;= 4095)) ||
              ((inport==port.id) && (ip.proto == 6) ) ||
              ((inport==port.id) && (eth.type == 0x86dd))) ||

              (((inport==port2.id) && (ip.proto == "tcp") && (1024 &lt;= tcp.src &lt;= 4095)
              && (ip.src==192.168.0.1/16)) ||
              ((outport==port2.id) && (ip.proto == "udp") && (1024 &lt;= tcp.src &lt;= 4095)) ||
              ((inport==port2.id) && (ip.proto == 6) ) ||
              ((inport==port2.id) && (eth.type == 0x86dd)))

     external_ids: {'neutron:security_group': security_group.id}


Which option to pick depends on OVN match field length capabilities, and the
trade off between better performance due to less ACL entries compared to the
complexity to manage them.

If the default behaviour is not "drop" for unmatched entries, a rule with
lowest priority must be added to drop all traffic ("match==1")

Spoofing protection rules are being added by OVN internally and we need to
ignore the automatically added rules in Neutron
