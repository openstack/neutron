.. _native_dhcp:

=============================================
Using the native DHCP feature provided by OVN
=============================================

DHCPv4
------

OVN implements a native DHCPv4 support which caters to the common use case of
providing an IP address to a booting instance by providing stateless replies to
DHCPv4 requests based on statically configured address mappings. To do this it
allows a short list of DHCPv4 options to be configured and applied at each
compute host running ovn-controller.

OVN northbound db provides a table 'DHCP_Options' to store the DHCP options.
Logical switch port has a reference to this table.

When a subnet is created and enable_dhcp is True, a new entry is created in
this table. The 'options' column stores the DHCPv4 options. These DHCPv4
options are included in the DHCPv4 reply by the ovn-controller when the VIF
attached to the logical switch port sends a DHCPv4 request.

In order to map the DHCP_Options row with the subnet, the OVN ML2 driver
stores the subnet id in the 'external_ids' column.

When a new port is created, the 'dhcpv4_options' column of the logical switch
port refers to the DHCP_Options row created for the subnet of the port.
If the port has multiple IPv4 subnets, then the first subnet in the 'fixed_ips'
is used.

If the port has extra DHCPv4 options defined, then a new entry is created
in the DHCP_Options table for the port. The default DHCP options are obtained
from the subnet DHCP_Options table and the extra DHCPv4 options of the port
are overridden. In order to map the port DHCP_Options row with the port,
the OVN ML2 driver stores both the subnet id and port id in the 'external_ids'
column.

If admin wants to disable native OVN DHCPv4 for any particular port, then the
admin needs to define the 'dhcp_disabled' with the value 'true' in the extra
DHCP options.

Ex. neutron port-update <PORT_ID> \
--extra-dhcp-opt ip_version=4, opt_name=dhcp_disabled, opt_value=false


DHCPv6
------

OVN implements a native DHCPv6 support similar to DHCPv4. When a v6 subnet is
created, the OVN ML2 driver will insert a new entry into DHCP_Options table
only when the subnet 'ipv6_address_mode' is not 'slaac', and enable_dhcp is
True.
