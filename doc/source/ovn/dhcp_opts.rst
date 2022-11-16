.. _ovn_dhcp_opts:

OVN supported DHCP options
==========================

This is a list of the current supported DHCP options in ML2/OVN:

IP version 4
~~~~~~~~~~~~

========================== ============================
Option name / code         OVN value
========================== ============================
arp-timeout                arp_cache_timeout
bootfile-name              bootfile_name
classless-static-route     classless_static_route
default-ttl                default_ttl
dns-server                 dns_server
domain-name                domain_name
domain-search              domain_search_list
ethernet-encap             ethernet_encap
ip-forward-enable          ip_forward_enable
lease-time                 lease_time
log-server                 log_server
lpr-server                 lpr_server
ms-classless-static-route  ms_classless_static_route
mtu                        mtu
netmask                    netmask
nis-server                 nis_server
ntp-server                 ntp_server
path-prefix                path_prefix
policy-filter              policy_filter
router-discovery           router_discovery
router                     router
router-solicitation        router_solicitation
server-id                  server_id
server-ip-address          tftp_server_address
swap-server                swap_server
T1                         T1
T2                         T2
tcp-ttl                    tcp_ttl
tcp-keepalive              tcp_keepalive_interval
tftp-server-address        tftp_server_address
tftp-server                tftp_server
wpad                       wpad
1                          netmask
3                          router
6                          dns_server
7                          log_server
9                          lpr_server
15                         domain_name
16                         swap_server
19                         ip_forward_enable
21                         policy_filter
23                         default_ttl
26                         mtu
31                         router_discovery
32                         router_solicitation
35                         arp_cache_timeout
36                         ethernet_encap
37                         tcp_ttl
38                         tcp_keepalive_interval
41                         nis_server
42                         ntp_server
51                         lease_time
54                         server_id
58                         T1
59                         T2
66                         tftp_server
67                         bootfile_name
119                        domain_search_list
121                        classless_static_route
150                        tftp_server_address
210                        path_prefix
249                        ms_classless_static_route
252                        wpad
========================== ============================

IP version 6
~~~~~~~~~~~~

==================  =============
Option name / code  OVN value
==================  =============
dns-server          dns_server
domain-search       domain_search
ia-addr             ia_addr
server-id           server_id
2                   server_id
5                   ia_addr
23                  dns_server
24                  domain_search
==================  =============

OVN Database information
~~~~~~~~~~~~~~~~~~~~~~~~

In OVN the DHCP options are stored on a table called ``DHCP_Options``
in the OVN Northbound database.

Let's add a DHCP option to a Neutron port:

.. code-block:: bash

    $ neutron port-update --extra-dhcp-opt opt_name='server-ip-address',opt_value='10.0.0.1' b4c3f265-369e-4bf5-8789-7caa9a1efb9c
    Updated port: b4c3f265-369e-4bf5-8789-7caa9a1efb9c

.. end

To find that port in OVN we can use command below:

.. code-block:: bash

   $ ovn-nbctl find Logical_Switch_Port name=b4c3f265-369e-4bf5-8789-7caa9a1efb9c
   ...
   dhcpv4_options      : 5f00d1a2-c57d-4d1f-83ea-09bf8be13288
   dhcpv6_options      : []
   ...

.. end

For DHCP, the columns that we care about are the ``dhcpv4_options``
and ``dhcpv6_options``. These columns has the uuids of entries in the
``DHCP_Options`` table with the DHCP information for this port.

.. code-block:: bash

   $ ovn-nbctl list DHCP_Options 5f00d1a2-c57d-4d1f-83ea-09bf8be13288
   _uuid               : 5f00d1a2-c57d-4d1f-83ea-09bf8be13288
   cidr                : "10.0.0.0/26"
   external_ids        : {"neutron:revision_number"="0", port_id="b4c3f265-369e-4bf5-8789-7caa9a1efb9c", subnet_id="5157ed8b-e7f1-4c56-b789-fa420098a687"}
   options             : {classless_static_route="{169.254.169.254/32,10.0.0.2, 0.0.0.0/0,10.0.0.1}", dns_server="{8.8.8.8}", domain_name="\"openstackgate.local\"", lease_time="43200", log_server="127.0.0.3", mtu="1442", router="10.0.0.1", server_id="10.0.0.1", server_mac="fa:16:3e:dc:57:22", tftp_server_address="10.0.0.1"}

.. end

Here you can see that the option ``tftp_server_address`` has been set in
the **options** column. Note that, the ``tftp_server_address`` option is
the OVN translated name for ``server-ip-address`` (option 150). Take a
look at the table in this document to find out more about the supported
options and their counterpart names in OVN.
