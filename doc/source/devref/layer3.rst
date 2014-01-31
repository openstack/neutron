Layer 3 Networking in Neutron - via Layer 3 agent & OpenVSwitch
===============================================================

This page discusses the usage of Neutron with Layer 3 functionality enabled.

Neutron logical network setup
-----------------------------
::

        vagrant@precise64:~/devstack$ neutron net-list
        +--------------------------------------+---------+--------------------------------------------------+
        | id                                   | name    | subnets                                          |
        +--------------------------------------+---------+--------------------------------------------------+
        | 84b6b0cc-503d-448a-962f-43def05e85be | public  | 3a56da7c-2f6e-41af-890a-b324d7bc374d             |
        | a4b4518c-800d-4357-9193-57dbb42ac5ee | private | 1a2d26fb-b733-4ab3-992e-88554a87afa6 10.0.0.0/24 |
        +--------------------------------------+---------+--------------------------------------------------+
        vagrant@precise64:~/devstack$ neutron subnet-list
        +--------------------------------------+------+-------------+--------------------------------------------+
        | id                                   | name | cidr        | allocation_pools                           |
        +--------------------------------------+------+-------------+--------------------------------------------+
        | 1a2d26fb-b733-4ab3-992e-88554a87afa6 |      | 10.0.0.0/24 | {"start": "10.0.0.2", "end": "10.0.0.254"} |
        +--------------------------------------+------+-------------+--------------------------------------------+
        vagrant@precise64:~/devstack$ neutron port-list
        +--------------------------------------+------+-------------------+---------------------------------------------------------------------------------+
        | id                                   | name | mac_address       | fixed_ips                                                                       |
        +--------------------------------------+------+-------------------+---------------------------------------------------------------------------------+
        | 0ba8700e-da06-4318-8fe9-00676dd994b8 |      | fa:16:3e:78:43:5b | {"subnet_id": "1a2d26fb-b733-4ab3-992e-88554a87afa6", "ip_address": "10.0.0.1"} |
        | b2044570-ad52-4f31-a2c3-5d767dc9a8a7 |      | fa:16:3e:5b:cf:4c | {"subnet_id": "1a2d26fb-b733-4ab3-992e-88554a87afa6", "ip_address": "10.0.0.3"} |
        | bb60d1bb-0cab-41cb-9678-30d2b2fdb169 |      | fa:16:3e:af:a9:bd | {"subnet_id": "1a2d26fb-b733-4ab3-992e-88554a87afa6", "ip_address": "10.0.0.2"} |
        +--------------------------------------+------+-------------------+---------------------------------------------------------------------------------+

        vagrant@precise64:~/devstack$ neutron subnet-show 1a2d26fb-b733-4ab3-992e-88554a87afa6
        +------------------+--------------------------------------------+
        | Field            | Value                                      |
        +------------------+--------------------------------------------+
        | allocation_pools | {"start": "10.0.0.2", "end": "10.0.0.254"} |
        | cidr             | 10.0.0.0/24                                |
        | dns_nameservers  |                                            |
        | enable_dhcp      | True                                       |
        | gateway_ip       | 10.0.0.1                                   |
        | host_routes      |                                            |
        | id               | 1a2d26fb-b733-4ab3-992e-88554a87afa6       |
        | ip_version       | 4                                          |
        | name             |                                            |
        | network_id       | a4b4518c-800d-4357-9193-57dbb42ac5ee       |
        | tenant_id        | 3368290ab10f417390acbb754160dbb2           |
        +------------------+--------------------------------------------+


Neutron logical router setup
----------------------------

* http://docs.openstack.org/admin-guide-cloud/content/ch_networking.html#under_the_hood_openvswitch_scenario1_network


::

        vagrant@precise64:~/devstack$ neutron router-list
        +--------------------------------------+---------+--------------------------------------------------------+
        | id                                   | name    | external_gateway_info                                  |
        +--------------------------------------+---------+--------------------------------------------------------+
        | 569469c7-a2a5-4d32-9cdd-f0b18a13f45e | router1 | {"network_id": "84b6b0cc-503d-448a-962f-43def05e85be"} |
        +--------------------------------------+---------+--------------------------------------------------------+
        vagrant@precise64:~/devstack$ neutron router-show router1
        +-----------------------+--------------------------------------------------------+
        | Field                 | Value                                                  |
        +-----------------------+--------------------------------------------------------+
        | admin_state_up        | True                                                   |
        | external_gateway_info | {"network_id": "84b6b0cc-503d-448a-962f-43def05e85be"} |
        | id                    | 569469c7-a2a5-4d32-9cdd-f0b18a13f45e                   |
        | name                  | router1                                                |
        | routes                |                                                        |
        | status                | ACTIVE                                                 |
        | tenant_id             | 3368290ab10f417390acbb754160dbb2                       |
        +-----------------------+--------------------------------------------------------+
        vagrant@precise64:~/devstack$ neutron router-port-list router1
        +--------------------------------------+------+-------------------+---------------------------------------------------------------------------------+
        | id                                   | name | mac_address       | fixed_ips                                                                       |
        +--------------------------------------+------+-------------------+---------------------------------------------------------------------------------+
        | 0ba8700e-da06-4318-8fe9-00676dd994b8 |      | fa:16:3e:78:43:5b | {"subnet_id": "1a2d26fb-b733-4ab3-992e-88554a87afa6", "ip_address": "10.0.0.1"} |
        +--------------------------------------+------+-------------------+---------------------------------------------------------------------------------+

Neutron Routers are realized in OpenVSwitch
-------------------------------------------

.. image:: http://docs.openstack.org/admin-guide-cloud/content/figures/10/a/common/figures/under-the-hood-scenario-1-ovs-network.png


"router1" in the Neutron logical network is realized through a port ("qr-0ba8700e-da") in OpenVSwitch - attached to "br-int"::

        vagrant@precise64:~/devstack$ sudo ovs-vsctl show
        b9b27fc3-5057-47e7-ba64-0b6afe70a398
            Bridge br-int
                Port "qr-0ba8700e-da"
                    tag: 1
                    Interface "qr-0ba8700e-da"
                        type: internal
                Port br-int
                    Interface br-int
                        type: internal
                Port int-br-ex
                    Interface int-br-ex
                Port "tapbb60d1bb-0c"
                    tag: 1
                    Interface "tapbb60d1bb-0c"
                        type: internal
                Port "qvob2044570-ad"
                    tag: 1
                    Interface "qvob2044570-ad"
                Port "int-br-eth1"
                    Interface "int-br-eth1"
            Bridge "br-eth1"
                Port "phy-br-eth1"
                    Interface "phy-br-eth1"
                Port "br-eth1"
                    Interface "br-eth1"
                        type: internal
            Bridge br-ex
                Port phy-br-ex
                    Interface phy-br-ex
                Port "qg-0143bce1-08"
                    Interface "qg-0143bce1-08"
                        type: internal
                Port br-ex
                    Interface br-ex
                        type: internal
            ovs_version: "1.4.0+build0"


        vagrant@precise64:~/devstack$ brctl show
        bridge name	bridge id		STP enabled	interfaces
        br-eth1		0000.e2e7fc5ccb4d	no
        br-ex		0000.82ee46beaf4d	no		phy-br-ex
                                                                qg-39efb3f9-f0
                                                                qg-77e0666b-cd
        br-int		0000.5e46cb509849	no		int-br-ex
                                                                qr-54c9cd83-43
                                                                qvo199abeb2-63
                                                                qvo1abbbb60-b8
                                                                tap74b45335-cc
        qbr199abeb2-63		8000.ba06e5f8675c	no		qvb199abeb2-63
                                                                tap199abeb2-63
        qbr1abbbb60-b8		8000.46a87ed4fb66	no		qvb1abbbb60-b8
                                                                tap1abbbb60-b8
        virbr0		8000.000000000000	yes

Finding the router in ip/ipconfig
---------------------------------

* http://docs.openstack.org/admin-guide-cloud/content/ch_networking.html

        The neutron-l3-agent uses the Linux IP stack and iptables to perform L3 forwarding and NAT.
        In order to support multiple routers with potentially overlapping IP addresses, neutron-l3-agent
        defaults to using Linux network namespaces to provide isolated forwarding contexts. As a result,
        the IP addresses of routers will not be visible simply by running "ip addr list" or "ifconfig" on
        the node. Similarly, you will not be able to directly ping fixed IPs.

        To do either of these things, you must run the command within a particular router's network
        namespace. The namespace will have the name "qrouter-<UUID of the router>.

.. image:: http://docs.openstack.org/admin-guide-cloud/content/figures/10/a/common/figures/under-the-hood-scenario-1-ovs-netns.png

For example::

        vagrant@precise64:~$ neutron router-list
        +--------------------------------------+---------+--------------------------------------------------------+
        | id                                   | name    | external_gateway_info                                  |
        +--------------------------------------+---------+--------------------------------------------------------+
        | ad948c6e-afb6-422a-9a7b-0fc44cbb3910 | router1 | {"network_id": "e6634fef-03fa-482a-9fa7-e0304ce5c995"} |
        +--------------------------------------+---------+--------------------------------------------------------+
        vagrant@precise64:~/devstack$ sudo ip netns exec qrouter-ad948c6e-afb6-422a-9a7b-0fc44cbb3910 ip addr list
        18: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue state UNKNOWN
            link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
            inet 127.0.0.1/8 scope host lo
            inet6 ::1/128 scope host
               valid_lft forever preferred_lft forever
        19: qr-54c9cd83-43: <BROADCAST,MULTICAST,PROMISC,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN
            link/ether fa:16:3e:dd:c1:8f brd ff:ff:ff:ff:ff:ff
            inet 10.0.0.1/24 brd 10.0.0.255 scope global qr-54c9cd83-43
            inet6 fe80::f816:3eff:fedd:c18f/64 scope link
               valid_lft forever preferred_lft forever
        20: qg-77e0666b-cd: <BROADCAST,MULTICAST,PROMISC,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN
            link/ether fa:16:3e:1f:d3:ec brd ff:ff:ff:ff:ff:ff
            inet 192.168.27.130/28 brd 192.168.27.143 scope global qg-77e0666b-cd
            inet6 fe80::f816:3eff:fe1f:d3ec/64 scope link
               valid_lft forever preferred_lft forever


Provider Networking
-------------------

Neutron can also be configured to create `provider networks <http://docs.openstack.org/admin-guide-cloud/content/ch_networking.html#provider_terminology>`_

Further Reading
---------------
* `Packet Pushers - Neutron Network Implementation on Linux <http://packetpushers.net/openstack-neutron-network-implementation-in-linux/>`_
* `OpenStack Cloud Administrator Guide <http://docs.openstack.org/admin-guide-cloud/content/ch_networking.html>`_
* `Neutron - Layer 3 API extension usage guide <http://docs.openstack.org/api/openstack-network/2.0/content/router_ext.html>`_
*  `Darragh O'Reilly -  The Quantum L3 router and floating IPs <http://techbackground.blogspot.com/2013/05/the-quantum-l3-router-and-floating-ips.html>`_
