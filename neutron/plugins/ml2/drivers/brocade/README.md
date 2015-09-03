Brocade ML2 Mechanism driver from ML2 plugin
============================================

* The real code now resides in stackforge:
  http://github.com/stackforge/networking-brocade

* up-to-date version of these instructions are located at:
  http://50.56.236.34/docs/brocade-ml2-mechanism.txt

* N.B.: Please see Prerequisites section  regarding ncclient (netconf client library)

* Supports VCS (Virtual Cluster of Switches)

* Issues/Questions/Bugs: sharis@brocade.com



   1. VDX 67xx series of switches
   2. VDX 87xx series of switches

ML2 plugin requires mechanism driver to support configuring of hardware switches.
Brocade Mechanism for ML2 uses NETCONF at the backend to configure the Brocade switch.
Currently the mechanism drivers support VLANs only.

             +------------+        +------------+          +-------------+
             |            |        |            |          |             |
   Neutron   |            |        |            |          |   Brocade   |
     v2.0    | Openstack  |        |  Brocade   |  NETCONF |  VCS Switch |
         ----+ Neutron    +--------+  Mechanism +----------+             |
             | ML2        |        |  Driver    |          |  VDX 67xx   |
             | Plugin     |        |            |          |  VDX 87xx   |
             |            |        |            |          |             |
             |            |        |            |          |             |
             +------------+        +------------+          +-------------+


Configuration

In order to use this mechnism the brocade configuration file needs to be edited with the appropriate
configuration information:

        % cat /etc/neutron/plugins/ml2/ml2_conf_brocade.ini
        [switch]
        username = admin
        password = password
        address  = <switch mgmt ip address>
        ostype   = NOS
        physical_networks = phys1

Additionally the brocade mechanism driver needs to be enabled from the ml2 config file:

       % cat /etc/neutron/plugins/ml2/ml2_conf.ini

       [ml2]
       tenant_network_types = vlan
       type_drivers = local,flat,vlan,gre,vxlan
       mechanism_drivers = openvswitch,brocade
       # OR mechanism_drivers = openvswitch,linuxbridge,hyperv,brocade
       ...
       ...
       ...


Required L2 Agent

This mechanism driver works in conjunction with an L2 Agent. The agent should be loaded as well in order for it to configure the virtual network int the host machine. Please see the configuration above. Atleast one of linuxbridge or openvswitch must be specified.



Hardware L3 Router (SVI)

Brocade Hardaware supports SVI (Switch Virtual Interface) which provides ASIC level routing/gateway functionality in the switch for configured VLANs. This Service plugin provides support for this feature which enables line rate routing/gateway functionality.

l3_router_plugin.py provides a hardware based l3 router.

Please refer to: https://blueprints.launchpad.net/neutron/+spec/brocade-l3-svi-service-plugin for more details
