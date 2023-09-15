.. _config-ovsfwdriver:

===================================
Open vSwitch Native Firewall Driver
===================================

Historically, Open vSwitch (OVS) could not interact directly with *iptables*
to implement security groups. Thus, the OVS agent and Compute service use
a Linux bridge between each instance (VM) and the OVS integration bridge
``br-int`` to implement security groups. The Linux bridge device contains
the *iptables* rules pertaining to the instance. In general, additional
components between instances and physical network infrastructure cause
scalability and performance problems. To alleviate such problems, the OVS
agent includes an optional firewall driver that natively implements security
groups as flows in OVS rather than the Linux bridge device and *iptables*.
This increases scalability and performance.

Configuring heterogeneous firewall drivers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

L2 agents can be configured to use differing firewall drivers. There is no
requirement that they all be the same. If an agent lacks a firewall driver
configuration, it will default to what is configured on its server. This also
means there is no requirement that the server has any firewall driver
configured at all, as long as the agents are configured correctly.

Prerequisites
~~~~~~~~~~~~~

The native OVS firewall implementation requires kernel and user space support
for *conntrack*, thus requiring minimum versions of the Linux kernel and
Open vSwitch. All cases require Open vSwitch version 2.5 or newer.

* Kernel version 4.3 or newer includes *conntrack* support.
* Kernel version 3.3, but less than 4.3, does not include *conntrack*
  support and requires building the OVS modules.

It also requires the conntrack kernel module(s) to be loaded, which
varies depending on the kernel version.

* Kernel version 4.19 or newer requires the *nf_conntrack* module.
* Kernel versions 4.18 or older require the *nf_conntrack_ipv4* and
  *nf_conntrack_ipv6* modules.

Enable the native OVS firewall driver
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* On nodes running the Open vSwitch agent, edit the
  ``openvswitch_agent.ini`` file and enable the firewall driver.

  .. code-block:: ini

     [securitygroup]
     firewall_driver = openvswitch

For more information, see the
:doc:`/contributor/internals/openvswitch_firewall`
and the `video <https://www.youtube.com/watch?v=SOHeZ3g9yxM>`_.

Using GRE tunnels inside VMs with OVS firewall driver
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If GRE tunnels from VM to VM are going to be used, the native OVS firewall
implementation requires ``nf_conntrack_proto_gre`` module to be loaded in
the kernel on nodes running the Open vSwitch agent.
It can be loaded with the command:

.. code-block:: console

    # modprobe nf_conntrack_proto_gre

Some Linux distributions have files that can be used to automatically load
kernel modules at boot time, for example, ``/etc/modules``. Check with your
distribution for further information.

This isn't necessary to use ``gre`` tunnel network type Neutron.

Differences between OVS and iptables firewall drivers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Both OVS and iptables firewall drivers should always behave in the same way if
the same rules are configured for the security group. But in some cases that is
not true and there may be slight differences between those drivers.

+----------------------------------------+-----------------------+-----------------------+
| Case                                   | OVS                   | iptables              |
+========================================+=======================+=======================+
| Traffic marked as INVALID by conntrack | Blocked               | Allowed because it    |
| but matching some of the SG rules      |                       | first matches SG rule,|
| (please check [1]_  and [2]_           |                       | never reaches rule to |
| for details)                           |                       | drop invalid packets  |
+----------------------------------------+-----------------------+-----------------------+
| Multicast traffic sent in the group    | Allowed always        | Blocked,              |
| 224.0.0.X                              |                       | Can be enabled by SG  |
| (please check [3]_ for details)        |                       | rule.                 |
+----------------------------------------+-----------------------+-----------------------+

Open Flow rules processing considerations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The native Open vSwitch firewall driver increases the number of Open Flow rules
to be installed in the integration bridge, that could be up to thousands of
entries, depending on the number or rules, rule type and number of ports in the
compute node.

By default, these rules are written into the integration bridge in batches. The
``_constants.AGENT_RES_PROCESSING_STEP`` constant defines how many rules are
written in a single operation. It is set to 100.

As seen in `LP#1934917 <https://bugs.launchpad.net/neutron/+bug/1934917>`_,
during the Open Flow processing (that could be better displayed during the OVS
agent initial transient period), there could be some inconsistencies in the
port rules. In order to avoid them, the configuration variable
``OVS.openflow_processed_per_port`` allows to process all Open Flow rules
related to a single port in a single transaction.

The following script provides a tool to measure, in each deployment, the
processing time when using ``OVS.openflow_processed_per_port`` or
the default ``_constants.AGENT_RES_PROCESSING_STEP``:

.. code-block:: bash

    # (1) Create a network with a single IPv4 subnet
    openstack network create net-scale
    openstack subnet create --subnet-range 10.250.0.0/16 --network net-scale snet-scale

    # (2) Create 400 ports bound to one host
    for i in {1..400}
    do
        openstack port create \
          --security-group <security_group_id> \
          --device-owner testing:scale \
          --binding-profile host_id=<compute_node_host_name> \
          --network net-scale test-large-scale-port-$i
    done

    # (3) Create 1000 security group rules, belonging to the same security
    #     group <security_group_id>
    for i in {3000..4000}
    do
      curl -g -i -X POST http://controller:9696/v2.0/security-group-rules \
      -H "User-Agent: python-neutronclient" -H "Content-Type: application/json" \
      -H "Accept: application/json" -H "X-Auth-Token: <token>" \
      -d '{
      "security_group_rule": {
        "direction": "ingress", "protocol": "tcp",
        "ethertype": "IPv4", "port_range_max": "'$i'",
        "port_range_min": "3000",
        "security_group_id": <security_group_id>}
      }' 2>&1 > /dev/null
    done

    # (4) Setup the port to the host <compute_node_host_name>
    # "grep" the test port list into file port_list.
    $ for p in `openstack port list -f value -c id -c name -c mac_address -c fixed_ips | grep test-large-scale-port`
      do
          mac=`echo $p | cut -f3 -d" "`
          ip_addr=`echo $p | cut -f7 -d" " | cut -f2 -d"'"`
          dev_id=`echo $p | cut -f1 -d" " | cut -b 1-11`
          dev_name="tp-$dev_id"
          echo "===" $mac "===" $ip_addr "===" $dev_id "===" $dev_name
          ovs-vsctl  --may-exist add-port br-int ${dev_name} -- set Interface \
            ${dev_name} type=internal \
            -- set Interface ${dev_name} external-ids:attached-mac="${mac}" \
            -- set Interface ${dev_name} external-ids:iface-id="${p}" \
            -- set Interface ${dev_name} external-ids:iface-status=active
          sleep 0.2

          ip link set dev ${dev_name} address ${mac}
          ip addr add ${ip_addr} dev ${dev_name}
          ip link set ${dev_name} up
      done

    # (5) Restart the OVS agent and check that all flows are in place.
    # (6) Check the OVS agent restart time, checking the "iteration" time and
    #     number.

Permitted ethertypes
~~~~~~~~~~~~~~~~~~~~

The OVS Firewall blocks traffic that does not have either the IPv4 or IPv6
ethertypes at present. This is a behavior change compared to the
"iptables_hybrid" firewall, which only operates on IP packets and thus does
not address other ethertypes. With the configuration option
``permitted_ethertypes`` it is possible to define a set of allowed ethertypes.
Any traffic with these allowed ethertypes with destination to a local port or
generated from a local port and MAC address, will be allowed.

References
~~~~~~~~~~

.. [1] https://bugs.launchpad.net/neutron/+bug/1460741
.. [2] https://bugs.launchpad.net/neutron/+bug/1896587
.. [3] https://bugs.launchpad.net/neutron/+bug/1889631
