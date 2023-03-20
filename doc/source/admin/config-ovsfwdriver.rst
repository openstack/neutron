.. _config-ovsfwdriver:

===================================
Native Open vSwitch firewall driver
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
