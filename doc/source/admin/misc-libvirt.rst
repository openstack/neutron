.. _misc-disable-libvirt-networking:

==========================
Disable libvirt networking
==========================

Most OpenStack deployments use the `libvirt <https://libvirt.org>`__
toolkit for interacting with the
hypervisor. Specifically, OpenStack Compute uses libvirt for tasks such as
booting and terminating virtual machine instances. When OpenStack Compute boots
a new instance, libvirt provides OpenStack with the VIF associated with the
instance, and OpenStack Compute plugs the VIF into a virtual device provided by
OpenStack Network. The libvirt toolkit itself does not provide any networking
functionality in OpenStack deployments.

However, libvirt is capable of providing networking services to the virtual
machines that it manages. In particular, libvirt can be configured to provide
networking functionality akin to a simplified, single-node version of
OpenStack. Users can use libvirt to create layer 2 networks that are similar to
OpenStack Networking's networks, confined to a single node.

libvirt network implementation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

By default, libvirt's networking functionality is enabled, and libvirt
creates a network when the system boots. To implement this network,
libvirt leverages some of the same technologies that OpenStack Network
does. In particular, libvirt uses:

* Linux bridging for implementing a layer 2 network
* dnsmasq for providing IP addresses to virtual machines using DHCP
* iptables to implement SNAT so instances can connect out to the public
  internet, and to ensure that virtual machines are permitted to communicate
  with dnsmasq using DHCP

By default, libvirt creates a network named *default*. The details of this
network may vary by distribution; on Ubuntu this network involves:

* a Linux bridge named ``virbr0`` with an IP address of ``192.0.2.1/24``
* a dnsmasq process that listens on the ``virbr0`` interface and hands out IP
  addresses in the range ``192.0.2.2-192.0.2.254``
* a set of iptables rules

When libvirt boots a virtual machine, it places the machine's VIF in the bridge
``virbr0`` unless explicitly told not to.

On Ubuntu, the iptables ruleset that libvirt creates includes the following
rules::

    *nat
    -A POSTROUTING -s 192.0.2.0/24 -d 224.0.0.0/24 -j RETURN
    -A POSTROUTING -s 192.0.2.0/24 -d 255.255.255.255/32 -j RETURN
    -A POSTROUTING -s 192.0.2.0/24 ! -d 192.0.2.0/24 -p tcp -j MASQUERADE --to-ports 1024-65535
    -A POSTROUTING -s 192.0.2.0/24 ! -d 192.0.2.0/24 -p udp -j MASQUERADE --to-ports 1024-65535
    -A POSTROUTING -s 192.0.2.0/24 ! -d 192.0.2.0/24 -j MASQUERADE
    *mangle
    -A POSTROUTING -o virbr0 -p udp -m udp --dport 68 -j CHECKSUM --checksum-fill
    *filter
    -A INPUT -i virbr0 -p udp -m udp --dport 53 -j ACCEPT
    -A INPUT -i virbr0 -p tcp -m tcp --dport 53 -j ACCEPT
    -A INPUT -i virbr0 -p udp -m udp --dport 67 -j ACCEPT
    -A INPUT -i virbr0 -p tcp -m tcp --dport 67 -j ACCEPT
    -A FORWARD -d 192.0.2.0/24 -o virbr0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    -A FORWARD -s 192.0.2.0/24 -i virbr0 -j ACCEPT
    -A FORWARD -i virbr0 -o virbr0 -j ACCEPT
    -A FORWARD -o virbr0 -j REJECT --reject-with icmp-port-unreachable
    -A FORWARD -i virbr0 -j REJECT --reject-with icmp-port-unreachable
    -A OUTPUT -o virbr0 -p udp -m udp --dport 68 -j ACCEPT

The following shows the dnsmasq process that libvirt manages as it appears in
the output of :command:`ps`::

 2881 ?        S      0:00 /usr/sbin/dnsmasq --conf-file=/var/lib/libvirt/dnsmasq/default.conf

How to disable libvirt networks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Although OpenStack does not make use of libvirt's networking, this
networking will not interfere with OpenStack's behavior, and can be
safely left enabled. However, libvirt's networking can be a nuisance
when debugging OpenStack networking issues. Because libvirt creates an
additional bridge, dnsmasq process, and iptables ruleset, these may
distract an operator engaged in network troubleshooting.
Unless you need to start up virtual machines using libvirt directly, you can
safely disable libvirt's network.

To view the defined libvirt networks and their state:

.. code-block:: console

   # virsh net-list
    Name                 State      Autostart     Persistent
   ----------------------------------------------------------
    default              active     yes           yes

To deactivate the libvirt network named ``default``:

.. code-block:: console

   # virsh net-destroy default

Deactivating the network will remove the ``virbr0`` bridge, terminate
the dnsmasq process, and remove the iptables rules.

To prevent the network from automatically starting on boot:

.. code-block:: console

   # virsh net-autostart --network default --disable

To activate the network after it has been deactivated:

.. code-block:: console

   # virsh net-start default
