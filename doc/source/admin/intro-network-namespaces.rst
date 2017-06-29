.. _intro-network-namespaces:

==================
Network namespaces
==================

A namespace is a way of scoping a particular set of identifiers. Using a
namespace, you can use the same identifier multiple times in different
namespaces. You can also restrict an identifier set visible to particular
processes.

For example, Linux provides namespaces for networking and processes, among
other things. If a process is running within a process namespace, it can only
see and communicate with other processes in the same namespace. So, if a shell
in a particular process namespace ran :command:`ps waux`, it would only show
the other processes in the same namespace.

Linux network namespaces
~~~~~~~~~~~~~~~~~~~~~~~~

In a network namespace, the scoped 'identifiers' are network devices; so a
given network device, such as ``eth0``, exists in a particular namespace.
Linux starts up with a default network namespace, so if your operating system
does not do anything special, that is where all the network devices will be
located. But it is also possible to create further non-default namespaces, and
create new devices in those namespaces, or to move an existing device from one
namespace to another.

Each network namespace also has its own routing table, and in fact this is the
main reason for namespaces to exist. A routing table is keyed by destination IP
address, so network namespaces are what you need if you want the same
destination IP address to mean different things at different times - which is
something that OpenStack Networking requires for its feature of providing
overlapping IP addresses in different virtual networks.

Each network namespace also has its own set of iptables (for both IPv4 and
IPv6). So, you can apply different security to flows with the same IP
addressing in different namespaces, as well as different routing.

Any given Linux process runs in a particular network namespace. By default this
is inherited from its parent process, but a process with the right capabilities
can switch itself into a different namespace; in practice this is mostly done
using the :command:`ip netns exec NETNS COMMAND...` invocation, which starts
``COMMAND`` running in the namespace named ``NETNS``. Suppose such a process
sends out a message to IP address A.B.C.D, the effect of the namespace is that
A.B.C.D will be looked up in that namespace's routing table, and that will
determine the network device that the message is transmitted through.

Virtual routing and forwarding (VRF)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Virtual routing and forwarding is an IP technology that allows multiple
instances of a routing table to coexist on the same router at the same time.
It is another name for the network namespace functionality described above.
