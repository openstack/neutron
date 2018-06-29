.. _intro-overlay-protocols:

==========================
Overlay (tunnel) protocols
==========================

Tunneling is a mechanism that makes transfer of payloads feasible over an
incompatible delivery network. It allows the network user to gain access to
denied or insecure networks. Data encryption may be employed to transport the
payload, ensuring that the encapsulated user network data appears as public
even though it is private and can easily pass the conflicting network.


Generic routing encapsulation (GRE)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Generic routing encapsulation (GRE) is a protocol that runs over IP and is
employed when delivery and payload protocols are compatible but payload
addresses are incompatible. For instance, a payload might think it is running
on a datalink layer but it is actually running over a transport layer using
datagram protocol over IP. GRE creates a private point-to-point connection
and works by encapsulating a payload. GRE is a foundation protocol for other
tunnel protocols but the GRE tunnels provide only weak authentication.

.. _VXLAN:

Virtual extensible local area network (VXLAN)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The purpose of VXLAN is to provide scalable network isolation. VXLAN is a
Layer 2 overlay scheme on a Layer 3 network. It allows an overlay layer-2
network to spread across multiple underlay layer-3 network domains. Each
overlay is termed a VXLAN segment. Only VMs within the same VXLAN segment
can communicate.

Generic Network Virtualization Encapsulation (GENEVE)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Geneve is designed to recognize and accommodate changing capabilities and
needs of different devices in network virtualization. It provides a
framework for tunneling rather than being prescriptive about the entire
system. Geneve defines the content of the metadata flexibly that is added
during encapsulation and tries to adapt to various virtualization scenarios.
It uses UDP as its transport protocol and is dynamic in size using extensible
option headers. Geneve supports unicast, multicast, and broadcast.
