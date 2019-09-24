==========================
Introduction to Networking
==========================

The Networking service, code-named neutron, provides an API that lets
you define network connectivity and addressing in the cloud. The
Networking service enables operators to leverage different networking
technologies to power their cloud networking. The Networking service
also provides an API to configure and manage a variety of network
services ranging from L3 forwarding and NAT to edge firewalls, and IPsec VPN.

For a detailed description of the Networking API abstractions and their
attributes, see the `OpenStack Networking API v2.0
Reference <https://docs.openstack.org/api-ref/network/v2/>`__.

.. note::

   If you use the Networking service, do not run the Compute
   ``nova-network`` service (like you do in traditional Compute deployments).
   When you configure networking, see the Compute-related topics in this
   Networking section.

Networking API
~~~~~~~~~~~~~~

Networking is a virtual network service that provides a powerful API to
define the network connectivity and IP addressing that devices from
other services, such as Compute, use.

The Compute API has a virtual server abstraction to describe computing
resources. Similarly, the Networking API has virtual network, subnet,
and port abstractions to describe networking resources.

+---------------+-------------------------------------------------------------+
| Resource      | Description                                                 |
+===============+=============================================================+
| **Network**   | An isolated L2 segment, analogous to VLAN in the physical   |
|               | networking world.                                           |
+---------------+-------------------------------------------------------------+
| **Subnet**    | A block of v4 or v6 IP addresses and associated             |
|               | configuration state.                                        |
+---------------+-------------------------------------------------------------+
| **Port**      | A connection point for attaching a single device, such as   |
|               | the NIC of a virtual server, to a virtual network. Also     |
|               | describes the associated network configuration, such as     |
|               | the MAC and IP addresses to be used on that port.           |
+---------------+-------------------------------------------------------------+

**Networking resources**

To configure rich network topologies, you can create and configure
networks and subnets and instruct other OpenStack services like Compute
to attach virtual devices to ports on these networks.

In particular, Networking supports each project having multiple private
networks and enables projects to choose their own IP addressing scheme,
even if those IP addresses overlap with those that other projects use.

The Networking service:

-  Enables advanced cloud networking use cases, such as building
   multi-tiered web applications and enabling migration of applications
   to the cloud without changing IP addresses.

-  Offers flexibility for administrators to customize network
   offerings.

-  Enables developers to extend the Networking API. Over time, the
   extended functionality becomes part of the core Networking API.

Configure SSL support for networking API
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

OpenStack Networking supports SSL for the Networking API server. By
default, SSL is disabled but you can enable it in the ``neutron.conf``
file.

Set these options to configure SSL:

``use_ssl = True``
    Enables SSL on the networking API server.

``ssl_cert_file = PATH_TO_CERTFILE``
    Certificate file that is used when you securely start the Networking
    API server.

``ssl_key_file = PATH_TO_KEYFILE``
    Private key file that is used when you securely start the Networking
    API server.

``ssl_ca_file = PATH_TO_CAFILE``
    Optional. CA certificate file that is used when you securely start
    the Networking API server. This file verifies connecting clients.
    Set this option when API clients must authenticate to the API server
    by using SSL certificates that are signed by a trusted CA.

``tcp_keepidle = 600``
    The value of TCP\_KEEPIDLE, in seconds, for each server socket when
    starting the API server. Not supported on OS X.

``retry_until_window = 30``
    Number of seconds to keep retrying to listen.

``backlog = 4096``
    Number of backlog requests with which to configure the socket.

Firewall-as-a-Service (FWaaS) overview
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For information on Firewall-as-a-Service (FWaaS), please consult the :doc:`Networking Guide <../fwaas>`.

Allowed-address-pairs
~~~~~~~~~~~~~~~~~~~~~

``Allowed-address-pairs`` enables you to specify
mac_address and ip_address(cidr) pairs that pass through a port regardless
of subnet. This enables the use of protocols such as VRRP, which floats
an IP address between two instances to enable fast data plane failover.

.. note::

   Currently, only the ML2, Open vSwitch, and VMware NSX plug-ins
   support the allowed-address-pairs extension.

**Basic allowed-address-pairs operations.**

- Create a port with a specified allowed address pair:

  .. code-block:: console

     $ openstack port create port1 --allowed-address \
     ip-address=<IP_CIDR>[,mac_address=<MAC_ADDRESS]

- Update a port by adding allowed address pairs:

  .. code-block:: console

     $ openstack port set PORT_UUID --allowed-address \
     ip-address=<IP_CIDR>[,mac_address=<MAC_ADDRESS]



Virtual-Private-Network-as-a-Service (VPNaaS)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The VPNaaS extension enables OpenStack projects to extend private networks
across the internet.

VPNaaS is a service. It is a parent object that associates a VPN
with a specific subnet and router. Only one VPN service object can be
created for each router and each subnet. However, each VPN service object
can have any number of IP security connections.

The Internet Key Exchange (IKE) policy specifies the authentication and
encryption algorithms to use during phase one and two negotiation of a VPN
connection. The IP security policy specifies the authentication and encryption
algorithm and encapsulation mode to use for the established VPN connection.
Note that you cannot update the IKE and IPSec parameters for live tunnels.

You can set parameters for site-to-site IPsec connections, including peer
CIDRs, MTU, authentication mode, peer address, DPD settings, and status.

The current implementation of the VPNaaS extension provides:

- Site-to-site VPN that connects two private networks.

- Multiple VPN connections per project.

- IKEv1 policy support with 3des, aes-128, aes-256, or aes-192 encryption.

- IPSec policy support with 3des, aes-128, aes-192, or aes-256 encryption,
  sha1 authentication, ESP, AH, or AH-ESP transform protocol, and tunnel or
  transport mode encapsulation.

- Dead Peer Detection (DPD) with hold, clear, restart, disabled, or
  restart-by-peer actions.

The VPNaaS driver plugin can be configured in the neutron configuration file.
You can then enable the service.
