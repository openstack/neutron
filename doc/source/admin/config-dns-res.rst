.. _config-dns-res:

============================
DNS Resolution for Instances
============================

The Networking service offers several methods to configure name
resolution (DNS) for instances. Most deployments should implement
case 1 or 2a. Case 2b requires security considerations to prevent
leaking internal DNS information to instances.

.. note::
   All of these setups require the configured DNS resolvers to be reachable
   from the virtual network in question. So unless the resolvers are located
   inside the virtual network itself, this implies the need for a router to
   be attached to that network having an external gateway configured.

Case 1: Each virtual network uses unique DNS resolver(s)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In this case, the DHCP agent offers one or more unique DNS resolvers
to instances via DHCP on each virtual network. You can configure a DNS
resolver when creating or updating a subnet. To configure more than
one DNS resolver, repeat the option multiple times.

* Configure a DNS resolver when creating a subnet.

  .. code-block:: console

     $ openstack subnet create --dns-nameserver DNS_RESOLVER

  Replace ``DNS_RESOLVER`` with the IP address of a DNS resolver reachable
  from the virtual network. Repeat the option if you want to specify
  multiple IP addresses. For example:

  .. code-block:: console

     $ openstack subnet create --dns-nameserver 203.0.113.8 --dns-nameserver 198.51.100.53

  .. note::

     This command requires additional options outside the scope of this
     content.

* Add a DNS resolver to an existing subnet.

  .. code-block:: console

     $ openstack subnet set --dns-nameserver DNS_RESOLVER SUBNET_ID_OR_NAME

  Replace ``DNS_RESOLVER`` with the IP address of a DNS resolver reachable
  from the virtual network and ``SUBNET_ID_OR_NAME`` with the UUID or name
  of the subnet. For example, using the ``selfservice`` subnet:

  .. code-block:: console

     $ openstack subnet set --dns-nameserver 203.0.113.9 selfservice

* Remove all DNS resolvers from a subnet.

  .. code-block:: console

     $ openstack subnet set --no-dns-nameservers SUBNET_ID_OR_NAME

  Replace ``SUBNET_ID_OR_NAME`` with the UUID or name
  of the subnet. For example, using the ``selfservice`` subnet:

  .. code-block:: console

     $ openstack subnet set --no-dns-nameservers selfservice

  .. note::
     You can use this option in combination with the previous one in order
     to replace all existing DNS resolver addresses with new ones.

You can also set the DNS resolver address to ``0.0.0.0`` for IPv4 subnets,
or ``::`` for IPv6 subnets, which are special values that indicate to the
DHCP agent that it should not announce any DNS resolver at all on the subnet.

.. note::
   When DNS resolvers are explicitly specified for a subnet this way, that
   setting will take precedence over the options presented in case 2.

Case 2: DHCP agents forward DNS queries from instances
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In this case, the DHCP agent offers the list of all DHCP agent's IP addresses
on a subnet as DNS resolver(s) to instances via DHCP on that subnet.

The DHCP agent then runs a masquerading forwarding DNS resolver with two
possible options to determine where the DNS queries are sent to.

.. note::
   The DHCP agent will answer queries for names and addresses of instances
   running within the virtual network directly instead of forwarding them.

Case 2a: Queries are forwarded to an explicitly configured set of DNS resolvers
-------------------------------------------------------------------------------

In the ``dhcp_agent.ini`` file, configure one or more DNS resolvers. To
configure more than one DNS resolver, use a comma between the values.

.. code-block:: ini

   [DEFAULT]
   dnsmasq_dns_servers = DNS_RESOLVER

Replace ``DNS_RESOLVER`` with a list of IP addresses of DNS resolvers reachable
from all virtual networks. For example:

.. code-block:: ini

   [DEFAULT]
   dnsmasq_dns_servers = 203.0.113.8, 198.51.100.53

.. note::

   You must configure this option for all eligible DHCP agents and
   restart them to activate the values.

Case 2b: Queries are forwarded to DNS resolver(s) configured on the host
------------------------------------------------------------------------

In this case, the DHCP agent forwards queries from the instances to
the DNS resolver(s) configured in the
``resolv.conf`` file on the host running the DHCP agent. This requires
these resolvers being reachable from all virtual networks.

In the ``dhcp_agent.ini`` file, enable using the DNS resolver(s) configured
on the host.

.. code-block:: ini

   [DEFAULT]
   dnsmasq_local_resolv = True

.. note::

   You must configure this option for all eligible DHCP agents and
   restart them to activate this setting.
