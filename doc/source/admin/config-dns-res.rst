.. _config-dns-res:

=============================
Name resolution for instances
=============================

The Networking service offers several methods to configure name
resolution (DNS) for instances. Most deployments should implement
case 1 or 2. Case 3 requires security considerations to prevent
leaking internal DNS information to instances.

Case 1: Each virtual network uses unique DNS resolver(s)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In this case, the DHCP agent offers one or more unique DNS resolvers
to instances via DHCP on each virtual network. You can configure a DNS
resolver when creating or updating a subnet. To configure more than
one DNS resolver, use a comma between each value.

* Configure a DNS resolver when creating a subnet.

  .. code-block:: console

     $ neutron subnet-create --dns-nameserver DNS_RESOLVER

  Replace ``DNS_RESOLVER`` with the IP address of a DNS resolver reachable
  from the virtual network. For example:

  .. code-block:: console

     $ neutron subnet-create --dns-nameserver 203.0.113.8,198.51.100.53

  .. note::

     This command requires other options outside the scope of this
     content.

* Configure a DNS resolver on an existing subnet.

  .. code-block:: console

     $ neutron subnet-update --dns-nameserver DNS_RESOLVER SUBNET_ID_OR_NAME

  Replace ``DNS_RESOLVER`` with the IP address of a DNS resolver reachable
  from the virtual network and ``SUBNET_ID_OR_NAME`` with the UUID or name
  of the subnet. For example, using the ``selfservice`` subnet:

  .. code-block:: console

     $ neutron subnet-update --dns-nameserver 203.0.113.8,198.51.100.53 selfservice

Case 2: All virtual networks use same DNS resolver(s)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In this case, the DHCP agent offers the same DNS resolver(s) to
instances via DHCP on all virtual networks.

* In the ``dhcp_agent.ini`` file, configure one or more DNS resolvers. To
  configure more than one DNS resolver, use a comma between each value.

  .. code-block:: ini

     [DEFAULT]
     dnsmasq_dns_servers = DNS_RESOLVER

  Replace ``DNS_RESOLVER`` with the IP address of a DNS resolver reachable
  from all virtual networks. For example:

  .. code-block:: ini

     [DEFAULT]
     dnsmasq_dns_servers = 203.0.113.8, 198.51.100.53

  .. note::

     You must configure this option for all eligible DHCP agents and
     restart them to activate the values.

Case 3: All virtual networks use DNS resolver(s) on the host
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In this case, the DHCP agent offers the DNS resolver(s) in the
``resolv.conf`` file on the host running the DHCP agent via DHCP to
instances on all virtual networks.

* In the ``dhcp_agent.ini`` file, enable advertisement of the DNS resolver(s)
  on the host.

  .. code-block:: ini

     [DEFAULT]
     dnsmasq_local_resolv = True

  .. note::

     You must configure this option for all eligible DHCP agents and
     restart them to activate the values.
