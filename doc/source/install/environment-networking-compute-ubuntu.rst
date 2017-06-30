Compute node
~~~~~~~~~~~~

Configure network interfaces
----------------------------

#. Configure the first interface as the management interface:

   IP address: 10.0.0.31

   Network mask: 255.255.255.0 (or /24)

   Default gateway: 10.0.0.1

   .. note::

      Additional compute nodes should use 10.0.0.32, 10.0.0.33, and so on.

#. The provider interface uses a special configuration without an IP
   address assigned to it. Configure the second interface as the provider
   interface:

   Replace ``INTERFACE_NAME`` with the actual interface name. For example,
   *eth1* or *ens224*.


* Edit the ``/etc/network/interfaces`` file to contain the following:

  .. path /etc/network/interfaces
  .. code-block:: bash

     # The provider network interface
     auto INTERFACE_NAME
     iface  INTERFACE_NAME inet manual
     up ip link set dev $IFACE up
     down ip link set dev $IFACE down

  .. end




#. Reboot the system to activate the changes.

Configure name resolution
-------------------------

#. Set the hostname of the node to ``compute1``.

#. .. include:: shared/edit_hosts_file.txt
