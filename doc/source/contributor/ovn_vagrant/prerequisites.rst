.. _prerequisites:

=====================
Vagrant prerequisites
=====================

Those are the prerequisites for using the vagrant file definitions

#. Install `VirtualBox <https://www.virtualbox.org/wiki/Downloads>`_ and
   `Vagrant <https://www.vagrantup.com/downloads.html>`_. Alternatively
   you can use parallels or libvirt vagrant plugin.

#. Install plug-ins for Vagrant::

     $ vagrant plugin install vagrant-cachier
     $ vagrant plugin install vagrant-vbguest

#. On Linux hosts, you can enable instances to access external networks such
   as the Internet by enabling IP forwarding and configuring SNAT from the IP
   address range of the provider network interface (typically vboxnet1) on
   the host to the external network interface on the host. For example, if
   the ``eth0`` network interface on the host provides external network
   connectivity::

     # sysctl -w net.ipv4.ip_forward=1
     # sysctl -p
     # iptables -t nat -A POSTROUTING -s 10.10.0.0/16 -o eth0 -j MASQUERADE

   Note: These commands do not persist after rebooting the host.
