.. _config-fip-port-forwardings:

===========================
Floating IP Port Forwarding
===========================

Floating IP port forwarding enables users to forward traffic from a
TCP/UDP/other protocol port of a floating IP to a TCP/UDP/other protocol port
associated to one of the fixed IPs of a Neutron port. This is accomplished by
associating ``port_forwarding`` sub-resource to a floating IP.

CRUD operations for port forwarding are implemented by a Neutron API extension
and a service plug-in. Please refer to the Neutron API Reference documentation
for details on the CRUD operations.

Configuring floating IP port forwarding
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To configure floating IP port forwarding, take the following steps:

* Add the ``port_forwarding`` service to the ``service_plugins`` setting in
  ``/etc/neutron/neutron.conf``. For example:

  .. code-block:: console

     service_plugins = router,segments,port_forwarding

* Set the ``extensions`` option in the ``[agent]`` section of
  ``/etc/neutron/l3_agent.ini`` to include ``port_forwarding``. This has to be
  done in each network and compute node where the L3 agent is running. For
  example:

  .. code-block:: console

     extensions = port_forwarding

.. note::

   The ``router`` service plug-in manages floating IPs and routers. As a
   consequence, it has to be configured along with the ``port_forwarding``
   service plug-in.

.. note::

   After updating the options in the configuration files, the neutron-server
   and every neutron-l3-agent need to be restarted for the new values to take
   effect.

After configuring floating IP port forwarding, the
``floating-ip-port-forwarding`` extension alias will be included in the output
of the following command:

.. code-block:: console

   $ openstack extension list --network
