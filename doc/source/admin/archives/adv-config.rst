==============================
Advanced configuration options
==============================

This section describes advanced configuration options for various system
components. For example, configuration options where the default works
but that the user wants to customize options. After installing from
packages, ``$NEUTRON_CONF_DIR`` is ``/etc/neutron``.

L3 metering agent
~~~~~~~~~~~~~~~~~

You can run an L3 metering agent that enables layer-3 traffic metering.
In general, you should launch the metering agent on all nodes that run
the L3 agent:

.. code-block:: console

   $ neutron-metering-agent --config-file NEUTRON_CONFIG_FILE \
     --config-file L3_METERING_CONFIG_FILE

You must configure a driver that matches the plug-in that runs on the
service. The driver adds metering to the routing interface.

+------------------------------------------+---------------------------------+
| Option                                   | Value                           |
+==========================================+=================================+
| **Open vSwitch**                         |                                 |
+------------------------------------------+---------------------------------+
| interface\_driver                        |                                 |
| ($NEUTRON\_CONF\_DIR/metering\_agent.ini)| openvswitch                     |
+------------------------------------------+---------------------------------+
| **Linux Bridge**                         |                                 |
+------------------------------------------+---------------------------------+
| interface\_driver                        |                                 |
| ($NEUTRON\_CONF\_DIR/metering\_agent.ini)| linuxbridge                     |
+------------------------------------------+---------------------------------+

L3 metering driver
------------------

You must configure any driver that implements the metering abstraction.
Currently the only available implementation uses iptables for metering.

.. code-block:: ini

   driver = iptables

L3 metering service driver
--------------------------

To enable L3 metering, you must set the following option in the
``neutron.conf`` file on the host that runs ``neutron-server``:

.. code-block:: ini

   service_plugins = metering
