======================
Plug-in configurations
======================

For configurations options, see `Networking configuration
options <https://docs.openstack.org/ocata/config-reference/networking/networking_options_reference.html>`__
in Configuration Reference. These sections explain how to configure
specific plug-ins.

Configure Big Switch (Floodlight REST Proxy) plug-in
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Edit the ``/etc/neutron/neutron.conf`` file and add this line:

   .. code-block:: ini

      core_plugin = bigswitch

#. In the ``/etc/neutron/neutron.conf`` file, set the ``service_plugins``
   option:

   .. code-block:: ini

      service_plugins = neutron.plugins.bigswitch.l3_router_plugin.L3RestProxy

#. Edit the ``/etc/neutron/plugins/bigswitch/restproxy.ini`` file for the
   plug-in and specify a comma-separated list of controller\_ip:port pairs:

   .. code-block:: ini

      server = CONTROLLER_IP:PORT

   For database configuration, see `Install Networking
   Services <https://docs.openstack.org/ocata/install-guide-ubuntu/neutron-controller-install.html>`__
   in the Installation Tutorials and Guides. (The link defaults to the Ubuntu
   version.)

#. Restart the ``neutron-server`` to apply the settings:

   .. code-block:: console

      # service neutron-server restart

Configure Brocade plug-in
~~~~~~~~~~~~~~~~~~~~~~~~~

#. Install the Brocade-modified Python netconf client (ncclient) library,
   which is available at https://github.com/brocade/ncclient:

   .. code-block:: console

      $ git clone https://github.com/brocade/ncclient

#. As root, run this command:

   .. code-block:: console

      # cd ncclient;python setup.py install

#. Edit the ``/etc/neutron/neutron.conf`` file and set the following
   option:

   .. code-block:: ini

      core_plugin = brocade

#. Edit the ``/etc/neutron/plugins/brocade/brocade.ini`` file for the
   Brocade plug-in and specify the admin user name, password, and IP
   address of the Brocade switch:

   .. code-block:: ini

      [SWITCH]
      username = ADMIN
      password = PASSWORD
      address  = SWITCH_MGMT_IP_ADDRESS
      ostype   = NOS

   For database configuration, see `Install Networking
   Services <https://docs.openstack.org/ocata/install-guide-ubuntu/neutron-controller-install.html>`__
   in any of the Installation Tutorials and Guides in the `OpenStack Documentation
   index <https://docs.openstack.org>`__. (The link defaults to the Ubuntu
   version.)

#. Restart the ``neutron-server`` service to apply the settings:

   .. code-block:: console

      # service neutron-server restart

Configure NSX-mh plug-in
~~~~~~~~~~~~~~~~~~~~~~~~

The instructions in this section refer to the VMware NSX-mh platform,
formerly known as Nicira NVP.

#. Install the NSX plug-in:

   .. code-block:: console

      # apt-get install python-vmware-nsx

#. Edit the ``/etc/neutron/neutron.conf`` file and set this line:

   .. code-block:: ini

      core_plugin = vmware

   Example ``neutron.conf`` file for NSX-mh integration:

   .. code-block:: ini

      core_plugin = vmware
      rabbit_host = 192.168.203.10

#. To configure the NSX-mh controller cluster for OpenStack Networking,
   locate the ``[default]`` section in the
   ``/etc/neutron/plugins/vmware/nsx.ini`` file and add the following
   entries:

   -  To establish and configure the connection with the controller cluster
      you must set some parameters, including NSX-mh API endpoints, access
      credentials, and optionally specify settings for HTTP timeouts,
      redirects and retries in case of connection failures:

      .. code-block:: ini

         nsx_user = ADMIN_USER_NAME
         nsx_password = NSX_USER_PASSWORD
         http_timeout = HTTP_REQUEST_TIMEOUT # (seconds) default 75 seconds
         retries = HTTP_REQUEST_RETRIES # default 2
         redirects = HTTP_REQUEST_MAX_REDIRECTS # default 2
         nsx_controllers = API_ENDPOINT_LIST # comma-separated list

      To ensure correct operations, the ``nsx_user`` user must have
      administrator credentials on the NSX-mh platform.

      A controller API endpoint consists of the IP address and port for the
      controller; if you omit the port, port 443 is used. If multiple API
      endpoints are specified, it is up to the user to ensure that all
      these endpoints belong to the same controller cluster. The OpenStack
      Networking VMware NSX-mh plug-in does not perform this check, and
      results might be unpredictable.

      When you specify multiple API endpoints, the plug-in takes care of
      load balancing requests on the various API endpoints.

   -  The UUID of the NSX-mh transport zone that should be used by default
      when a project creates a network. You can get this value from the
      Transport Zones page for the NSX-mh manager:

      Alternatively the transport zone identifier can be retrieved by query
      the NSX-mh API: ``/ws.v1/transport-zone``

      .. code-block:: ini

         default_tz_uuid = TRANSPORT_ZONE_UUID

   -  .. code-block:: ini

         default_l3_gw_service_uuid = GATEWAY_SERVICE_UUID

      .. warning::

         Ubuntu packaging currently does not update the neutron init
         script to point to the NSX-mh configuration file. Instead, you
         must manually update ``/etc/default/neutron-server`` to add this
         line:

         .. code-block:: ini

            NEUTRON_PLUGIN_CONFIG = /etc/neutron/plugins/vmware/nsx.ini

      For database configuration, see `Install Networking
      Services <https://docs.openstack.org/ocata/install-guide-ubuntu/neutron-controller-install.html>`__
      in the Installation Tutorials and Guides.

#. Restart ``neutron-server`` to apply settings:

   .. code-block:: console

      # service neutron-server restart

   .. warning::

      The neutron NSX-mh plug-in does not implement initial
      re-synchronization of Neutron resources. Therefore resources that
      might already exist in the database when Neutron is switched to the
      NSX-mh plug-in will not be created on the NSX-mh backend upon
      restart.

Example ``nsx.ini`` file:

.. code-block:: ini

   [DEFAULT]
   default_tz_uuid = d3afb164-b263-4aaa-a3e4-48e0e09bb33c
   default_l3_gw_service_uuid=5c8622cc-240a-40a1-9693-e6a5fca4e3cf
   nsx_user=admin
   nsx_password=changeme
   nsx_controllers=10.127.0.100,10.127.0.200:8888

.. note::

   To debug :file:`nsx.ini` configuration issues, run this command from the
   host that runs neutron-server:

.. code-block:: console

   # neutron-check-nsx-config PATH_TO_NSX.INI

This command tests whether ``neutron-server`` can log into all of the
NSX-mh controllers and the SQL server, and whether all UUID values
are correct.

Configure PLUMgrid plug-in
~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Edit the ``/etc/neutron/neutron.conf`` file and set this line:

   .. code-block:: ini

      core_plugin = plumgrid

#. Edit the [PLUMgridDirector] section in the
   ``/etc/neutron/plugins/plumgrid/plumgrid.ini`` file and specify the IP
   address, port, admin user name, and password of the PLUMgrid Director:

   .. code-block:: ini

      [PLUMgridDirector]
      director_server = "PLUMgrid-director-ip-address"
      director_server_port = "PLUMgrid-director-port"
      username = "PLUMgrid-director-admin-username"
      password = "PLUMgrid-director-admin-password"

   For database configuration, see `Install Networking
   Services <https://docs.openstack.org/ocata/install-guide-ubuntu/neutron-controller-install.html>`__
   in the Installation Tutorials and Guides.

#. Restart the ``neutron-server`` service to apply the settings:

   .. code-block:: console

      # service neutron-server restart
