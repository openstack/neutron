Install and configure compute node
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The compute node handles connectivity and security groups for instances.


Install the components
----------------------

.. code-block:: console

   # apt install neutron-openvswitch-agent

.. end




Configure the common component
------------------------------

The Networking common component configuration includes the
authentication mechanism, message queue, and plug-in.

.. include:: shared/note_configuration_vary_by_distribution.rst

* Edit the ``/etc/neutron/neutron.conf`` file and complete the following
  actions:

  * In the ``[database]`` section, comment out any ``connection`` options
    because compute nodes do not directly access the database.

  * In the ``[DEFAULT]`` section, configure ``RabbitMQ``
    message queue access:

    .. path /etc/neutron/neutron.conf
    .. code-block:: ini

       [DEFAULT]
       # ...
       transport_url = rabbit://openstack:RABBIT_PASS@controller

    .. end

    Replace ``RABBIT_PASS`` with the password you chose for the ``openstack``
    account in RabbitMQ.

  * In the ``[DEFAULT]`` and ``[keystone_authtoken]`` sections, configure
    Identity service access:

    .. path /etc/neutron/neutron.conf
    .. code-block:: ini

       [DEFAULT]
       # ...
       auth_strategy = keystone

       [keystone_authtoken]
       # ...
       www_authenticate_uri = http://controller:5000
       auth_url = http://controller:5000
       memcached_servers = controller:11211
       auth_type = password
       project_domain_name = Default
       user_domain_name = Default
       project_name = service
       username = neutron
       password = NEUTRON_PASS

    .. end

    Replace ``NEUTRON_PASS`` with the password you chose for the ``neutron``
    user in the Identity service.

    .. note::

       Comment out or remove any other options in the
       ``[keystone_authtoken]`` section.


* In the ``[oslo_concurrency]`` section, configure the lock path:

  .. path /etc/neutron/neutron.conf
  .. code-block:: ini

     [oslo_concurrency]
     # ...
     lock_path = /var/lib/neutron/tmp

  .. end



Configure networking options
----------------------------

Choose the same networking option that you chose for the controller node to
configure services specific to it. Afterwards, return here and proceed to
:ref:`neutron-compute-compute-ubuntu`.

.. toctree::
   :maxdepth: 1

   compute-install-option1-ubuntu.rst
   compute-install-option2-ubuntu.rst

.. _neutron-compute-compute-ubuntu:

Configure the Compute service to use the Networking service
-----------------------------------------------------------

* Edit the ``/etc/nova/nova.conf`` file and complete the following actions:

  * In the ``[neutron]`` section, configure access parameters:

    .. path /etc/nova/nova.conf
    .. code-block:: ini

       [neutron]
       # ...
       auth_url = http://controller:5000
       auth_type = password
       project_domain_name = Default
       user_domain_name = Default
       region_name = RegionOne
       project_name = service
       username = neutron
       password = NEUTRON_PASS

    .. end

    Replace ``NEUTRON_PASS`` with the password you chose for the ``neutron``
    user in the Identity service.

    See the :nova-doc:`compute service configuration guide <configuration/config.html#neutron>`
    for the full set of options including overriding the service catalog
    endpoint URL if necessary.

Finalize installation
---------------------




#. Restart the Compute service:

   .. code-block:: console

      # service nova-compute restart

   .. end

#. Restart the Linux bridge agent:

   .. code-block:: console

      # service neutron-openvswitch-agent restart

   .. end

