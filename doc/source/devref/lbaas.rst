Loadbalancer as a Service
=========================


https://wiki.openstack.org/wiki/Neutron/LBaaS/Architecture

https://wiki.openstack.org/wiki/Neutron/LBaaS/API_1.0


Plugin
------
.. automodule:: neutron.services.loadbalancer.plugin

.. autoclass:: LoadBalancerPlugin
   :members:

Database layer
--------------

.. automodule:: neutron.db.loadbalancer.loadbalancer_db

.. autoclass:: LoadBalancerPluginDb
   :members:


Driver layer
------------

.. automodule:: neutron.services.loadbalancer.drivers.abstract_driver

.. autoclass:: LoadBalancerAbstractDriver
   :members:
