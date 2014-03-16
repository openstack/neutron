Firewall as a Service
=====================

`Design Document`_

.. _Design Document: https://docs.google.com/document/d/1PJaKvsX2MzMRlLGfR0fBkrMraHYF0flvl0sqyZ704tA/edit#heading=h.aed6tiupj0qk

Plugin
------
.. automodule:: neutron.services.firewall.fwaas_plugin

.. autoclass:: FirewallPlugin
   :members:

Database layer
--------------

.. automodule:: neutron.db.firewall.firewall_db

.. autoclass:: Firewall_db_mixin
   :members:


Driver layer
------------

.. automodule:: neutron.services.firewall.drivers.fwaas_base

.. autoclass:: FwaasDriverBase
   :members:
