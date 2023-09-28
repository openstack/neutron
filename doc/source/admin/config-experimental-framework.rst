.. _config-experimental-framework:

===============================
Experimental Features Framework
===============================

Some Neutron features are not supported because the community doesn't have
the resources and/or technical expertise to maintain them anymore. As they
arise, the Neutron team designates these features as experimental. Deployers
can continue using these features at their own risk, by explicitly enabling
them in the ``experimental`` section of ``neutron.conf``.

.. note::
   Of course, the Neutron core team would love to return experimetal features
   to the supported status, if interested parties step up to maintain them. If
   you are interested in maintaining any of the experimental features listed
   below, please contact the PTL shown in the
   `Neutron project page
   <https://governance.openstack.org/tc/reference/projects/neutron.html>`_.

The following table shows the Neutron features currently designated as
experimetal:

.. table:: **Neutron Experimental features**

    =========================  ===================================
     Feature                    Option in neutron.conf to enable
    =========================  ===================================
     ML2 Linuxbridge driver     linuxbridge
    =========================  ===================================

This is an example of how to enable the use of an experimental feature:

.. code-block:: none

   [experimental]
   linuxbridge = true
