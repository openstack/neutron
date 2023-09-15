.. _config-ipam:

==================
IPAM Configuration
==================

Starting with the Liberty release, OpenStack Networking includes a pluggable
interface for the IP Address Management (IPAM) function. This interface creates
a driver framework for the allocation and de-allocation of subnets and IP
addresses, enabling the integration of alternate IPAM implementations or
third-party IP Address Management systems.

The basics
~~~~~~~~~~

In Liberty and Mitaka, the IPAM implementation within OpenStack Networking
provided a pluggable and non-pluggable flavor. As of Newton, the non-pluggable
flavor is no longer available. Instead, it is completely replaced with a
reference driver implementation of the pluggable framework. All data will
be automatically migrated during the upgrade process, unless you have
previously configured a pluggable IPAM driver. In that case, no migration
is necessary.

To configure a driver other than the reference driver, specify it
in the ``neutron.conf`` file. Do this after the migration is
complete. There is no need to specify any value if you wish to use the
reference driver.

.. code-block:: ini

   ipam_driver = ipam-driver-name

There is no need to specify any value if you wish to use the reference
driver, though specifying ``internal`` will explicitly choose the reference
driver. The documentation for any alternate drivers will include the value to
use when specifying that driver.

Known limitations
~~~~~~~~~~~~~~~~~

* The driver interface is designed to allow separate drivers for each
  subnet pool. However, the current implementation allows only a single
  IPAM driver system-wide.
* Third-party drivers must provide their own migration mechanisms to convert
  existing OpenStack installations to their IPAM.
