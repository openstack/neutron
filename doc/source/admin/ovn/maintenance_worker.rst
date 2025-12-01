.. _maintenance_worker:

======================
OVN Maintenance Worker
======================

The maintenance worker is needed by the ML2/OVN mechanism driver to sync the
Neutron and OVN databases. Periodic tasks for these inconsistency checks are
implemented in ``DBInconsistenciesPeriodics``.

On initialization of the maintenance thread the ML2/OVN mechanism driver
will add periodics objects, at least ``DBInconsistenciesPeriodics``.
Plugins may need to add their own periodic tasks to the OVN maintenance
worker. If a plugin implements the ``ovn_maintenance_periodics``
method it should return a list of periodics objects. The mechanism driver
will add the returned periodics to the maintenance thread.
