WARNING
=======

The files under this path were copied from tempest as part of the move
of the api tests, and they will be removed as the required
functionality is transitioned from tempest to tempest-lib.  While it
exists, only neutron.tests.api and neutron.tests.retargetable should
be importing files from this path.  neutron.tests.tempest.config uses
the global cfg.CONF instance and importing it outside of the api tests
has the potential to break Neutron's use of cfg.CONF.
