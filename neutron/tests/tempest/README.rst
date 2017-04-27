WARNING
=======

Some files under this path were copied from tempest as part of the move of the
api tests, and they will be removed as required over time to minimize the
dependency on the tempest testing framework.  While it exists, only
neutron.tests.tempest.* should be importing files from this path.
neutron.tests.tempest.config uses the global cfg.CONF instance and importing it
outside of the api tests has the potential to break Neutron's use of cfg.CONF.
