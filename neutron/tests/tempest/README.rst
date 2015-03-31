WARNING
=======

The files under this path are maintained automatically by the script
tools/copy_api_tests_from_tempest.sh.  It's contents should not be
manually modified until further notice.

Note that neutron.tests.tempest.config uses the global cfg.CONF
instance for now and importing it outside of the api tests has the
potential to break Neutron's use of cfg.CONF.
