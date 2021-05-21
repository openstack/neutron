Neutron Style Commandments
==========================

- Step 1: Read the OpenStack Style Commandments
  https://docs.openstack.org/hacking/latest/
- Step 2: Read on

Neutron Specific Commandments
-----------------------------

Some rules are enforced by `neutron-lib hacking factory
<https://docs.openstack.org/neutron-lib/latest/user/hacking.html>`_
while other rules are specific to Neutron repository.

Below you can find a list of checks specific to this repository.

- [N322] Detect common errors with assert_called_once_with
- [N328] Detect wrong usage with assertEqual
- [N329] Use assertCountEqual() instead of assertItemsEqual()
- [N330] Use assertEqual(*empty*, observed) instead of
         assertEqual(observed, *empty*)
- [N331] Detect wrong usage with assertTrue(isinstance()).
- [N332] Use assertEqual(expected_http_code, observed_http_code) instead of
         assertEqual(observed_http_code, expected_http_code).
- [N340] Check usage of <module>.i18n (and neutron.i18n)
- [N341] Check usage of _ from python builtins
- [N343] Production code must not import from neutron.tests.*
- [N344] Python 3: Do not use filter(lambda obj: test(obj), data). Replace it
  with [obj for obj in data if test(obj)].
- [N346] Use neutron_lib.db.api.sqla_listen rather than sqlalchemy
- [N347] Test code must not import mock library
- [N348] Test code must not import six library

.. note::
   When adding a new hacking check to this repository or ``neutron-lib``, make
   sure its number (Nxxx) doesn't clash with any other check.

.. note::
   As you may have noticed, the numbering for Neutron checks has gaps. This is
   because some checks were removed or moved to ``neutron-lib``.

Creating Unit Tests
-------------------
For every new feature, unit tests should be created that both test and
(implicitly) document the usage of said feature. If submitting a patch for a
bug that had no unit test, a new passing unit test should be added. If a
submitted bug fix does have a unit test, be sure to add a new one that fails
without the patch and passes with the patch.

All unittest classes must ultimately inherit from testtools.TestCase. In the
Neutron test suite, this should be done by inheriting from
neutron.tests.base.BaseTestCase.

All setUp and tearDown methods must upcall using the super() method.
tearDown methods should be avoided and addCleanup calls should be preferred.
Never manually create tempfiles. Always use the tempfile fixtures from
the fixture library to ensure that they are cleaned up.
