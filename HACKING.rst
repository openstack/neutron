Neutron Style Commandments
=======================

- Step 1: Read the OpenStack Style Commandments
  http://docs.openstack.org/developer/hacking/
- Step 2: Read on

Neutron Specific Commandments
--------------------------

- [N319] Validate that debug level logs are not translated
- [N320] Validate that LOG messages, except debug ones, have translations
- [N321] Validate that jsonutils module is used instead of json
- [N322] Detect common errors with assert_called_once_with
- [N323] Enforce namespace-less imports for oslo libraries

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
