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
- [N332] Use assertEqual(expected_http_code, observed_http_code) instead of
         assertEqual(observed_http_code, expected_http_code).
- [N340] Check usage of <module>.i18n (and neutron.i18n)
- [N341] Check usage of _ from python builtins
- [N343] Production code must not import from neutron.tests.*
- [N344] Python 3: Do not use filter(lambda obj: test(obj), data). Replace it
  with [obj for obj in data if test(obj)].
- [N346] Use neutron_lib.db.api.sqla_listen rather than sqlalchemy
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

Running Tests
-------------
The testing system is based on a combination of tox and stestr. The canonical
approach to running tests is to simply run the command ``tox``. This will
create virtual environments, populate them with dependencies and run all of
the tests that the OpenStack CI systems run. Behind the scenes, tox is running
``stestr run``, but is set up such that you can supply any additional
stestr arguments that are needed to tox. For example, you can run:
``tox -- --analyze-isolation`` to cause tox to tell stestr to add
--analyze-isolation to its argument list.

To run only pep8::

    tox -e pep8

Since pep8 includes running pylint on all files, it can take quite some time
to run. To restrict the pylint check to only the files altered by the latest
patch changes::

    tox -e pep8 -- HEAD~1

To run only the unit tests::

    tox -e py3

To run a single or restricted set of tests, pass a regex that matches
the class name containing the tests as an extra ``tox`` argument;
e.g. ``tox -e py3 neutron.tests.unit.test_manager`` will test the manager
module; ``tox -e py3 neutron.tests.unit.test_manager.NeutronManagerTestCase``
would run just that test case, and
``tox -e py3 neutron.tests.unit.test_manager.NeutronManagerTestCase.test_service_plugin_is_loaded``
would run a single test.

It is also possible to run the tests inside of a virtual environment
you have created, or it is possible that you have all of the dependencies
installed locally already. In this case, you can interact with the stestr
command directly. Running ``stestr run`` will run the entire test suite.
``stestr run --concurrency=1`` will run tests serially (by default, stestr runs
tests in parallel). More information about stestr can be found at:
http://stestr.readthedocs.io/

To run functional tests that do not require sudo privileges::

    tox -e functional

To run all the functional tests, including those requiring sudo privileges
and system-specific dependencies, the environment must first be configured
using ``tools/configure_for_func_testing.sh``. This script relies on DevStack
to perform extensive modification to the underlying host, so it is
recommended to run it only on a clean and disposable VM::

    git clone https://opendev.org/openstack/devstack ../devstack
    ./tools/configure_for_func_testing.sh ../devstack -i
    tox -e dsvm-functional

The ``-i`` option instructs the script to use DevStack to install and
configure all of Neutron's package dependencies. It is not necessary if
DevStack has already been used to deploy Neutron to the target host.

For more details, see the ``Functional Tests`` section in ``TESTING.rst``.

To run unit tests with coverage reporting::

    tox -e cover

The coverage report will fail if the overall coverage drops below a minimum
threshold. Inspect the ``[testenv:cover]`` section in ``tox.ini`` and look for
the ``--fail-under`` parameter to see the current value.

To generate sample configuration files::

    tox -e genconfig

By default tests log at ``INFO`` level. It is possible to make them
log at ``DEBUG`` level by exporting the ``OS_DEBUG`` environment
variable to ``True``.

For more information on testing, including fullstack and tempest tests, see
``TESTING.rst``.
