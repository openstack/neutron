..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.


      Convention for heading levels in Neutron devref:
      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4
      (Avoid deeper levels because they do not render well.)


Testing Neutron
===============

Overview
--------

Neutron relies on unit, functional, fullstack and API tests to ensure its
quality, as described below. In addition to in-tree testing, `Tempest`_ is
responsible for validating Neutron's integration with other OpenStack
components via scenario tests, and `Rally`_ is responsible for benchmarking.

.. _Tempest: http://docs.openstack.org/developer/tempest/
.. _Rally: http://rally.readthedocs.org/en/latest/

Unit Tests
~~~~~~~~~~

Unit tests (neutron/test/unit/) are meant to cover as much code as
possible. They are designed to test the various pieces of the Neutron tree to
make sure any new changes don't break existing functionality. Unit tests have
no requirements nor make changes to the system they are running on. They use
an in-memory sqlite database to test DB interaction.

Functional Tests
~~~~~~~~~~~~~~~~

Functional tests (neutron/tests/functional/) are intended to
validate actual system interaction. Mocks should be used sparingly,
if at all. Care should be taken to ensure that existing system
resources are not modified and that resources created in tests are
properly cleaned up both on test success and failure.

Fullstack Tests
~~~~~~~~~~~~~~~

Fullstack tests (neutron/tests/fullstack/) target Neutron as a whole.
The test infrastructure itself manages the Neutron server and its agents.
Fullstack tests are a form of integration testing and fill a void between
unit/functional tests and Tempest. More information may be found
`here. <fullstack_testing.html>`_

API Tests
~~~~~~~~~

API tests (neutron/tests/api/) are intended to ensure the function
and stability of the Neutron API. As much as possible, changes to
this path should not be made at the same time as changes to the code
to limit the potential for introducing backwards-incompatible changes,
although the same patch that introduces a new API should include an API
test.

Since API tests target a deployed Neutron daemon that is not test-managed,
they should not depend on controlling the runtime configuration
of the target daemon. API tests should be black-box - no assumptions should
be made about implementation. Only the contract defined by Neutron's REST API
should be validated, and all interaction with the daemon should be via
a REST client.

neutron/tests/api was copied from the Tempest project. The Tempest networking
API directory was frozen and any new tests belong to the Neutron repository.

Development Process
-------------------

It is expected that any new changes that are proposed for merge
come with tests for that feature or code area. Ideally any bugs
fixes that are submitted also have tests to prove that they stay
fixed! In addition, before proposing for merge, all of the
current tests should be passing.

Structure of the Unit Test Tree
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The structure of the unit test tree should match the structure of the
code tree, e.g. ::

 - target module: neutron.agent.utils

 - test module: neutron.tests.unit.agent.test_utils

Unit test modules should have the same path under neutron/tests/unit/
as the module they target has under neutron/, and their name should be
the name of the target module prefixed by `test_`. This requirement
is intended to make it easier for developers to find the unit tests
for a given module.

Similarly, when a test module targets a package, that module's name
should be the name of the package prefixed by `test_` with the same
path as when a test targets a module, e.g. ::

 - target package: neutron.ipam

 - test module: neutron.tests.unit.test_ipam

The following command can be used to validate whether the unit test
tree is structured according to the above requirements: ::

    ./tools/check_unit_test_structure.sh

Where appropriate, exceptions can be added to the above script. If
code is not part of the Neutron namespace, for example, it's probably
reasonable to exclude their unit tests from the check.

Running Tests
-------------

There are three mechanisms for running tests: run_tests.sh, tox,
and nose2. Before submitting a patch for review you should always
ensure all test pass; a tox run is triggered by the jenkins gate
executed on gerrit for each patch pushed for review.

With these mechanisms you can either run the tests in the standard
environment or create a virtual environment to run them in.

By default after running all of the tests, any pep8 errors
found in the tree will be reported.


With `run_tests.sh`
~~~~~~~~~~~~~~~~~~~

You can use the `run_tests.sh` script in the root source directory to execute
tests in a virtualenv::

    ./run_tests -V


With `nose2`
~~~~~~~~~~~~

You can use `nose2`_ to run individual tests, as well as use for debugging
portions of your code::

    source .venv/bin/activate
    pip install nose2
    nose2

There are disadvantages to running nose2 - the tests are run sequentially, so
race condition bugs will not be triggered, and the full test suite will
take significantly longer than tox & testr. The upside is that testr has
some rough edges when it comes to diagnosing errors and failures, and there is
no easy way to set a breakpoint in the Neutron code, and enter an
interactive debugging session while using testr.

Note that nose2's predecessor, `nose`_, does not understand
`load_tests protocol`_ introduced in Python 2.7. This limitation will result in
errors being reported for modules that depend on load_tests
(usually due to use of `testscenarios`_). nose, therefore, is not supported,
while nose2 is.

.. _nose2: http://nose2.readthedocs.org/en/latest/index.html
.. _nose: https://nose.readthedocs.org/en/latest/index.html
.. _load_tests protocol: https://docs.python.org/2/library/unittest.html#load-tests-protocol
.. _testscenarios: https://pypi.python.org/pypi/testscenarios/

With `tox`
~~~~~~~~~~

Neutron, like other OpenStack projects, uses `tox`_ for managing the virtual
environments for running test cases. It uses `Testr`_ for managing the running
of the test cases.

Tox handles the creation of a series of `virtualenvs`_ that target specific
versions of Python.

Testr handles the parallel execution of series of test cases as well as
the tracking of long-running tests and other things.

For more information on the standard Tox-based test infrastructure used by
OpenStack and how to do some common test/debugging procedures with Testr,
see this wiki page:

  https://wiki.openstack.org/wiki/Testr

.. _Testr: https://wiki.openstack.org/wiki/Testr
.. _tox: http://tox.readthedocs.org/en/latest/
.. _virtualenvs: https://pypi.python.org/pypi/virtualenv

PEP8 and Unit Tests
+++++++++++++++++++

Running pep8 and unit tests is as easy as executing this in the root
directory of the Neutron source code::

    tox

To run only pep8::

    tox -e pep8

Since pep8 includes running pylint on all files, it can take quite some time to run.
To restrict the pylint check to only the files altered by the latest patch changes::

    tox -e pep8 HEAD~1

To run only the unit tests::

    tox -e py27

Functional Tests
++++++++++++++++

To run functional tests that do not require sudo privileges or
specific-system dependencies::

    tox -e functional

To run all the functional tests, including those requiring sudo
privileges and system-specific dependencies, the procedure defined by
tools/configure_for_func_testing.sh should be followed.

IMPORTANT: configure_for_func_testing.sh relies on DevStack to perform
extensive modification to the underlying host. Execution of the
script requires sudo privileges and it is recommended that the
following commands be invoked only on a clean and disposeable VM.
A VM that has had DevStack previously installed on it is also fine. ::

    git clone https://git.openstack.org/openstack-dev/devstack ../devstack
    ./tools/configure_for_func_testing.sh ../devstack -i
    tox -e dsvm-functional

The '-i' option is optional and instructs the script to use DevStack
to install and configure all of Neutron's package dependencies. It is
not necessary to provide this option if DevStack has already been used
to deploy Neutron to the target host.

Fullstack Tests
+++++++++++++++

To run all the full-stack tests, you may use: ::

    tox -e dsvm-fullstack

Since full-stack tests often require the same resources and
dependencies as the functional tests, using the configuration script
tools/configure_for_func_testing.sh is advised (As described above).
When running full-stack tests on a clean VM for the first time, we
advise to run ./stack.sh successfully to make sure all Neutron's
dependencies are met. Full-stack based Neutron daemons produce logs to a
sub-folder in /tmp/fullstack-logs (for example, a test named
"test_example" will produce logs to /tmp/fullstack-logs/test_example/),
so that will be a good place to look if your test is failing.

API Tests
+++++++++

To run the api tests, deploy Tempest and Neutron with DevStack and
then run the following command: ::

    tox -e api

If tempest.conf cannot be found at the default location used by
DevStack (/opt/stack/tempest/etc) it may be necessary to set
TEMPEST_CONFIG_DIR before invoking tox: ::

    export TEMPEST_CONFIG_DIR=[path to dir containing tempest.conf]
    tox -e api


Running Individual Tests
~~~~~~~~~~~~~~~~~~~~~~~~

For running individual test modules, cases or tests, you just need to pass
the dot-separated path you want as an argument to it.

For example, the following would run only a single test or test case::

      $ ./run_tests.sh neutron.tests.unit.test_manager
      $ ./run_tests.sh neutron.tests.unit.test_manager.NeutronManagerTestCase
      $ ./run_tests.sh neutron.tests.unit.test_manager.NeutronManagerTestCase.test_service_plugin_is_loaded

or::

      $ tox -e py27 neutron.tests.unit.test_manager
      $ tox -e py27 neutron.tests.unit.test_manager.NeutronManagerTestCase
      $ tox -e py27 neutron.tests.unit.test_manager.NeutronManagerTestCase.test_service_plugin_is_loaded

Coverage
--------

Neutron has a fast growing code base and there are plenty of areas that
need better coverage.

To get a grasp of the areas where tests are needed, you can check
current unit tests coverage by running::

    $ ./run_tests.sh -c

Since the coverage command can only show unit test coverage, a coverage
document is maintained that shows test coverage per area of code in:
doc/source/devref/testing_coverage.rst.

Debugging
---------

By default, calls to pdb.set_trace() will be ignored when tests
are run. For pdb statements to work, invoke run_tests as follows::

    $ ./run_tests.sh -d [test module path]

It's possible to debug tests in a tox environment::

    $ tox -e venv -- python -m testtools.run [test module path]

Tox-created virtual environments (venv's) can also be activated
after a tox run and reused for debugging::

    $ tox -e venv
    $ . .tox/venv/bin/activate
    $ python -m testtools.run [test module path]

Tox packages and installs the Neutron source tree in a given venv
on every invocation, but if modifications need to be made between
invocation (e.g. adding more pdb statements), it is recommended
that the source tree be installed in the venv in editable mode::

    # run this only after activating the venv
    $ pip install --editable .

Editable mode ensures that changes made to the source tree are
automatically reflected in the venv, and that such changes are not
overwritten during the next tox run.

Post-mortem Debugging
~~~~~~~~~~~~~~~~~~~~~

Setting OS_POST_MORTEM_DEBUGGER in the shell environment will ensure
that the debugger .post_mortem() method will be invoked on test failure::

    $ OS_POST_MORTEM_DEBUGGER=pdb ./run_tests.sh -d [test module path]

Supported debuggers are pdb, and pudb. Pudb is full-screen, console-based
visual debugger for Python which let you inspect variables, the stack,
and breakpoints in a very visual way, keeping a high degree of compatibility
with pdb::

    $ ./.venv/bin/pip install pudb

    $ OS_POST_MORTEM_DEBUGGER=pudb ./run_tests.sh -d [test module path]

References
~~~~~~~~~~

.. [#pudb] PUDB debugger:
   https://pypi.python.org/pypi/pudb
