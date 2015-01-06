Testing Neutron
=============================================================

Overview
--------

The unit tests (neutron/test/unit/) are meant to cover as much code as
possible and should be executed without the service running. They are
designed to test the various pieces of the neutron tree to make sure
any new changes don't break existing functionality.

The functional tests (neutron/tests/functional/) are intended to
validate actual system interaction.  Mocks should be used sparingly,
if at all.  Care should be taken to ensure that existing system
resources are not modified and that resources created in tests are
properly cleaned up.

Development process
-------------------

It is expected that any new changes that are proposed for merge
come with tests for that feature or code area. Ideally any bugs
fixes that are submitted also have tests to prove that they stay
fixed!  In addition, before proposing for merge, all of the
current tests should be passing.

Virtual environments
~~~~~~~~~~~~~~~~~~~~

Testing OpenStack projects, including Neutron, is made easier with `DevStack <https://git.openstack.org/cgit/openstack-dev/devstack>`_.

Create a machine (such as a VM or Vagrant box) running a distribution supported
by DevStack and install DevStack there. For example, there is a Vagrant script
for DevStack at https://github.com/bcwaldon/vagrant_devstack.

 .. note::

    If you prefer not to use DevStack, you can still check out source code on your local
    machine and develop from there.


Running unit tests
------------------

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
~~~~~~~~~~~

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

It is also possible to use nose2's predecessor, `nose`_, to run the tests::

    source .venv/bin/activate
    pip install nose
    nosetests

nose has one additional disadvantage over nose2 - it does not
understand the `load_tests protocol`_ introduced in Python 2.7.  This
limitation will result in errors being reported for modules that
depend on load_tests (usually due to use of `testscenarios`_).

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
versions of Python (2.6, 2.7, 3.3, etc).

Testr handles the parallel execution of series of test cases as well as
the tracking of long-running tests and other things.

Running unit tests is as easy as executing this in the root directory of the
Neutron source code::

    tox

To run functional tests that do not require sudo privileges or
specific-system dependencies::

    tox -e functional

To run all the functional tests in an environment that has been configured
by devstack to support sudo and system-specific dependencies::

    tox -e dsvm-functional

For more information on the standard Tox-based test infrastructure used by
OpenStack and how to do some common test/debugging procedures with Testr,
see this wiki page:

  https://wiki.openstack.org/wiki/Testr

.. _Testr: https://wiki.openstack.org/wiki/Testr
.. _tox: http://tox.readthedocs.org/en/latest/
.. _virtualenvs: https://pypi.python.org/pypi/virtualenv


Running individual tests
~~~~~~~~~~~~~~~~~~~~~~~~

For running individual test modules or cases, you just need to pass
the dot-separated path to the module you want as an argument to it.

For executing a specific test case, specify the name of the test case
class separating it from the module path with a colon.

For example, the following would run only the JSONV2TestCase tests from
neutron/tests/unit/test_api_v2.py::

      $ ./run_tests.sh neutron.tests.unit.test_api_v2.JSONV2TestCase

or::

      $ tox -e py27 neutron.tests.unit.test_api_v2.JSONV2TestCase

Adding more tests
~~~~~~~~~~~~~~~~~

Neutron has a fast growing code base and there is plenty of areas that
need to be covered by unit and functional tests.

To get a grasp of the areas where tests are needed, you can check
current coverage by running::

    $ ./run_tests.sh -c

Debugging
---------

By default, calls to pdb.set_trace() will be ignored when tests
are run.  For pdb statements to work, invoke run_tests as follows::

    $ ./run_tests.sh -d [test module path]

It's possible to debug tests in a tox environment::

    $ tox -e venv -- python -m testtools.run [test module path]

Tox-created virtual environments (venv's) can also be activated
after a tox run and reused for debugging::

    $ tox -e venv
    $ . .tox/venv/bin/activate
    $ python -m testtools.run [test module path]

Tox packages and installs the neutron source tree in a given venv
on every invocation, but if modifications need to be made between
invocation (e.g. adding more pdb statements), it is recommended
that the source tree be installed in the venv in editable mode::

    # run this only after activating the venv
    $ pip install --editable .

Editable mode ensures that changes made to the source tree are
automatically reflected in the venv, and that such changes are not
overwritten during the next tox run.

Post-mortem debugging
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
==========

.. [#pudb] PUDB debugger:
   https://pypi.python.org/pypi/pudb
