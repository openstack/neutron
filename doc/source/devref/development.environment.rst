..
      Copyright 2010-2013 United States Government as represented by the
      Administrator of the National Aeronautics and Space Administration.
      All Rights Reserved.

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

Setting Up a Development Environment
====================================

This page describes how to setup a working Python development
environment that can be used in developing Neutron on Ubuntu, Fedora or
Mac OS X. These instructions assume you're already familiar with
Git and Gerrit, which is a code repository mirror and code review toolset
, however if you aren't please see `this Git tutorial_` for an introduction
to using Git and `this wiki page_` for a tutorial on using Gerrit and Git for
code contribution to Openstack projects.

.. _this Git tutorial: http://git-scm.com/book/en/Getting-Started
.. _this wiki page: https://wiki.openstack.org/wiki/Gerrit_Workflow

Following these instructions will allow you to run the Neutron unit
tests. If you want to be able to run Neutron in a full OpenStack environment,
you can use the excellent `DevStack_` project to do so. There is a wiki page
that describes `setting up Neutron using DevStack_`.

.. _DevStack: https://github.com/openstack-dev/devstack
.. _setting up Neutron using Devstack: https://wiki.openstack.org/wiki/NeutronDevstack

Virtual environments
--------------------

Testing OpenStack projects, including Neutron, is made easier with `DevStack_`.

Create a machine (such as a VM or Vagrant box) running a distribution supported
by DevStack and install DevStack there. For example, there is a Vagrant script
for DevStack at https://github.com/jogo/DevstackUp.

 .. note::

    If you prefer not to use DevStack, you can still check out source code on your local
    machine and develop from there.

Getting the code
----------------

Grab the code from GitHub::

    git clone git://git.openstack.org/openstack/neutron.git
    cd neutron


Running unit tests
------------------

With `run_tests.sh`
~~~~~~~~~~~~~~~~~~~

You can use the `run_tests.sh` script in the root source directory to execute
tests in a virtualenv:

    ./run_tests -V

With `tox`
~~~~~~~~~~

Neutron, like other OpenStack projects, uses `tox_` for managing the virtual
environments for running test cases. It uses `Testr_` for managing the running
of the test cases.

Tox handles the creation of a series of `virtualenvs_` that target specific
versions of Python (2.6, 2.7, 3.3, etc).

Testr handles the parallel execution of series of test cases as well as
the tracking of long-running tests and other things.

Running unit tests is as easy as executing this in the root directory of the
Neutron source code::

    tox

For more information on the standard Tox-based test infrastructure used by
OpenStack and how to do some common test/debugging procedures with Testr,
see this wiki page:

  https://wiki.openstack.org/wiki/Testr

.. _Testr: https://wiki.openstack.org/wiki/Testr
.. _tox: http://tox.readthedocs.org/en/latest/
.. _virtualenvs: https://pypi.python.org/pypi/virtualenv


Using a remote debugger
-----------------------

.. todo:: Beef up and add examples to content at
  https://wiki.openstack.org/wiki/NeutronDevelopment#How_to_debug_Neutron_.28and_other_OpenStack_projects_probably_.29
