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


      Convention for heading levels in Neutron devref:
      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4
      (Avoid deeper levels because they do not render well.)


Setting Up a Development Environment
====================================

This page describes how to setup a working Python development
environment that can be used in developing Neutron on Ubuntu, Fedora or
Mac OS X. These instructions assume you're already familiar with
Git and Gerrit, which is a code repository mirror and code review toolset
, however if you aren't please see `this Git tutorial`_ for an introduction
to using Git and `this guide`_ for a tutorial on using Gerrit and Git for
code contribution to OpenStack projects.

.. _this Git tutorial: http://git-scm.com/book/en/Getting-Started
.. _this guide: http://docs.openstack.org/infra/manual/developers.html#development-workflow

Following these instructions will allow you to run the Neutron unit
tests. If you want to be able to run Neutron in a full OpenStack environment,
you can use the excellent `DevStack`_ project to do so. There is a wiki page
that describes `setting up Neutron using DevStack`_.

.. _DevStack: https://opendev.org/openstack/devstack
.. _setting up Neutron using Devstack: https://wiki.openstack.org/wiki/NeutronDevstack

Getting the code
----------------

Grab the code::

    git clone https://opendev.org/openstack/neutron.git
    cd neutron

About ignore files
------------------
In the .gitignore files, add patterns to exclude files created by tools
integrated, such as test frameworks from the project's recommended workflow,
rendered documentation and package builds.

Don't add patterns to exclude files created by preferred personal like for
example editors, IDEs or operating system.
These should instead be maintained outside the repository, for example in a
~/.gitignore file added with::

    git config --global core.excludesfile '~/.gitignore'

Ignores files for all repositories that you work with.


Testing Neutron
---------------

See :ref:`testing_neutron`.
