..
      Copyright 2010-2011 United States Government as represented by the
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

=================
Contributor Guide
=================

This document describes Neutron for contributors of the project, and assumes
that you are already familiar with Neutron from an
:doc:`end-user perspective </admin/index>`.

Basic Information
-----------------

.. toctree::
    :maxdepth: 2

    contributing

Neutron Policies
----------------

.. toctree::
   :maxdepth: 2

   policies/index

Gerrit Rechecks
---------------

.. toctree::
   :maxdepth: 2

   gerrit-recheck

Neutron Stadium
---------------

.. toctree::
   :maxdepth: 2

   stadium/index

Developer Guide
---------------

In the Developer Guide, you will find information on Neutron's lower level
programming APIs. There are sections that cover the core pieces of Neutron,
including its database, message queue, and scheduler components. There are
also subsections that describe specific plugins inside Neutron. Finally,
the developer guide includes information about Neutron testing infrastructure.

.. toctree::
   :maxdepth: 2

   effective_neutron
   development_environment
   ovn_vagrant/index
   contribute
   neutron_api
   client_command_extensions
   alembic_migrations
   upgrade_checks
   testing/index

Neutron Internals
-----------------

.. toctree::
   :maxdepth: 2

   internals/index
   modules

OVN Driver
----------

.. toctree::
   :maxdepth: 2

   ovn/index

Dashboards
----------

There is a collection of dashboards to help developers and reviewers
located here.

.. toctree::
   :maxdepth: 2

   dashboards/index
