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

.. _ci_jobs:

Neutron Jobs Running in Zuul CI
===============================

Different kinds of CI jobs are running against patches proposed for Neutron in
Gerrit. They have different purposes and complexity. Some jobs are more
lightweight (for example, unit tests or linters), while others are more
heavyweight (for example, tempest or grenade jobs).

Mainline Tempest and Grenade jobs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Neutron CI runs a number of tempest and grenade (upgrade) jobs in CI. These
jobs are required to pass to merge a patch.

Periodic and experimental jobs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Due to a significant number of jobs, not all of them are run on every patch.
Some of them are instead executed periodically or on-demand. The periodic jobs
are run on a schedule, while the experimental jobs are run on-demand by making
a ``check experimental`` comment in Gerrit under a patch.

Where to find job definitions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You may inspect the list of jobs defined for the project by either looking
under ``zuul.d/`` in the Neutron repository or by visiting the Zuul web
interface at https://zuul.opendev.org/

Some jobs are not defined in this repository, but in the
`neutron-tempest-plugin
<https://opendev.org/openstack/neutron-tempest-plugin>`_ repository.

Finally, some jobs are defined through templates. Please consult
``zuul.d/project.yaml`` for the list of templates used in the Neutron project.

Alternatively, you may also inspect the list of jobs in a recent patch in
Gerrit comments. (Note that the list executed for a particular patch may be
affected by ``irrelevant-files`` filters. You may consult these in the
``zuul.d/`` configuration files.)
