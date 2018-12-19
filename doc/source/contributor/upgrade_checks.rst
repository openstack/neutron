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

.. _upgrade_checks:

Upgrade checks
==============

Introduction
------------

CLI tool ``neutron-status upgrade check`` contains checks which perform a
release-specific readiness check before restarting services with new code.
For more details see `neutron-status command-line client
</cli/neutron-status.html>`_ page.

3rd party plugins checks
------------------------

Neutron upgrade checks script allows to add checks by stadium and 3rd party
projects.
The ``neutron-status`` script detects which sub-projects have been installed by
enumerating the ``neutron.status.upgrade.checks`` entrypoints. For more details
see the `Entry Points section of Contributing extensions to Neutron
<contribute.html#entry-points>`_.
Checks can be run in random order and should be independent from each other.

The recommended entry point name is a repository name: For example,
'neutron-fwaas' for FWaaS and 'networking-sfc' for SFC:

.. code-block:: ini

    neutron.status.upgrade.checks =
        neutron-fwaas = neutron_fwaas.upgrade.checks:Checks

Entrypoint should be class which inherits from
``neutron.cmd.upgrade_checks.base.BaseChecks``.

An example of a checks class can be found in
``neutron.cmd.upgrade_checks.checks.CoreChecks``.
