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


ML2 Extension Manager
=====================

The extension manager for ML2 was introduced in Juno (more details
can be found in the approved `spec <http://specs.openstack.org/openstack/neutron-specs/specs/juno/neutron-ml2-mechanismdriver-extensions.html>`_). The features allows for extending ML2 resources without
actually having to introduce cross cutting concerns to ML2. The
mechanism has been applied for a number of use cases, and extensions
that currently use this frameworks are available under `ml2/extensions <https://github.com/openstack/neutron/tree/master/neutron/plugins/ml2/extensions>`_.
