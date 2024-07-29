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

Neutron API policies and supported roles
========================================

As part of the ``Consistent and Secure Default RBAC`` community goal [#]_
Neutron implemented support for various scopes and personas in all of the API
policies which are defined in the Neutron code.

Roles supported by the default Neutron API policies
---------------------------------------------------

Roles supported by the default Neutron API policies are:

* PROJECT_READER - this role is intended to have read-only access to the
  project owned resources.
* PROJECT_MEMBER - this role inherits all of the privileges from the
  PROJECT_READER role and also has access to ``create``, ``update`` and
  ``delete`` project-owned resources.
* PROJECT_MANAGER - this role inherits all of the privileges from the
  PROJECT_MEMBER role and additionally is allowed to do more operations on the
  project-owned resources.
* ADMIN - this role is the same as it was in the "old" default policies. A user
  with granted ADMIN role is allowed to do almost every possible modification
  on all resources, even those which belong to different projects.
* SERVICE - this is a special role designed to be used for service-to-service
  communication only, for example, between Nova and Neutron. It does
  not inherit any privileges from any other roles mentioned above.

Default API policies defined in Neutron
---------------------------------------

By default, all of the existing API policies can be used with ``project``
scoped tokens only. Tokens with ``service`` scope are not supported by any of
the policies defined in the Neutron code.

Default API policies
--------------------

Default API policies defined in the Neutron code can be found in the
:ref:`Policy Reference` document.

References
----------

.. [#] https://governance.openstack.org/tc/goals/selected/consistent-and-secure-rbac.html
