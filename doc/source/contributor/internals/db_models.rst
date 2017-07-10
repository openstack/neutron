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


Relocation of Database Models
=============================

This document is intended to track and notify developers that db models in
neutron will be centralized and moved to a new tree under neutron/db/models.
This was discussed in [1]. The reason for relocating db models is to solve
the cyclic import issue while implementing oslo versioned objects for
resources in neutron.

The reason behind this relocation is Mixin class and db models for some
resources in neutron are in same module. In Mixin classes, there are methods
which provide functionality of fetching, adding, updating and deleting data
via queries. These queries will be replaced with use of versioned objects and
definition of versioned object will be using db models. So object files will
be importing models and Mixin need to import those objects which will end up
in cyclic import.

Structure of Model Definitions
------------------------------

We have decided to move all models definitions to neutron/db/models/
with no further nesting after that point. The deprecation method to move
models has already been added to avoid breakage of third party plugins using
those models. All relocated models need to use deprecate method that
will generate a warning and return new class for use of old class. Some
examples of relocated models [2] and [3]. In future if you define new models
please make sure they are separated from mixins and are under tree
neutron/db/models/ .

References
~~~~~~~~~~

[1]. https://www.mail-archive.com/openstack-dev@lists.openstack.org/msg88910.html
[2]. https://review.openstack.org/#/c/348562/
[3]. https://review.openstack.org/#/c/348757/
