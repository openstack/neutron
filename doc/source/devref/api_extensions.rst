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


API Extensions
==============

API extensions is the standard way of introducing new functionality
to the Neutron project, it allows plugins to
determine if they wish to support the functionality or not.

Examples
--------

The easiest way to demonstrate how an API extension is written, is
by studying an existing API extension and explaining the different layers.

.. toctree::
   :maxdepth: 1

   security_group_api

Extensions for Resources with standard attributes
-------------------------------------------------

Resources that inherit from the HasStandardAttributes DB class can
automatically have the extensions written for standard attributes
(e.g. timestamps, revision number, etc) extend their resources
by defining the 'api_collections' on their model. These are used
by extensions for standard attr resources to generate the extended
resources map.

Any new addition of a resource to the standard attributes collection
must be accompanied with a new extension to ensure that it is discoverable
via the API. If it's a completely new resource, the extension describing
that resource will suffice. If it's an existing resource that was released
in a previous cycle having the standard attributes added for the first time,
then a dummy extension needs to be added indicating that the resource
now has standard attributes. This ensures that an API caller can always
discover if an attribute will be available.

For example, if Flavors were migrated to include standard attributes, we
need a new 'flavor-standardattr' extension. Then as an API caller, I will
know that flavors will have timestamps by checking for 'flavor-standardattr'
and 'timestamps'.

Current API resources extended by standard attr extensions:

- subnets: neutron.db.models_v2.Subnet
- trunks: neutron.services.trunk.models.Trunk
- routers: neutron.db.l3_db.Router
- segments: neutron.db.segments_db.NetworkSegment
- security_group_rules: neutron.db.models.securitygroup.SecurityGroupRule
- networks: neutron.db.models_v2.Network
- policies: neutron.db.qos.models.QosPolicy
- subnetpools: neutron.db.models_v2.SubnetPool
- ports: neutron.db.models_v2.Port
- security_groups: neutron.db.models.securitygroup.SecurityGroup
- floatingips: neutron.db.l3_db.FloatingIP
