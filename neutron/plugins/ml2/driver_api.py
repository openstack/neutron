# Copyright (c) 2013 OpenStack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from neutron_lib.plugins.ml2 import api


# TODO(boden): remove once consumers are moved over to lib's version
MechanismDriver = api.MechanismDriver
ID = api.ID
NETWORK_TYPE = api.NETWORK_TYPE
PHYSICAL_NETWORK = api.PHYSICAL_NETWORK
SEGMENTATION_ID = api.SEGMENTATION_ID
MTU = api.MTU
NETWORK_ID = api.NETWORK_ID
BOUND_DRIVER = api.BOUND_DRIVER
BOUND_SEGMENT = api.BOUND_SEGMENT
TypeDriver = api.TypeDriver
ML2TypeDriver = api.ML2TypeDriver
NetworkContext = api.NetworkContext
SubnetContext = api.SubnetContext
PortContext = api.PortContext
ExtensionDriver = api.ExtensionDriver
