# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010-2011 ????
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
#    @author: Salvatore Orlando, Citrix Systems

import quantum.api.attachments as atts
import quantum.api.networks as nets
import quantum.api.ports as ports
import quantum.tests.unit._test_api as test_api


class APITestV10(test_api.AbstractAPITest):

    def setUp(self):
        super(APITestV10, self).setUp('quantum.api.APIRouterV10',
             {test_api.NETS: nets.ControllerV10._serialization_metadata,
              test_api.PORTS: ports.ControllerV10._serialization_metadata,
              test_api.ATTS: atts.ControllerV10._serialization_metadata})


class APITestV11(test_api.AbstractAPITest):

    def setUp(self):
        super(APITestV11, self).setUp('quantum.api.APIRouterV11',
             {test_api.NETS: nets.ControllerV11._serialization_metadata,
              test_api.PORTS: ports.ControllerV11._serialization_metadata,
              test_api.ATTS: atts.ControllerV11._serialization_metadata})
