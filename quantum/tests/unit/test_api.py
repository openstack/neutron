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

from quantum.common.test_lib import test_config


class APITestV10(test_api.AbstractAPITest):

    def assert_network(self, **kwargs):
        self.assertEqual({'id': kwargs['id'],
                          'name': kwargs['name']},
                          kwargs['network_data'])

    def assert_network_details(self, **kwargs):
        self.assertEqual({'id': kwargs['id'],
                          'name': kwargs['name'],
                          'ports': [{'id': kwargs['port_id'],
                                     'state': 'ACTIVE'}]},
                         kwargs['network_data'])

    def assert_port(self, **kwargs):
        self.assertEqual({'id': kwargs['id'],
                          'state': kwargs['state']},
                         kwargs['port_data'])

    def assert_port_attachment(self, **kwargs):
        self.assertEqual({'id': kwargs['id'], 'state': kwargs['state'],
                          'attachment': {'id': kwargs['interface_id']}},
                         kwargs['port_data'])

    def setUp(self):
        super(APITestV10, self).setUp('quantum.api.APIRouterV10',
             {test_api.NETS: nets.ControllerV10._serialization_metadata,
              test_api.PORTS: ports.ControllerV10._serialization_metadata,
              test_api.ATTS: atts.ControllerV10._serialization_metadata})


class APITestV11(test_api.AbstractAPITest):

    def assert_network(self, **kwargs):
        self.assertEqual({'id': kwargs['id'],
                          'name': kwargs['name'],
                          'op-status': self.net_op_status},
                          kwargs['network_data'])

    def assert_network_details(self, **kwargs):
        self.assertEqual({'id': kwargs['id'],
                          'name': kwargs['name'],
                          'op-status': self.net_op_status,
                          'ports': [{'id': kwargs['port_id'],
                                     'state': 'ACTIVE',
                                     'op-status': self.port_op_status}]},
                         kwargs['network_data'])

    def assert_port(self, **kwargs):
        self.assertEqual({'id': kwargs['id'],
                          'state': kwargs['state'],
                          'op-status': self.port_op_status},
                         kwargs['port_data'])

    def assert_port_attachment(self, **kwargs):
        self.assertEqual({'id': kwargs['id'], 'state': kwargs['state'],
                          'op-status': self.port_op_status,
                          'attachment': {'id': kwargs['interface_id']}},
                         kwargs['port_data'])

    def setUp(self):
        self.net_op_status = test_config.get('default_net_op_status',
                                             'UNKNOWN')
        self.port_op_status = test_config.get('default_port_op_status',
                                              'UNKNOWN')
        super(APITestV11, self).setUp('quantum.api.APIRouterV11',
             {test_api.NETS: nets.ControllerV11._serialization_metadata,
              test_api.PORTS: ports.ControllerV11._serialization_metadata,
              test_api.ATTS: atts.ControllerV11._serialization_metadata})
