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


import logging
from webob import exc

import quantum.api.attachments as atts
import quantum.api.networks as nets
import quantum.api.ports as ports
import quantum.tests.unit._test_api as test_api
import quantum.tests.unit.testlib_api as testlib

from quantum.common.test_lib import test_config


LOG = logging.getLogger('quantum.tests.test_api')


class APITestV10(test_api.BaseAPIOperationsTest):

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
        self._network_not_found_code = 420
        self._network_in_use_code = 421
        self._port_not_found_code = 430
        self._port_state_invalid_code = 431
        self._port_in_use_code = 432
        self._already_attached_code = 440


class APITestV11(test_api.BaseAPIOperationsTest):

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
        self._network_not_found_code = exc.HTTPNotFound.code
        self._network_in_use_code = exc.HTTPConflict.code
        self._port_not_found_code = exc.HTTPNotFound.code
        self._port_state_invalid_code = exc.HTTPBadRequest.code
        self._port_in_use_code = exc.HTTPConflict.code
        self._already_attached_code = exc.HTTPConflict.code


class APIFiltersTest(test_api.AbstractAPITest):
    """ Test case for API filters.
        Uses controller for API v1.1
    """

    def _do_filtered_network_list_request(self, flt):
        list_network_req = testlib.network_list_request(self.tenant_id,
                                                        self.fmt,
                                                        query_string=flt)
        list_network_res = list_network_req.get_response(self.api)
        self.assertEqual(list_network_res.status_int, 200)
        network_data = self._net_deserializers[self.content_type].\
                            deserialize(list_network_res.body)['body']
        return network_data

    def _do_filtered_port_list_request(self, flt, network_id):
        list_port_req = testlib.port_list_request(self.tenant_id,
                                                  network_id,
                                                  self.fmt,
                                                  query_string=flt)
        list_port_res = list_port_req.get_response(self.api)
        self.assertEqual(list_port_res.status_int, 200)
        port_data = self._port_deserializers[self.content_type].\
                            deserialize(list_port_res.body)['body']
        return port_data

    def setUp(self):
        super(APIFiltersTest, self).setUp('quantum.api.APIRouterV11',
             {test_api.NETS: nets.ControllerV11._serialization_metadata,
              test_api.PORTS: ports.ControllerV11._serialization_metadata,
              test_api.ATTS: atts.ControllerV11._serialization_metadata})
        self.net_op_status = test_config.get('default_net_op_status',
                                             'UNKNOWN')
        self.port_op_status = test_config.get('default_port_op_status',
                                              'UNKNOWN')
        self.fmt = "xml"
        self.content_type = "application/%s" % self.fmt
        # create data for validating filters
        # Create network "test-1"
        self.net1_id = self._create_network(self.fmt, name="test-1")
        # Add 2 ports, 1 ACTIVE, 1 DOWN
        self.port11_id = self._create_port(self.net1_id, "ACTIVE", self.fmt)
        self.port12_id = self._create_port(self.net1_id, "DOWN", self.fmt)
        # Put attachment "test-1-att" in active port
        self._set_attachment(self.net1_id,
                             self.port11_id,
                             "test-1-att",
                             self.fmt)
        # Create network "test-2"
        # Add 2 ports, 2 ACTIVE, 0 DOWN
        self.net2_id = self._create_network(self.fmt, name="test-2")
        self.port21_id = self._create_port(self.net2_id, "ACTIVE", self.fmt)
        self.port22_id = self._create_port(self.net2_id, "ACTIVE", self.fmt)

    def test_network_name_filter(self):
        LOG.debug("test_network_name_filter - START")
        flt = "name=test-1"
        network_data = self._do_filtered_network_list_request(flt)
        # Check network count: should return 1
        self.assertEqual(len(network_data['networks']), 1)
        self.assertEqual(network_data['networks'][0]['id'], self.net1_id)

        flt = "name=non-existent"
        network_data = self._do_filtered_network_list_request(flt)
        # Check network count: should return 0
        self.assertEqual(len(network_data['networks']), 0)

        LOG.debug("test_network_name_filter - END")

    def test_network_op_status_filter(self):
        LOG.debug("test_network_op_status_filter - START")
        # First filter for networks in default status
        flt = "op-status=%s" % self.net_op_status
        network_data = self._do_filtered_network_list_request(flt)
        # Check network count: should return 2
        self.assertEqual(len(network_data['networks']), 2)

        # And then for networks in 'DOWN' status
        flt = "op-status=DOWN"
        network_data = self._do_filtered_network_list_request(flt)
        # Check network count: should return 0
        self.assertEqual(len(network_data['networks']), 0)
        LOG.debug("test_network_op_status_filter - END")

    def test_network_port_op_status_filter(self):
        LOG.debug("test_network_port_op_status_filter - START")
        # First filter for networks with ports in default op status
        flt = "port-op-status=%s" % self.port_op_status
        network_data = self._do_filtered_network_list_request(flt)
        # Check network count: should return 2
        self.assertEqual(len(network_data['networks']), 2)
        LOG.debug("test_network_port_op_status_filter - END")

    def test_network_port_state_filter(self):
        LOG.debug("test_network_port_state_filter - START")
        # First filter for networks with ports 'ACTIVE'
        flt = "port-state=ACTIVE"
        network_data = self._do_filtered_network_list_request(flt)
        # Check network count: should return 2
        self.assertEqual(len(network_data['networks']), 2)

        # And then for networks with ports in 'DOWN' admin state
        flt = "port-state=DOWN"
        network_data = self._do_filtered_network_list_request(flt)
        # Check network count: should return 1
        self.assertEqual(len(network_data['networks']), 1)
        LOG.debug("test_network_port_state_filter - END")

    def test_network_has_attachment_filter(self):
        LOG.debug("test_network_has_attachment_filter - START")
        # First filter for networks with ports 'ACTIVE'
        flt = "has-attachment=True"
        network_data = self._do_filtered_network_list_request(flt)
        # Check network count: should return 1
        self.assertEqual(len(network_data['networks']), 1)

        # And then for networks with ports in 'DOWN' admin state
        flt = "has-attachment=False"
        network_data = self._do_filtered_network_list_request(flt)
        # Check network count: should return 1
        self.assertEqual(len(network_data['networks']), 1)
        LOG.debug("test_network_has_attachment_filter - END")

    def test_network_port_filter(self):
        LOG.debug("test_network_port_filter - START")

        flt = "port=%s" % self.port11_id
        network_data = self._do_filtered_network_list_request(flt)
        # Check network count: should return 1
        self.assertEqual(len(network_data['networks']), 1)
        self.assertEqual(network_data['networks'][0]['id'], self.net1_id)

        flt = "port=%s" % self.port21_id
        network_data = self._do_filtered_network_list_request(flt)
        # Check network count: should return 1
        self.assertEqual(len(network_data['networks']), 1)
        self.assertEqual(network_data['networks'][0]['id'], self.net2_id)
        LOG.debug("test_network_port_filter - END")

    def test_network_attachment_filter(self):
        LOG.debug("test_network_attachment_filter - START")

        flt = "attachment=test-1-att"
        network_data = self._do_filtered_network_list_request(flt)
        # Check network count: should return 1
        self.assertEqual(len(network_data['networks']), 1)
        self.assertEqual(network_data['networks'][0]['id'], self.net1_id)

        flt = "attachment=non-existent"
        network_data = self._do_filtered_network_list_request(flt)
        # Check network count: should return 0
        self.assertEqual(len(network_data['networks']), 0)
        LOG.debug("test_network_attachment_filter - END")

    def test_network_multiple_filters(self):
        LOG.debug("test_network_multiple_filters - START")
        # Add some data for having more fun
        another_net_id = self._create_network(self.fmt, name="test-1")
        # Add 1 ACTIVE port
        self._create_port(another_net_id, "ACTIVE", self.fmt)
        # Do the filtering
        flt = "name=test-1&port-state=ACTIVE&attachment=test-1-att"
        network_data = self._do_filtered_network_list_request(flt)
        # Check network count: should return 1
        self.assertEqual(len(network_data['networks']), 1)
        self.assertEqual(network_data['networks'][0]['id'], self.net1_id)
        LOG.debug("test_network_multiple_filters - END")

    def test_port_state_filter(self):
        LOG.debug("test_port_state_filter - START")
        # First filter for 'ACTIVE' ports in 1st network
        flt = "state=ACTIVE"
        port_data = self._do_filtered_port_list_request(flt, self.net1_id)
        # Check port count: should return 1
        self.assertEqual(len(port_data['ports']), 1)

        # And then in 2nd network
        port_data = self._do_filtered_port_list_request(flt, self.net2_id)
        # Check port count: should return 2
        self.assertEqual(len(port_data['ports']), 2)
        LOG.debug("test_port_state_filter - END")

    def test_port_op_status_filter(self):
        LOG.debug("test_port_op_status_filter - START")
        # First filter for 'UP' ports in 1st network
        flt = "op-status=%s" % self.port_op_status
        port_data = self._do_filtered_port_list_request(flt, self.net1_id)
        # Check port count: should return 2
        self.assertEqual(len(port_data['ports']), 2)
        LOG.debug("test_port_op_status_filter - END")

    def test_port_has_attachment_filter(self):
        LOG.debug("test_port_has_attachment_filter - START")
        # First search for ports with attachments in 1st network
        flt = "has-attachment=True"
        port_data = self._do_filtered_port_list_request(flt, self.net1_id)
        # Check port count: should return 1
        self.assertEqual(len(port_data['ports']), 1)
        self.assertEqual(port_data['ports'][0]['id'], self.port11_id)

        # And then for ports without attachment in 2nd network
        flt = "has-attachment=False"
        port_data = self._do_filtered_port_list_request(flt, self.net2_id)
        # Check port count: should return 2
        self.assertEqual(len(port_data['ports']), 2)
        LOG.debug("test_port_has_attachment_filter - END")

    def test_port_attachment_filter(self):
        LOG.debug("test_port_attachment_filter - START")
        # First search for ports with attachments in 1st network
        flt = "attachment=test-1-att"
        port_data = self._do_filtered_port_list_request(flt, self.net1_id)
        # Check port count: should return 1
        self.assertEqual(len(port_data['ports']), 1)
        self.assertEqual(port_data['ports'][0]['id'], self.port11_id)

        # And then for a non-existent attachment in 2nd network
        flt = "attachment=non-existent"
        port_data = self._do_filtered_port_list_request(flt, self.net2_id)
        # Check port count: should return 0
        self.assertEqual(len(port_data['ports']), 0)
        LOG.debug("test_port_has_attachment_filter - END")

    def test_port_multiple_filters(self):
        LOG.debug("test_port_multiple_filters - START")
        flt = "op-status=%s&state=DOWN" % self.port_op_status
        port_data = self._do_filtered_port_list_request(flt, self.net1_id)
        # Check port count: should return 1
        self.assertEqual(len(port_data['ports']), 1)
        self.assertEqual(port_data['ports'][0]['id'], self.port12_id)

        flt = "state=ACTIVE&attachment=test-1-att"
        port_data = self._do_filtered_port_list_request(flt, self.net1_id)
        # Check port count: should return 1
        self.assertEqual(len(port_data['ports']), 1)
        self.assertEqual(port_data['ports'][0]['id'], self.port11_id)

        flt = "state=ACTIVE&has-attachment=False"
        port_data = self._do_filtered_port_list_request(flt, self.net2_id)
        # Check port count: should return 2
        self.assertEqual(len(port_data['ports']), 2)
        LOG.debug("test_port_multiple_filters - END")
