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
#    @author: Brad Hall, Nicira Networks
#    @author: Salvatore Orlando, Citrix Systems

import logging
import unittest

import tests.unit.testlib as testlib

from quantum import api as server
from quantum.common.wsgi import Serializer

LOG = logging.getLogger('quantum.tests.test_api')


class APIPortsTest(unittest.TestCase):
    def setUp(self):
        self.api = server.APIRouterV01()
        self.tenant_id = "test_tenant"
        self.network_name = "test_network"

    def tearDown(self):
        """Clear the test environment"""
        # Remove all the networks.
        network_req = testlib.create_network_list_request(self.tenant_id)
        network_res = network_req.get_response(self.api)
        network_data = Serializer().deserialize(network_res.body,
                                                "application/xml")
        for network in network_data["networks"].values():
            network_delete_req = testlib. \
                create_network_delete_request(self.tenant_id, network['id'])
            network_delete_req.get_response(self.api)

#    Fault names copied here for reference
#
#    _fault_names = {
#            400: "malformedRequest",
#            401: "unauthorized",
#            420: "networkNotFound",
#            421: "networkInUse",
#            430: "portNotFound",
#            431: "requestedStateInvalid",
#            432: "portInUse",
#            440: "alreadyAttached",
#            470: "serviceUnavailable",
#            471: "pluginFault"}

    def _test_delete_port(self, format):
        LOG.debug("_test_delete_port - format:%s - START", format)
        content_type = "application/" + format
        port_state = "ACTIVE"
        LOG.debug("Creating network and port")
        network_req = testlib.create_new_network_request(self.tenant_id,
                                                         self.network_name,
                                                         format)
        network_res = network_req.get_response(self.api)
        self.assertEqual(network_res.status_int, 200)
        network_data = Serializer().deserialize(network_res.body,
                                                content_type)
        network_id = network_data['networks']['network']['id']
        port_req = testlib.create_new_port_request(self.tenant_id,
                                                   network_id, port_state,
                                                   format)
        port_res = port_req.get_response(self.api)
        self.assertEqual(port_res.status_int, 200)
        port_data = Serializer().deserialize(port_res.body, content_type)
        port_id = port_data['ports']['port']['id']
        LOG.debug("Deleting port %(port_id)s for network %(network_id)s"\
                  " of tenant %(tenant_id)s", locals())
        delete_port_req = testlib.create_port_delete_request(self.tenant_id,
                                                             network_id,
                                                             port_id,
                                                             format)
        delete_port_res = delete_port_req.get_response(self.api)
        self.assertEqual(delete_port_res.status_int, 202)
        list_port_req = testlib.create_port_list_request(self.tenant_id,
                                                         network_id,
                                                         format)
        list_port_res = list_port_req.get_response(self.api)
        port_list_data = Serializer().deserialize(list_port_res.body,
                                                  content_type)
        port_count = len(port_list_data['ports'])
        self.assertEqual(port_count, 0)
        LOG.debug("_test_delete_port - format:%s - END", format)

    def test_delete_port_xml(self):
        self._test_delete_port('xml')

    def test_delete_port_json(self):
        self._test_delete_port('json')

    def _test_delete_port_in_use(self):
        # Test for portinuse
        #rv = self.port.create(req, tenant, network_id)
        #port_id = rv["ports"]["port"]["id"]
        #req = testlib.create_attachment_request(tenant, network_id,
        #  port_id, "fudd")
        #rv = self.port.attach_resource(req, tenant, network_id, port_id)
        #self.assertEqual(rv.status_int, 202)
        #rv = self.port.delete("", tenant, network_id, port_id)
        #self.assertEqual(rv.wrapped_exc.status_int, 432)
        pass


    def _test_delete_port_with_bad_id(self,format):
        LOG.debug("_test_delete_port - format:%s - START", format)
        content_type = "application/" + format
        port_state = "ACTIVE"
        LOG.debug("Creating network and port")
        network_req = testlib.create_new_network_request(self.tenant_id,
                                                         self.network_name,
                                                         format)
        network_res = network_req.get_response(self.api)
        self.assertEqual(network_res.status_int, 200)
        network_data = Serializer().deserialize(network_res.body,
                                                content_type)
        network_id = network_data['networks']['network']['id']
        port_req = testlib.create_new_port_request(self.tenant_id,
                                                   network_id, port_state,
                                                   format)
        port_res = port_req.get_response(self.api)
        self.assertEqual(port_res.status_int, 200)

        # Test for portnotfound
        delete_port_req = testlib.create_port_delete_request(self.tenant_id,
                                                             network_id,
                                                             "A_BAD_ID",
                                                             format)
        delete_port_res = delete_port_req.get_response(self.api)
        self.assertEqual(delete_port_res.status_int, 430)
        
    def test_delete_port_with_bad_id_xml(self):
        self._test_delete_port_wth_bad_id('xml')

    def test_delete_port_with_bad_id_json(self):
        self._test_delete_port_with_bad_id('json')

