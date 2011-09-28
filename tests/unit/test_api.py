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

import tests.unit.testlib_api as testlib

from quantum import api as server
from quantum.db import api as db
from quantum.common.test_lib import test_config
from quantum.common.wsgi import Serializer

LOG = logging.getLogger('quantum.tests.test_api')


class APITest(unittest.TestCase):

    def _create_network(self, format, name=None, custom_req_body=None,
                        expected_res_status=200):
        LOG.debug("Creating network")
        content_type = "application/" + format
        if name:
            net_name = name
        else:
            net_name = self.network_name
        network_req = testlib.new_network_request(self.tenant_id,
                                                  net_name, format,
                                                  custom_req_body)
        network_res = network_req.get_response(self.api)
        self.assertEqual(network_res.status_int, expected_res_status)
        if expected_res_status in (200, 202):
            network_data = Serializer().deserialize(network_res.body,
                                                    content_type)
            return network_data['network']['id']

    def _create_port(self, network_id, port_state, format,
                     custom_req_body=None, expected_res_status=200):
        LOG.debug("Creating port for network %s", network_id)
        content_type = "application/%s" % format
        port_req = testlib.new_port_request(self.tenant_id, network_id,
                                            port_state, format,
                                            custom_req_body)
        port_res = port_req.get_response(self.api)
        self.assertEqual(port_res.status_int, expected_res_status)
        if expected_res_status in (200, 202):
            port_data = Serializer().deserialize(port_res.body, content_type)
            return port_data['port']['id']

    def _test_create_network(self, format):
        LOG.debug("_test_create_network - format:%s - START", format)
        content_type = "application/%s" % format
        network_id = self._create_network(format)
        show_network_req = testlib.show_network_request(self.tenant_id,
                                                        network_id,
                                                        format)
        show_network_res = show_network_req.get_response(self.api)
        self.assertEqual(show_network_res.status_int, 200)
        network_data = Serializer().deserialize(show_network_res.body,
                                                content_type)
        self.assertEqual(network_id, network_data['network']['id'])
        LOG.debug("_test_create_network - format:%s - END", format)

    def _test_create_network_badrequest(self, format):
        LOG.debug("_test_create_network_badrequest - format:%s - START",
                  format)
        bad_body = {'network': {'bad-attribute': 'very-bad'}}
        self._create_network(format, custom_req_body=bad_body,
                             expected_res_status=400)
        LOG.debug("_test_create_network_badrequest - format:%s - END",
                  format)

    def _test_list_networks(self, format):
        LOG.debug("_test_list_networks - format:%s - START", format)
        content_type = "application/%s" % format
        self._create_network(format, "net_1")
        self._create_network(format, "net_2")
        list_network_req = testlib.network_list_request(self.tenant_id,
                                                        format)
        list_network_res = list_network_req.get_response(self.api)
        self.assertEqual(list_network_res.status_int, 200)
        network_data = self._net_serializer.deserialize(
                           list_network_res.body, content_type)
        # Check network count: should return 2
        self.assertEqual(len(network_data['networks']), 2)
        LOG.debug("_test_list_networks - format:%s - END", format)

    def _test_list_networks_detail(self, format):
        LOG.debug("_test_list_networks_detail - format:%s - START", format)
        content_type = "application/%s" % format
        self._create_network(format, "net_1")
        self._create_network(format, "net_2")
        list_network_req = testlib.network_list_detail_request(self.tenant_id,
                                                               format)
        list_network_res = list_network_req.get_response(self.api)
        self.assertEqual(list_network_res.status_int, 200)
        network_data = self._net_serializer.deserialize(
                           list_network_res.body, content_type)
        # Check network count: should return 2
        self.assertEqual(len(network_data['networks']), 2)
        # Check contents - id & name for each network
        for network in network_data['networks']:
            self.assertTrue('id' in network and 'name' in network)
            self.assertTrue(network['id'] and network['name'])
        LOG.debug("_test_list_networks_detail - format:%s - END", format)

    def _test_show_network(self, format):
        LOG.debug("_test_show_network - format:%s - START", format)
        content_type = "application/%s" % format
        network_id = self._create_network(format)
        show_network_req = testlib.show_network_request(self.tenant_id,
                                                        network_id,
                                                        format)
        show_network_res = show_network_req.get_response(self.api)
        self.assertEqual(show_network_res.status_int, 200)
        network_data = self._net_serializer.deserialize(
                           show_network_res.body, content_type)
        self.assertEqual({'id': network_id,
                          'name': self.network_name},
                         network_data['network'])
        LOG.debug("_test_show_network - format:%s - END", format)

    def _test_show_network_detail(self, format):
        LOG.debug("_test_show_network_detail - format:%s - START", format)
        content_type = "application/%s" % format
        # Create a network and a port
        network_id = self._create_network(format)
        port_id = self._create_port(network_id, "ACTIVE", format)
        show_network_req = testlib.show_network_detail_request(
                                    self.tenant_id, network_id, format)
        show_network_res = show_network_req.get_response(self.api)
        self.assertEqual(show_network_res.status_int, 200)
        network_data = self._net_serializer.deserialize(
                           show_network_res.body, content_type)
        self.assertEqual({'id': network_id,
                          'name': self.network_name,
                          'ports': [{'id': port_id,
                                     'state': 'ACTIVE'}]},
                         network_data['network'])
        LOG.debug("_test_show_network_detail - format:%s - END", format)

    def _test_show_network_not_found(self, format):
        LOG.debug("_test_show_network_not_found - format:%s - START", format)
        show_network_req = testlib.show_network_request(self.tenant_id,
                                                        "A_BAD_ID",
                                                        format)
        show_network_res = show_network_req.get_response(self.api)
        self.assertEqual(show_network_res.status_int, 420)
        LOG.debug("_test_show_network_not_found - format:%s - END", format)

    def _test_rename_network(self, format):
        LOG.debug("_test_rename_network - format:%s - START", format)
        content_type = "application/%s" % format
        new_name = 'new_network_name'
        network_id = self._create_network(format)
        update_network_req = testlib.update_network_request(self.tenant_id,
                                                            network_id,
                                                            new_name,
                                                            format)
        update_network_res = update_network_req.get_response(self.api)
        self.assertEqual(update_network_res.status_int, 204)
        show_network_req = testlib.show_network_request(self.tenant_id,
                                                        network_id,
                                                        format)
        show_network_res = show_network_req.get_response(self.api)
        self.assertEqual(show_network_res.status_int, 200)
        network_data = self._net_serializer.deserialize(
                           show_network_res.body, content_type)
        self.assertEqual({'id': network_id,
                          'name': new_name},
                         network_data['network'])
        LOG.debug("_test_rename_network - format:%s - END", format)

    def _test_rename_network_badrequest(self, format):
        LOG.debug("_test_rename_network_badrequest - format:%s - START",
                  format)
        network_id = self._create_network(format)
        bad_body = {'network': {'bad-attribute': 'very-bad'}}
        update_network_req = testlib.\
                             update_network_request(self.tenant_id,
                                                    network_id, format,
                                                    custom_req_body=bad_body)
        update_network_res = update_network_req.get_response(self.api)
        self.assertEqual(update_network_res.status_int, 400)
        LOG.debug("_test_rename_network_badrequest - format:%s - END",
                  format)

    def _test_rename_network_not_found(self, format):
        LOG.debug("_test_rename_network_not_found - format:%s - START",
                  format)
        new_name = 'new_network_name'
        update_network_req = testlib.update_network_request(self.tenant_id,
                                                            "A BAD ID",
                                                            new_name,
                                                            format)
        update_network_res = update_network_req.get_response(self.api)
        self.assertEqual(update_network_res.status_int, 420)
        LOG.debug("_test_rename_network_not_found - format:%s - END",
                  format)

    def _test_delete_network(self, format):
        LOG.debug("_test_delete_network - format:%s - START", format)
        content_type = "application/%s" % format
        network_id = self._create_network(format)
        LOG.debug("Deleting network %s"\
                  " of tenant %s" % (network_id, self.tenant_id))
        delete_network_req = testlib.network_delete_request(self.tenant_id,
                                                            network_id,
                                                            format)
        delete_network_res = delete_network_req.get_response(self.api)
        self.assertEqual(delete_network_res.status_int, 204)
        list_network_req = testlib.network_list_request(self.tenant_id,
                                                        format)
        list_network_res = list_network_req.get_response(self.api)
        network_list_data = self._net_serializer.deserialize(
                                list_network_res.body, content_type)
        network_count = len(network_list_data['networks'])
        self.assertEqual(network_count, 0)
        LOG.debug("_test_delete_network - format:%s - END", format)

    def _test_delete_network_in_use(self, format):
        LOG.debug("_test_delete_network_in_use - format:%s - START", format)
        content_type = "application/%s" % format
        port_state = "ACTIVE"
        attachment_id = "test_attachment"
        network_id = self._create_network(format)
        LOG.debug("Deleting network %s"\
                  " of tenant %s" % (network_id, self.tenant_id))
        port_id = self._create_port(network_id, port_state, format)
        #plug an attachment into the port
        LOG.debug("Putting attachment into port %s", port_id)
        attachment_req = testlib.put_attachment_request(self.tenant_id,
                                                        network_id,
                                                        port_id,
                                                        attachment_id)
        attachment_res = attachment_req.get_response(self.api)
        self.assertEquals(attachment_res.status_int, 204)

        LOG.debug("Deleting network %s"\
                  " of tenant %s" % (network_id, self.tenant_id))
        delete_network_req = testlib.network_delete_request(self.tenant_id,
                                                            network_id,
                                                            format)
        delete_network_res = delete_network_req.get_response(self.api)
        self.assertEqual(delete_network_res.status_int, 421)
        LOG.debug("_test_delete_network_in_use - format:%s - END", format)

    def _test_delete_network_with_unattached_port(self, format):
        LOG.debug("_test_delete_network_with_unattached_port "\
                    "- format:%s - START", format)
        content_type = "application/%s" % format
        port_state = "ACTIVE"
        network_id = self._create_network(format)
        LOG.debug("Deleting network %s"\
                  " of tenant %s" % (network_id, self.tenant_id))
        port_id = self._create_port(network_id, port_state, format)

        LOG.debug("Deleting network %s"\
                  " of tenant %s" % (network_id, self.tenant_id))
        delete_network_req = testlib.network_delete_request(self.tenant_id,
                                                            network_id,
                                                            format)
        delete_network_res = delete_network_req.get_response(self.api)
        self.assertEqual(delete_network_res.status_int, 204)
        LOG.debug("_test_delete_network_with_unattached_port "\
                    "- format:%s - END", format)

    def _test_list_ports(self, format):
        LOG.debug("_test_list_ports - format:%s - START", format)
        content_type = "application/%s" % format
        port_state = "ACTIVE"
        network_id = self._create_network(format)
        self._create_port(network_id, port_state, format)
        self._create_port(network_id, port_state, format)
        list_port_req = testlib.port_list_request(self.tenant_id,
                                                   network_id, format)
        list_port_res = list_port_req.get_response(self.api)
        self.assertEqual(list_port_res.status_int, 200)
        port_data = self._port_serializer.deserialize(
                        list_port_res.body, content_type)
        # Check port count: should return 2
        self.assertEqual(len(port_data['ports']), 2)
        LOG.debug("_test_list_ports - format:%s - END", format)

    def _test_list_ports_networknotfound(self, format):
        LOG.debug("_test_list_ports_networknotfound"
                    " - format:%s - START", format)
        list_port_req = testlib.port_list_request(self.tenant_id,
                                                  "A_BAD_ID", format)
        list_port_res = list_port_req.get_response(self.api)
        self.assertEqual(list_port_res.status_int, 420)
        LOG.debug("_test_list_ports_networknotfound - format:%s - END", format)

    def _test_list_ports_detail(self, format):
        LOG.debug("_test_list_ports_detail - format:%s - START", format)
        content_type = "application/%s" % format
        port_state = "ACTIVE"
        network_id = self._create_network(format)
        self._create_port(network_id, port_state, format)
        self._create_port(network_id, port_state, format)
        list_port_req = testlib.port_list_detail_request(self.tenant_id,
                                                         network_id, format)
        list_port_res = list_port_req.get_response(self.api)
        self.assertEqual(list_port_res.status_int, 200)
        port_data = self._port_serializer.deserialize(
                        list_port_res.body, content_type)
        # Check port count: should return 2
        self.assertEqual(len(port_data['ports']), 2)
        # Check contents - id & name for each network
        for port in port_data['ports']:
            self.assertTrue('id' in port and 'state' in port)
            self.assertTrue(port['id'] and port['state'])
        LOG.debug("_test_list_ports_detail - format:%s - END", format)

    def _test_show_port(self, format):
        LOG.debug("_test_show_port - format:%s - START", format)
        content_type = "application/%s" % format
        port_state = "ACTIVE"
        network_id = self._create_network(format)
        port_id = self._create_port(network_id, port_state, format)
        show_port_req = testlib.show_port_request(self.tenant_id,
                                                  network_id, port_id,
                                                  format)
        show_port_res = show_port_req.get_response(self.api)
        self.assertEqual(show_port_res.status_int, 200)
        port_data = self._port_serializer.deserialize(
                        show_port_res.body, content_type)
        self.assertEqual({'id': port_id, 'state': port_state},
                         port_data['port'])
        LOG.debug("_test_show_port - format:%s - END", format)

    def _test_show_port_detail(self, format):
        LOG.debug("_test_show_port - format:%s - START", format)
        content_type = "application/%s" % format
        port_state = "ACTIVE"
        network_id = self._create_network(format)
        port_id = self._create_port(network_id, port_state, format)

        # Part 1 - no attachment
        show_port_req = testlib.show_port_detail_request(self.tenant_id,
                                    network_id, port_id, format)
        show_port_res = show_port_req.get_response(self.api)
        self.assertEqual(show_port_res.status_int, 200)
        port_data = self._port_serializer.deserialize(
                        show_port_res.body, content_type)
        self.assertEqual({'id': port_id, 'state': port_state},
                         port_data['port'])

        # Part 2 - plug attachment into port
        interface_id = "test_interface"
        put_attachment_req = testlib.put_attachment_request(self.tenant_id,
                                                            network_id,
                                                            port_id,
                                                            interface_id,
                                                            format)
        put_attachment_res = put_attachment_req.get_response(self.api)
        self.assertEqual(put_attachment_res.status_int, 204)
        show_port_req = testlib.show_port_detail_request(self.tenant_id,
                                    network_id, port_id, format)
        show_port_res = show_port_req.get_response(self.api)
        self.assertEqual(show_port_res.status_int, 200)
        port_data = self._port_serializer.deserialize(
                        show_port_res.body, content_type)
        self.assertEqual({'id': port_id, 'state': port_state,
                          'attachment': {'id': interface_id}},
                         port_data['port'])

        LOG.debug("_test_show_port_detail - format:%s - END", format)

    def _test_show_port_networknotfound(self, format):
        LOG.debug("_test_show_port_networknotfound - format:%s - START",
                  format)
        port_state = "ACTIVE"
        network_id = self._create_network(format)
        port_id = self._create_port(network_id, port_state, format)
        show_port_req = testlib.show_port_request(self.tenant_id,
                                                        "A_BAD_ID", port_id,
                                                        format)
        show_port_res = show_port_req.get_response(self.api)
        self.assertEqual(show_port_res.status_int, 420)
        LOG.debug("_test_show_port_networknotfound - format:%s - END",
                  format)

    def _test_show_port_portnotfound(self, format):
        LOG.debug("_test_show_port_portnotfound - format:%s - START", format)
        network_id = self._create_network(format)
        show_port_req = testlib.show_port_request(self.tenant_id,
                                                        network_id,
                                                        "A_BAD_ID",
                                                        format)
        show_port_res = show_port_req.get_response(self.api)
        self.assertEqual(show_port_res.status_int, 430)
        LOG.debug("_test_show_port_portnotfound - format:%s - END", format)

    def _test_create_port_noreqbody(self, format):
        LOG.debug("_test_create_port_noreqbody - format:%s - START", format)
        content_type = "application/%s" % format
        network_id = self._create_network(format)
        port_id = self._create_port(network_id, None, format,
                                    custom_req_body='')
        show_port_req = testlib.show_port_request(self.tenant_id,
                                                  network_id, port_id, format)
        show_port_res = show_port_req.get_response(self.api)
        self.assertEqual(show_port_res.status_int, 200)
        port_data = self._port_serializer.deserialize(
                        show_port_res.body, content_type)
        self.assertEqual(port_id, port_data['port']['id'])
        LOG.debug("_test_create_port_noreqbody - format:%s - END", format)

    def _test_create_port(self, format):
        LOG.debug("_test_create_port - format:%s - START", format)
        content_type = "application/%s" % format
        port_state = "ACTIVE"
        network_id = self._create_network(format)
        port_id = self._create_port(network_id, port_state, format)
        show_port_req = testlib.show_port_request(self.tenant_id,
                                                  network_id, port_id, format)
        show_port_res = show_port_req.get_response(self.api)
        self.assertEqual(show_port_res.status_int, 200)
        port_data = self._port_serializer.deserialize(
                        show_port_res.body, content_type)
        self.assertEqual(port_id, port_data['port']['id'])
        LOG.debug("_test_create_port - format:%s - END", format)

    def _test_create_port_networknotfound(self, format):
        LOG.debug("_test_create_port_networknotfound - format:%s - START",
                  format)
        port_state = "ACTIVE"
        self._create_port("A_BAD_ID", port_state, format,
                          expected_res_status=420)
        LOG.debug("_test_create_port_networknotfound - format:%s - END",
                  format)

    def _test_create_port_badrequest(self, format):
        LOG.debug("_test_create_port_badrequest - format:%s - START", format)
        bad_body = {'bad-resource': {'bad-attribute': 'bad-value'}}
        network_id = self._create_network(format)
        port_state = "ACTIVE"
        self._create_port(network_id, port_state, format,
                          custom_req_body=bad_body, expected_res_status=400)
        LOG.debug("_test_create_port_badrequest - format:%s - END", format)

    def _test_delete_port(self, format):
        LOG.debug("_test_delete_port - format:%s - START", format)
        content_type = "application/%s" % format
        port_state = "ACTIVE"
        network_id = self._create_network(format)
        port_id = self._create_port(network_id, port_state, format)
        LOG.debug("Deleting port %s for network %s"\
                  " of tenant %s" % (port_id, network_id,
                    self.tenant_id))
        delete_port_req = testlib.port_delete_request(self.tenant_id,
                                                      network_id, port_id,
                                                      format)
        delete_port_res = delete_port_req.get_response(self.api)
        self.assertEqual(delete_port_res.status_int, 204)
        list_port_req = testlib.port_list_request(self.tenant_id, network_id,
                                                  format)
        list_port_res = list_port_req.get_response(self.api)
        port_list_data = self._port_serializer.deserialize(
                             list_port_res.body, content_type)
        port_count = len(port_list_data['ports'])
        self.assertEqual(port_count, 0)
        LOG.debug("_test_delete_port - format:%s - END", format)

    def _test_delete_port_in_use(self, format):
        LOG.debug("_test_delete_port_in_use - format:%s - START", format)
        content_type = "application/" + format
        port_state = "ACTIVE"
        attachment_id = "test_attachment"
        network_id = self._create_network(format)
        port_id = self._create_port(network_id, port_state, format)
        #plug an attachment into the port
        LOG.debug("Putting attachment into port %s", port_id)
        attachment_req = testlib.put_attachment_request(self.tenant_id,
                                                        network_id,
                                                        port_id,
                                                        attachment_id)
        attachment_res = attachment_req.get_response(self.api)
        self.assertEquals(attachment_res.status_int, 204)
        LOG.debug("Deleting port %s for network %s"\
                  " of tenant %s" % (port_id, network_id,
                    self.tenant_id))
        delete_port_req = testlib.port_delete_request(self.tenant_id,
                                                      network_id, port_id,
                                                      format)
        delete_port_res = delete_port_req.get_response(self.api)
        self.assertEqual(delete_port_res.status_int, 432)
        LOG.debug("_test_delete_port_in_use - format:%s - END", format)

    def _test_delete_port_with_bad_id(self, format):
        LOG.debug("_test_delete_port_with_bad_id - format:%s - START",
                  format)
        port_state = "ACTIVE"
        network_id = self._create_network(format)
        self._create_port(network_id, port_state, format)
        # Test for portnotfound
        delete_port_req = testlib.port_delete_request(self.tenant_id,
                                                      network_id, "A_BAD_ID",
                                                      format)
        delete_port_res = delete_port_req.get_response(self.api)
        self.assertEqual(delete_port_res.status_int, 430)
        LOG.debug("_test_delete_port_with_bad_id - format:%s - END", format)

    def _test_delete_port_networknotfound(self, format):
        LOG.debug("_test_delete_port_networknotfound - format:%s - START",
                  format)
        port_state = "ACTIVE"
        network_id = self._create_network(format)
        port_id = self._create_port(network_id, port_state, format)
        delete_port_req = testlib.port_delete_request(self.tenant_id,
                                                      "A_BAD_ID", port_id,
                                                      format)
        delete_port_res = delete_port_req.get_response(self.api)
        self.assertEqual(delete_port_res.status_int, 420)
        LOG.debug("_test_delete_port_networknotfound - format:%s - END",
                  format)

    def _test_set_port_state(self, format):
        LOG.debug("_test_set_port_state - format:%s - START", format)
        content_type = "application/%s" % format
        port_state = 'DOWN'
        new_port_state = 'ACTIVE'
        network_id = self._create_network(format)
        port_id = self._create_port(network_id, port_state, format)
        update_port_req = testlib.update_port_request(self.tenant_id,
                                                        network_id, port_id,
                                                        new_port_state,
                                                        format)
        update_port_res = update_port_req.get_response(self.api)
        self.assertEqual(update_port_res.status_int, 204)
        show_port_req = testlib.show_port_request(self.tenant_id,
                                                  network_id, port_id,
                                                  format)
        show_port_res = show_port_req.get_response(self.api)
        self.assertEqual(show_port_res.status_int, 200)
        port_data = self._port_serializer.deserialize(
                        show_port_res.body, content_type)
        self.assertEqual({'id': port_id, 'state': new_port_state},
                         port_data['port'])
        # now set it back to the original value
        update_port_req = testlib.update_port_request(self.tenant_id,
                                                        network_id, port_id,
                                                        port_state,
                                                        format)
        update_port_res = update_port_req.get_response(self.api)
        self.assertEqual(update_port_res.status_int, 204)
        show_port_req = testlib.show_port_request(self.tenant_id,
                                                  network_id, port_id,
                                                  format)
        show_port_res = show_port_req.get_response(self.api)
        self.assertEqual(show_port_res.status_int, 200)
        port_data = self._port_serializer.deserialize(
                        show_port_res.body, content_type)
        self.assertEqual({'id': port_id, 'state': port_state},
                         port_data['port'])
        LOG.debug("_test_set_port_state - format:%s - END", format)

    def _test_set_port_state_networknotfound(self, format):
        LOG.debug("_test_set_port_state_networknotfound - format:%s - START",
                  format)
        port_state = 'DOWN'
        new_port_state = 'ACTIVE'
        network_id = self._create_network(format)
        port_id = self._create_port(network_id, port_state, format)
        update_port_req = testlib.update_port_request(self.tenant_id,
                                                        "A_BAD_ID", port_id,
                                                        new_port_state,
                                                        format)
        update_port_res = update_port_req.get_response(self.api)
        self.assertEqual(update_port_res.status_int, 420)
        LOG.debug("_test_set_port_state_networknotfound - format:%s - END",
                  format)

    def _test_set_port_state_portnotfound(self, format):
        LOG.debug("_test_set_port_state_portnotfound - format:%s - START",
                  format)
        port_state = 'DOWN'
        new_port_state = 'ACTIVE'
        network_id = self._create_network(format)
        self._create_port(network_id, port_state, format)
        update_port_req = testlib.update_port_request(self.tenant_id,
                                                        network_id,
                                                        "A_BAD_ID",
                                                        new_port_state,
                                                        format)
        update_port_res = update_port_req.get_response(self.api)
        self.assertEqual(update_port_res.status_int, 430)
        LOG.debug("_test_set_port_state_portnotfound - format:%s - END",
                  format)

    def _test_set_port_state_stateinvalid(self, format):
        LOG.debug("_test_set_port_state_stateinvalid - format:%s - START",
                  format)
        port_state = 'DOWN'
        new_port_state = 'A_BAD_STATE'
        network_id = self._create_network(format)
        port_id = self._create_port(network_id, port_state, format)
        update_port_req = testlib.update_port_request(self.tenant_id,
                                                        network_id, port_id,
                                                        new_port_state,
                                                        format)
        update_port_res = update_port_req.get_response(self.api)
        self.assertEqual(update_port_res.status_int, 431)
        LOG.debug("_test_set_port_state_stateinvalid - format:%s - END",
                  format)

    def _test_show_attachment(self, format):
        LOG.debug("_test_show_attachment - format:%s - START", format)
        content_type = "application/%s" % format
        port_state = "ACTIVE"
        network_id = self._create_network(format)
        interface_id = "test_interface"
        port_id = self._create_port(network_id, port_state, format)
        put_attachment_req = testlib.put_attachment_request(self.tenant_id,
                                                            network_id,
                                                            port_id,
                                                            interface_id,
                                                            format)
        put_attachment_res = put_attachment_req.get_response(self.api)
        self.assertEqual(put_attachment_res.status_int, 204)
        get_attachment_req = testlib.get_attachment_request(self.tenant_id,
                                                            network_id,
                                                            port_id,
                                                            format)
        get_attachment_res = get_attachment_req.get_response(self.api)
        attachment_data = Serializer().deserialize(get_attachment_res.body,
                                                   content_type)
        self.assertEqual(attachment_data['attachment']['id'], interface_id)
        LOG.debug("_test_show_attachment - format:%s - END", format)

    def _test_show_attachment_none_set(self, format):
        LOG.debug("_test_show_attachment_none_set - format:%s - START", format)
        content_type = "application/%s" % format
        port_state = "ACTIVE"
        network_id = self._create_network(format)
        port_id = self._create_port(network_id, port_state, format)
        get_attachment_req = testlib.get_attachment_request(self.tenant_id,
                                                            network_id,
                                                            port_id,
                                                            format)
        get_attachment_res = get_attachment_req.get_response(self.api)
        attachment_data = Serializer().deserialize(get_attachment_res.body,
                                                   content_type)
        self.assertTrue('id' not in attachment_data['attachment'])
        LOG.debug("_test_show_attachment_none_set - format:%s - END", format)

    def _test_show_attachment_networknotfound(self, format):
        LOG.debug("_test_show_attachment_networknotfound - format:%s - START",
                  format)
        port_state = "ACTIVE"
        network_id = self._create_network(format)
        port_id = self._create_port(network_id, port_state, format)
        get_attachment_req = testlib.get_attachment_request(self.tenant_id,
                                                            "A_BAD_ID",
                                                            port_id,
                                                            format)
        get_attachment_res = get_attachment_req.get_response(self.api)
        self.assertEqual(get_attachment_res.status_int, 420)
        LOG.debug("_test_show_attachment_networknotfound - format:%s - END",
                  format)

    def _test_show_attachment_portnotfound(self, format):
        LOG.debug("_test_show_attachment_portnotfound - format:%s - START",
                  format)
        port_state = "ACTIVE"
        network_id = self._create_network(format)
        self._create_port(network_id, port_state, format)
        get_attachment_req = testlib.get_attachment_request(self.tenant_id,
                                                            network_id,
                                                            "A_BAD_ID",
                                                            format)
        get_attachment_res = get_attachment_req.get_response(self.api)
        self.assertEqual(get_attachment_res.status_int, 430)
        LOG.debug("_test_show_attachment_portnotfound - format:%s - END",
                  format)

    def _test_put_attachment(self, format):
        LOG.debug("_test_put_attachment - format:%s - START", format)
        port_state = "ACTIVE"
        network_id = self._create_network(format)
        interface_id = "test_interface"
        port_id = self._create_port(network_id, port_state, format)
        put_attachment_req = testlib.put_attachment_request(self.tenant_id,
                                                            network_id,
                                                            port_id,
                                                            interface_id,
                                                            format)
        put_attachment_res = put_attachment_req.get_response(self.api)
        self.assertEqual(put_attachment_res.status_int, 204)
        LOG.debug("_test_put_attachment - format:%s - END", format)

    def _test_put_attachment_networknotfound(self, format):
        LOG.debug("_test_put_attachment_networknotfound - format:%s - START",
                  format)
        port_state = 'DOWN'
        interface_id = "test_interface"
        network_id = self._create_network(format)
        port_id = self._create_port(network_id, port_state, format)
        put_attachment_req = testlib.put_attachment_request(self.tenant_id,
                                                            "A_BAD_ID",
                                                            port_id,
                                                            interface_id,
                                                            format)
        put_attachment_res = put_attachment_req.get_response(self.api)
        self.assertEqual(put_attachment_res.status_int, 420)
        LOG.debug("_test_put_attachment_networknotfound - format:%s - END",
                  format)

    def _test_put_attachment_portnotfound(self, format):
        LOG.debug("_test_put_attachment_portnotfound - format:%s - START",
                  format)
        port_state = 'DOWN'
        interface_id = "test_interface"
        network_id = self._create_network(format)
        self._create_port(network_id, port_state, format)
        put_attachment_req = testlib.put_attachment_request(self.tenant_id,
                                                            network_id,
                                                            "A_BAD_ID",
                                                            interface_id,
                                                            format)
        put_attachment_res = put_attachment_req.get_response(self.api)
        self.assertEqual(put_attachment_res.status_int, 430)
        LOG.debug("_test_put_attachment_portnotfound - format:%s - END",
                  format)

    def _test_delete_attachment(self, format):
        LOG.debug("_test_delete_attachment - format:%s - START", format)
        port_state = "ACTIVE"
        network_id = self._create_network(format)
        interface_id = "test_interface"
        port_id = self._create_port(network_id, port_state, format)
        put_attachment_req = testlib.put_attachment_request(self.tenant_id,
                                                            network_id,
                                                            port_id,
                                                            interface_id,
                                                            format)
        put_attachment_res = put_attachment_req.get_response(self.api)
        self.assertEqual(put_attachment_res.status_int, 204)
        del_attachment_req = testlib.delete_attachment_request(self.tenant_id,
                                                               network_id,
                                                               port_id,
                                                               format)
        del_attachment_res = del_attachment_req.get_response(self.api)
        self.assertEqual(del_attachment_res.status_int, 204)
        LOG.debug("_test_delete_attachment - format:%s - END", format)

    def _test_delete_attachment_networknotfound(self, format):
        LOG.debug("_test_delete_attachment_networknotfound -" \
                  " format:%s - START", format)
        port_state = "ACTIVE"
        network_id = self._create_network(format)
        port_id = self._create_port(network_id, port_state, format)
        del_attachment_req = testlib.delete_attachment_request(self.tenant_id,
                                                               "A_BAD_ID",
                                                               port_id,
                                                               format)
        del_attachment_res = del_attachment_req.get_response(self.api)
        self.assertEqual(del_attachment_res.status_int, 420)
        LOG.debug("_test_delete_attachment_networknotfound -" \
                  " format:%s - END", format)

    def _test_delete_attachment_portnotfound(self, format):
        LOG.debug("_test_delete_attachment_portnotfound - " \
                  " format:%s - START", format)
        port_state = "ACTIVE"
        network_id = self._create_network(format)
        self._create_port(network_id, port_state, format)
        del_attachment_req = testlib.delete_attachment_request(self.tenant_id,
                                                               network_id,
                                                               "A_BAD_ID",
                                                               format)
        del_attachment_res = del_attachment_req.get_response(self.api)
        self.assertEqual(del_attachment_res.status_int, 430)
        LOG.debug("_test_delete_attachment_portnotfound - " \
                  "format:%s - END", format)

    def _test_unparsable_data(self, format):
        LOG.debug("_test_unparsable_data - " \
                  " format:%s - START", format)

        data = "this is not json or xml"
        method = 'POST'
        content_type = "application/%s" % format
        tenant_id = self.tenant_id
        path = "/tenants/%(tenant_id)s/networks.%(format)s" % locals()
        network_req = testlib.create_request(path, data, content_type, method)
        network_res = network_req.get_response(self.api)
        self.assertEqual(network_res.status_int, 400)

        LOG.debug("_test_unparsable_data - " \
                  "format:%s - END", format)

    def setUp(self):
        options = {}
        options['plugin_provider'] = test_config['plugin_name']
        self.api = server.APIRouterV1(options)
        self.tenant_id = "test_tenant"
        self.network_name = "test_network"
        self._net_serializer = \
            Serializer(server.networks.Controller._serialization_metadata)
        self._port_serializer = \
            Serializer(server.ports.Controller._serialization_metadata)

    def tearDown(self):
        """Clear the test environment"""
        # Remove database contents
        db.clear_db()

    def test_list_networks_json(self):
        self._test_list_networks('json')

    def test_list_networks_xml(self):
        self._test_list_networks('xml')

    def test_list_networks_detail_json(self):
        self._test_list_networks_detail('json')

    def test_list_networks_detail_xml(self):
        self._test_list_networks_detail('xml')

    def test_create_network_json(self):
        self._test_create_network('json')

    def test_create_network_xml(self):
        self._test_create_network('xml')

    def test_create_network_badrequest_json(self):
        self._test_create_network_badrequest('json')

    def test_create_network_badreqyest_xml(self):
        self._test_create_network_badrequest('xml')

    def test_show_network_not_found_json(self):
        self._test_show_network_not_found('json')

    def test_show_network_not_found_xml(self):
        self._test_show_network_not_found('xml')

    def test_show_network_json(self):
        self._test_show_network('json')

    def test_show_network_xml(self):
        self._test_show_network('xml')

    def test_show_network_detail_json(self):
        self._test_show_network_detail('json')

    def test_show_network_detail_xml(self):
        self._test_show_network_detail('xml')

    def test_delete_network_json(self):
        self._test_delete_network('json')

    def test_delete_network_xml(self):
        self._test_delete_network('xml')

    def test_rename_network_json(self):
        self._test_rename_network('json')

    def test_rename_network_xml(self):
        self._test_rename_network('xml')

    def test_rename_network_badrequest_json(self):
        self._test_rename_network_badrequest('json')

    def test_rename_network_badrequest_xml(self):
        self._test_rename_network_badrequest('xml')

    def test_rename_network_not_found_json(self):
        self._test_rename_network_not_found('json')

    def test_rename_network_not_found_xml(self):
        self._test_rename_network_not_found('xml')

    def test_delete_network_in_use_json(self):
        self._test_delete_network_in_use('json')

    def test_delete_network_in_use_xml(self):
        self._test_delete_network_in_use('xml')

    def test_delete_network_with_unattached_port_xml(self):
        self._test_delete_network_with_unattached_port('xml')

    def test_delete_network_with_unattached_port_json(self):
        self._test_delete_network_with_unattached_port('json')

    def test_list_ports_json(self):
        self._test_list_ports('json')

    def test_list_ports_xml(self):
        self._test_list_ports('xml')

    def test_list_ports_networknotfound_json(self):
        self._test_list_ports_networknotfound('json')

    def test_list_ports_networknotfound_xml(self):
        self._test_list_ports_networknotfound('xml')

    def test_list_ports_detail_json(self):
        self._test_list_ports_detail('json')

    def test_list_ports_detail_xml(self):
        self._test_list_ports_detail('xml')

    def test_show_port_json(self):
        self._test_show_port('json')

    def test_show_port_xml(self):
        self._test_show_port('xml')

    def test_show_port_detail_json(self):
        self._test_show_port_detail('json')

    def test_show_port_detail_xml(self):
        self._test_show_port_detail('xml')

    def test_show_port_networknotfound_json(self):
        self._test_show_port_networknotfound('json')

    def test_show_port_networknotfound_xml(self):
        self._test_show_port_networknotfound('xml')

    def test_show_port_portnotfound_json(self):
        self._test_show_port_portnotfound('json')

    def test_show_port_portnotfound_xml(self):
        self._test_show_port_portnotfound('xml')

    def test_create_port_json(self):
        self._test_create_port('json')

    def test_create_port_xml(self):
        self._test_create_port('xml')

    def test_create_port_noreqbody_json(self):
        self._test_create_port_noreqbody('json')

    def test_create_port_noreqbody_xml(self):
        self._test_create_port_noreqbody('xml')

    def test_create_port_networknotfound_json(self):
        self._test_create_port_networknotfound('json')

    def test_create_port_networknotfound_xml(self):
        self._test_create_port_networknotfound('xml')

    def test_create_port_badrequest_json(self):
        self._test_create_port_badrequest('json')

    def test_create_port_badrequest_xml(self):
        self._test_create_port_badrequest('xml')

    def test_delete_port_xml(self):
        self._test_delete_port('xml')

    def test_delete_port_json(self):
        self._test_delete_port('json')

    def test_delete_port_in_use_xml(self):
        self._test_delete_port_in_use('xml')

    def test_delete_port_in_use_json(self):
        self._test_delete_port_in_use('json')

    def test_delete_port_networknotfound_xml(self):
        self._test_delete_port_networknotfound('xml')

    def test_delete_port_networknotfound_json(self):
        self._test_delete_port_networknotfound('json')

    def test_delete_port_with_bad_id_xml(self):
        self._test_delete_port_with_bad_id('xml')

    def test_delete_port_with_bad_id_json(self):
        self._test_delete_port_with_bad_id('json')

    def test_set_port_state_xml(self):
        self._test_set_port_state('xml')

    def test_set_port_state_json(self):
        self._test_set_port_state('json')

    def test_set_port_state_networknotfound_xml(self):
        self._test_set_port_state_networknotfound('xml')

    def test_set_port_state_networknotfound_json(self):
        self._test_set_port_state_networknotfound('json')

    def test_set_port_state_portnotfound_xml(self):
        self._test_set_port_state_portnotfound('xml')

    def test_set_port_state_portnotfound_json(self):
        self._test_set_port_state_portnotfound('json')

    def test_set_port_state_stateinvalid_xml(self):
        self._test_set_port_state_stateinvalid('xml')

    def test_set_port_state_stateinvalid_json(self):
        self._test_set_port_state_stateinvalid('json')

    def test_show_attachment_xml(self):
        self._test_show_attachment('xml')

    def test_show_attachment_json(self):
        self._test_show_attachment('json')

    def test_show_attachment_none_set_xml(self):
        self._test_show_attachment_none_set('xml')

    def test_show_attachment_none_set_json(self):
        self._test_show_attachment_none_set('json')

    def test_show_attachment_networknotfound_xml(self):
        self._test_show_attachment_networknotfound('xml')

    def test_show_attachment_networknotfound_json(self):
        self._test_show_attachment_networknotfound('json')

    def test_show_attachment_portnotfound_xml(self):
        self._test_show_attachment_portnotfound('xml')

    def test_show_attachment_portnotfound_json(self):
        self._test_show_attachment_portnotfound('json')

    def test_put_attachment_xml(self):
        self._test_put_attachment('xml')

    def test_put_attachment_json(self):
        self._test_put_attachment('json')

    def test_put_attachment_networknotfound_xml(self):
        self._test_put_attachment_networknotfound('xml')

    def test_put_attachment_networknotfound_json(self):
        self._test_put_attachment_networknotfound('json')

    def test_put_attachment_portnotfound_xml(self):
        self._test_put_attachment_portnotfound('xml')

    def test_put_attachment_portnotfound_json(self):
        self._test_put_attachment_portnotfound('json')

    def test_delete_attachment_xml(self):
        self._test_delete_attachment('xml')

    def test_delete_attachment_json(self):
        self._test_delete_attachment('json')

    def test_delete_attachment_networknotfound_xml(self):
        self._test_delete_attachment_networknotfound('xml')

    def test_delete_attachment_networknotfound_json(self):
        self._test_delete_attachment_networknotfound('json')

    def test_delete_attachment_portnotfound_xml(self):
        self._test_delete_attachment_portnotfound('xml')

    def test_delete_attachment_portnotfound_json(self):
        self._test_delete_attachment_portnotfound('json')

    def test_unparsable_data_xml(self):
        self._test_unparsable_data('xml')

    def test_unparsable_data_json(self):
        self._test_unparsable_data('json')
