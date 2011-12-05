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

import quantum.tests.unit.testlib_api as testlib

from quantum.db import api as db
from quantum.common import utils
from quantum.common.test_lib import test_config
from quantum.wsgi import XMLDeserializer, JSONDeserializer

LOG = logging.getLogger('quantum.tests.test_api')
NETS = "networks"
PORTS = "ports"
ATTS = "attachments"


class AbstractAPITest(unittest.TestCase):
    """Abstract base class for Quantum API unit tests
    Defined according to operations defined for Quantum API v1.0

    """

    def _deserialize_net_response(self, content_type, response):
        network_data = self._net_deserializers[content_type].\
                            deserialize(response.body)['body']
        # do not taint assertions with xml namespace
        if 'xmlns' in network_data['network']:
            del network_data['network']['xmlns']
        return network_data

    def _deserialize_port_response(self, content_type, response):
        port_data = self._port_deserializers[content_type].\
                         deserialize(response.body)['body']
        # do not taint assertions with xml namespace
        if 'xmlns' in port_data['port']:
            del port_data['port']['xmlns']
        return port_data

    def _create_network(self, fmt, name=None, custom_req_body=None,
                        expected_res_status=202):
        LOG.debug("Creating network")
        content_type = "application/" + fmt
        if name:
            net_name = name
        else:
            net_name = self.network_name
        network_req = testlib.new_network_request(self.tenant_id,
                                                  net_name, fmt,
                                                  custom_req_body)
        network_res = network_req.get_response(self.api)
        self.assertEqual(network_res.status_int, expected_res_status)
        if expected_res_status in (200, 202):
            network_data = self._deserialize_net_response(content_type,
                                                          network_res)
            return network_data['network']['id']

    def _create_port(self, network_id, port_state, fmt,
                     custom_req_body=None, expected_res_status=202):
        LOG.debug("Creating port for network %s", network_id)
        content_type = "application/%s" % fmt
        port_req = testlib.new_port_request(self.tenant_id, network_id,
                                            port_state, fmt,
                                            custom_req_body)
        port_res = port_req.get_response(self.api)
        self.assertEqual(port_res.status_int, expected_res_status)
        if expected_res_status in (200, 202):
            port_data = self._deserialize_port_response(content_type,
                                                        port_res)
            LOG.debug("PORT RESPONSE:%s", port_res.body)
            LOG.debug("PORT DATA:%s", port_data)
            return port_data['port']['id']

    def _test_create_network(self, fmt):
        LOG.debug("_test_create_network - fmt:%s - START", fmt)
        content_type = "application/%s" % fmt
        network_id = self._create_network(fmt)
        show_network_req = testlib.show_network_request(self.tenant_id,
                                                        network_id,
                                                        fmt)
        show_network_res = show_network_req.get_response(self.api)
        self.assertEqual(show_network_res.status_int, 200)
        network_data = self._net_deserializers[content_type].\
                            deserialize(show_network_res.body)['body']
        self.assertEqual(network_id, network_data['network']['id'])
        LOG.debug("_test_create_network - fmt:%s - END", fmt)

    def _test_create_network_badrequest(self, fmt):
        LOG.debug("_test_create_network_badrequest - fmt:%s - START",
                  fmt)
        bad_body = {'network': {'bad-attribute': 'very-bad'}}
        self._create_network(fmt, custom_req_body=bad_body,
                             expected_res_status=400)
        LOG.debug("_test_create_network_badrequest - fmt:%s - END",
                  fmt)

    def _test_list_networks(self, fmt):
        LOG.debug("_test_list_networks - fmt:%s - START", fmt)
        content_type = "application/%s" % fmt
        self._create_network(fmt, "net_1")
        self._create_network(fmt, "net_2")
        list_network_req = testlib.network_list_request(self.tenant_id,
                                                        fmt)
        list_network_res = list_network_req.get_response(self.api)
        self.assertEqual(list_network_res.status_int, 200)
        network_data = self._net_deserializers[content_type].\
                            deserialize(list_network_res.body)['body']
        # Check network count: should return 2
        self.assertEqual(len(network_data['networks']), 2)
        LOG.debug("_test_list_networks - fmt:%s - END", fmt)

    def _test_list_networks_detail(self, fmt):
        LOG.debug("_test_list_networks_detail - fmt:%s - START", fmt)
        content_type = "application/%s" % fmt
        self._create_network(fmt, "net_1")
        self._create_network(fmt, "net_2")
        list_network_req = testlib.network_list_detail_request(self.tenant_id,
                                                               fmt)
        list_network_res = list_network_req.get_response(self.api)
        self.assertEqual(list_network_res.status_int, 200)
        network_data = self._net_deserializers[content_type].\
                            deserialize(list_network_res.body)['body']
        # Check network count: should return 2
        self.assertEqual(len(network_data['networks']), 2)
        # Check contents - id & name for each network
        for network in network_data['networks']:
            self.assertTrue('id' in network and 'name' in network)
            self.assertTrue(network['id'] and network['name'])
        LOG.debug("_test_list_networks_detail - fmt:%s - END", fmt)

    def _test_show_network(self, fmt):
        LOG.debug("_test_show_network - fmt:%s - START", fmt)
        content_type = "application/%s" % fmt
        network_id = self._create_network(fmt)
        show_network_req = testlib.show_network_request(self.tenant_id,
                                                        network_id,
                                                        fmt)
        show_network_res = show_network_req.get_response(self.api)
        self.assertEqual(show_network_res.status_int, 200)
        network_data = self._deserialize_net_response(content_type,
                                                      show_network_res)
        self.assert_network(id=network_id, name=self.network_name,
                            network_data=network_data['network'])
        LOG.debug("_test_show_network - fmt:%s - END", fmt)

    def _test_show_network_detail(self, fmt):
        LOG.debug("_test_show_network_detail - fmt:%s - START", fmt)
        content_type = "application/%s" % fmt
        # Create a network and a port
        network_id = self._create_network(fmt)
        port_id = self._create_port(network_id, "ACTIVE", fmt)
        show_network_req = testlib.show_network_detail_request(
                                    self.tenant_id, network_id, fmt)
        show_network_res = show_network_req.get_response(self.api)
        self.assertEqual(show_network_res.status_int, 200)
        network_data = self._deserialize_net_response(content_type,
                                                      show_network_res)
        self.assert_network_details(id=network_id, name=self.network_name,
                                    port_id=port_id, port_state='ACTIVE',
                                    network_data=network_data['network'])
        LOG.debug("_test_show_network_detail - fmt:%s - END", fmt)

    def _test_show_network_not_found(self, fmt):
        LOG.debug("_test_show_network_not_found - fmt:%s - START", fmt)
        show_network_req = testlib.show_network_request(self.tenant_id,
                                                        "A_BAD_ID",
                                                        fmt)
        show_network_res = show_network_req.get_response(self.api)
        self.assertEqual(show_network_res.status_int, 420)
        LOG.debug("_test_show_network_not_found - fmt:%s - END", fmt)

    def _test_rename_network(self, fmt):
        LOG.debug("_test_rename_network - fmt:%s - START", fmt)
        content_type = "application/%s" % fmt
        new_name = 'new_network_name'
        network_id = self._create_network(fmt)
        update_network_req = testlib.update_network_request(self.tenant_id,
                                                            network_id,
                                                            new_name,
                                                            fmt)
        update_network_res = update_network_req.get_response(self.api)
        self.assertEqual(update_network_res.status_int, 204)
        show_network_req = testlib.show_network_request(self.tenant_id,
                                                        network_id,
                                                        fmt)
        show_network_res = show_network_req.get_response(self.api)
        self.assertEqual(show_network_res.status_int, 200)
        network_data = self._deserialize_net_response(content_type,
                                                      show_network_res)
        self.assert_network(id=network_id, name=new_name,
                            network_data=network_data['network'])
        LOG.debug("_test_rename_network - fmt:%s - END", fmt)

    def _test_rename_network_badrequest(self, fmt):
        LOG.debug("_test_rename_network_badrequest - fmt:%s - START",
                  fmt)
        network_id = self._create_network(fmt)
        bad_body = {'network': {'bad-attribute': 'very-bad'}}
        update_network_req = testlib.\
                             update_network_request(self.tenant_id,
                                                    network_id, fmt,
                                                    custom_req_body=bad_body)
        update_network_res = update_network_req.get_response(self.api)
        self.assertEqual(update_network_res.status_int, 400)
        LOG.debug("_test_rename_network_badrequest - fmt:%s - END",
                  fmt)

    def _test_rename_network_not_found(self, fmt):
        LOG.debug("_test_rename_network_not_found - fmt:%s - START",
                  fmt)
        new_name = 'new_network_name'
        update_network_req = testlib.update_network_request(self.tenant_id,
                                                            "A BAD ID",
                                                            new_name,
                                                            fmt)
        update_network_res = update_network_req.get_response(self.api)
        self.assertEqual(update_network_res.status_int, 420)
        LOG.debug("_test_rename_network_not_found - fmt:%s - END",
                  fmt)

    def _test_delete_network(self, fmt):
        LOG.debug("_test_delete_network - fmt:%s - START", fmt)
        content_type = "application/%s" % fmt
        network_id = self._create_network(fmt)
        LOG.debug("Deleting network %s"\
                  " of tenant %s" % (network_id, self.tenant_id))
        delete_network_req = testlib.network_delete_request(self.tenant_id,
                                                            network_id,
                                                            fmt)
        delete_network_res = delete_network_req.get_response(self.api)
        self.assertEqual(delete_network_res.status_int, 204)
        list_network_req = testlib.network_list_request(self.tenant_id,
                                                        fmt)
        list_network_res = list_network_req.get_response(self.api)
        network_list_data = self._net_deserializers[content_type].\
                                 deserialize(list_network_res.body)['body']
        network_count = len(network_list_data['networks'])
        self.assertEqual(network_count, 0)
        LOG.debug("_test_delete_network - fmt:%s - END", fmt)

    def _test_delete_network_in_use(self, fmt):
        LOG.debug("_test_delete_network_in_use - fmt:%s - START", fmt)
        port_state = "ACTIVE"
        attachment_id = "test_attachment"
        network_id = self._create_network(fmt)
        LOG.debug("Deleting network %s"\
                  " of tenant %s" % (network_id, self.tenant_id))
        port_id = self._create_port(network_id, port_state, fmt)
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
                                                            fmt)
        delete_network_res = delete_network_req.get_response(self.api)
        self.assertEqual(delete_network_res.status_int, 421)
        LOG.debug("_test_delete_network_in_use - fmt:%s - END", fmt)

    def _test_delete_network_with_unattached_port(self, fmt):
        LOG.debug("_test_delete_network_with_unattached_port "\
                    "- fmt:%s - START", fmt)
        port_state = "ACTIVE"
        network_id = self._create_network(fmt)
        LOG.debug("Deleting network %s"\
                  " of tenant %s" % (network_id, self.tenant_id))
        self._create_port(network_id, port_state, fmt)

        LOG.debug("Deleting network %s"\
                  " of tenant %s" % (network_id, self.tenant_id))
        delete_network_req = testlib.network_delete_request(self.tenant_id,
                                                            network_id,
                                                            fmt)
        delete_network_res = delete_network_req.get_response(self.api)
        self.assertEqual(delete_network_res.status_int, 204)
        LOG.debug("_test_delete_network_with_unattached_port "\
                    "- fmt:%s - END", fmt)

    def _test_list_ports(self, fmt):
        LOG.debug("_test_list_ports - fmt:%s - START", fmt)
        content_type = "application/%s" % fmt
        port_state = "ACTIVE"
        network_id = self._create_network(fmt)
        self._create_port(network_id, port_state, fmt)
        self._create_port(network_id, port_state, fmt)
        list_port_req = testlib.port_list_request(self.tenant_id,
                                                   network_id, fmt)
        list_port_res = list_port_req.get_response(self.api)
        self.assertEqual(list_port_res.status_int, 200)
        port_data = self._port_deserializers[content_type].\
                         deserialize(list_port_res.body)['body']
        # Check port count: should return 2
        self.assertEqual(len(port_data['ports']), 2)
        LOG.debug("_test_list_ports - fmt:%s - END", fmt)

    def _test_list_ports_networknotfound(self, fmt):
        LOG.debug("_test_list_ports_networknotfound"
                    " - fmt:%s - START", fmt)
        list_port_req = testlib.port_list_request(self.tenant_id,
                                                  "A_BAD_ID", fmt)
        list_port_res = list_port_req.get_response(self.api)
        self.assertEqual(list_port_res.status_int, 420)
        LOG.debug("_test_list_ports_networknotfound - fmt:%s - END", fmt)

    def _test_list_ports_detail(self, fmt):
        LOG.debug("_test_list_ports_detail - fmt:%s - START", fmt)
        content_type = "application/%s" % fmt
        port_state = "ACTIVE"
        network_id = self._create_network(fmt)
        self._create_port(network_id, port_state, fmt)
        self._create_port(network_id, port_state, fmt)
        list_port_req = testlib.port_list_detail_request(self.tenant_id,
                                                         network_id, fmt)
        list_port_res = list_port_req.get_response(self.api)
        self.assertEqual(list_port_res.status_int, 200)
        port_data = self._port_deserializers[content_type].\
                         deserialize(list_port_res.body)['body']
        # Check port count: should return 2
        self.assertEqual(len(port_data['ports']), 2)
        # Check contents - id & name for each network
        for port in port_data['ports']:
            self.assertTrue('id' in port and 'state' in port)
            self.assertTrue(port['id'] and port['state'])
        LOG.debug("_test_list_ports_detail - fmt:%s - END", fmt)

    def _test_show_port(self, fmt):
        LOG.debug("_test_show_port - fmt:%s - START", fmt)
        content_type = "application/%s" % fmt
        port_state = "ACTIVE"
        network_id = self._create_network(fmt)
        port_id = self._create_port(network_id, port_state, fmt)
        show_port_req = testlib.show_port_request(self.tenant_id,
                                                  network_id, port_id,
                                                  fmt)
        show_port_res = show_port_req.get_response(self.api)
        self.assertEqual(show_port_res.status_int, 200)
        port_data = self._deserialize_port_response(content_type,
                                                    show_port_res)
        self.assert_port(id=port_id, state=port_state,
                        port_data=port_data['port'])
        LOG.debug("_test_show_port - fmt:%s - END", fmt)

    def _test_show_port_detail(self, fmt):
        LOG.debug("_test_show_port - fmt:%s - START", fmt)
        content_type = "application/%s" % fmt
        port_state = "ACTIVE"
        network_id = self._create_network(fmt)
        port_id = self._create_port(network_id, port_state, fmt)

        # Part 1 - no attachment
        show_port_req = testlib.show_port_detail_request(self.tenant_id,
                                    network_id, port_id, fmt)
        show_port_res = show_port_req.get_response(self.api)
        self.assertEqual(show_port_res.status_int, 200)
        port_data = self._deserialize_port_response(content_type,
                                                    show_port_res)
        self.assert_port(id=port_id, state=port_state,
                        port_data=port_data['port'])

        # Part 2 - plug attachment into port
        interface_id = "test_interface"
        put_attachment_req = testlib.put_attachment_request(self.tenant_id,
                                                            network_id,
                                                            port_id,
                                                            interface_id,
                                                            fmt)
        put_attachment_res = put_attachment_req.get_response(self.api)
        self.assertEqual(put_attachment_res.status_int, 204)
        show_port_req = testlib.show_port_detail_request(self.tenant_id,
                                    network_id, port_id, fmt)
        show_port_res = show_port_req.get_response(self.api)
        self.assertEqual(show_port_res.status_int, 200)
        port_data = self._deserialize_port_response(content_type,
                                                    show_port_res)
        self.assert_port_attachment(id=port_id, state=port_state,
                                    interface_id=interface_id,
                                    port_data=port_data['port'])

        LOG.debug("_test_show_port_detail - fmt:%s - END", fmt)

    def _test_show_port_networknotfound(self, fmt):
        LOG.debug("_test_show_port_networknotfound - fmt:%s - START",
                  fmt)
        port_state = "ACTIVE"
        network_id = self._create_network(fmt)
        port_id = self._create_port(network_id, port_state, fmt)
        show_port_req = testlib.show_port_request(self.tenant_id,
                                                        "A_BAD_ID", port_id,
                                                        fmt)
        show_port_res = show_port_req.get_response(self.api)
        self.assertEqual(show_port_res.status_int, 420)
        LOG.debug("_test_show_port_networknotfound - fmt:%s - END",
                  fmt)

    def _test_show_port_portnotfound(self, fmt):
        LOG.debug("_test_show_port_portnotfound - fmt:%s - START", fmt)
        network_id = self._create_network(fmt)
        show_port_req = testlib.show_port_request(self.tenant_id,
                                                        network_id,
                                                        "A_BAD_ID",
                                                        fmt)
        show_port_res = show_port_req.get_response(self.api)
        self.assertEqual(show_port_res.status_int, 430)
        LOG.debug("_test_show_port_portnotfound - fmt:%s - END", fmt)

    def _test_create_port_noreqbody(self, fmt):
        LOG.debug("_test_create_port_noreqbody - fmt:%s - START", fmt)
        content_type = "application/%s" % fmt
        network_id = self._create_network(fmt)
        port_id = self._create_port(network_id, None, fmt,
                                    custom_req_body='')
        show_port_req = testlib.show_port_request(self.tenant_id,
                                                  network_id, port_id, fmt)
        show_port_res = show_port_req.get_response(self.api)
        self.assertEqual(show_port_res.status_int, 200)
        port_data = self._port_deserializers[content_type].\
                         deserialize(show_port_res.body)['body']
        self.assertEqual(port_id, port_data['port']['id'])
        LOG.debug("_test_create_port_noreqbody - fmt:%s - END", fmt)

    def _test_create_port(self, fmt):
        LOG.debug("_test_create_port - fmt:%s - START", fmt)
        content_type = "application/%s" % fmt
        port_state = "ACTIVE"
        network_id = self._create_network(fmt)
        port_id = self._create_port(network_id, port_state, fmt)
        show_port_req = testlib.show_port_request(self.tenant_id,
                                                  network_id, port_id, fmt)
        show_port_res = show_port_req.get_response(self.api)
        self.assertEqual(show_port_res.status_int, 200)
        port_data = self._port_deserializers[content_type].\
                         deserialize(show_port_res.body)['body']
        self.assertEqual(port_id, port_data['port']['id'])
        LOG.debug("_test_create_port - fmt:%s - END", fmt)

    def _test_create_port_networknotfound(self, fmt):
        LOG.debug("_test_create_port_networknotfound - fmt:%s - START",
                  fmt)
        port_state = "ACTIVE"
        self._create_port("A_BAD_ID", port_state, fmt,
                          expected_res_status=420)
        LOG.debug("_test_create_port_networknotfound - fmt:%s - END",
                  fmt)

    def _test_create_port_badrequest(self, fmt):
        LOG.debug("_test_create_port_badrequest - fmt:%s - START", fmt)
        bad_body = {'bad-resource': {'bad-attribute': 'bad-value'}}
        network_id = self._create_network(fmt)
        port_state = "ACTIVE"
        self._create_port(network_id, port_state, fmt,
                          custom_req_body=bad_body, expected_res_status=400)
        LOG.debug("_test_create_port_badrequest - fmt:%s - END", fmt)

    def _test_delete_port(self, fmt):
        LOG.debug("_test_delete_port - fmt:%s - START", fmt)
        content_type = "application/%s" % fmt
        port_state = "ACTIVE"
        network_id = self._create_network(fmt)
        port_id = self._create_port(network_id, port_state, fmt)
        LOG.debug("Deleting port %s for network %s"\
                  " of tenant %s" % (port_id, network_id,
                    self.tenant_id))
        delete_port_req = testlib.port_delete_request(self.tenant_id,
                                                      network_id, port_id,
                                                      fmt)
        delete_port_res = delete_port_req.get_response(self.api)
        self.assertEqual(delete_port_res.status_int, 204)
        list_port_req = testlib.port_list_request(self.tenant_id, network_id,
                                                  fmt)
        list_port_res = list_port_req.get_response(self.api)
        port_list_data = self._port_deserializers[content_type].\
                              deserialize(list_port_res.body)['body']
        port_count = len(port_list_data['ports'])
        self.assertEqual(port_count, 0)
        LOG.debug("_test_delete_port - fmt:%s - END", fmt)

    def _test_delete_port_in_use(self, fmt):
        LOG.debug("_test_delete_port_in_use - fmt:%s - START", fmt)
        port_state = "ACTIVE"
        attachment_id = "test_attachment"
        network_id = self._create_network(fmt)
        port_id = self._create_port(network_id, port_state, fmt)
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
                                                      fmt)
        delete_port_res = delete_port_req.get_response(self.api)
        self.assertEqual(delete_port_res.status_int, 432)
        LOG.debug("_test_delete_port_in_use - fmt:%s - END", fmt)

    def _test_delete_port_with_bad_id(self, fmt):
        LOG.debug("_test_delete_port_with_bad_id - fmt:%s - START",
                  fmt)
        port_state = "ACTIVE"
        network_id = self._create_network(fmt)
        self._create_port(network_id, port_state, fmt)
        # Test for portnotfound
        delete_port_req = testlib.port_delete_request(self.tenant_id,
                                                      network_id, "A_BAD_ID",
                                                      fmt)
        delete_port_res = delete_port_req.get_response(self.api)
        self.assertEqual(delete_port_res.status_int, 430)
        LOG.debug("_test_delete_port_with_bad_id - fmt:%s - END", fmt)

    def _test_delete_port_networknotfound(self, fmt):
        LOG.debug("_test_delete_port_networknotfound - fmt:%s - START",
                  fmt)
        port_state = "ACTIVE"
        network_id = self._create_network(fmt)
        port_id = self._create_port(network_id, port_state, fmt)
        delete_port_req = testlib.port_delete_request(self.tenant_id,
                                                      "A_BAD_ID", port_id,
                                                      fmt)
        delete_port_res = delete_port_req.get_response(self.api)
        self.assertEqual(delete_port_res.status_int, 420)
        LOG.debug("_test_delete_port_networknotfound - fmt:%s - END",
                  fmt)

    def _test_set_port_state(self, fmt):
        LOG.debug("_test_set_port_state - fmt:%s - START", fmt)
        content_type = "application/%s" % fmt
        port_state = 'DOWN'
        new_port_state = 'ACTIVE'
        network_id = self._create_network(fmt)
        port_id = self._create_port(network_id, port_state, fmt)
        update_port_req = testlib.update_port_request(self.tenant_id,
                                                        network_id, port_id,
                                                        new_port_state,
                                                        fmt)
        update_port_res = update_port_req.get_response(self.api)
        self.assertEqual(update_port_res.status_int, 204)
        show_port_req = testlib.show_port_request(self.tenant_id,
                                                  network_id, port_id,
                                                  fmt)
        show_port_res = show_port_req.get_response(self.api)
        self.assertEqual(show_port_res.status_int, 200)
        port_data = self._deserialize_port_response(content_type,
                                                    show_port_res)
        self.assert_port(id=port_id, state=new_port_state,
                         port_data=port_data['port'])
        # now set it back to the original value
        update_port_req = testlib.update_port_request(self.tenant_id,
                                                        network_id, port_id,
                                                        port_state,
                                                        fmt)
        update_port_res = update_port_req.get_response(self.api)
        self.assertEqual(update_port_res.status_int, 204)
        show_port_req = testlib.show_port_request(self.tenant_id,
                                                  network_id, port_id,
                                                  fmt)
        show_port_res = show_port_req.get_response(self.api)
        self.assertEqual(show_port_res.status_int, 200)
        port_data = self._deserialize_port_response(content_type,
                                                    show_port_res)
        self.assert_port(id=port_id, state=port_state,
                         port_data=port_data['port'])
        LOG.debug("_test_set_port_state - fmt:%s - END", fmt)

    def _test_set_port_state_networknotfound(self, fmt):
        LOG.debug("_test_set_port_state_networknotfound - fmt:%s - START",
                  fmt)
        port_state = 'DOWN'
        new_port_state = 'ACTIVE'
        network_id = self._create_network(fmt)
        port_id = self._create_port(network_id, port_state, fmt)
        update_port_req = testlib.update_port_request(self.tenant_id,
                                                        "A_BAD_ID", port_id,
                                                        new_port_state,
                                                        fmt)
        update_port_res = update_port_req.get_response(self.api)
        self.assertEqual(update_port_res.status_int, 420)
        LOG.debug("_test_set_port_state_networknotfound - fmt:%s - END",
                  fmt)

    def _test_set_port_state_portnotfound(self, fmt):
        LOG.debug("_test_set_port_state_portnotfound - fmt:%s - START",
                  fmt)
        port_state = 'DOWN'
        new_port_state = 'ACTIVE'
        network_id = self._create_network(fmt)
        self._create_port(network_id, port_state, fmt)
        update_port_req = testlib.update_port_request(self.tenant_id,
                                                        network_id,
                                                        "A_BAD_ID",
                                                        new_port_state,
                                                        fmt)
        update_port_res = update_port_req.get_response(self.api)
        self.assertEqual(update_port_res.status_int, 430)
        LOG.debug("_test_set_port_state_portnotfound - fmt:%s - END",
                  fmt)

    def _test_set_port_state_stateinvalid(self, fmt):
        LOG.debug("_test_set_port_state_stateinvalid - fmt:%s - START",
                  fmt)
        port_state = 'DOWN'
        new_port_state = 'A_BAD_STATE'
        network_id = self._create_network(fmt)
        port_id = self._create_port(network_id, port_state, fmt)
        update_port_req = testlib.update_port_request(self.tenant_id,
                                                        network_id, port_id,
                                                        new_port_state,
                                                        fmt)
        update_port_res = update_port_req.get_response(self.api)
        self.assertEqual(update_port_res.status_int, 431)
        LOG.debug("_test_set_port_state_stateinvalid - fmt:%s - END",
                  fmt)

    def _test_show_attachment(self, fmt):
        LOG.debug("_test_show_attachment - fmt:%s - START", fmt)
        content_type = "application/%s" % fmt
        port_state = "ACTIVE"
        network_id = self._create_network(fmt)
        interface_id = "test_interface"
        port_id = self._create_port(network_id, port_state, fmt)
        put_attachment_req = testlib.put_attachment_request(self.tenant_id,
                                                            network_id,
                                                            port_id,
                                                            interface_id,
                                                            fmt)
        put_attachment_res = put_attachment_req.get_response(self.api)
        self.assertEqual(put_attachment_res.status_int, 204)
        get_attachment_req = testlib.get_attachment_request(self.tenant_id,
                                                            network_id,
                                                            port_id,
                                                            fmt)
        get_attachment_res = get_attachment_req.get_response(self.api)
        attachment_data = self._att_deserializers[content_type].\
                               deserialize(get_attachment_res.body)['body']
        self.assertEqual(attachment_data['attachment']['id'], interface_id)
        LOG.debug("_test_show_attachment - fmt:%s - END", fmt)

    def _test_show_attachment_none_set(self, fmt):
        LOG.debug("_test_show_attachment_none_set - fmt:%s - START", fmt)
        content_type = "application/%s" % fmt
        port_state = "ACTIVE"
        network_id = self._create_network(fmt)
        port_id = self._create_port(network_id, port_state, fmt)
        get_attachment_req = testlib.get_attachment_request(self.tenant_id,
                                                            network_id,
                                                            port_id,
                                                            fmt)
        get_attachment_res = get_attachment_req.get_response(self.api)
        attachment_data = self._att_deserializers[content_type].\
                               deserialize(get_attachment_res.body)['body']
        self.assertTrue('id' not in attachment_data['attachment'])
        LOG.debug("_test_show_attachment_none_set - fmt:%s - END", fmt)

    def _test_show_attachment_networknotfound(self, fmt):
        LOG.debug("_test_show_attachment_networknotfound - fmt:%s - START",
                  fmt)
        port_state = "ACTIVE"
        network_id = self._create_network(fmt)
        port_id = self._create_port(network_id, port_state, fmt)
        get_attachment_req = testlib.get_attachment_request(self.tenant_id,
                                                            "A_BAD_ID",
                                                            port_id,
                                                            fmt)
        get_attachment_res = get_attachment_req.get_response(self.api)
        self.assertEqual(get_attachment_res.status_int, 420)
        LOG.debug("_test_show_attachment_networknotfound - fmt:%s - END",
                  fmt)

    def _test_show_attachment_portnotfound(self, fmt):
        LOG.debug("_test_show_attachment_portnotfound - fmt:%s - START",
                  fmt)
        port_state = "ACTIVE"
        network_id = self._create_network(fmt)
        self._create_port(network_id, port_state, fmt)
        get_attachment_req = testlib.get_attachment_request(self.tenant_id,
                                                            network_id,
                                                            "A_BAD_ID",
                                                            fmt)
        get_attachment_res = get_attachment_req.get_response(self.api)
        self.assertEqual(get_attachment_res.status_int, 430)
        LOG.debug("_test_show_attachment_portnotfound - fmt:%s - END",
                  fmt)

    def _test_put_attachment(self, fmt):
        LOG.debug("_test_put_attachment - fmt:%s - START", fmt)
        port_state = "ACTIVE"
        network_id = self._create_network(fmt)
        interface_id = "test_interface"
        port_id = self._create_port(network_id, port_state, fmt)
        put_attachment_req = testlib.put_attachment_request(self.tenant_id,
                                                            network_id,
                                                            port_id,
                                                            interface_id,
                                                            fmt)
        put_attachment_res = put_attachment_req.get_response(self.api)
        self.assertEqual(put_attachment_res.status_int, 204)
        LOG.debug("_test_put_attachment - fmt:%s - END", fmt)

    def _test_put_attachment_networknotfound(self, fmt):
        LOG.debug("_test_put_attachment_networknotfound - fmt:%s - START",
                  fmt)
        port_state = 'DOWN'
        interface_id = "test_interface"
        network_id = self._create_network(fmt)
        port_id = self._create_port(network_id, port_state, fmt)
        put_attachment_req = testlib.put_attachment_request(self.tenant_id,
                                                            "A_BAD_ID",
                                                            port_id,
                                                            interface_id,
                                                            fmt)
        put_attachment_res = put_attachment_req.get_response(self.api)
        self.assertEqual(put_attachment_res.status_int, 420)
        LOG.debug("_test_put_attachment_networknotfound - fmt:%s - END",
                  fmt)

    def _test_put_attachment_portnotfound(self, fmt):
        LOG.debug("_test_put_attachment_portnotfound - fmt:%s - START",
                  fmt)
        port_state = 'DOWN'
        interface_id = "test_interface"
        network_id = self._create_network(fmt)
        self._create_port(network_id, port_state, fmt)
        put_attachment_req = testlib.put_attachment_request(self.tenant_id,
                                                            network_id,
                                                            "A_BAD_ID",
                                                            interface_id,
                                                            fmt)
        put_attachment_res = put_attachment_req.get_response(self.api)
        self.assertEqual(put_attachment_res.status_int, 430)
        LOG.debug("_test_put_attachment_portnotfound - fmt:%s - END",
                  fmt)

    def _test_delete_attachment(self, fmt):
        LOG.debug("_test_delete_attachment - fmt:%s - START", fmt)
        port_state = "ACTIVE"
        network_id = self._create_network(fmt)
        interface_id = "test_interface"
        port_id = self._create_port(network_id, port_state, fmt)
        put_attachment_req = testlib.put_attachment_request(self.tenant_id,
                                                            network_id,
                                                            port_id,
                                                            interface_id,
                                                            fmt)
        put_attachment_res = put_attachment_req.get_response(self.api)
        self.assertEqual(put_attachment_res.status_int, 204)
        del_attachment_req = testlib.delete_attachment_request(self.tenant_id,
                                                               network_id,
                                                               port_id,
                                                               fmt)
        del_attachment_res = del_attachment_req.get_response(self.api)
        self.assertEqual(del_attachment_res.status_int, 204)
        LOG.debug("_test_delete_attachment - fmt:%s - END", fmt)

    def _test_delete_attachment_networknotfound(self, fmt):
        LOG.debug("_test_delete_attachment_networknotfound -" \
                  " fmt:%s - START", fmt)
        port_state = "ACTIVE"
        network_id = self._create_network(fmt)
        port_id = self._create_port(network_id, port_state, fmt)
        del_attachment_req = testlib.delete_attachment_request(self.tenant_id,
                                                               "A_BAD_ID",
                                                               port_id,
                                                               fmt)
        del_attachment_res = del_attachment_req.get_response(self.api)
        self.assertEqual(del_attachment_res.status_int, 420)
        LOG.debug("_test_delete_attachment_networknotfound -" \
                  " fmt:%s - END", fmt)

    def _test_delete_attachment_portnotfound(self, fmt):
        LOG.debug("_test_delete_attachment_portnotfound - " \
                  " fmt:%s - START", fmt)
        port_state = "ACTIVE"
        network_id = self._create_network(fmt)
        self._create_port(network_id, port_state, fmt)
        del_attachment_req = testlib.delete_attachment_request(self.tenant_id,
                                                               network_id,
                                                               "A_BAD_ID",
                                                               fmt)
        del_attachment_res = del_attachment_req.get_response(self.api)
        self.assertEqual(del_attachment_res.status_int, 430)
        LOG.debug("_test_delete_attachment_portnotfound - " \
                  "fmt:%s - END", fmt)

    def _test_unparsable_data(self, fmt):
        LOG.debug("_test_unparsable_data - " \
                  " fmt:%s - START", fmt)

        data = "this is not json or xml"
        method = 'POST'
        content_type = "application/%s" % fmt
        tenant_id = self.tenant_id
        path = "/tenants/%(tenant_id)s/networks.%(fmt)s" % locals()
        network_req = testlib.create_request(path, data, content_type, method)
        network_res = network_req.get_response(self.api)
        self.assertEqual(network_res.status_int, 400)

        LOG.debug("_test_unparsable_data - " \
                  "fmt:%s - END", fmt)

    def setUp(self, api_router_klass, xml_metadata_dict):
        options = {}
        options['plugin_provider'] = test_config['plugin_name']
        api_router_cls = utils.import_class(api_router_klass)
        self.api = api_router_cls(options)
        self.tenant_id = "test_tenant"
        self.network_name = "test_network"

        # Prepare XML & JSON deserializers
        net_xml_deserializer = XMLDeserializer(xml_metadata_dict[NETS])
        port_xml_deserializer = XMLDeserializer(xml_metadata_dict[PORTS])
        att_xml_deserializer = XMLDeserializer(xml_metadata_dict[ATTS])

        json_deserializer = JSONDeserializer()

        self._net_deserializers = {
            'application/xml': net_xml_deserializer,
            'application/json': json_deserializer,
        }
        self._port_deserializers = {
            'application/xml': port_xml_deserializer,
            'application/json': json_deserializer,
        }
        self._att_deserializers = {
            'application/xml': att_xml_deserializer,
            'application/json': json_deserializer,
        }

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

    def test_create_network_badrequest_xml(self):
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
