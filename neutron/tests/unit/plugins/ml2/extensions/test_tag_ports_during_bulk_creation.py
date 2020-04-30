# Copyright (c) 2019 Verizon Media
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

import copy
from unittest import mock

from neutron_lib.plugins import directory
from oslo_config import cfg

from neutron.plugins.ml2.extensions import tag_ports_during_bulk_creation
from neutron.tests.unit.plugins.ml2 import test_plugin


TAGS = [
    ['tag-1', 'tag-2', 'tag-3'],
    ['tag-1', 'tag-2'],
    ['tag-1', 'tag-3'],
    []
]


class TagPortsDuringBulkCreationTestCase(test_plugin.Ml2PluginV2TestCase):
    _extension_drivers = ['tag_ports_during_bulk_creation']
    fmt = 'json'

    def get_additional_service_plugins(self):
        p = super(TagPortsDuringBulkCreationTestCase,
                self).get_additional_service_plugins()
        p.update({'tag_name': 'tag'})
        return p

    def setUp(self):
        cfg.CONF.set_override('extension_drivers',
                              self._extension_drivers,
                              group='ml2')
        super(TagPortsDuringBulkCreationTestCase, self).setUp()
        self.plugin = directory.get_plugin()

    def test_create_ports_bulk_with_tags(self):
        num_ports = 3
        tenant_id = 'some_tenant'
        with self.network(tenant_id=tenant_id) as network_to_use:
            net_id = network_to_use['network']['id']
            port = {'port': {'network_id': net_id,
                             'admin_state_up': True,
                             'tenant_id': tenant_id}}
            ports = [copy.deepcopy(port) for x in range(num_ports)]
            ports_tags_map = {}
            for port, tags in zip(ports, TAGS):
                port['port']['tags'] = tags
                port['port']['name'] = '-'.join(tags)
                ports_tags_map[port['port']['name']] = tags
            req_body = {'ports': ports}
            ports_req = self.new_create_request('ports', req_body)
            res = ports_req.get_response(self.api)
            self.assertEqual(201, res.status_int)
            created_ports = self.deserialize(self.fmt, res)

        for port in created_ports['ports']:
            self.assertEqual(ports_tags_map[port['name']], port['tags'])

    def test_create_ports_bulk_no_tags(self):
        num_ports = 2
        tenant_id = 'some_tenant'
        with self.network(tenant_id=tenant_id) as network_to_use:
            net_id = network_to_use['network']['id']
            port = {'port': {'name': 'port',
                             'network_id': net_id,
                             'admin_state_up': True,
                             'tenant_id': tenant_id}}
            ports = [copy.deepcopy(port) for x in range(num_ports)]
            req_body = {'ports': ports}
            ports_req = self.new_create_request('ports', req_body)
            res = ports_req.get_response(self.api)
            self.assertEqual(201, res.status_int)
            created_ports = self.deserialize(self.fmt, res)
            for port in created_ports['ports']:
                self.assertFalse(port['tags'])

    def test_create_port_with_tags(self):
        tenant_id = 'some_tenant'
        with self.network(tenant_id=tenant_id) as network_to_use:
            net_id = network_to_use['network']['id']
            req_body = {'port': {'name': 'port',
                                 'network_id': net_id,
                                 'admin_state_up': True,
                                 'tenant_id': tenant_id,
                                 'tags': TAGS[0]}}
            port_req = self.new_create_request('ports', req_body)
            res = port_req.get_response(self.api)
            self.assertEqual(201, res.status_int)
            created_port = self.deserialize(self.fmt, res)
            self.assertEqual(TAGS[0], created_port['port']['tags'])

    def test_type_args_passed_to_extension(self):
        num_ports = 2
        tenant_id = 'some_tenant'
        extension = tag_ports_during_bulk_creation
        with mock.patch.object(
                extension.TagPortsDuringBulkCreationExtensionDriver,
                'process_create_port') as patched_method:
            with self.network(tenant_id=tenant_id) as network_to_use:
                net_id = network_to_use['network']['id']
                port = {'port': {'network_id': net_id,
                                 'admin_state_up': True,
                                 'tenant_id': tenant_id}}
                ports = [copy.deepcopy(port) for x in range(num_ports)]
                ports[0]['port']['tags'] = TAGS[0]
                ports[1]['port']['tags'] = TAGS[1]
                req_body = {'ports': ports}
                ports_req = self.new_create_request('ports', req_body)
                res = ports_req.get_response(self.api)
                self.assertEqual(201, res.status_int)
                self.assertIsInstance(patched_method.call_args[0][1],
                                      dict)
                self.assertIsInstance(patched_method.call_args[0][2],
                                      dict)
