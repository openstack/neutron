# Copyright 2014 Alcatel-Lucent USA Inc.
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

import contextlib
import uuid
import webob.exc

from neutron import manager
from neutron.plugins.nuage.extensions import netpartition as netpart_ext
from neutron.tests.unit.nuage import test_nuage_plugin
from neutron.tests.unit import test_extensions


class NetPartitionTestExtensionManager(object):
    def get_resources(self):
        return netpart_ext.Netpartition.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class NetPartitionTestCase(test_nuage_plugin.NuagePluginV2TestCase):
    def setUp(self):
        ext_mgr = NetPartitionTestExtensionManager()
        super(NetPartitionTestCase, self).setUp()
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)

    def _make_netpartition(self, fmt, name):
        data = {
            'net_partition': {
                'name': name,
                'tenant_id': uuid.uuid4()
            }
        }
        netpart_req = self.new_create_request('net-partitions', data, fmt)
        resp = netpart_req.get_response(self.ext_api)
        if resp.status_int >= webob.exc.HTTPClientError.code:
            raise webob.exc.HTTPClientError(code=resp.status_int)
        return self.deserialize(fmt, resp)

    def _del_netpartition(self, id):
        self._delete('net-partitions', id)

    @contextlib.contextmanager
    def netpartition(self, name='netpartition1',
                     fmt=None,
                     **kwargs):
        netpart = self._make_netpartition(fmt or self.fmt, name)

        yield netpart

    def test_create_netpartition(self):
        name = 'netpart1'
        keys = [('name', name)]
        with self.netpartition(name=name) as netpart:
            for k, v in keys:
                self.assertEqual(netpart['net_partition'][k], v)

    def test_delete_netpartition(self):
        name = 'netpart1'
        netpart = self._make_netpartition(self.fmt, name)
        req = self.new_delete_request('net-partitions',
                                      netpart['net_partition']['id'])
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, webob.exc.HTTPNoContent.code)

    def test_show_netpartition(self):
        with self.netpartition(name='netpart1') as npart:
            req = self.new_show_request('net-partitions',
                                        npart['net_partition']['id'])
            res = self.deserialize(self.fmt, req.get_response(self.ext_api))
            self.assertEqual(res['net_partition']['name'],
                             npart['net_partition']['name'])

    def test_create_existing_default_netpartition(self):
        name = 'default_test_np'
        netpart1 = self._make_netpartition(self.fmt, name)
        nuage_plugin = manager.NeutronManager.get_plugin()
        netpart2 = nuage_plugin._create_default_net_partition(name)
        self.assertEqual(netpart1['net_partition']['name'],
                         netpart2['name'])
