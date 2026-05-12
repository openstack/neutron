# Copyright 2026 Red Hat, LLC
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

from neutron_lib.api.definitions import provider_net as pnet
import webob

from neutron.tests.unit.plugins.ml2 import test_plugin as ml2_test

BGP_PLUGIN = 'neutron.services.bgp.plugin.BGPServicePlugin'


class BGPServicePluginAPITestCase(ml2_test.Ml2PluginV2TestCase):

    def get_additional_service_plugins(self):
        return {'bgp_plugin': BGP_PLUGIN}

    def test_create_network_vlan_rejected(self):
        data = {'network': {'name': 'net-vlan',
                            'project_id': self._project_id,
                            pnet.NETWORK_TYPE: 'vlan',
                            pnet.PHYSICAL_NETWORK: 'physnet1',
                            pnet.SEGMENTATION_ID: 1}}
        req = self.new_create_request('networks', data, as_admin=True)
        res = req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_network_flat_allowed(self):
        data = {'network': {'name': 'net-flat',
                            'project_id': self._project_id,
                            pnet.NETWORK_TYPE: 'flat',
                            pnet.PHYSICAL_NETWORK: 'physnet1'}}
        req = self.new_create_request('networks', data, as_admin=True)
        res = req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPCreated.code, res.status_int)

    def test_create_network_geneve_allowed(self):
        res = self._create_network(
            self.fmt, 'net-geneve', network_type='geneve',
            admin_state_up=True, as_admin=True)
        self.assertEqual(webob.exc.HTTPCreated.code, res.status_int)

    def test_create_second_flat_network_rejected(self):
        data = {'network': {'name': 'net-flat-1',
                            'project_id': self._project_id,
                            pnet.NETWORK_TYPE: 'flat',
                            pnet.PHYSICAL_NETWORK: 'physnet1'}}
        req = self.new_create_request('networks', data, as_admin=True)
        res = req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPCreated.code, res.status_int)

        data = {'network': {'name': 'net-flat-2',
                            'project_id': self._project_id,
                            pnet.NETWORK_TYPE: 'flat',
                            pnet.PHYSICAL_NETWORK: 'physnet2'}}
        req = self.new_create_request('networks', data, as_admin=True)
        res = req.get_response(self.api)
        self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)
