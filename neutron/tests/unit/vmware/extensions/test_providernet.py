# Copyright (c) 2014 OpenStack Foundation.
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

from oslo.config import cfg

from neutron.extensions import multiprovidernet as mpnet
from neutron.extensions import providernet as pnet
from neutron.tests.unit.vmware import NSXEXT_PATH
from neutron.tests.unit.vmware.test_nsx_plugin import NsxPluginV2TestCase


class TestProvidernet(NsxPluginV2TestCase):

    def test_create_provider_network_default_physical_net(self):
        data = {'network': {'name': 'net1',
                            'admin_state_up': True,
                            'tenant_id': 'admin',
                            pnet.NETWORK_TYPE: 'vlan',
                            pnet.SEGMENTATION_ID: 411}}
        network_req = self.new_create_request('networks', data, self.fmt)
        net = self.deserialize(self.fmt, network_req.get_response(self.api))
        self.assertEqual(net['network'][pnet.NETWORK_TYPE], 'vlan')
        self.assertEqual(net['network'][pnet.SEGMENTATION_ID], 411)

    def test_create_provider_network(self):
        data = {'network': {'name': 'net1',
                            'admin_state_up': True,
                            'tenant_id': 'admin',
                            pnet.NETWORK_TYPE: 'vlan',
                            pnet.SEGMENTATION_ID: 411,
                            pnet.PHYSICAL_NETWORK: 'physnet1'}}
        network_req = self.new_create_request('networks', data, self.fmt)
        net = self.deserialize(self.fmt, network_req.get_response(self.api))
        self.assertEqual(net['network'][pnet.NETWORK_TYPE], 'vlan')
        self.assertEqual(net['network'][pnet.SEGMENTATION_ID], 411)
        self.assertEqual(net['network'][pnet.PHYSICAL_NETWORK], 'physnet1')


class TestMultiProviderNetworks(NsxPluginV2TestCase):

    def setUp(self, plugin=None):
        cfg.CONF.set_override('api_extensions_path', NSXEXT_PATH)
        super(TestMultiProviderNetworks, self).setUp()

    def test_create_network_provider(self):
        data = {'network': {'name': 'net1',
                            pnet.NETWORK_TYPE: 'vlan',
                            pnet.PHYSICAL_NETWORK: 'physnet1',
                            pnet.SEGMENTATION_ID: 1,
                            'tenant_id': 'tenant_one'}}
        network_req = self.new_create_request('networks', data)
        network = self.deserialize(self.fmt,
                                   network_req.get_response(self.api))
        self.assertEqual(network['network'][pnet.NETWORK_TYPE], 'vlan')
        self.assertEqual(network['network'][pnet.PHYSICAL_NETWORK], 'physnet1')
        self.assertEqual(network['network'][pnet.SEGMENTATION_ID], 1)
        self.assertNotIn(mpnet.SEGMENTS, network['network'])

    def test_create_network_provider_flat(self):
        data = {'network': {'name': 'net1',
                            pnet.NETWORK_TYPE: 'flat',
                            pnet.PHYSICAL_NETWORK: 'physnet1',
                            'tenant_id': 'tenant_one'}}
        network_req = self.new_create_request('networks', data)
        network = self.deserialize(self.fmt,
                                   network_req.get_response(self.api))
        self.assertEqual('flat', network['network'][pnet.NETWORK_TYPE])
        self.assertEqual('physnet1', network['network'][pnet.PHYSICAL_NETWORK])
        self.assertEqual(0, network['network'][pnet.SEGMENTATION_ID])
        self.assertNotIn(mpnet.SEGMENTS, network['network'])

    def test_create_network_single_multiple_provider(self):
        data = {'network': {'name': 'net1',
                            mpnet.SEGMENTS:
                            [{pnet.NETWORK_TYPE: 'vlan',
                              pnet.PHYSICAL_NETWORK: 'physnet1',
                              pnet.SEGMENTATION_ID: 1}],
                            'tenant_id': 'tenant_one'}}
        net_req = self.new_create_request('networks', data)
        network = self.deserialize(self.fmt, net_req.get_response(self.api))
        for provider_field in [pnet.NETWORK_TYPE, pnet.PHYSICAL_NETWORK,
                               pnet.SEGMENTATION_ID]:
            self.assertNotIn(provider_field, network['network'])
        tz = network['network'][mpnet.SEGMENTS][0]
        self.assertEqual(tz[pnet.NETWORK_TYPE], 'vlan')
        self.assertEqual(tz[pnet.PHYSICAL_NETWORK], 'physnet1')
        self.assertEqual(tz[pnet.SEGMENTATION_ID], 1)

        # Tests get_network()
        net_req = self.new_show_request('networks', network['network']['id'])
        network = self.deserialize(self.fmt, net_req.get_response(self.api))
        tz = network['network'][mpnet.SEGMENTS][0]
        self.assertEqual(tz[pnet.NETWORK_TYPE], 'vlan')
        self.assertEqual(tz[pnet.PHYSICAL_NETWORK], 'physnet1')
        self.assertEqual(tz[pnet.SEGMENTATION_ID], 1)

    def test_create_network_multprovider(self):
        data = {'network': {'name': 'net1',
                            mpnet.SEGMENTS:
                            [{pnet.NETWORK_TYPE: 'vlan',
                              pnet.PHYSICAL_NETWORK: 'physnet1',
                              pnet.SEGMENTATION_ID: 1},
                             {pnet.NETWORK_TYPE: 'stt',
                              pnet.PHYSICAL_NETWORK: 'physnet1'}],
                            'tenant_id': 'tenant_one'}}
        network_req = self.new_create_request('networks', data)
        network = self.deserialize(self.fmt,
                                   network_req.get_response(self.api))
        tz = network['network'][mpnet.SEGMENTS]
        for tz in data['network'][mpnet.SEGMENTS]:
            for field in [pnet.NETWORK_TYPE, pnet.PHYSICAL_NETWORK,
                          pnet.SEGMENTATION_ID]:
                self.assertEqual(tz.get(field), tz.get(field))

        # Tests get_network()
        net_req = self.new_show_request('networks', network['network']['id'])
        network = self.deserialize(self.fmt, net_req.get_response(self.api))
        tz = network['network'][mpnet.SEGMENTS]
        for tz in data['network'][mpnet.SEGMENTS]:
            for field in [pnet.NETWORK_TYPE, pnet.PHYSICAL_NETWORK,
                          pnet.SEGMENTATION_ID]:
                self.assertEqual(tz.get(field), tz.get(field))

    def test_create_network_with_provider_and_multiprovider_fail(self):
        data = {'network': {'name': 'net1',
                            mpnet.SEGMENTS:
                            [{pnet.NETWORK_TYPE: 'vlan',
                              pnet.PHYSICAL_NETWORK: 'physnet1',
                              pnet.SEGMENTATION_ID: 1}],
                            pnet.NETWORK_TYPE: 'vlan',
                            pnet.PHYSICAL_NETWORK: 'physnet1',
                            pnet.SEGMENTATION_ID: 1,
                            'tenant_id': 'tenant_one'}}

        network_req = self.new_create_request('networks', data)
        res = network_req.get_response(self.api)
        self.assertEqual(res.status_int, 400)

    def test_create_network_duplicate_segments(self):
        data = {'network': {'name': 'net1',
                            mpnet.SEGMENTS:
                            [{pnet.NETWORK_TYPE: 'vlan',
                              pnet.PHYSICAL_NETWORK: 'physnet1',
                              pnet.SEGMENTATION_ID: 1},
                             {pnet.NETWORK_TYPE: 'vlan',
                              pnet.PHYSICAL_NETWORK: 'physnet1',
                              pnet.SEGMENTATION_ID: 1}],
                            'tenant_id': 'tenant_one'}}
        network_req = self.new_create_request('networks', data)
        res = network_req.get_response(self.api)
        self.assertEqual(res.status_int, 400)
