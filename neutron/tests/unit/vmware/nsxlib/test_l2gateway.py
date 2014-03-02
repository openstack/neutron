# Copyright (c) 2014 VMware, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from neutron.plugins.vmware.api_client import exception
from neutron.plugins.vmware.nsxlib import l2gateway as l2gwlib
from neutron.plugins.vmware.nsxlib import switch as switchlib
from neutron.tests.unit import test_api_v2
from neutron.tests.unit.vmware.nsxlib import base

_uuid = test_api_v2._uuid


class L2GatewayNegativeTestCase(base.NsxlibNegativeBaseTestCase):

    def test_create_l2_gw_service_on_failure(self):
        self.assertRaises(exception.NsxApiException,
                          l2gwlib.create_l2_gw_service,
                          self.fake_cluster,
                          'fake-tenant',
                          'fake-gateway',
                          [{'id': _uuid(),
                           'interface_name': 'xxx'}])

    def test_delete_l2_gw_service_on_failure(self):
        self.assertRaises(exception.NsxApiException,
                          l2gwlib.delete_l2_gw_service,
                          self.fake_cluster,
                          'fake-gateway')

    def test_get_l2_gw_service_on_failure(self):
        self.assertRaises(exception.NsxApiException,
                          l2gwlib.get_l2_gw_service,
                          self.fake_cluster,
                          'fake-gateway')

    def test_update_l2_gw_service_on_failure(self):
        self.assertRaises(exception.NsxApiException,
                          l2gwlib.update_l2_gw_service,
                          self.fake_cluster,
                          'fake-gateway',
                          'pluto')


class L2GatewayTestCase(base.NsxlibTestCase):

    def _create_gw_service(self, node_uuid, display_name,
                           tenant_id='fake_tenant'):
        return l2gwlib.create_l2_gw_service(self.fake_cluster,
                                            tenant_id,
                                            display_name,
                                            [{'id': node_uuid,
                                              'interface_name': 'xxx'}])

    def test_create_l2_gw_service(self):
        display_name = 'fake-gateway'
        node_uuid = _uuid()
        response = self._create_gw_service(node_uuid, display_name)
        self.assertEqual(response.get('type'), 'L2GatewayServiceConfig')
        self.assertEqual(response.get('display_name'), display_name)
        gateways = response.get('gateways', [])
        self.assertEqual(len(gateways), 1)
        self.assertEqual(gateways[0]['type'], 'L2Gateway')
        self.assertEqual(gateways[0]['device_id'], 'xxx')
        self.assertEqual(gateways[0]['transport_node_uuid'], node_uuid)

    def test_update_l2_gw_service(self):
        display_name = 'fake-gateway'
        new_display_name = 'still-fake-gateway'
        node_uuid = _uuid()
        res1 = self._create_gw_service(node_uuid, display_name)
        gw_id = res1['uuid']
        res2 = l2gwlib.update_l2_gw_service(
            self.fake_cluster, gw_id, new_display_name)
        self.assertEqual(res2['display_name'], new_display_name)

    def test_get_l2_gw_service(self):
        display_name = 'fake-gateway'
        node_uuid = _uuid()
        gw_id = self._create_gw_service(node_uuid, display_name)['uuid']
        response = l2gwlib.get_l2_gw_service(self.fake_cluster, gw_id)
        self.assertEqual(response.get('type'), 'L2GatewayServiceConfig')
        self.assertEqual(response.get('display_name'), display_name)
        self.assertEqual(response.get('uuid'), gw_id)

    def test_list_l2_gw_service(self):
        gw_ids = []
        for name in ('fake-1', 'fake-2'):
            gw_ids.append(self._create_gw_service(_uuid(), name)['uuid'])
        results = l2gwlib.get_l2_gw_services(self.fake_cluster)
        self.assertEqual(len(results), 2)
        self.assertEqual(sorted(gw_ids), sorted([r['uuid'] for r in results]))

    def test_list_l2_gw_service_by_tenant(self):
        gw_ids = [self._create_gw_service(
                  _uuid(), name, tenant_id=name)['uuid']
                  for name in ('fake-1', 'fake-2')]
        results = l2gwlib.get_l2_gw_services(self.fake_cluster,
                                             tenant_id='fake-1')
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['uuid'], gw_ids[0])

    def test_delete_l2_gw_service(self):
        display_name = 'fake-gateway'
        node_uuid = _uuid()
        gw_id = self._create_gw_service(node_uuid, display_name)['uuid']
        l2gwlib.delete_l2_gw_service(self.fake_cluster, gw_id)
        results = l2gwlib.get_l2_gw_services(self.fake_cluster)
        self.assertEqual(len(results), 0)

    def test_plug_l2_gw_port_attachment(self):
        tenant_id = 'pippo'
        node_uuid = _uuid()
        transport_zones_config = [{'zone_uuid': _uuid(),
                                   'transport_type': 'stt'}]
        lswitch = switchlib.create_lswitch(
            self.fake_cluster, _uuid(), tenant_id,
            'fake-switch', transport_zones_config)
        gw_id = self._create_gw_service(node_uuid, 'fake-gw')['uuid']
        lport = switchlib.create_lport(
            self.fake_cluster, lswitch['uuid'], tenant_id, _uuid(),
            'fake-gw-port', gw_id, True)
        l2gwlib.plug_l2_gw_service(
            self.fake_cluster, lswitch['uuid'],
            lport['uuid'], gw_id)
        uri = l2gwlib._build_uri_path(switchlib.LSWITCHPORT_RESOURCE,
                                      lport['uuid'],
                                      lswitch['uuid'],
                                      is_attachment=True)
        resp_obj = l2gwlib.do_request("GET", uri,
                                      cluster=self.fake_cluster)
        self.assertIn('LogicalPortAttachment', resp_obj)
        self.assertEqual(resp_obj['LogicalPortAttachment']['type'],
                         'L2GatewayAttachment')
