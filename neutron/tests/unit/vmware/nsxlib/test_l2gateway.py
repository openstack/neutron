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

import mock
from oslo_serialization import jsonutils

from neutron.plugins.vmware.api_client import exception
from neutron.plugins.vmware.common import utils as nsx_utils
from neutron.plugins.vmware import nsxlib
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
        uri = nsxlib._build_uri_path(switchlib.LSWITCHPORT_RESOURCE,
                                     lport['uuid'],
                                     lswitch['uuid'],
                                     is_attachment=True)
        resp_obj = nsxlib.do_request("GET", uri,
                                     cluster=self.fake_cluster)
        self.assertIn('LogicalPortAttachment', resp_obj)
        self.assertEqual(resp_obj['LogicalPortAttachment']['type'],
                         'L2GatewayAttachment')

    def _create_expected_req_body(self, display_name, neutron_id,
                                  connector_type, connector_ip,
                                  client_certificate):
        body = {
            "display_name": display_name,
            "tags": [{"tag": neutron_id, "scope": "q_gw_dev_id"},
                     {"tag": 'fake_tenant', "scope": "os_tid"},
                     {"tag": nsx_utils.NEUTRON_VERSION,
                      "scope": "quantum"}],
            "transport_connectors": [
                {"transport_zone_uuid": 'fake_tz_uuid',
                    "ip_address": connector_ip,
                    "type": '%sConnector' % connector_type}],
            "admin_status_enabled": True
        }
        body.get("tags").sort()
        if client_certificate:
            body["credential"] = {
                "client_certificate": {
                    "pem_encoded": client_certificate},
                "type": "SecurityCertificateCredential"}
        return body

    def test_create_gw_device(self):
        # NOTE(salv-orlando): This unit test mocks backend calls rather than
        # leveraging the fake NSX API client
        display_name = 'fake-device'
        neutron_id = 'whatever'
        connector_type = 'stt'
        connector_ip = '1.1.1.1'
        client_certificate = 'this_should_be_a_certificate'
        with mock.patch.object(nsxlib, 'do_request') as request_mock:
            expected_req_body = self._create_expected_req_body(
                display_name, neutron_id, connector_type.upper(),
                connector_ip, client_certificate)
            l2gwlib.create_gateway_device(
                self.fake_cluster, 'fake_tenant', display_name, neutron_id,
                'fake_tz_uuid', connector_type, connector_ip,
                client_certificate)
            request_mock.assert_called_once_with(
                "POST",
                "/ws.v1/transport-node",
                jsonutils.dumps(expected_req_body, sort_keys=True),
                cluster=self.fake_cluster)

    def test_update_gw_device(self):
        # NOTE(salv-orlando): This unit test mocks backend calls rather than
        # leveraging the fake NSX API client
        display_name = 'fake-device'
        neutron_id = 'whatever'
        connector_type = 'stt'
        connector_ip = '1.1.1.1'
        client_certificate = 'this_should_be_a_certificate'
        with mock.patch.object(nsxlib, 'do_request') as request_mock:
            expected_req_body = self._create_expected_req_body(
                display_name, neutron_id, connector_type.upper(),
                connector_ip, client_certificate)
            l2gwlib.update_gateway_device(
                self.fake_cluster, 'whatever', 'fake_tenant',
                display_name, neutron_id,
                'fake_tz_uuid', connector_type, connector_ip,
                client_certificate)

            request_mock.assert_called_once_with(
                "PUT",
                "/ws.v1/transport-node/whatever",
                jsonutils.dumps(expected_req_body, sort_keys=True),
                cluster=self.fake_cluster)

    def test_update_gw_device_without_certificate(self):
        # NOTE(salv-orlando): This unit test mocks backend calls rather than
        # leveraging the fake NSX API client
        display_name = 'fake-device'
        neutron_id = 'whatever'
        connector_type = 'stt'
        connector_ip = '1.1.1.1'
        with mock.patch.object(nsxlib, 'do_request') as request_mock:
            expected_req_body = self._create_expected_req_body(
                display_name, neutron_id, connector_type.upper(),
                connector_ip, None)
            l2gwlib.update_gateway_device(
                self.fake_cluster, 'whatever', 'fake_tenant',
                display_name, neutron_id,
                'fake_tz_uuid', connector_type, connector_ip,
                client_certificate=None)

            request_mock.assert_called_once_with(
                "PUT",
                "/ws.v1/transport-node/whatever",
                jsonutils.dumps(expected_req_body, sort_keys=True),
                cluster=self.fake_cluster)

    def test_get_gw_device_status(self):
        # NOTE(salv-orlando): This unit test mocks backend calls rather than
        # leveraging the fake NSX API client
        with mock.patch.object(nsxlib, 'do_request') as request_mock:
            l2gwlib.get_gateway_device_status(self.fake_cluster, 'whatever')
            request_mock.assert_called_once_with(
                "GET",
                "/ws.v1/transport-node/whatever/status",
                cluster=self.fake_cluster)

    def test_get_gw_devices_status(self):
        # NOTE(salv-orlando): This unit test mocks backend calls rather than
        # leveraging the fake NSX API client
        with mock.patch.object(nsxlib, 'do_request') as request_mock:
            request_mock.return_value = {
                'results': [],
                'page_cursor': None,
                'result_count': 0}
            l2gwlib.get_gateway_devices_status(self.fake_cluster)
            request_mock.assert_called_once_with(
                "GET",
                ("/ws.v1/transport-node?fields=uuid,tags&"
                 "relations=TransportNodeStatus&"
                 "_page_length=1000&tag_scope=quantum"),
                cluster=self.fake_cluster)

    def test_get_gw_devices_status_filter_by_tenant(self):
        # NOTE(salv-orlando): This unit test mocks backend calls rather than
        # leveraging the fake NSX API client
        with mock.patch.object(nsxlib, 'do_request') as request_mock:
            request_mock.return_value = {
                'results': [],
                'page_cursor': None,
                'result_count': 0}
            l2gwlib.get_gateway_devices_status(self.fake_cluster,
                                               tenant_id='ssc_napoli')
            request_mock.assert_called_once_with(
                "GET",
                ("/ws.v1/transport-node?fields=uuid,tags&"
                 "relations=TransportNodeStatus&"
                 "tag=ssc_napoli&tag_scope=os_tid&"
                 "_page_length=1000&tag_scope=quantum"),
                cluster=self.fake_cluster)

    def test_delete_gw_device(self):
        # NOTE(salv-orlando): This unit test mocks backend calls rather than
        # leveraging the fake NSX API client
        with mock.patch.object(nsxlib, 'do_request') as request_mock:
            l2gwlib.delete_gateway_device(self.fake_cluster, 'whatever')
            request_mock.assert_called_once_with(
                "DELETE",
                "/ws.v1/transport-node/whatever",
                cluster=self.fake_cluster)
