# Copyright (c) 2013 OpenStack Foundation.
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
# @author: Salvatore Orlando, VMware

import mock
import os

from quantum.openstack.common import jsonutils as json
import quantum.plugins.nicira.nicira_nvp_plugin as nvp_plugin
from quantum.plugins.nicira.nicira_nvp_plugin import nvp_cluster
from quantum.plugins.nicira.nicira_nvp_plugin import NvpApiClient
from quantum.plugins.nicira.nicira_nvp_plugin import nvplib
from quantum.tests import base
from quantum.tests.unit.nicira import fake_nvpapiclient
from quantum.tests.unit import test_api_v2

NICIRA_PKG_PATH = nvp_plugin.__name__
_uuid = test_api_v2._uuid


class NvplibTestCase(base.BaseTestCase):

    def setUp(self):
        # mock nvp api client
        etc_path = os.path.join(os.path.dirname(__file__), 'etc')
        self.fc = fake_nvpapiclient.FakeClient(etc_path)
        self.mock_nvpapi = mock.patch('%s.NvpApiClient.NVPApiHelper'
                                      % NICIRA_PKG_PATH, autospec=True)
        instance = self.mock_nvpapi.start()
        instance.return_value.login.return_value = "the_cookie"

        def _fake_request(*args, **kwargs):
            return self.fc.fake_request(*args, **kwargs)

        instance.return_value.request.side_effect = _fake_request
        self.fake_cluster = nvp_cluster.NVPCluster('fake-cluster')
        self.fake_cluster.add_controller('1.1.1.1', '999', 'foo', 'bar',
                                         9, 9, 9, 9, _uuid())
        self.fake_cluster.api_client = NvpApiClient.NVPApiHelper(
            ('1.1.1.1', '999', True),
            self.fake_cluster.user, self.fake_cluster.password,
            self.fake_cluster.request_timeout, self.fake_cluster.http_timeout,
            self.fake_cluster.retries, self.fake_cluster.redirects)

        super(NvplibTestCase, self).setUp()
        self.addCleanup(self.fc.reset_all)
        self.addCleanup(self.mock_nvpapi.stop)


class TestNvplibNatRules(NvplibTestCase):

    def _test_create_lrouter_dnat_rule(self, func):
        tenant_id = 'pippo'
        lrouter = nvplib.create_lrouter(self.fake_cluster,
                                        tenant_id,
                                        'fake_router',
                                        '192.168.0.1')
        nat_rule = func(self.fake_cluster, lrouter['uuid'], '10.0.0.99',
                        match_criteria={'destination_ip_addresses':
                                        '192.168.0.5'})
        uri = nvplib._build_uri_path(nvplib.LROUTERNAT_RESOURCE,
                                     nat_rule['uuid'],
                                     lrouter['uuid'])
        return json.loads(nvplib.do_single_request("GET", uri,
                                                   cluster=self.fake_cluster))

    def test_create_lrouter_dnat_rule_v2(self):
        resp_obj = self._test_create_lrouter_dnat_rule(
            nvplib.create_lrouter_dnat_rule_v2)
        self.assertEqual('DestinationNatRule', resp_obj['type'])
        self.assertEqual('192.168.0.5',
                         resp_obj['match']['destination_ip_addresses'])

    def test_create_lrouter_dnat_rule_v3(self):
        resp_obj = self._test_create_lrouter_dnat_rule(
            nvplib.create_lrouter_dnat_rule_v2)
        # TODO(salvatore-orlando): Extend FakeNVPApiClient to deal with
        # different versions of NVP API
        self.assertEqual('DestinationNatRule', resp_obj['type'])
        self.assertEqual('192.168.0.5',
                         resp_obj['match']['destination_ip_addresses'])


class NvplibL2GatewayTestCase(NvplibTestCase):

    def _create_gw_service(self, node_uuid, display_name):
        return nvplib.create_l2_gw_service(self.fake_cluster,
                                           'fake-tenant',
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
        res2 = nvplib.update_l2_gw_service(self.fake_cluster, gw_id,
                                           new_display_name)
        self.assertEqual(res2['display_name'], new_display_name)

    def test_get_l2_gw_service(self):
        display_name = 'fake-gateway'
        node_uuid = _uuid()
        gw_id = self._create_gw_service(node_uuid, display_name)['uuid']
        response = nvplib.get_l2_gw_service(self.fake_cluster, gw_id)
        self.assertEqual(response.get('type'), 'L2GatewayServiceConfig')
        self.assertEqual(response.get('display_name'), display_name)
        self.assertEqual(response.get('uuid'), gw_id)

    def test_list_l2_gw_service(self):
        gw_ids = []
        for name in ('fake-1', 'fake-2'):
            gw_ids.append(self._create_gw_service(_uuid(), name)['uuid'])
        results = nvplib.get_l2_gw_services(self.fake_cluster)
        self.assertEqual(len(results), 2)
        self.assertEqual(sorted(gw_ids), sorted([r['uuid'] for r in results]))

    def test_delete_l2_gw_service(self):
        display_name = 'fake-gateway'
        node_uuid = _uuid()
        gw_id = self._create_gw_service(node_uuid, display_name)['uuid']
        nvplib.delete_l2_gw_service(self.fake_cluster, gw_id)
        results = nvplib.get_l2_gw_services(self.fake_cluster)
        self.assertEqual(len(results), 0)

    def test_plug_l2_gw_port_attachment(self):
        tenant_id = 'pippo'
        node_uuid = _uuid()
        lswitch = nvplib.create_lswitch(self.fake_cluster, tenant_id,
                                        'fake-switch')
        gw_id = self._create_gw_service(node_uuid, 'fake-gw')['uuid']
        lport = nvplib.create_lport(self.fake_cluster,
                                    lswitch['uuid'],
                                    tenant_id,
                                    _uuid(),
                                    'fake-gw-port',
                                    gw_id,
                                    True)
        json.loads(nvplib.plug_l2_gw_service(self.fake_cluster,
                                             lswitch['uuid'],
                                             lport['uuid'],
                                             gw_id))
        uri = nvplib._build_uri_path(nvplib.LSWITCHPORT_RESOURCE,
                                     lport['uuid'],
                                     lswitch['uuid'],
                                     is_attachment=True)
        resp_obj = json.loads(
            nvplib.do_single_request("GET", uri,
                                     cluster=self.fake_cluster))
        self.assertIn('LogicalPortAttachment', resp_obj)
        self.assertEqual(resp_obj['LogicalPortAttachment']['type'],
                         'L2GatewayAttachment')


class TestNvpLibLogicalPorts(NvplibTestCase):

    def test_get_port_by_tag(self):
        tenant_id = 'pippo'
        quantum_port_id = 'whatever'
        lswitch = nvplib.create_lswitch(self.fake_cluster, tenant_id,
                                        'fake-switch')
        lport = nvplib.create_lport(self.fake_cluster, lswitch['uuid'],
                                    tenant_id, quantum_port_id,
                                    'name', 'device_id', True)
        lport2 = nvplib.get_port_by_quantum_tag(self.fake_cluster,
                                                lswitch['uuid'],
                                                quantum_port_id)
        self.assertIsNotNone(lport2)
        self.assertEqual(lport['uuid'], lport2['uuid'])

    def test_get_port_by_tag_not_found_returns_None(self):
        tenant_id = 'pippo'
        quantum_port_id = 'whatever'
        lswitch = nvplib.create_lswitch(self.fake_cluster, tenant_id,
                                        'fake-switch')
        lport = nvplib.get_port_by_quantum_tag(self.fake_cluster,
                                               lswitch['uuid'],
                                               quantum_port_id)
        self.assertIsNone(lport)


class TestNvplibVersioning(base.BaseTestCase):

    def test_function_handling_missing_minor(self):
        version = NvpApiClient.NVPVersion('2.0')
        func_name = 'create_lrouter_dnat_rule'
        function = nvplib.get_function_by_version(func_name, version)
        self.assertEqual(nvplib.create_lrouter_dnat_rule_v2,
                         function)

    def test_function_handling_with_both_major_and_minor(self):
        version = NvpApiClient.NVPVersion('3.2')
        func_name = 'create_lrouter_dnat_rule'
        function = nvplib.get_function_by_version(func_name, version)
        self.assertEqual(nvplib.create_lrouter_dnat_rule_v3,
                         function)

    def test_function_handling_with_newer_major(self):
        version = NvpApiClient.NVPVersion('5.2')
        func_name = 'create_lrouter_dnat_rule'
        function = nvplib.get_function_by_version(func_name, version)
        self.assertEqual(nvplib.create_lrouter_dnat_rule_v3,
                         function)

    def test_function_handling_with_obsolete_major(self):
        version = NvpApiClient.NVPVersion('1.2')
        func_name = 'create_lrouter_dnat_rule'
        self.assertRaises(NotImplementedError,
                          nvplib.get_function_by_version,
                          func_name, version)

    def test_function_handling_with_unknown_version(self):
        func_name = 'create_lrouter_dnat_rule'
        self.assertRaises(NvpApiClient.ServiceUnavailable,
                          nvplib.get_function_by_version,
                          func_name, None)
