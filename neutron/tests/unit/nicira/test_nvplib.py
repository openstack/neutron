# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

import hashlib
import mock

from neutron.common import constants
from neutron.common import exceptions
from neutron.plugins.nicira.common import config  # noqa
from neutron.plugins.nicira.common import exceptions as nvp_exc
from neutron.plugins.nicira.common import utils
from neutron.plugins.nicira import nvp_cluster
from neutron.plugins.nicira import NvpApiClient
from neutron.plugins.nicira import nvplib
from neutron.tests import base
from neutron.tests.unit.nicira import fake_nvpapiclient
from neutron.tests.unit.nicira import NVPAPI_NAME
from neutron.tests.unit.nicira import STUBS_PATH
from neutron.tests.unit import test_api_v2


_uuid = test_api_v2._uuid


class NvplibTestCase(base.BaseTestCase):

    def setUp(self):
        # mock nvp api client
        self.fc = fake_nvpapiclient.FakeClient(STUBS_PATH)
        self.mock_nvpapi = mock.patch(NVPAPI_NAME, autospec=True)
        instance = self.mock_nvpapi.start()
        instance.return_value.login.return_value = "the_cookie"
        fake_version = getattr(self, 'fake_version', "3.0")
        instance.return_value.get_nvp_version.return_value = (
            NvpApiClient.NVPVersion(fake_version))

        def _fake_request(*args, **kwargs):
            return self.fc.fake_request(*args, **kwargs)

        instance.return_value.request.side_effect = _fake_request
        self.fake_cluster = nvp_cluster.NVPCluster(
            name='fake-cluster', nvp_controllers=['1.1.1.1:999'],
            default_tz_uuid=_uuid(), nvp_user='foo', nvp_password='bar')
        self.fake_cluster.api_client = NvpApiClient.NVPApiHelper(
            ('1.1.1.1', '999', True),
            self.fake_cluster.nvp_user, self.fake_cluster.nvp_password,
            self.fake_cluster.req_timeout, self.fake_cluster.http_timeout,
            self.fake_cluster.retries, self.fake_cluster.redirects)

        super(NvplibTestCase, self).setUp()
        self.addCleanup(self.fc.reset_all)
        self.addCleanup(self.mock_nvpapi.stop)

    def _build_tag_dict(self, tags):
        # This syntax is needed for python 2.6 compatibility
        return dict((t['scope'], t['tag']) for t in tags)


class TestNvplibNatRules(NvplibTestCase):

    def _test_create_lrouter_dnat_rule(self, version):
        with mock.patch.object(self.fake_cluster.api_client,
                               'get_nvp_version',
                               new=lambda: NvpApiClient.NVPVersion(version)):
            tenant_id = 'pippo'
            lrouter = nvplib.create_lrouter(self.fake_cluster,
                                            tenant_id,
                                            'fake_router',
                                            '192.168.0.1')
            nat_rule = nvplib.create_lrouter_dnat_rule(
                self.fake_cluster, lrouter['uuid'], '10.0.0.99',
                match_criteria={'destination_ip_addresses':
                                '192.168.0.5'})
            uri = nvplib._build_uri_path(nvplib.LROUTERNAT_RESOURCE,
                                         nat_rule['uuid'],
                                         lrouter['uuid'])
            resp_obj = nvplib.do_request("GET", uri, cluster=self.fake_cluster)
            self.assertEqual('DestinationNatRule', resp_obj['type'])
            self.assertEqual('192.168.0.5',
                             resp_obj['match']['destination_ip_addresses'])

    def test_create_lrouter_dnat_rule_v2(self):
        self._test_create_lrouter_dnat_rule('2.9')

    def test_create_lrouter_dnat_rule_v31(self):
        self._test_create_lrouter_dnat_rule('3.1')


class NvplibNegativeTests(base.BaseTestCase):

    def setUp(self):
        # mock nvp api client
        self.fc = fake_nvpapiclient.FakeClient(STUBS_PATH)
        self.mock_nvpapi = mock.patch(NVPAPI_NAME, autospec=True)
        instance = self.mock_nvpapi.start()
        instance.return_value.login.return_value = "the_cookie"
        # Choose 3.0, but the version is irrelevant for the aim of
        # these tests as calls are throwing up errors anyway
        fake_version = getattr(self, 'fake_version', "3.0")
        instance.return_value.get_nvp_version.return_value = (
            NvpApiClient.NVPVersion(fake_version))

        def _faulty_request(*args, **kwargs):
            raise nvplib.NvpApiClient.NvpApiException

        instance.return_value.request.side_effect = _faulty_request
        self.fake_cluster = nvp_cluster.NVPCluster(
            name='fake-cluster', nvp_controllers=['1.1.1.1:999'],
            default_tz_uuid=_uuid(), nvp_user='foo', nvp_password='bar')
        self.fake_cluster.api_client = NvpApiClient.NVPApiHelper(
            ('1.1.1.1', '999', True),
            self.fake_cluster.nvp_user, self.fake_cluster.nvp_password,
            self.fake_cluster.req_timeout, self.fake_cluster.http_timeout,
            self.fake_cluster.retries, self.fake_cluster.redirects)

        super(NvplibNegativeTests, self).setUp()
        self.addCleanup(self.fc.reset_all)
        self.addCleanup(self.mock_nvpapi.stop)

    def test_create_l2_gw_service_on_failure(self):
        self.assertRaises(nvplib.NvpApiClient.NvpApiException,
                          nvplib.create_l2_gw_service,
                          self.fake_cluster,
                          'fake-tenant',
                          'fake-gateway',
                          [{'id': _uuid(),
                          'interface_name': 'xxx'}])

    def test_delete_l2_gw_service_on_failure(self):
        self.assertRaises(nvplib.NvpApiClient.NvpApiException,
                          nvplib.delete_l2_gw_service,
                          self.fake_cluster,
                          'fake-gateway')

    def test_get_l2_gw_service_on_failure(self):
        self.assertRaises(nvplib.NvpApiClient.NvpApiException,
                          nvplib.get_l2_gw_service,
                          self.fake_cluster,
                          'fake-gateway')

    def test_update_l2_gw_service_on_failure(self):
        self.assertRaises(nvplib.NvpApiClient.NvpApiException,
                          nvplib.update_l2_gw_service,
                          self.fake_cluster,
                          'fake-gateway',
                          'pluto')

    def test_create_lrouter_on_failure(self):
        self.assertRaises(nvplib.NvpApiClient.NvpApiException,
                          nvplib.create_lrouter,
                          self.fake_cluster,
                          'pluto',
                          'fake_router',
                          'my_hop')

    def test_delete_lrouter_on_failure(self):
        self.assertRaises(nvplib.NvpApiClient.NvpApiException,
                          nvplib.delete_lrouter,
                          self.fake_cluster,
                          'fake_router')

    def test_get_lrouter_on_failure(self):
        self.assertRaises(nvplib.NvpApiClient.NvpApiException,
                          nvplib.get_lrouter,
                          self.fake_cluster,
                          'fake_router')

    def test_update_lrouter_on_failure(self):
        self.assertRaises(nvplib.NvpApiClient.NvpApiException,
                          nvplib.update_lrouter,
                          self.fake_cluster,
                          'fake_router',
                          'pluto',
                          'new_hop')


class TestNvplibL2Gateway(NvplibTestCase):

    def _create_gw_service(self, node_uuid, display_name,
                           tenant_id='fake_tenant'):
        return nvplib.create_l2_gw_service(self.fake_cluster,
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

    def test_list_l2_gw_service_by_tenant(self):
        gw_ids = [self._create_gw_service(
                  _uuid(), name, tenant_id=name)['uuid']
                  for name in ('fake-1', 'fake-2')]
        results = nvplib.get_l2_gw_services(self.fake_cluster,
                                            tenant_id='fake-1')
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['uuid'], gw_ids[0])

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
        transport_zones_config = [{'zone_uuid': _uuid(),
                                   'transport_type': 'stt'}]
        lswitch = nvplib.create_lswitch(self.fake_cluster, tenant_id,
                                        'fake-switch', transport_zones_config)
        gw_id = self._create_gw_service(node_uuid, 'fake-gw')['uuid']
        lport = nvplib.create_lport(self.fake_cluster,
                                    lswitch['uuid'],
                                    tenant_id,
                                    _uuid(),
                                    'fake-gw-port',
                                    gw_id,
                                    True)
        nvplib.plug_l2_gw_service(self.fake_cluster,
                                  lswitch['uuid'],
                                  lport['uuid'],
                                  gw_id)
        uri = nvplib._build_uri_path(nvplib.LSWITCHPORT_RESOURCE,
                                     lport['uuid'],
                                     lswitch['uuid'],
                                     is_attachment=True)
        resp_obj = nvplib.do_request("GET", uri,
                                     cluster=self.fake_cluster)
        self.assertIn('LogicalPortAttachment', resp_obj)
        self.assertEqual(resp_obj['LogicalPortAttachment']['type'],
                         'L2GatewayAttachment')


class TestNvplibLogicalSwitches(NvplibTestCase):

    def test_create_and_get_lswitches_single(self):
        tenant_id = 'pippo'
        transport_zones_config = [{'zone_uuid': _uuid(),
                                   'transport_type': 'stt'}]
        lswitch = nvplib.create_lswitch(self.fake_cluster,
                                        tenant_id,
                                        'fake-switch',
                                        transport_zones_config)
        res_lswitch = nvplib.get_lswitches(self.fake_cluster,
                                           lswitch['uuid'])
        self.assertEqual(len(res_lswitch), 1)
        self.assertEqual(res_lswitch[0]['uuid'],
                         lswitch['uuid'])

    def test_create_and_get_lswitches_single_name_exceeds_40_chars(self):
        tenant_id = 'pippo'
        transport_zones_config = [{'zone_uuid': _uuid(),
                                   'transport_type': 'stt'}]
        lswitch = nvplib.create_lswitch(self.fake_cluster,
                                        tenant_id,
                                        '*' * 50,
                                        transport_zones_config)
        res_lswitch = nvplib.get_lswitches(self.fake_cluster,
                                           lswitch['uuid'])
        self.assertEqual(len(res_lswitch), 1)
        self.assertEqual(res_lswitch[0]['uuid'], lswitch['uuid'])
        self.assertEqual(res_lswitch[0]['display_name'], '*' * 40)

    def test_create_and_get_lswitches_multiple(self):
        tenant_id = 'pippo'
        transport_zones_config = [{'zone_uuid': _uuid(),
                                   'transport_type': 'stt'}]
        main_lswitch = nvplib.create_lswitch(
            self.fake_cluster, tenant_id, 'fake-switch',
            transport_zones_config,
            tags=[{'scope': 'multi_lswitch', 'tag': 'True'}])
        # Create secondary lswitch
        nvplib.create_lswitch(
            self.fake_cluster, tenant_id, 'fake-switch-2',
            transport_zones_config,
            neutron_net_id=main_lswitch['uuid'])
        res_lswitch = nvplib.get_lswitches(self.fake_cluster,
                                           main_lswitch['uuid'])
        self.assertEqual(len(res_lswitch), 2)
        self.assertEqual(res_lswitch[0]['uuid'],
                         main_lswitch['uuid'])
        switch_1_tags = self._build_tag_dict(res_lswitch[0]['tags'])
        switch_2_tags = self._build_tag_dict(res_lswitch[1]['tags'])
        self.assertIn('multi_lswitch', switch_1_tags)
        self.assertNotIn('multi_lswitch', switch_2_tags)
        self.assertNotIn('quantum_net_id', switch_1_tags)
        self.assertIn('quantum_net_id', switch_2_tags)
        self.assertEqual(switch_2_tags['quantum_net_id'],
                         main_lswitch['uuid'])

    def test_update_lswitch(self):
        new_name = 'new-name'
        new_tags = [{'scope': 'new_tag', 'tag': 'xxx'}]
        transport_zones_config = [{'zone_uuid': _uuid(),
                                   'transport_type': 'stt'}]
        lswitch = nvplib.create_lswitch(self.fake_cluster,
                                        'pippo',
                                        'fake-switch',
                                        transport_zones_config)
        nvplib.update_lswitch(self.fake_cluster, lswitch['uuid'],
                              new_name, tags=new_tags)
        res_lswitch = nvplib.get_lswitches(self.fake_cluster,
                                           lswitch['uuid'])
        self.assertEqual(len(res_lswitch), 1)
        self.assertEqual(res_lswitch[0]['display_name'], new_name)
        switch_tags = self._build_tag_dict(res_lswitch[0]['tags'])
        self.assertIn('new_tag', switch_tags)
        self.assertEqual(switch_tags['new_tag'], 'xxx')

    def test_update_non_existing_lswitch_raises(self):
        self.assertRaises(exceptions.NetworkNotFound,
                          nvplib.update_lswitch,
                          self.fake_cluster, 'whatever',
                          'foo', 'bar')

    def test_delete_networks(self):
        transport_zones_config = [{'zone_uuid': _uuid(),
                                   'transport_type': 'stt'}]
        lswitch = nvplib.create_lswitch(self.fake_cluster,
                                        'pippo',
                                        'fake-switch',
                                        transport_zones_config)
        nvplib.delete_networks(self.fake_cluster, lswitch['uuid'],
                               [lswitch['uuid']])
        self.assertRaises(exceptions.NotFound,
                          nvplib.get_lswitches,
                          self.fake_cluster,
                          lswitch['uuid'])

    def test_delete_non_existing_lswitch_raises(self):
        self.assertRaises(exceptions.NetworkNotFound,
                          nvplib.delete_networks,
                          self.fake_cluster, 'whatever', ['whatever'])


class TestNvplibExplicitLRouters(NvplibTestCase):

    def setUp(self):
        self.fake_version = '3.2'
        super(TestNvplibExplicitLRouters, self).setUp()

    def _get_lrouter(self, tenant_id, router_name, router_id, relations=None):
        schema = '/ws.v1/schema/RoutingTableRoutingConfig'

        router = {'display_name': router_name,
                  'uuid': router_id,
                  'tags': [{'scope': 'quantum', 'tag': nvplib.NEUTRON_VERSION},
                           {'scope': 'os_tid', 'tag': '%s' % tenant_id}],
                  'distributed': False,
                  'routing_config': {'type': 'RoutingTableRoutingConfig',
                                     '_schema': schema},
                  '_schema': schema,
                  'nat_synchronization_enabled': True,
                  'replication_mode': 'service',
                  'type': 'LogicalRouterConfig',
                  '_href': '/ws.v1/lrouter/%s' % router_id, }
        if relations:
            router['_relations'] = relations
        return router

    def _get_single_route(self, router_id, route_id='fake_route_id_0',
                          prefix='0.0.0.0/0', next_hop_ip='1.1.1.1'):
        return {'protocol': 'static',
                '_href': '/ws.v1/lrouter/%s/rib/%s' % (router_id, route_id),
                'prefix': prefix,
                '_schema': '/ws.v1/schema/RoutingTableEntry',
                'next_hop_ip': next_hop_ip,
                'action': 'accept',
                'uuid': route_id}

    def test_prepare_body_with_implicit_routing_config(self):
        router_name = 'fake_router_name'
        tenant_id = 'fake_tenant_id'
        router_type = 'SingleDefaultRouteImplicitRoutingConfig'
        route_config = {
            'default_route_next_hop': {'gateway_ip_address': 'fake_address',
                                       'type': 'RouterNextHop'}, }
        body = nvplib._prepare_lrouter_body(router_name, tenant_id,
                                            router_type, **route_config)
        expected = {'display_name': 'fake_router_name',
                    'routing_config': {
                        'default_route_next_hop':
                        {'gateway_ip_address': 'fake_address',
                         'type': 'RouterNextHop'},
                    'type': 'SingleDefaultRouteImplicitRoutingConfig'},
                    'tags': [{'scope': 'os_tid', 'tag': 'fake_tenant_id'},
                             {'scope': 'quantum',
                              'tag': nvplib.NEUTRON_VERSION}],
                    'type': 'LogicalRouterConfig'}
        self.assertEqual(expected, body)

    def test_prepare_body_without_routing_config(self):
        router_name = 'fake_router_name'
        tenant_id = 'fake_tenant_id'
        router_type = 'RoutingTableRoutingConfig'
        body = nvplib._prepare_lrouter_body(router_name, tenant_id,
                                            router_type)
        expected = {'display_name': 'fake_router_name',
                    'routing_config': {'type': 'RoutingTableRoutingConfig'},
                    'tags': [{'scope': 'os_tid', 'tag': 'fake_tenant_id'},
                             {'scope': 'quantum',
                              'tag': nvplib.NEUTRON_VERSION}],
                    'type': 'LogicalRouterConfig'}
        self.assertEqual(expected, body)

    def test_get_lrouter(self):
        tenant_id = 'fake_tenant_id'
        router_name = 'fake_router_name'
        router_id = 'fake_router_id'
        relations = {
            'LogicalRouterStatus':
            {'_href': '/ws.v1/lrouter/%s/status' % router_id,
             'lport_admin_up_count': 1,
             '_schema': '/ws.v1/schema/LogicalRouterStatus',
             'lport_count': 1,
             'fabric_status': True,
             'type': 'LogicalRouterStatus',
             'lport_link_up_count': 0, }, }

        with mock.patch(_nicira_method('do_request'),
                        return_value=self._get_lrouter(tenant_id,
                                                       router_name,
                                                       router_id,
                                                       relations)):
            lrouter = nvplib.get_lrouter(self.fake_cluster, router_id)
            self.assertTrue(
                lrouter['_relations']['LogicalRouterStatus']['fabric_status'])

    def test_create_lrouter(self):
        tenant_id = 'fake_tenant_id'
        router_name = 'fake_router_name'
        router_id = 'fake_router_id'
        nexthop_ip = '10.0.0.1'
        with mock.patch(_nicira_method('do_request'),
                        return_value=self._get_lrouter(tenant_id,
                                                       router_name,
                                                       router_id)):
            lrouter = nvplib.create_lrouter(self.fake_cluster, tenant_id,
                                            router_name, nexthop_ip)
            self.assertEqual(lrouter['routing_config']['type'],
                             'RoutingTableRoutingConfig')
            self.assertNotIn('default_route_next_hop',
                             lrouter['routing_config'])

    def test_update_lrouter_nvp_with_no_routes(self):
        router_id = 'fake_router_id'
        new_routes = [{"nexthop": "10.0.0.2",
                       "destination": "169.254.169.0/30"}, ]

        nvp_routes = [self._get_single_route(router_id)]
        with mock.patch(_nicira_method('get_explicit_routes_lrouter'),
                        return_value=nvp_routes):
            with mock.patch(_nicira_method('create_explicit_route_lrouter'),
                            return_value='fake_uuid'):
                old_routes = nvplib.update_explicit_routes_lrouter(
                    self.fake_cluster, router_id, new_routes)
        self.assertEqual(old_routes, nvp_routes)

    def test_update_lrouter_nvp_with_no_routes_raise_nvp_exception(self):
        router_id = 'fake_router_id'
        new_routes = [{"nexthop": "10.0.0.2",
                       "destination": "169.254.169.0/30"}, ]

        nvp_routes = [self._get_single_route(router_id)]
        with mock.patch(_nicira_method('get_explicit_routes_lrouter'),
                        return_value=nvp_routes):
            with mock.patch(_nicira_method('create_explicit_route_lrouter'),
                            side_effect=NvpApiClient.NvpApiException):
                self.assertRaises(NvpApiClient.NvpApiException,
                                  nvplib.update_explicit_routes_lrouter,
                                  self.fake_cluster, router_id, new_routes)

    def test_update_lrouter_with_routes(self):
        router_id = 'fake_router_id'
        new_routes = [{"next_hop_ip": "10.0.0.2",
                       "prefix": "169.254.169.0/30"}, ]

        nvp_routes = [self._get_single_route(router_id),
                      self._get_single_route(router_id, 'fake_route_id_1',
                                             '0.0.0.1/24', '10.0.0.3'),
                      self._get_single_route(router_id, 'fake_route_id_2',
                                             '0.0.0.2/24', '10.0.0.4'), ]

        with mock.patch(_nicira_method('get_explicit_routes_lrouter'),
                        return_value=nvp_routes):
            with mock.patch(_nicira_method('delete_explicit_route_lrouter'),
                            return_value=None):
                with mock.patch(_nicira_method(
                    'create_explicit_route_lrouter'),
                    return_value='fake_uuid'):
                    old_routes = nvplib.update_explicit_routes_lrouter(
                        self.fake_cluster, router_id, new_routes)
        self.assertEqual(old_routes, nvp_routes)

    def test_update_lrouter_with_routes_raises_nvp_expception(self):
        router_id = 'fake_router_id'
        new_routes = [{"nexthop": "10.0.0.2",
                       "destination": "169.254.169.0/30"}, ]

        nvp_routes = [self._get_single_route(router_id),
                      self._get_single_route(router_id, 'fake_route_id_1',
                                             '0.0.0.1/24', '10.0.0.3'),
                      self._get_single_route(router_id, 'fake_route_id_2',
                                             '0.0.0.2/24', '10.0.0.4'), ]

        with mock.patch(_nicira_method('get_explicit_routes_lrouter'),
                        return_value=nvp_routes):
            with mock.patch(_nicira_method('delete_explicit_route_lrouter'),
                            side_effect=NvpApiClient.NvpApiException):
                with mock.patch(
                    _nicira_method('create_explicit_route_lrouter'),
                    return_value='fake_uuid'):
                    self.assertRaises(
                        NvpApiClient.NvpApiException,
                        nvplib.update_explicit_routes_lrouter,
                        self.fake_cluster, router_id, new_routes)


class TestNvplibLogicalRouters(NvplibTestCase):

    def _verify_lrouter(self, res_lrouter,
                        expected_uuid,
                        expected_display_name,
                        expected_nexthop,
                        expected_tenant_id,
                        expected_distributed=None):
        self.assertEqual(res_lrouter['uuid'], expected_uuid)
        nexthop = (res_lrouter['routing_config']
                   ['default_route_next_hop']['gateway_ip_address'])
        self.assertEqual(nexthop, expected_nexthop)
        router_tags = self._build_tag_dict(res_lrouter['tags'])
        self.assertIn('os_tid', router_tags)
        self.assertEqual(res_lrouter['display_name'], expected_display_name)
        self.assertEqual(expected_tenant_id, router_tags['os_tid'])
        if expected_distributed is not None:
            self.assertEqual(expected_distributed,
                             res_lrouter['distributed'])

    def test_get_lrouters(self):
        lrouter_uuids = [nvplib.create_lrouter(
            self.fake_cluster, 'pippo', 'fake-lrouter-%s' % k,
            '10.0.0.1')['uuid'] for k in range(0, 3)]
        routers = nvplib.get_lrouters(self.fake_cluster, 'pippo')
        for router in routers:
            self.assertIn(router['uuid'], lrouter_uuids)

    def _create_lrouter(self, version, distributed=None):
        with mock.patch.object(
            self.fake_cluster.api_client, 'get_nvp_version',
            return_value=NvpApiClient.NVPVersion(version)):
                lrouter = nvplib.create_lrouter(
                    self.fake_cluster, 'pippo', 'fake-lrouter',
                    '10.0.0.1', distributed=distributed)
                return nvplib.get_lrouter(self.fake_cluster,
                                          lrouter['uuid'])

    def test_create_and_get_lrouter_v30(self):
        res_lrouter = self._create_lrouter('3.0')
        self._verify_lrouter(res_lrouter, res_lrouter['uuid'],
                             'fake-lrouter', '10.0.0.1', 'pippo')

    def test_create_and_get_lrouter_v31_centralized(self):
        res_lrouter = self._create_lrouter('3.1', distributed=False)
        self._verify_lrouter(res_lrouter, res_lrouter['uuid'],
                             'fake-lrouter', '10.0.0.1', 'pippo',
                             expected_distributed=False)

    def test_create_and_get_lrouter_v31_distributed(self):
        res_lrouter = self._create_lrouter('3.1', distributed=True)
        self._verify_lrouter(res_lrouter, res_lrouter['uuid'],
                             'fake-lrouter', '10.0.0.1', 'pippo',
                             expected_distributed=True)

    def test_create_and_get_lrouter_name_exceeds_40chars(self):
        display_name = '*' * 50
        lrouter = nvplib.create_lrouter(self.fake_cluster,
                                        'pippo',
                                        display_name,
                                        '10.0.0.1')
        res_lrouter = nvplib.get_lrouter(self.fake_cluster,
                                         lrouter['uuid'])
        self._verify_lrouter(res_lrouter, lrouter['uuid'],
                             '*' * 40, '10.0.0.1', 'pippo')

    def _test_version_dependent_update_lrouter(self, version):
        def foo(*args, **kwargs):
            return version

        foo_func_dict = {
            'update_lrouter': {
                2: {-1: foo},
                3: {-1: foo, 2: foo}
            }
        }

        with mock.patch.object(self.fake_cluster.api_client,
                               'get_nvp_version',
                               return_value=NvpApiClient.NVPVersion(version)):
            with mock.patch.dict(nvplib.NVPLIB_FUNC_DICT,
                                 foo_func_dict, clear=True):
                return nvplib.update_lrouter(
                    self.fake_cluster, 'foo_router_id', 'foo_router_name',
                    'foo_nexthop', routes={'foo_destination': 'foo_address'})

    def test_version_dependent_update_lrouter_old_versions(self):
        self.assertRaises(nvp_exc.NvpInvalidVersion,
                          self._test_version_dependent_update_lrouter,
                          "2.9")
        self.assertRaises(nvp_exc.NvpInvalidVersion,
                          self._test_version_dependent_update_lrouter,
                          "3.0")
        self.assertRaises(nvp_exc.NvpInvalidVersion,
                          self._test_version_dependent_update_lrouter,
                          "3.1")

    def test_version_dependent_update_lrouter_new_versions(self):
        self.assertEqual("3.2",
                         self._test_version_dependent_update_lrouter("3.2"))
        self.assertEqual("4.0",
                         self._test_version_dependent_update_lrouter("4.0"))
        self.assertEqual("4.1",
                         self._test_version_dependent_update_lrouter("4.1"))

    def test_update_lrouter_no_nexthop(self):
        lrouter = nvplib.create_lrouter(self.fake_cluster,
                                        'pippo',
                                        'fake-lrouter',
                                        '10.0.0.1')
        lrouter = nvplib.update_lrouter(self.fake_cluster,
                                        lrouter['uuid'],
                                        'new_name',
                                        None)
        res_lrouter = nvplib.get_lrouter(self.fake_cluster,
                                         lrouter['uuid'])
        self._verify_lrouter(res_lrouter, lrouter['uuid'],
                             'new_name', '10.0.0.1', 'pippo')

    def test_update_lrouter(self):
        lrouter = nvplib.create_lrouter(self.fake_cluster,
                                        'pippo',
                                        'fake-lrouter',
                                        '10.0.0.1')
        lrouter = nvplib.update_lrouter(self.fake_cluster,
                                        lrouter['uuid'],
                                        'new_name',
                                        '192.168.0.1')
        res_lrouter = nvplib.get_lrouter(self.fake_cluster,
                                         lrouter['uuid'])
        self._verify_lrouter(res_lrouter, lrouter['uuid'],
                             'new_name', '192.168.0.1', 'pippo')

    def test_update_nonexistent_lrouter_raises(self):
        self.assertRaises(exceptions.NotFound,
                          nvplib.update_lrouter,
                          self.fake_cluster, 'whatever',
                          'foo', '9.9.9.9')

    def test_delete_lrouter(self):
        lrouter = nvplib.create_lrouter(self.fake_cluster,
                                        'pippo',
                                        'fake-lrouter',
                                        '10.0.0.1')
        nvplib.delete_lrouter(self.fake_cluster, lrouter['uuid'])
        self.assertRaises(exceptions.NotFound,
                          nvplib.get_lrouter,
                          self.fake_cluster,
                          lrouter['uuid'])

    def test_query_lrouter_ports(self):
        lrouter = nvplib.create_lrouter(self.fake_cluster,
                                        'pippo',
                                        'fake-lrouter',
                                        '10.0.0.1')
        router_port_uuids = [nvplib.create_router_lport(
            self.fake_cluster, lrouter['uuid'], 'pippo',
            'qp_id_%s' % k, 'port-%s' % k, True,
            ['192.168.0.%s' % k], '00:11:22:33:44:55')['uuid']
            for k in range(0, 3)]
        ports = nvplib.query_lrouter_lports(self.fake_cluster, lrouter['uuid'])
        self.assertEqual(len(ports), 3)
        for res_port in ports:
            self.assertIn(res_port['uuid'], router_port_uuids)

    def test_query_lrouter_lports_nonexistent_lrouter_raises(self):
        self.assertRaises(
            exceptions.NotFound, nvplib.create_router_lport,
            self.fake_cluster, 'booo', 'pippo', 'neutron_port_id',
            'name', True, ['192.168.0.1'], '00:11:22:33:44:55')

    def test_create_and_get_lrouter_port(self):
        lrouter = nvplib.create_lrouter(self.fake_cluster,
                                        'pippo',
                                        'fake-lrouter',
                                        '10.0.0.1')
        nvplib.create_router_lport(
            self.fake_cluster, lrouter['uuid'], 'pippo', 'neutron_port_id',
            'name', True, ['192.168.0.1'], '00:11:22:33:44:55')
        ports = nvplib.query_lrouter_lports(self.fake_cluster, lrouter['uuid'])
        self.assertEqual(len(ports), 1)
        res_port = ports[0]
        port_tags = self._build_tag_dict(res_port['tags'])
        self.assertEqual(['192.168.0.1'], res_port['ip_addresses'])
        self.assertIn('os_tid', port_tags)
        self.assertIn('q_port_id', port_tags)
        self.assertEqual('pippo', port_tags['os_tid'])
        self.assertEqual('neutron_port_id', port_tags['q_port_id'])

    def test_create_lrouter_port_nonexistent_router_raises(self):
        self.assertRaises(
            exceptions.NotFound, nvplib.create_router_lport,
            self.fake_cluster, 'booo', 'pippo', 'neutron_port_id',
            'name', True, ['192.168.0.1'], '00:11:22:33:44:55')

    def test_update_lrouter_port(self):
        lrouter = nvplib.create_lrouter(self.fake_cluster,
                                        'pippo',
                                        'fake-lrouter',
                                        '10.0.0.1')
        lrouter_port = nvplib.create_router_lport(
            self.fake_cluster, lrouter['uuid'], 'pippo', 'neutron_port_id',
            'name', True, ['192.168.0.1'], '00:11:22:33:44:55')
        nvplib.update_router_lport(
            self.fake_cluster, lrouter['uuid'], lrouter_port['uuid'],
            'pippo', 'another_port_id', 'name', False,
            ['192.168.0.1', '10.10.10.254'])

        ports = nvplib.query_lrouter_lports(self.fake_cluster, lrouter['uuid'])
        self.assertEqual(len(ports), 1)
        res_port = ports[0]
        port_tags = self._build_tag_dict(res_port['tags'])
        self.assertEqual(['192.168.0.1', '10.10.10.254'],
                         res_port['ip_addresses'])
        self.assertEqual('False', res_port['admin_status_enabled'])
        self.assertIn('os_tid', port_tags)
        self.assertIn('q_port_id', port_tags)
        self.assertEqual('pippo', port_tags['os_tid'])
        self.assertEqual('another_port_id', port_tags['q_port_id'])

    def test_update_lrouter_port_nonexistent_router_raises(self):
        self.assertRaises(
            exceptions.NotFound, nvplib.update_router_lport,
            self.fake_cluster, 'boo-router', 'boo-port', 'pippo',
            'neutron_port_id', 'name', True, ['192.168.0.1'])

    def test_update_lrouter_port_nonexistent_port_raises(self):
        lrouter = nvplib.create_lrouter(self.fake_cluster,
                                        'pippo',
                                        'fake-lrouter',
                                        '10.0.0.1')
        self.assertRaises(
            exceptions.NotFound, nvplib.update_router_lport,
            self.fake_cluster, lrouter['uuid'], 'boo-port', 'pippo',
            'neutron_port_id', 'name', True, ['192.168.0.1'])

    def test_delete_lrouter_port(self):
        lrouter = nvplib.create_lrouter(self.fake_cluster,
                                        'pippo',
                                        'fake-lrouter',
                                        '10.0.0.1')
        lrouter_port = nvplib.create_router_lport(
            self.fake_cluster, lrouter['uuid'], 'pippo', 'x', 'y', True, [],
            '00:11:22:33:44:55')
        ports = nvplib.query_lrouter_lports(self.fake_cluster, lrouter['uuid'])
        self.assertEqual(len(ports), 1)
        nvplib.delete_router_lport(self.fake_cluster, lrouter['uuid'],
                                   lrouter_port['uuid'])
        ports = nvplib.query_lrouter_lports(self.fake_cluster, lrouter['uuid'])
        self.assertFalse(len(ports))

    def test_delete_lrouter_port_nonexistent_router_raises(self):
        self.assertRaises(exceptions.NotFound,
                          nvplib.delete_router_lport,
                          self.fake_cluster, 'xyz', 'abc')

    def test_delete_lrouter_port_nonexistent_port_raises(self):
        lrouter = nvplib.create_lrouter(self.fake_cluster,
                                        'pippo',
                                        'fake-lrouter',
                                        '10.0.0.1')
        self.assertRaises(exceptions.NotFound,
                          nvplib.delete_router_lport,
                          self.fake_cluster, lrouter['uuid'], 'abc')

    def test_delete_peer_lrouter_port(self):
        lrouter = nvplib.create_lrouter(self.fake_cluster,
                                        'pippo',
                                        'fake-lrouter',
                                        '10.0.0.1')
        lrouter_port = nvplib.create_router_lport(
            self.fake_cluster, lrouter['uuid'], 'pippo', 'x', 'y', True, [],
            '00:11:22:33:44:55')

        def fakegetport(*args, **kwargs):
            return {'_relations': {'LogicalPortAttachment':
                                   {'peer_port_uuid': lrouter_port['uuid']}}}
        # mock get_port
        with mock.patch.object(nvplib, 'get_port', new=fakegetport):
            nvplib.delete_peer_router_lport(self.fake_cluster,
                                            lrouter_port['uuid'],
                                            'whatwever', 'whatever')

    def test_update_lrouter_port_ips_add_only(self):
        lrouter = nvplib.create_lrouter(self.fake_cluster,
                                        'pippo',
                                        'fake-lrouter',
                                        '10.0.0.1')
        lrouter_port = nvplib.create_router_lport(
            self.fake_cluster, lrouter['uuid'], 'pippo', 'neutron_port_id',
            'name', True, ['192.168.0.1'], '00:11:22:33:44:55')
        nvplib.update_lrouter_port_ips(
            self.fake_cluster, lrouter['uuid'], lrouter_port['uuid'],
            ['10.10.10.254'], [])
        ports = nvplib.query_lrouter_lports(self.fake_cluster, lrouter['uuid'])
        self.assertEqual(len(ports), 1)
        res_port = ports[0]
        self.assertEqual(['10.10.10.254', '192.168.0.1'],
                         res_port['ip_addresses'])

    def test_update_lrouter_port_ips_remove_only(self):
        lrouter = nvplib.create_lrouter(self.fake_cluster,
                                        'pippo',
                                        'fake-lrouter',
                                        '10.0.0.1')
        lrouter_port = nvplib.create_router_lport(
            self.fake_cluster, lrouter['uuid'], 'pippo', 'neutron_port_id',
            'name', True, ['192.168.0.1', '10.10.10.254'],
            '00:11:22:33:44:55')
        nvplib.update_lrouter_port_ips(
            self.fake_cluster, lrouter['uuid'], lrouter_port['uuid'],
            [], ['10.10.10.254'])
        ports = nvplib.query_lrouter_lports(self.fake_cluster, lrouter['uuid'])
        self.assertEqual(len(ports), 1)
        res_port = ports[0]
        self.assertEqual(['192.168.0.1'], res_port['ip_addresses'])

    def test_update_lrouter_port_ips_add_and_remove(self):
        lrouter = nvplib.create_lrouter(self.fake_cluster,
                                        'pippo',
                                        'fake-lrouter',
                                        '10.0.0.1')
        lrouter_port = nvplib.create_router_lport(
            self.fake_cluster, lrouter['uuid'], 'pippo', 'neutron_port_id',
            'name', True, ['192.168.0.1'], '00:11:22:33:44:55')
        nvplib.update_lrouter_port_ips(
            self.fake_cluster, lrouter['uuid'], lrouter_port['uuid'],
            ['10.10.10.254'], ['192.168.0.1'])
        ports = nvplib.query_lrouter_lports(self.fake_cluster, lrouter['uuid'])
        self.assertEqual(len(ports), 1)
        res_port = ports[0]
        self.assertEqual(['10.10.10.254'], res_port['ip_addresses'])

    def test_update_lrouter_port_ips_nonexistent_router_raises(self):
        self.assertRaises(
            nvp_exc.NvpPluginException, nvplib.update_lrouter_port_ips,
            self.fake_cluster, 'boo-router', 'boo-port', [], [])

    def test_update_lrouter_port_ips_nvp_exception_raises(self):
        lrouter = nvplib.create_lrouter(self.fake_cluster,
                                        'pippo',
                                        'fake-lrouter',
                                        '10.0.0.1')
        lrouter_port = nvplib.create_router_lport(
            self.fake_cluster, lrouter['uuid'], 'pippo', 'neutron_port_id',
            'name', True, ['192.168.0.1'], '00:11:22:33:44:55')

        def raise_nvp_exc(*args, **kwargs):
            raise NvpApiClient.NvpApiException()

        with mock.patch.object(nvplib, 'do_request', new=raise_nvp_exc):
            self.assertRaises(
                nvp_exc.NvpPluginException, nvplib.update_lrouter_port_ips,
                self.fake_cluster, lrouter['uuid'],
                lrouter_port['uuid'], [], [])

    def test_plug_lrouter_port_patch_attachment(self):
        tenant_id = 'pippo'
        transport_zones_config = [{'zone_uuid': _uuid(),
                                   'transport_type': 'stt'}]
        lswitch = nvplib.create_lswitch(self.fake_cluster,
                                        tenant_id, 'fake-switch',
                                        transport_zones_config)
        lport = nvplib.create_lport(self.fake_cluster, lswitch['uuid'],
                                    tenant_id, 'xyz',
                                    'name', 'device_id', True)
        lrouter = nvplib.create_lrouter(self.fake_cluster,
                                        tenant_id,
                                        'fake-lrouter',
                                        '10.0.0.1')
        lrouter_port = nvplib.create_router_lport(
            self.fake_cluster, lrouter['uuid'], 'pippo', 'neutron_port_id',
            'name', True, ['192.168.0.1'], '00:11:22:33:44:55:66')
        result = nvplib.plug_router_port_attachment(
            self.fake_cluster, lrouter['uuid'],
            lrouter_port['uuid'],
            lport['uuid'], 'PatchAttachment')
        self.assertEqual(lport['uuid'],
                         result['LogicalPortAttachment']['peer_port_uuid'])

    def test_plug_lrouter_port_l3_gw_attachment(self):
        lrouter = nvplib.create_lrouter(self.fake_cluster,
                                        'pippo',
                                        'fake-lrouter',
                                        '10.0.0.1')
        lrouter_port = nvplib.create_router_lport(
            self.fake_cluster, lrouter['uuid'], 'pippo', 'neutron_port_id',
            'name', True, ['192.168.0.1'], '00:11:22:33:44:55:66')
        result = nvplib.plug_router_port_attachment(
            self.fake_cluster, lrouter['uuid'],
            lrouter_port['uuid'],
            'gw_att', 'L3GatewayAttachment')
        self.assertEqual(
            'gw_att',
            result['LogicalPortAttachment']['l3_gateway_service_uuid'])

    def test_plug_lrouter_port_l3_gw_attachment_with_vlan(self):
        lrouter = nvplib.create_lrouter(self.fake_cluster,
                                        'pippo',
                                        'fake-lrouter',
                                        '10.0.0.1')
        lrouter_port = nvplib.create_router_lport(
            self.fake_cluster, lrouter['uuid'], 'pippo', 'neutron_port_id',
            'name', True, ['192.168.0.1'], '00:11:22:33:44:55')
        result = nvplib.plug_router_port_attachment(
            self.fake_cluster, lrouter['uuid'],
            lrouter_port['uuid'],
            'gw_att', 'L3GatewayAttachment', 123)
        self.assertEqual(
            'gw_att',
            result['LogicalPortAttachment']['l3_gateway_service_uuid'])
        self.assertEqual(
            '123',
            result['LogicalPortAttachment']['vlan_id'])

    def test_plug_lrouter_port_invalid_attachment_type_raises(self):
        lrouter = nvplib.create_lrouter(self.fake_cluster,
                                        'pippo',
                                        'fake-lrouter',
                                        '10.0.0.1')
        lrouter_port = nvplib.create_router_lport(
            self.fake_cluster, lrouter['uuid'], 'pippo', 'neutron_port_id',
            'name', True, ['192.168.0.1'], '00:11:22:33:44:55')
        self.assertRaises(nvp_exc.NvpInvalidAttachmentType,
                          nvplib.plug_router_port_attachment,
                          self.fake_cluster, lrouter['uuid'],
                          lrouter_port['uuid'], 'gw_att', 'BadType')

    def _test_create_router_snat_rule(self, version):
        lrouter = nvplib.create_lrouter(self.fake_cluster,
                                        'pippo',
                                        'fake-lrouter',
                                        '10.0.0.1')
        with mock.patch.object(self.fake_cluster.api_client,
                               'get_nvp_version',
                               new=lambda: NvpApiClient.NVPVersion(version)):
            nvplib.create_lrouter_snat_rule(
                self.fake_cluster, lrouter['uuid'],
                '10.0.0.2', '10.0.0.2', order=200,
                match_criteria={'source_ip_addresses': '192.168.0.24'})
            rules = nvplib.query_nat_rules(self.fake_cluster, lrouter['uuid'])
            self.assertEqual(len(rules), 1)

    def test_create_router_snat_rule_v3(self):
        self._test_create_router_snat_rule('3.0')

    def test_create_router_snat_rule_v2(self):
        self._test_create_router_snat_rule('2.0')

    def _test_create_router_dnat_rule(self, version, dest_port=None):
        lrouter = nvplib.create_lrouter(self.fake_cluster,
                                        'pippo',
                                        'fake-lrouter',
                                        '10.0.0.1')
        with mock.patch.object(self.fake_cluster.api_client,
                               'get_nvp_version',
                               return_value=NvpApiClient.NVPVersion(version)):
            nvplib.create_lrouter_dnat_rule(
                self.fake_cluster, lrouter['uuid'], '192.168.0.2', order=200,
                dest_port=dest_port,
                match_criteria={'destination_ip_addresses': '10.0.0.3'})
            rules = nvplib.query_nat_rules(self.fake_cluster, lrouter['uuid'])
            self.assertEqual(len(rules), 1)

    def test_create_router_dnat_rule_v3(self):
        self._test_create_router_dnat_rule('3.0')

    def test_create_router_dnat_rule_v2(self):
        self._test_create_router_dnat_rule('2.0')

    def test_create_router_dnat_rule_v2_with_destination_port(self):
        self._test_create_router_dnat_rule('2.0', 8080)

    def test_create_router_dnat_rule_v3_with_destination_port(self):
        self._test_create_router_dnat_rule('3.0', 8080)

    def test_create_router_snat_rule_invalid_match_keys_raises(self):
        # In this case the version does not make a difference
        lrouter = nvplib.create_lrouter(self.fake_cluster,
                                        'pippo',
                                        'fake-lrouter',
                                        '10.0.0.1')

        with mock.patch.object(self.fake_cluster.api_client,
                               'get_nvp_version',
                               new=lambda: '2.0'):
            self.assertRaises(AttributeError,
                              nvplib.create_lrouter_snat_rule,
                              self.fake_cluster, lrouter['uuid'],
                              '10.0.0.2', '10.0.0.2', order=200,
                              match_criteria={'foo': 'bar'})

    def _test_create_router_nosnat_rule(self, version, expected=1):
        lrouter = nvplib.create_lrouter(self.fake_cluster,
                                        'pippo',
                                        'fake-lrouter',
                                        '10.0.0.1')
        with mock.patch.object(self.fake_cluster.api_client,
                               'get_nvp_version',
                               new=lambda: NvpApiClient.NVPVersion(version)):
            nvplib.create_lrouter_nosnat_rule(
                self.fake_cluster, lrouter['uuid'],
                order=100,
                match_criteria={'destination_ip_addresses': '192.168.0.0/24'})
            rules = nvplib.query_nat_rules(self.fake_cluster, lrouter['uuid'])
            # NoSNAT rules do not exist in V2
            self.assertEqual(len(rules), expected)

    def test_create_router_nosnat_rule_v2(self):
        self._test_create_router_nosnat_rule('2.0', expected=0)

    def test_create_router_nosnat_rule_v3(self):
        self._test_create_router_nosnat_rule('3.0')

    def _prepare_nat_rules_for_delete_tests(self):
        lrouter = nvplib.create_lrouter(self.fake_cluster,
                                        'pippo',
                                        'fake-lrouter',
                                        '10.0.0.1')
        # v2 or v3 makes no difference for this test
        with mock.patch.object(self.fake_cluster.api_client,
                               'get_nvp_version',
                               new=lambda: NvpApiClient.NVPVersion('2.0')):
            nvplib.create_lrouter_snat_rule(
                self.fake_cluster, lrouter['uuid'],
                '10.0.0.2', '10.0.0.2', order=220,
                match_criteria={'source_ip_addresses': '192.168.0.0/24'})
            nvplib.create_lrouter_snat_rule(
                self.fake_cluster, lrouter['uuid'],
                '10.0.0.3', '10.0.0.3', order=200,
                match_criteria={'source_ip_addresses': '192.168.0.2/32'})
            nvplib.create_lrouter_dnat_rule(
                self.fake_cluster, lrouter['uuid'], '192.168.0.2', order=200,
                match_criteria={'destination_ip_addresses': '10.0.0.3'})
        return lrouter

    def test_delete_router_nat_rules_by_match_on_destination_ip(self):
        lrouter = self._prepare_nat_rules_for_delete_tests()
        rules = nvplib.query_nat_rules(self.fake_cluster, lrouter['uuid'])
        self.assertEqual(len(rules), 3)
        nvplib.delete_nat_rules_by_match(
            self.fake_cluster, lrouter['uuid'], 'DestinationNatRule', 1, 1,
            destination_ip_addresses='10.0.0.3')
        rules = nvplib.query_nat_rules(self.fake_cluster, lrouter['uuid'])
        self.assertEqual(len(rules), 2)

    def test_delete_router_nat_rules_by_match_on_source_ip(self):
        lrouter = self._prepare_nat_rules_for_delete_tests()
        rules = nvplib.query_nat_rules(self.fake_cluster, lrouter['uuid'])
        self.assertEqual(len(rules), 3)
        nvplib.delete_nat_rules_by_match(
            self.fake_cluster, lrouter['uuid'], 'SourceNatRule', 1, 1,
            source_ip_addresses='192.168.0.2/32')
        rules = nvplib.query_nat_rules(self.fake_cluster, lrouter['uuid'])
        self.assertEqual(len(rules), 2)

    def test_delete_router_nat_rules_by_match_no_match_expected(self):
        lrouter = self._prepare_nat_rules_for_delete_tests()
        rules = nvplib.query_nat_rules(self.fake_cluster, lrouter['uuid'])
        self.assertEqual(len(rules), 3)
        nvplib.delete_nat_rules_by_match(
            self.fake_cluster, lrouter['uuid'], 'SomeWeirdType', 0)
        rules = nvplib.query_nat_rules(self.fake_cluster, lrouter['uuid'])
        self.assertEqual(len(rules), 3)
        nvplib.delete_nat_rules_by_match(
            self.fake_cluster, lrouter['uuid'], 'DestinationNatRule', 0,
            destination_ip_addresses='99.99.99.99')
        rules = nvplib.query_nat_rules(self.fake_cluster, lrouter['uuid'])
        self.assertEqual(len(rules), 3)

    def test_delete_router_nat_rules_by_match_no_match_raises(self):
        lrouter = self._prepare_nat_rules_for_delete_tests()
        rules = nvplib.query_nat_rules(self.fake_cluster, lrouter['uuid'])
        self.assertEqual(len(rules), 3)
        self.assertRaises(
            nvp_exc.NvpNatRuleMismatch,
            nvplib.delete_nat_rules_by_match,
            self.fake_cluster, lrouter['uuid'],
            'SomeWeirdType', 1, 1)


class TestNvplibSecurityProfile(NvplibTestCase):

    def test_create_and_get_security_profile(self):
        sec_prof = nvplib.create_security_profile(self.fake_cluster,
                                                  'pippo', {'name': 'test'})
        sec_prof_res = nvplib.do_request(
            nvplib.HTTP_GET,
            nvplib._build_uri_path('security-profile',
                                   resource_id=sec_prof['uuid']),
            cluster=self.fake_cluster)
        self.assertEqual(sec_prof['uuid'], sec_prof_res['uuid'])
        # Check for builtin rules
        self.assertEqual(len(sec_prof_res['logical_port_egress_rules']), 1)
        self.assertEqual(len(sec_prof_res['logical_port_ingress_rules']), 2)

    def test_create_and_get_default_security_profile(self):
        sec_prof = nvplib.create_security_profile(self.fake_cluster,
                                                  'pippo',
                                                  {'name': 'default'})
        sec_prof_res = nvplib.do_request(
            nvplib.HTTP_GET,
            nvplib._build_uri_path('security-profile',
                                   resource_id=sec_prof['uuid']),
            cluster=self.fake_cluster)
        self.assertEqual(sec_prof['uuid'], sec_prof_res['uuid'])
        # Check for builtin rules
        self.assertEqual(len(sec_prof_res['logical_port_egress_rules']), 3)
        self.assertEqual(len(sec_prof_res['logical_port_ingress_rules']), 2)

    def test_update_security_profile_rules(self):
        sec_prof = nvplib.create_security_profile(self.fake_cluster,
                                                  'pippo', {'name': 'test'})
        ingress_rule = {'ethertype': 'IPv4'}
        egress_rule = {'ethertype': 'IPv4', 'profile_uuid': 'xyz'}
        new_rules = {'logical_port_egress_rules': [egress_rule],
                     'logical_port_ingress_rules': [ingress_rule]}
        nvplib.update_security_group_rules(self.fake_cluster,
                                           sec_prof['uuid'],
                                           new_rules)
        sec_prof_res = nvplib.do_request(
            nvplib.HTTP_GET,
            nvplib._build_uri_path('security-profile',
                                   resource_id=sec_prof['uuid']),
            cluster=self.fake_cluster)
        self.assertEqual(sec_prof['uuid'], sec_prof_res['uuid'])
        # Check for builtin rules
        self.assertEqual(len(sec_prof_res['logical_port_egress_rules']), 2)
        self.assertIn(egress_rule,
                      sec_prof_res['logical_port_egress_rules'])
        self.assertEqual(len(sec_prof_res['logical_port_ingress_rules']), 1)
        self.assertIn(ingress_rule,
                      sec_prof_res['logical_port_ingress_rules'])

    def test_update_security_profile_rules_noingress(self):
        sec_prof = nvplib.create_security_profile(self.fake_cluster,
                                                  'pippo', {'name': 'test'})
        hidden_ingress_rule = {'ethertype': 'IPv4',
                               'ip_prefix': '127.0.0.1/32'}
        egress_rule = {'ethertype': 'IPv4', 'profile_uuid': 'xyz'}
        new_rules = {'logical_port_egress_rules': [egress_rule],
                     'logical_port_ingress_rules': []}
        nvplib.update_security_group_rules(self.fake_cluster,
                                           sec_prof['uuid'],
                                           new_rules)
        sec_prof_res = nvplib.do_request(
            nvplib.HTTP_GET,
            nvplib._build_uri_path('security-profile',
                                   resource_id=sec_prof['uuid']),
            cluster=self.fake_cluster)
        self.assertEqual(sec_prof['uuid'], sec_prof_res['uuid'])
        # Check for builtin rules
        self.assertEqual(len(sec_prof_res['logical_port_egress_rules']), 2)
        self.assertIn(egress_rule,
                      sec_prof_res['logical_port_egress_rules'])
        self.assertEqual(len(sec_prof_res['logical_port_ingress_rules']), 1)
        self.assertIn(hidden_ingress_rule,
                      sec_prof_res['logical_port_ingress_rules'])

    def test_update_non_existing_securityprofile_raises(self):
        self.assertRaises(exceptions.NeutronException,
                          nvplib.update_security_group_rules,
                          self.fake_cluster, 'whatever',
                          {'logical_port_egress_rules': [],
                           'logical_port_ingress_rules': []})

    def test_delete_security_profile(self):
        sec_prof = nvplib.create_security_profile(self.fake_cluster,
                                                  'pippo', {'name': 'test'})
        nvplib.delete_security_profile(self.fake_cluster, sec_prof['uuid'])
        self.assertRaises(exceptions.NotFound,
                          nvplib.do_request,
                          nvplib.HTTP_GET,
                          nvplib._build_uri_path(
                              'security-profile',
                              resource_id=sec_prof['uuid']),
                          cluster=self.fake_cluster)

    def test_delete_non_existing_securityprofile_raises(self):
        self.assertRaises(exceptions.NeutronException,
                          nvplib.delete_security_profile,
                          self.fake_cluster, 'whatever')


class TestNvplibLQueue(NvplibTestCase):

    def test_create_and_get_lqueue(self):
        queue_id = nvplib.create_lqueue(self.fake_cluster,
                                        {'display_name': 'fake_queue',
                                         'min_bandwidth_rate': 0,
                                         'max_bandwidth_rate': 256,
                                         'dscp': 0,
                                         'qos_marking': False})
        queue_res = nvplib.do_request(
            nvplib.HTTP_GET,
            nvplib._build_uri_path('lqueue', resource_id=queue_id),
            cluster=self.fake_cluster)
        self.assertEqual(queue_id, queue_res['uuid'])
        self.assertEqual('fake_queue', queue_res['display_name'])

    def test_create_lqueue_nvp_error_raises(self):
        def raise_nvp_exc(*args, **kwargs):
            raise NvpApiClient.NvpApiException()

        with mock.patch.object(nvplib, 'do_request', new=raise_nvp_exc):
            self.assertRaises(
                exceptions.NeutronException, nvplib.create_lqueue,
                self.fake_cluster, {})

    def test_delete_lqueue(self):
        queue_id = nvplib.create_lqueue(self.fake_cluster,
                                        {'display_name': 'fake_queue',
                                         'min_bandwidth_rate': 0,
                                         'max_bandwidth_rate': 256,
                                         'dscp': 0,
                                         'qos_marking': False})
        nvplib.delete_lqueue(self.fake_cluster, queue_id)
        self.assertRaises(exceptions.NotFound,
                          nvplib.do_request,
                          nvplib.HTTP_GET,
                          nvplib._build_uri_path(
                              'lqueue', resource_id=queue_id),
                          cluster=self.fake_cluster)

    def test_delete_non_existing_lqueue_raises(self):
        self.assertRaises(exceptions.NeutronException,
                          nvplib.delete_lqueue,
                          self.fake_cluster, 'whatever')


class TestNvplibLogicalPorts(NvplibTestCase):

    def _create_switch_and_port(self, tenant_id='pippo',
                                neutron_port_id='whatever',
                                name='name', device_id='device_id'):
        transport_zones_config = [{'zone_uuid': _uuid(),
                                   'transport_type': 'stt'}]
        lswitch = nvplib.create_lswitch(self.fake_cluster,
                                        tenant_id, 'fake-switch',
                                        transport_zones_config)
        lport = nvplib.create_lport(self.fake_cluster, lswitch['uuid'],
                                    tenant_id, neutron_port_id,
                                    name, device_id, True)
        return lswitch, lport

    def test_create_and_get_port(self):
        lswitch, lport = self._create_switch_and_port()
        lport_res = nvplib.get_port(self.fake_cluster,
                                    lswitch['uuid'], lport['uuid'])
        self.assertEqual(lport['uuid'], lport_res['uuid'])
        # Try again with relation
        lport_res = nvplib.get_port(self.fake_cluster,
                                    lswitch['uuid'], lport['uuid'],
                                    relations='LogicalPortStatus')
        self.assertEqual(lport['uuid'], lport_res['uuid'])

    def test_plug_interface(self):
        lswitch, lport = self._create_switch_and_port()
        nvplib.plug_interface(self.fake_cluster, lswitch['uuid'],
                              lport['uuid'], 'VifAttachment', 'fake')
        lport_res = nvplib.get_port(self.fake_cluster,
                                    lswitch['uuid'], lport['uuid'])
        self.assertEqual(lport['uuid'], lport_res['uuid'])

    def test_get_port_by_tag(self):
        lswitch, lport = self._create_switch_and_port()
        lport2 = nvplib.get_port_by_neutron_tag(self.fake_cluster,
                                                lswitch['uuid'],
                                                'whatever')
        self.assertIsNotNone(lport2)
        self.assertEqual(lport['uuid'], lport2['uuid'])

    def test_get_port_by_tag_not_found_with_switch_id_raises_not_found(self):
        tenant_id = 'pippo'
        neutron_port_id = 'whatever'
        transport_zones_config = [{'zone_uuid': _uuid(),
                                   'transport_type': 'stt'}]
        lswitch = nvplib.create_lswitch(self.fake_cluster, tenant_id,
                                        'fake-switch', transport_zones_config)
        self.assertRaises(exceptions.NotFound,
                          nvplib.get_port_by_neutron_tag,
                          self.fake_cluster, lswitch['uuid'],
                          neutron_port_id)

    def test_get_port_by_tag_not_find_wildcard_lswitch_returns_none(self):
        tenant_id = 'pippo'
        neutron_port_id = 'whatever'
        transport_zones_config = [{'zone_uuid': _uuid(),
                                   'transport_type': 'stt'}]
        nvplib.create_lswitch(self.fake_cluster, tenant_id,
                              'fake-switch', transport_zones_config)
        lport = nvplib.get_port_by_neutron_tag(self.fake_cluster,
                                               '*', neutron_port_id)
        self.assertIsNone(lport)

    def test_get_port_status(self):
        lswitch, lport = self._create_switch_and_port()
        status = nvplib.get_port_status(self.fake_cluster,
                                        lswitch['uuid'],
                                        lport['uuid'])
        self.assertEqual(constants.PORT_STATUS_ACTIVE, status)

    def test_get_port_status_non_existent_raises(self):
        self.assertRaises(exceptions.PortNotFoundOnNetwork,
                          nvplib.get_port_status,
                          self.fake_cluster,
                          'boo', 'boo')

    def test_update_port(self):
        lswitch, lport = self._create_switch_and_port()
        nvplib.update_port(
            self.fake_cluster, lswitch['uuid'], lport['uuid'],
            'neutron_port_id', 'pippo2', 'new_name', 'device_id', False)
        lport_res = nvplib.get_port(self.fake_cluster,
                                    lswitch['uuid'], lport['uuid'])
        self.assertEqual(lport['uuid'], lport_res['uuid'])
        self.assertEqual('new_name', lport_res['display_name'])
        self.assertEqual('False', lport_res['admin_status_enabled'])
        port_tags = self._build_tag_dict(lport_res['tags'])
        self.assertIn('os_tid', port_tags)
        self.assertIn('q_port_id', port_tags)
        self.assertIn('vm_id', port_tags)

    def test_create_port_device_id_less_than_40_chars(self):
        lswitch, lport = self._create_switch_and_port()
        lport_res = nvplib.get_port(self.fake_cluster,
                                    lswitch['uuid'], lport['uuid'])
        port_tags = self._build_tag_dict(lport_res['tags'])
        self.assertEqual('device_id', port_tags['vm_id'])

    def test_create_port_device_id_more_than_40_chars(self):
        dev_id = "this_is_a_very_long_device_id_with_lots_of_characters"
        lswitch, lport = self._create_switch_and_port(device_id=dev_id)
        lport_res = nvplib.get_port(self.fake_cluster,
                                    lswitch['uuid'], lport['uuid'])
        port_tags = self._build_tag_dict(lport_res['tags'])
        self.assertNotEqual(len(dev_id), len(port_tags['vm_id']))

    def test_get_ports_with_obsolete_and_new_vm_id_tag(self):
        def obsolete(device_id, obfuscate=False):
            return hashlib.sha1(device_id).hexdigest()

        with mock.patch.object(nvplib, 'device_id_to_vm_id', new=obsolete):
            dev_id1 = "short-dev-id-1"
            _, lport1 = self._create_switch_and_port(device_id=dev_id1)
        dev_id2 = "short-dev-id-2"
        _, lport2 = self._create_switch_and_port(device_id=dev_id2)

        lports = nvplib.get_ports(self.fake_cluster, None, [dev_id1])
        port_tags = self._build_tag_dict(lports['whatever']['tags'])
        self.assertNotEqual(dev_id1, port_tags['vm_id'])

        lports = nvplib.get_ports(self.fake_cluster, None, [dev_id2])
        port_tags = self._build_tag_dict(lports['whatever']['tags'])
        self.assertEqual(dev_id2, port_tags['vm_id'])

    def test_update_non_existent_port_raises(self):
        self.assertRaises(exceptions.PortNotFoundOnNetwork,
                          nvplib.update_port, self.fake_cluster,
                          'boo', 'boo', 'boo', 'boo', 'boo', 'boo', False)

    def test_delete_port(self):
        lswitch, lport = self._create_switch_and_port()
        nvplib.delete_port(self.fake_cluster,
                           lswitch['uuid'], lport['uuid'])
        self.assertRaises(exceptions.PortNotFoundOnNetwork,
                          nvplib.get_port, self.fake_cluster,
                          lswitch['uuid'], lport['uuid'])

    def test_delete_non_existent_port_raises(self):
        lswitch = self._create_switch_and_port()[0]
        self.assertRaises(exceptions.PortNotFoundOnNetwork,
                          nvplib.delete_port, self.fake_cluster,
                          lswitch['uuid'], 'bad_port_uuid')

    def test_query_lswitch_ports(self):
        lswitch, lport = self._create_switch_and_port()
        switch_port_uuids = [
            nvplib.create_lport(
                self.fake_cluster, lswitch['uuid'], 'pippo', 'qportid-%s' % k,
                'port-%s' % k, 'deviceid-%s' % k, True)['uuid']
            for k in range(0, 2)]
        switch_port_uuids.append(lport['uuid'])
        ports = nvplib.query_lswitch_lports(self.fake_cluster, lswitch['uuid'])
        self.assertEqual(len(ports), 3)
        for res_port in ports:
            self.assertIn(res_port['uuid'], switch_port_uuids)


class TestNvplibClusterManagement(NvplibTestCase):

    def test_get_cluster_version(self):

        def fakedorequest(*args, **kwargs):
            uri = args[1]
            if 'node/xyz' in uri:
                return {'version': '3.0.9999'}
            elif 'node' in uri:
                return {'result_count': 1,
                        'results': [{'uuid': 'xyz'}]}

        with mock.patch.object(nvplib, 'do_request', new=fakedorequest):
            version = nvplib.get_cluster_version('whatever')
            self.assertEqual(version, '3.0')

    def test_get_cluster_version_no_nodes(self):
        def fakedorequest(*args, **kwargs):
            uri = args[1]
            if 'node' in uri:
                return {'result_count': 0}

        with mock.patch.object(nvplib, 'do_request', new=fakedorequest):
            version = nvplib.get_cluster_version('whatever')
            self.assertIsNone(version)

    def test_cluster_in_readonly_mode(self):
        with mock.patch.object(self.fake_cluster.api_client,
                               'request',
                               side_effect=NvpApiClient.ReadOnlyMode):
            self.assertRaises(nvp_exc.MaintenanceInProgress,
                              nvplib.do_request, cluster=self.fake_cluster)

    def test_cluster_method_not_implemetned(self):
        self.assertRaises(NvpApiClient.NvpApiException,
                          nvplib.do_request,
                          nvplib.HTTP_GET,
                          nvplib._build_uri_path('MY_FAKE_RESOURCE',
                                                 resource_id='foo'),
                          cluster=self.fake_cluster)


class TestNvplibVersioning(base.BaseTestCase):

    def test_function_handling_missing_minor(self):
        version = NvpApiClient.NVPVersion('2.0')
        function = nvplib.get_function_by_version('create_lrouter', version)
        self.assertEqual(nvplib.create_implicit_routing_lrouter,
                         function)

    def test_function_handling_with_both_major_and_minor(self):
        version = NvpApiClient.NVPVersion('3.2')
        function = nvplib.get_function_by_version('create_lrouter', version)
        self.assertEqual(nvplib.create_explicit_routing_lrouter,
                         function)

    def test_function_handling_with_newer_major(self):
        version = NvpApiClient.NVPVersion('5.2')
        function = nvplib.get_function_by_version('create_lrouter', version)
        self.assertEqual(nvplib.create_explicit_routing_lrouter,
                         function)

    def test_function_handling_with_obsolete_major(self):
        version = NvpApiClient.NVPVersion('1.2')
        self.assertRaises(NotImplementedError,
                          nvplib.get_function_by_version,
                          'create_lrouter', version)

    def test_function_handling_with_unknown_version(self):
        self.assertRaises(NvpApiClient.ServiceUnavailable,
                          nvplib.get_function_by_version,
                          'create_lrouter', None)


class NvplibMiscTestCase(base.BaseTestCase):

    def test_check_and_truncate_name_with_none(self):
        name = None
        result = utils.check_and_truncate(name)
        self.assertEqual('', result)

    def test_check_and_truncate_name_with_short_name(self):
        name = 'foo_port_name'
        result = utils.check_and_truncate(name)
        self.assertEqual(name, result)

    def test_check_and_truncate_name_long_name(self):
        name = 'this_is_a_port_whose_name_is_longer_than_40_chars'
        result = utils.check_and_truncate(name)
        self.assertEqual(len(result), utils.MAX_DISPLAY_NAME_LEN)


def _nicira_method(method_name, module_name='nvplib'):
    return '%s.%s.%s' % ('neutron.plugins.nicira', module_name, method_name)
