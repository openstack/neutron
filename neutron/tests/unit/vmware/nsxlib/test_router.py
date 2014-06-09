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

from oslo.config import cfg

from neutron.common import exceptions
from neutron.openstack.common import uuidutils
from neutron.plugins.vmware.api_client import exception as api_exc
from neutron.plugins.vmware.api_client import version as version_module
from neutron.plugins.vmware.common import exceptions as nsx_exc
from neutron.plugins.vmware.common import utils
from neutron.plugins.vmware import nsxlib
from neutron.plugins.vmware.nsxlib import router as routerlib
from neutron.plugins.vmware.nsxlib import switch as switchlib
from neutron.tests.unit import test_api_v2
from neutron.tests.unit.vmware.nsxlib import base

_uuid = test_api_v2._uuid


class TestNatRules(base.NsxlibTestCase):

    def _test_create_lrouter_dnat_rule(self, version):
        with mock.patch.object(self.fake_cluster.api_client,
                               'get_version',
                               new=lambda: version_module.Version(version)):
            tenant_id = 'pippo'
            lrouter = routerlib.create_lrouter(self.fake_cluster,
                                               uuidutils.generate_uuid(),
                                               tenant_id,
                                               'fake_router',
                                               '192.168.0.1')
            nat_rule = routerlib.create_lrouter_dnat_rule(
                self.fake_cluster, lrouter['uuid'], '10.0.0.99',
                match_criteria={'destination_ip_addresses':
                                '192.168.0.5'})
            uri = nsxlib._build_uri_path(routerlib.LROUTERNAT_RESOURCE,
                                         nat_rule['uuid'],
                                         lrouter['uuid'])
            resp_obj = nsxlib.do_request("GET", uri, cluster=self.fake_cluster)
            self.assertEqual('DestinationNatRule', resp_obj['type'])
            self.assertEqual('192.168.0.5',
                             resp_obj['match']['destination_ip_addresses'])

    def test_create_lrouter_dnat_rule_v2(self):
        self._test_create_lrouter_dnat_rule('2.9')

    def test_create_lrouter_dnat_rule_v31(self):
        self._test_create_lrouter_dnat_rule('3.1')


class TestExplicitLRouters(base.NsxlibTestCase):

    def setUp(self):
        self.fake_version = '3.2'
        super(TestExplicitLRouters, self).setUp()

    def _get_lrouter(self, tenant_id, router_name, router_id, relations=None):
        schema = '/ws.v1/schema/RoutingTableRoutingConfig'

        router = {'display_name': router_name,
                  'uuid': router_id,
                  'tags': utils.get_tags(os_tid=tenant_id),
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
        neutron_router_id = 'pipita_higuain'
        router_type = 'SingleDefaultRouteImplicitRoutingConfig'
        route_config = {
            'default_route_next_hop': {'gateway_ip_address': 'fake_address',
                                       'type': 'RouterNextHop'}, }
        body = routerlib._prepare_lrouter_body(router_name, neutron_router_id,
                                               tenant_id, router_type,
                                               **route_config)
        expected = {'display_name': 'fake_router_name',
                    'routing_config': {
                        'default_route_next_hop':
                        {'gateway_ip_address': 'fake_address',
                         'type': 'RouterNextHop'},
                        'type': 'SingleDefaultRouteImplicitRoutingConfig'},
                    'tags': utils.get_tags(os_tid='fake_tenant_id',
                                           q_router_id='pipita_higuain'),
                    'type': 'LogicalRouterConfig',
                    'replication_mode': cfg.CONF.NSX.replication_mode}
        self.assertEqual(expected, body)

    def test_prepare_body_without_routing_config(self):
        router_name = 'fake_router_name'
        tenant_id = 'fake_tenant_id'
        neutron_router_id = 'marekiaro_hamsik'
        router_type = 'RoutingTableRoutingConfig'
        body = routerlib._prepare_lrouter_body(router_name, neutron_router_id,
                                               tenant_id, router_type)
        expected = {'display_name': 'fake_router_name',
                    'routing_config': {'type': 'RoutingTableRoutingConfig'},
                    'tags': utils.get_tags(os_tid='fake_tenant_id',
                                           q_router_id='marekiaro_hamsik'),
                    'type': 'LogicalRouterConfig',
                    'replication_mode': cfg.CONF.NSX.replication_mode}
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

        with mock.patch.object(nsxlib, 'do_request',
                               return_value=self._get_lrouter(tenant_id,
                                                              router_name,
                                                              router_id,
                                                              relations)):
            lrouter = routerlib.get_lrouter(self.fake_cluster, router_id)
            self.assertTrue(
                lrouter['_relations']['LogicalRouterStatus']['fabric_status'])

    def test_create_lrouter(self):
        tenant_id = 'fake_tenant_id'
        router_name = 'fake_router_name'
        router_id = 'fake_router_id'
        nexthop_ip = '10.0.0.1'
        with mock.patch.object(
            nsxlib, 'do_request',
            return_value=self._get_lrouter(tenant_id,
                                           router_name,
                                           router_id)):
            lrouter = routerlib.create_lrouter(self.fake_cluster,
                                               uuidutils.generate_uuid(),
                                               tenant_id,
                                               router_name, nexthop_ip)
            self.assertEqual(lrouter['routing_config']['type'],
                             'RoutingTableRoutingConfig')
            self.assertNotIn('default_route_next_hop',
                             lrouter['routing_config'])

    def test_update_lrouter_with_no_routes(self):
        router_id = 'fake_router_id'
        new_routes = [{"nexthop": "10.0.0.2",
                       "destination": "169.254.169.0/30"}, ]

        nsx_routes = [self._get_single_route(router_id)]
        with mock.patch.object(routerlib, 'get_explicit_routes_lrouter',
                               return_value=nsx_routes):
            with mock.patch.object(routerlib, 'create_explicit_route_lrouter',
                                   return_value='fake_uuid'):
                old_routes = routerlib.update_explicit_routes_lrouter(
                    self.fake_cluster, router_id, new_routes)
        self.assertEqual(old_routes, nsx_routes)

    def test_update_lrouter_with_no_routes_raise_nsx_exception(self):
        router_id = 'fake_router_id'
        new_routes = [{"nexthop": "10.0.0.2",
                       "destination": "169.254.169.0/30"}, ]

        nsx_routes = [self._get_single_route(router_id)]
        with mock.patch.object(routerlib, 'get_explicit_routes_lrouter',
                               return_value=nsx_routes):
            with mock.patch.object(routerlib, 'create_explicit_route_lrouter',
                                   side_effect=api_exc.NsxApiException):
                self.assertRaises(api_exc.NsxApiException,
                                  routerlib.update_explicit_routes_lrouter,
                                  self.fake_cluster, router_id, new_routes)

    def test_update_lrouter_with_routes(self):
        router_id = 'fake_router_id'
        new_routes = [{"next_hop_ip": "10.0.0.2",
                       "prefix": "169.254.169.0/30"}, ]

        nsx_routes = [self._get_single_route(router_id),
                      self._get_single_route(router_id, 'fake_route_id_1',
                                             '0.0.0.1/24', '10.0.0.3'),
                      self._get_single_route(router_id, 'fake_route_id_2',
                                             '0.0.0.2/24', '10.0.0.4'), ]

        with mock.patch.object(routerlib, 'get_explicit_routes_lrouter',
                               return_value=nsx_routes):
            with mock.patch.object(routerlib, 'delete_explicit_route_lrouter',
                                   return_value=None):
                with mock.patch.object(routerlib,
                                       'create_explicit_route_lrouter',
                                       return_value='fake_uuid'):
                    old_routes = routerlib.update_explicit_routes_lrouter(
                        self.fake_cluster, router_id, new_routes)
        self.assertEqual(old_routes, nsx_routes)

    def test_update_lrouter_with_routes_raises_nsx_expception(self):
        router_id = 'fake_router_id'
        new_routes = [{"nexthop": "10.0.0.2",
                       "destination": "169.254.169.0/30"}, ]

        nsx_routes = [self._get_single_route(router_id),
                      self._get_single_route(router_id, 'fake_route_id_1',
                                             '0.0.0.1/24', '10.0.0.3'),
                      self._get_single_route(router_id, 'fake_route_id_2',
                                             '0.0.0.2/24', '10.0.0.4'), ]

        with mock.patch.object(routerlib, 'get_explicit_routes_lrouter',
                               return_value=nsx_routes):
            with mock.patch.object(routerlib, 'delete_explicit_route_lrouter',
                                   side_effect=api_exc.NsxApiException):
                with mock.patch.object(
                    routerlib, 'create_explicit_route_lrouter',
                    return_value='fake_uuid'):
                    self.assertRaises(
                        api_exc.NsxApiException,
                        routerlib.update_explicit_routes_lrouter,
                        self.fake_cluster, router_id, new_routes)


class RouterNegativeTestCase(base.NsxlibNegativeBaseTestCase):

    def test_create_lrouter_on_failure(self):
        self.assertRaises(api_exc.NsxApiException,
                          routerlib.create_lrouter,
                          self.fake_cluster,
                          uuidutils.generate_uuid(),
                          'pluto',
                          'fake_router',
                          'my_hop')

    def test_delete_lrouter_on_failure(self):
        self.assertRaises(api_exc.NsxApiException,
                          routerlib.delete_lrouter,
                          self.fake_cluster,
                          'fake_router')

    def test_get_lrouter_on_failure(self):
        self.assertRaises(api_exc.NsxApiException,
                          routerlib.get_lrouter,
                          self.fake_cluster,
                          'fake_router')

    def test_update_lrouter_on_failure(self):
        self.assertRaises(api_exc.NsxApiException,
                          routerlib.update_lrouter,
                          self.fake_cluster,
                          'fake_router',
                          'pluto',
                          'new_hop')


class TestLogicalRouters(base.NsxlibTestCase):

    def _verify_lrouter(self, res_lrouter,
                        expected_uuid,
                        expected_display_name,
                        expected_nexthop,
                        expected_tenant_id,
                        expected_neutron_id=None,
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
        if expected_neutron_id:
            self.assertIn('q_router_id', router_tags)
            self.assertEqual(expected_neutron_id, router_tags['q_router_id'])

    def test_get_lrouters(self):
        lrouter_uuids = [routerlib.create_lrouter(
            self.fake_cluster, 'whatever', 'pippo', 'fake-lrouter-%s' % k,
            '10.0.0.1')['uuid'] for k in range(3)]
        routers = routerlib.get_lrouters(self.fake_cluster, 'pippo')
        for router in routers:
            self.assertIn(router['uuid'], lrouter_uuids)

    def _create_lrouter(self, version, neutron_id=None, distributed=None):
        with mock.patch.object(
            self.fake_cluster.api_client, 'get_version',
            return_value=version_module.Version(version)):
            if not neutron_id:
                neutron_id = uuidutils.generate_uuid()
            lrouter = routerlib.create_lrouter(
                self.fake_cluster, neutron_id, 'pippo',
                'fake-lrouter', '10.0.0.1', distributed=distributed)
            return routerlib.get_lrouter(self.fake_cluster,
                                         lrouter['uuid'])

    def test_create_and_get_lrouter_v30(self):
        neutron_id = uuidutils.generate_uuid()
        res_lrouter = self._create_lrouter('3.0', neutron_id=neutron_id)
        self._verify_lrouter(res_lrouter, res_lrouter['uuid'],
                             'fake-lrouter', '10.0.0.1', 'pippo',
                             expected_neutron_id=neutron_id)

    def test_create_and_get_lrouter_v31_centralized(self):
        neutron_id = uuidutils.generate_uuid()
        res_lrouter = self._create_lrouter('3.1', neutron_id=neutron_id,
                                           distributed=False)
        self._verify_lrouter(res_lrouter, res_lrouter['uuid'],
                             'fake-lrouter', '10.0.0.1', 'pippo',
                             expected_neutron_id=neutron_id,
                             expected_distributed=False)

    def test_create_and_get_lrouter_v31_distributed(self):
        neutron_id = uuidutils.generate_uuid()
        res_lrouter = self._create_lrouter('3.1', neutron_id=neutron_id,
                                           distributed=True)
        self._verify_lrouter(res_lrouter, res_lrouter['uuid'],
                             'fake-lrouter', '10.0.0.1', 'pippo',
                             expected_neutron_id=neutron_id,
                             expected_distributed=True)

    def test_create_and_get_lrouter_name_exceeds_40chars(self):
        neutron_id = uuidutils.generate_uuid()
        display_name = '*' * 50
        lrouter = routerlib.create_lrouter(self.fake_cluster,
                                           neutron_id,
                                           'pippo',
                                           display_name,
                                           '10.0.0.1')
        res_lrouter = routerlib.get_lrouter(self.fake_cluster,
                                            lrouter['uuid'])
        self._verify_lrouter(res_lrouter, lrouter['uuid'],
                             '*' * 40, '10.0.0.1', 'pippo',
                             expected_neutron_id=neutron_id)

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
                               'get_version',
                               return_value=version_module.Version(version)):
            with mock.patch.dict(routerlib.ROUTER_FUNC_DICT,
                                 foo_func_dict, clear=True):
                return routerlib.update_lrouter(
                    self.fake_cluster, 'foo_router_id', 'foo_router_name',
                    'foo_nexthop', routes={'foo_destination': 'foo_address'})

    def test_version_dependent_update_lrouter_old_versions(self):
        self.assertRaises(nsx_exc.InvalidVersion,
                          self._test_version_dependent_update_lrouter,
                          "2.9")
        self.assertRaises(nsx_exc.InvalidVersion,
                          self._test_version_dependent_update_lrouter,
                          "3.0")
        self.assertRaises(nsx_exc.InvalidVersion,
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
        neutron_id = uuidutils.generate_uuid()
        lrouter = routerlib.create_lrouter(self.fake_cluster,
                                           neutron_id,
                                           'pippo',
                                           'fake-lrouter',
                                           '10.0.0.1')
        lrouter = routerlib.update_lrouter(self.fake_cluster,
                                           lrouter['uuid'],
                                           'new_name',
                                           None)
        res_lrouter = routerlib.get_lrouter(self.fake_cluster,
                                            lrouter['uuid'])
        self._verify_lrouter(res_lrouter, lrouter['uuid'],
                             'new_name', '10.0.0.1', 'pippo',
                             expected_neutron_id=neutron_id)

    def test_update_lrouter(self):
        neutron_id = uuidutils.generate_uuid()
        lrouter = routerlib.create_lrouter(self.fake_cluster,
                                           neutron_id,
                                           'pippo',
                                           'fake-lrouter',
                                           '10.0.0.1')
        lrouter = routerlib.update_lrouter(self.fake_cluster,
                                           lrouter['uuid'],
                                           'new_name',
                                           '192.168.0.1')
        res_lrouter = routerlib.get_lrouter(self.fake_cluster,
                                            lrouter['uuid'])
        self._verify_lrouter(res_lrouter, lrouter['uuid'],
                             'new_name', '192.168.0.1', 'pippo',
                             expected_neutron_id=neutron_id)

    def test_update_nonexistent_lrouter_raises(self):
        self.assertRaises(exceptions.NotFound,
                          routerlib.update_lrouter,
                          self.fake_cluster,
                          'whatever',
                          'foo', '9.9.9.9')

    def test_delete_lrouter(self):
        lrouter = routerlib.create_lrouter(self.fake_cluster,
                                           uuidutils.generate_uuid(),
                                           'pippo',
                                           'fake-lrouter',
                                           '10.0.0.1')
        routerlib.delete_lrouter(self.fake_cluster, lrouter['uuid'])
        self.assertRaises(exceptions.NotFound,
                          routerlib.get_lrouter,
                          self.fake_cluster,
                          lrouter['uuid'])

    def test_query_lrouter_ports(self):
        lrouter = routerlib.create_lrouter(self.fake_cluster,
                                           uuidutils.generate_uuid(),
                                           'pippo',
                                           'fake-lrouter',
                                           '10.0.0.1')
        router_port_uuids = [routerlib.create_router_lport(
            self.fake_cluster, lrouter['uuid'], 'pippo',
            'qp_id_%s' % k, 'port-%s' % k, True,
            ['192.168.0.%s' % k], '00:11:22:33:44:55')['uuid']
            for k in range(3)]
        ports = routerlib.query_lrouter_lports(
            self.fake_cluster, lrouter['uuid'])
        self.assertEqual(len(ports), 3)
        for res_port in ports:
            self.assertIn(res_port['uuid'], router_port_uuids)

    def test_query_lrouter_lports_nonexistent_lrouter_raises(self):
        self.assertRaises(
            exceptions.NotFound, routerlib.create_router_lport,
            self.fake_cluster, 'booo', 'pippo', 'neutron_port_id',
            'name', True, ['192.168.0.1'], '00:11:22:33:44:55')

    def test_create_and_get_lrouter_port(self):
        lrouter = routerlib.create_lrouter(self.fake_cluster,
                                           uuidutils.generate_uuid(),
                                           'pippo',
                                           'fake-lrouter',
                                           '10.0.0.1')
        routerlib.create_router_lport(
            self.fake_cluster, lrouter['uuid'], 'pippo', 'neutron_port_id',
            'name', True, ['192.168.0.1'], '00:11:22:33:44:55')
        ports = routerlib.query_lrouter_lports(
            self.fake_cluster, lrouter['uuid'])
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
            exceptions.NotFound, routerlib.create_router_lport,
            self.fake_cluster, 'booo', 'pippo', 'neutron_port_id',
            'name', True, ['192.168.0.1'], '00:11:22:33:44:55')

    def test_update_lrouter_port(self):
        lrouter = routerlib.create_lrouter(self.fake_cluster,
                                           uuidutils.generate_uuid(),
                                           'pippo',
                                           'fake-lrouter',
                                           '10.0.0.1')
        lrouter_port = routerlib.create_router_lport(
            self.fake_cluster, lrouter['uuid'], 'pippo', 'neutron_port_id',
            'name', True, ['192.168.0.1'], '00:11:22:33:44:55')
        routerlib.update_router_lport(
            self.fake_cluster, lrouter['uuid'], lrouter_port['uuid'],
            'pippo', 'another_port_id', 'name', False,
            ['192.168.0.1', '10.10.10.254'])

        ports = routerlib.query_lrouter_lports(
            self.fake_cluster, lrouter['uuid'])
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
            exceptions.NotFound, routerlib.update_router_lport,
            self.fake_cluster, 'boo-router', 'boo-port', 'pippo',
            'neutron_port_id', 'name', True, ['192.168.0.1'])

    def test_update_lrouter_port_nonexistent_port_raises(self):
        lrouter = routerlib.create_lrouter(self.fake_cluster,
                                           uuidutils.generate_uuid(),
                                           'pippo',
                                           'fake-lrouter',
                                           '10.0.0.1')
        self.assertRaises(
            exceptions.NotFound, routerlib.update_router_lport,
            self.fake_cluster, lrouter['uuid'], 'boo-port', 'pippo',
            'neutron_port_id', 'name', True, ['192.168.0.1'])

    def test_delete_lrouter_port(self):
        lrouter = routerlib.create_lrouter(self.fake_cluster,
                                           uuidutils.generate_uuid(),
                                           'pippo',
                                           'fake-lrouter',
                                           '10.0.0.1')
        lrouter_port = routerlib.create_router_lport(
            self.fake_cluster, lrouter['uuid'], 'pippo', 'x', 'y', True, [],
            '00:11:22:33:44:55')
        ports = routerlib.query_lrouter_lports(
            self.fake_cluster, lrouter['uuid'])
        self.assertEqual(len(ports), 1)
        routerlib.delete_router_lport(self.fake_cluster, lrouter['uuid'],
                                      lrouter_port['uuid'])
        ports = routerlib.query_lrouter_lports(
            self.fake_cluster, lrouter['uuid'])
        self.assertFalse(len(ports))

    def test_delete_lrouter_port_nonexistent_router_raises(self):
        self.assertRaises(exceptions.NotFound,
                          routerlib.delete_router_lport,
                          self.fake_cluster, 'xyz', 'abc')

    def test_delete_lrouter_port_nonexistent_port_raises(self):
        lrouter = routerlib.create_lrouter(self.fake_cluster,
                                           uuidutils.generate_uuid(),
                                           'pippo',
                                           'fake-lrouter',
                                           '10.0.0.1')
        self.assertRaises(exceptions.NotFound,
                          routerlib.delete_router_lport,
                          self.fake_cluster, lrouter['uuid'], 'abc')

    def test_delete_peer_lrouter_port(self):
        lrouter = routerlib.create_lrouter(self.fake_cluster,
                                           uuidutils.generate_uuid(),
                                           'pippo',
                                           'fake-lrouter',
                                           '10.0.0.1')
        lrouter_port = routerlib.create_router_lport(
            self.fake_cluster, lrouter['uuid'], 'pippo', 'x', 'y', True, [],
            '00:11:22:33:44:55')

        def fakegetport(*args, **kwargs):
            return {'_relations': {'LogicalPortAttachment':
                                   {'peer_port_uuid': lrouter_port['uuid']}}}
        # mock get_port
        with mock.patch.object(switchlib, 'get_port', new=fakegetport):
            routerlib.delete_peer_router_lport(self.fake_cluster,
                                               lrouter_port['uuid'],
                                               'whatwever', 'whatever')

    def test_update_lrouter_port_ips_add_only(self):
        lrouter = routerlib.create_lrouter(self.fake_cluster,
                                           uuidutils.generate_uuid(),
                                           'pippo',
                                           'fake-lrouter',
                                           '10.0.0.1')
        lrouter_port = routerlib.create_router_lport(
            self.fake_cluster, lrouter['uuid'], 'pippo', 'neutron_port_id',
            'name', True, ['192.168.0.1'], '00:11:22:33:44:55')
        routerlib.update_lrouter_port_ips(
            self.fake_cluster, lrouter['uuid'], lrouter_port['uuid'],
            ['10.10.10.254'], [])
        ports = routerlib.query_lrouter_lports(
            self.fake_cluster, lrouter['uuid'])
        self.assertEqual(len(ports), 1)
        res_port = ports[0]
        self.assertEqual(['10.10.10.254', '192.168.0.1'],
                         res_port['ip_addresses'])

    def test_update_lrouter_port_ips_remove_only(self):
        lrouter = routerlib.create_lrouter(self.fake_cluster,
                                           uuidutils.generate_uuid(),
                                           'pippo',
                                           'fake-lrouter',
                                           '10.0.0.1')
        lrouter_port = routerlib.create_router_lport(
            self.fake_cluster, lrouter['uuid'], 'pippo', 'neutron_port_id',
            'name', True, ['192.168.0.1', '10.10.10.254'],
            '00:11:22:33:44:55')
        routerlib.update_lrouter_port_ips(
            self.fake_cluster, lrouter['uuid'], lrouter_port['uuid'],
            [], ['10.10.10.254'])
        ports = routerlib.query_lrouter_lports(
            self.fake_cluster, lrouter['uuid'])
        self.assertEqual(len(ports), 1)
        res_port = ports[0]
        self.assertEqual(['192.168.0.1'], res_port['ip_addresses'])

    def test_update_lrouter_port_ips_add_and_remove(self):
        lrouter = routerlib.create_lrouter(self.fake_cluster,
                                           uuidutils.generate_uuid(),
                                           'pippo',
                                           'fake-lrouter',
                                           '10.0.0.1')
        lrouter_port = routerlib.create_router_lport(
            self.fake_cluster, lrouter['uuid'], 'pippo', 'neutron_port_id',
            'name', True, ['192.168.0.1'], '00:11:22:33:44:55')
        routerlib.update_lrouter_port_ips(
            self.fake_cluster, lrouter['uuid'], lrouter_port['uuid'],
            ['10.10.10.254'], ['192.168.0.1'])
        ports = routerlib.query_lrouter_lports(
            self.fake_cluster, lrouter['uuid'])
        self.assertEqual(len(ports), 1)
        res_port = ports[0]
        self.assertEqual(['10.10.10.254'], res_port['ip_addresses'])

    def test_update_lrouter_port_ips_nonexistent_router_raises(self):
        self.assertRaises(
            nsx_exc.NsxPluginException, routerlib.update_lrouter_port_ips,
            self.fake_cluster, 'boo-router', 'boo-port', [], [])

    def test_update_lrouter_port_ips_nsx_exception_raises(self):
        lrouter = routerlib.create_lrouter(self.fake_cluster,
                                           uuidutils.generate_uuid(),
                                           'pippo',
                                           'fake-lrouter',
                                           '10.0.0.1')
        lrouter_port = routerlib.create_router_lport(
            self.fake_cluster, lrouter['uuid'], 'pippo', 'neutron_port_id',
            'name', True, ['192.168.0.1'], '00:11:22:33:44:55')

        def raise_nsx_exc(*args, **kwargs):
            raise api_exc.NsxApiException()

        with mock.patch.object(nsxlib, 'do_request', new=raise_nsx_exc):
            self.assertRaises(
                nsx_exc.NsxPluginException, routerlib.update_lrouter_port_ips,
                self.fake_cluster, lrouter['uuid'],
                lrouter_port['uuid'], [], [])

    def test_plug_lrouter_port_patch_attachment(self):
        tenant_id = 'pippo'
        transport_zones_config = [{'zone_uuid': _uuid(),
                                   'transport_type': 'stt'}]
        lswitch = switchlib.create_lswitch(self.fake_cluster,
                                           _uuid(),
                                           tenant_id, 'fake-switch',
                                           transport_zones_config)
        lport = switchlib.create_lport(self.fake_cluster, lswitch['uuid'],
                                       tenant_id, 'xyz',
                                       'name', 'device_id', True)
        lrouter = routerlib.create_lrouter(self.fake_cluster,
                                           uuidutils.generate_uuid(),
                                           tenant_id,
                                           'fake-lrouter',
                                           '10.0.0.1')
        lrouter_port = routerlib.create_router_lport(
            self.fake_cluster, lrouter['uuid'], 'pippo', 'neutron_port_id',
            'name', True, ['192.168.0.1'], '00:11:22:33:44:55:66')
        result = routerlib.plug_router_port_attachment(
            self.fake_cluster, lrouter['uuid'],
            lrouter_port['uuid'],
            lport['uuid'], 'PatchAttachment')
        self.assertEqual(lport['uuid'],
                         result['LogicalPortAttachment']['peer_port_uuid'])

    def test_plug_lrouter_port_l3_gw_attachment(self):
        lrouter = routerlib.create_lrouter(self.fake_cluster,
                                           uuidutils.generate_uuid(),
                                           'pippo',
                                           'fake-lrouter',
                                           '10.0.0.1')
        lrouter_port = routerlib.create_router_lport(
            self.fake_cluster, lrouter['uuid'], 'pippo', 'neutron_port_id',
            'name', True, ['192.168.0.1'], '00:11:22:33:44:55:66')
        result = routerlib.plug_router_port_attachment(
            self.fake_cluster, lrouter['uuid'],
            lrouter_port['uuid'],
            'gw_att', 'L3GatewayAttachment')
        self.assertEqual(
            'gw_att',
            result['LogicalPortAttachment']['l3_gateway_service_uuid'])

    def test_plug_lrouter_port_l3_gw_attachment_with_vlan(self):
        lrouter = routerlib.create_lrouter(self.fake_cluster,
                                           uuidutils.generate_uuid(),
                                           'pippo',
                                           'fake-lrouter',
                                           '10.0.0.1')
        lrouter_port = routerlib.create_router_lport(
            self.fake_cluster, lrouter['uuid'], 'pippo', 'neutron_port_id',
            'name', True, ['192.168.0.1'], '00:11:22:33:44:55')
        result = routerlib.plug_router_port_attachment(
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
        lrouter = routerlib.create_lrouter(self.fake_cluster,
                                           uuidutils.generate_uuid(),
                                           'pippo',
                                           'fake-lrouter',
                                           '10.0.0.1')
        lrouter_port = routerlib.create_router_lport(
            self.fake_cluster, lrouter['uuid'], 'pippo', 'neutron_port_id',
            'name', True, ['192.168.0.1'], '00:11:22:33:44:55')
        self.assertRaises(nsx_exc.InvalidAttachmentType,
                          routerlib.plug_router_port_attachment,
                          self.fake_cluster, lrouter['uuid'],
                          lrouter_port['uuid'], 'gw_att', 'BadType')

    def _test_create_router_snat_rule(self, version):
        lrouter = routerlib.create_lrouter(self.fake_cluster,
                                           uuidutils.generate_uuid(),
                                           'pippo',
                                           'fake-lrouter',
                                           '10.0.0.1')
        with mock.patch.object(self.fake_cluster.api_client,
                               'get_version',
                               new=lambda: version_module.Version(version)):
            routerlib.create_lrouter_snat_rule(
                self.fake_cluster, lrouter['uuid'],
                '10.0.0.2', '10.0.0.2', order=200,
                match_criteria={'source_ip_addresses': '192.168.0.24'})
            rules = routerlib.query_nat_rules(
                self.fake_cluster, lrouter['uuid'])
            self.assertEqual(len(rules), 1)

    def test_create_router_snat_rule_v3(self):
        self._test_create_router_snat_rule('3.0')

    def test_create_router_snat_rule_v2(self):
        self._test_create_router_snat_rule('2.0')

    def _test_create_router_dnat_rule(self, version, dest_port=None):
        lrouter = routerlib.create_lrouter(self.fake_cluster,
                                           uuidutils.generate_uuid(),
                                           'pippo',
                                           'fake-lrouter',
                                           '10.0.0.1')
        with mock.patch.object(self.fake_cluster.api_client,
                               'get_version',
                               return_value=version_module.Version(version)):
            routerlib.create_lrouter_dnat_rule(
                self.fake_cluster, lrouter['uuid'], '192.168.0.2', order=200,
                dest_port=dest_port,
                match_criteria={'destination_ip_addresses': '10.0.0.3'})
            rules = routerlib.query_nat_rules(
                self.fake_cluster, lrouter['uuid'])
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
        lrouter = routerlib.create_lrouter(self.fake_cluster,
                                           uuidutils.generate_uuid(),
                                           'pippo',
                                           'fake-lrouter',
                                           '10.0.0.1')

        with mock.patch.object(self.fake_cluster.api_client,
                               'get_version',
                               new=lambda: '2.0'):
            self.assertRaises(AttributeError,
                              routerlib.create_lrouter_snat_rule,
                              self.fake_cluster, lrouter['uuid'],
                              '10.0.0.2', '10.0.0.2', order=200,
                              match_criteria={'foo': 'bar'})

    def _test_create_router_nosnat_rule(self, version, expected=1):
        lrouter = routerlib.create_lrouter(self.fake_cluster,
                                           uuidutils.generate_uuid(),
                                           'pippo',
                                           'fake-lrouter',
                                           '10.0.0.1')
        with mock.patch.object(self.fake_cluster.api_client,
                               'get_version',
                               new=lambda: version_module.Version(version)):
            routerlib.create_lrouter_nosnat_rule(
                self.fake_cluster, lrouter['uuid'],
                order=100,
                match_criteria={'destination_ip_addresses': '192.168.0.0/24'})
            rules = routerlib.query_nat_rules(
                self.fake_cluster, lrouter['uuid'])
            # NoSNAT rules do not exist in V2
            self.assertEqual(len(rules), expected)

    def test_create_router_nosnat_rule_v2(self):
        self._test_create_router_nosnat_rule('2.0', expected=0)

    def test_create_router_nosnat_rule_v3(self):
        self._test_create_router_nosnat_rule('3.0')

    def _prepare_nat_rules_for_delete_tests(self):
        lrouter = routerlib.create_lrouter(self.fake_cluster,
                                           uuidutils.generate_uuid(),
                                           'pippo',
                                           'fake-lrouter',
                                           '10.0.0.1')
        # v2 or v3 makes no difference for this test
        with mock.patch.object(self.fake_cluster.api_client,
                               'get_version',
                               new=lambda: version_module.Version('2.0')):
            routerlib.create_lrouter_snat_rule(
                self.fake_cluster, lrouter['uuid'],
                '10.0.0.2', '10.0.0.2', order=220,
                match_criteria={'source_ip_addresses': '192.168.0.0/24'})
            routerlib.create_lrouter_snat_rule(
                self.fake_cluster, lrouter['uuid'],
                '10.0.0.3', '10.0.0.3', order=200,
                match_criteria={'source_ip_addresses': '192.168.0.2/32'})
            routerlib.create_lrouter_dnat_rule(
                self.fake_cluster, lrouter['uuid'], '192.168.0.2', order=200,
                match_criteria={'destination_ip_addresses': '10.0.0.3'})
        return lrouter

    def test_delete_router_nat_rules_by_match_on_destination_ip(self):
        lrouter = self._prepare_nat_rules_for_delete_tests()
        rules = routerlib.query_nat_rules(self.fake_cluster, lrouter['uuid'])
        self.assertEqual(len(rules), 3)
        routerlib.delete_nat_rules_by_match(
            self.fake_cluster, lrouter['uuid'], 'DestinationNatRule', 1, 1,
            destination_ip_addresses='10.0.0.3')
        rules = routerlib.query_nat_rules(self.fake_cluster, lrouter['uuid'])
        self.assertEqual(len(rules), 2)

    def test_delete_router_nat_rules_by_match_on_source_ip(self):
        lrouter = self._prepare_nat_rules_for_delete_tests()
        rules = routerlib.query_nat_rules(self.fake_cluster, lrouter['uuid'])
        self.assertEqual(len(rules), 3)
        routerlib.delete_nat_rules_by_match(
            self.fake_cluster, lrouter['uuid'], 'SourceNatRule', 1, 1,
            source_ip_addresses='192.168.0.2/32')
        rules = routerlib.query_nat_rules(self.fake_cluster, lrouter['uuid'])
        self.assertEqual(len(rules), 2)

    def test_delete_router_nat_rules_by_match_no_match_expected(self):
        lrouter = self._prepare_nat_rules_for_delete_tests()
        rules = routerlib.query_nat_rules(self.fake_cluster, lrouter['uuid'])
        self.assertEqual(len(rules), 3)
        routerlib.delete_nat_rules_by_match(
            self.fake_cluster, lrouter['uuid'], 'SomeWeirdType', 0)
        rules = routerlib.query_nat_rules(self.fake_cluster, lrouter['uuid'])
        self.assertEqual(len(rules), 3)
        routerlib.delete_nat_rules_by_match(
            self.fake_cluster, lrouter['uuid'], 'DestinationNatRule', 0,
            destination_ip_addresses='99.99.99.99')
        rules = routerlib.query_nat_rules(self.fake_cluster, lrouter['uuid'])
        self.assertEqual(len(rules), 3)

    def test_delete_router_nat_rules_by_match_no_match_raises(self):
        lrouter = self._prepare_nat_rules_for_delete_tests()
        rules = routerlib.query_nat_rules(self.fake_cluster, lrouter['uuid'])
        self.assertEqual(len(rules), 3)
        self.assertRaises(
            nsx_exc.NatRuleMismatch,
            routerlib.delete_nat_rules_by_match,
            self.fake_cluster, lrouter['uuid'],
            'SomeWeirdType', 1, 1)

    def test_delete_nat_rules_by_match_len_mismatch_does_not_raise(self):
        lrouter = self._prepare_nat_rules_for_delete_tests()
        rules = routerlib.query_nat_rules(self.fake_cluster, lrouter['uuid'])
        self.assertEqual(len(rules), 3)
        deleted_rules = routerlib.delete_nat_rules_by_match(
            self.fake_cluster, lrouter['uuid'],
            'DestinationNatRule',
            max_num_expected=1, min_num_expected=1,
            raise_on_len_mismatch=False,
            destination_ip_addresses='99.99.99.99')
        self.assertEqual(0, deleted_rules)
        # add an extra rule to emulate a duplicate one
        with mock.patch.object(self.fake_cluster.api_client,
                               'get_version',
                               new=lambda: version_module.Version('2.0')):
            routerlib.create_lrouter_snat_rule(
                self.fake_cluster, lrouter['uuid'],
                '10.0.0.2', '10.0.0.2', order=220,
                match_criteria={'source_ip_addresses': '192.168.0.0/24'})
        deleted_rules_2 = routerlib.delete_nat_rules_by_match(
            self.fake_cluster, lrouter['uuid'], 'SourceNatRule',
            min_num_expected=1, max_num_expected=1,
            raise_on_len_mismatch=False,
            source_ip_addresses='192.168.0.0/24')
        self.assertEqual(2, deleted_rules_2)
