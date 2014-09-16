# Copyright 2014 Cisco Systems, Inc.  All rights reserved.
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
import mock
from oslo.config import cfg

from neutron.common import config as base_config
from neutron.common import constants as l3_constants
from neutron.common import rpc as n_rpc
from neutron.openstack.common import log as logging
from neutron.openstack.common import uuidutils
from neutron.plugins.cisco.cfg_agent import cfg_agent
from neutron.plugins.cisco.cfg_agent import cfg_exceptions
from neutron.plugins.cisco.cfg_agent.service_helpers.routing_svc_helper import(
    RouterInfo)
from neutron.plugins.cisco.cfg_agent.service_helpers.routing_svc_helper import(
    RoutingServiceHelper)


from neutron.tests import base


_uuid = uuidutils.generate_uuid
HOST = 'myhost'
FAKE_ID = _uuid()

LOG = logging.getLogger(__name__)


def prepare_router_data(enable_snat=None, num_internal_ports=1):
    router_id = _uuid()
    ex_gw_port = {'id': _uuid(),
                  'network_id': _uuid(),
                  'fixed_ips': [{'ip_address': '19.4.4.4',
                                 'subnet_id': _uuid()}],
                  'subnet': {'cidr': '19.4.4.0/24',
                             'gateway_ip': '19.4.4.1'}}
    int_ports = []
    for i in range(num_internal_ports):
        int_ports.append({'id': _uuid(),
                          'network_id': _uuid(),
                          'admin_state_up': True,
                          'fixed_ips': [{'ip_address': '35.4.%s.4' % i,
                                         'subnet_id': _uuid()}],
                          'mac_address': 'ca:fe:de:ad:be:ef',
                          'subnet': {'cidr': '35.4.%s.0/24' % i,
                                     'gateway_ip': '35.4.%s.1' % i}})
    hosting_device = {'id': _uuid(),
                      "name": "CSR1kv_template",
                      "booting_time": 300,
                      "host_category": "VM",
                      'management_ip_address': '20.0.0.5',
                      'protocol_port': 22,
                      "credentials": {
                          "username": "user",
                          "password": "4getme"},
                      }
    router = {
        'id': router_id,
        'admin_state_up': True,
        l3_constants.INTERFACE_KEY: int_ports,
        'routes': [],
        'gw_port': ex_gw_port,
        'hosting_device': hosting_device}
    if enable_snat is not None:
        router['enable_snat'] = enable_snat
    return router, int_ports


class TestRouterInfo(base.BaseTestCase):

    def setUp(self):
        super(TestRouterInfo, self).setUp()
        self.ex_gw_port = {'id': _uuid(),
                           'network_id': _uuid(),
                           'fixed_ips': [{'ip_address': '19.4.4.4',
                                          'subnet_id': _uuid()}],
                           'subnet': {'cidr': '19.4.4.0/24',
                                      'gateway_ip': '19.4.4.1'}}
        self.router = {'id': _uuid(),
                       'enable_snat': True,
                       'routes': [],
                       'gw_port': self.ex_gw_port}

    def test_router_info_create(self):
        router_id = _uuid()
        fake_router = {}
        ri = RouterInfo(router_id, fake_router)

        self.assertTrue(ri.router_name().endswith(router_id))

    def test_router_info_create_with_router(self):
        router_id = _uuid()
        ri = RouterInfo(router_id, self.router)
        self.assertTrue(ri.router_name().endswith(router_id))
        self.assertEqual(ri.router, self.router)
        self.assertEqual(ri._router, self.router)
        self.assertTrue(ri.snat_enabled)
        self.assertIsNone(ri.ex_gw_port)

    def test_router_info_create_snat_disabled(self):
        router_id = _uuid()
        self.router['enable_snat'] = False
        ri = RouterInfo(router_id, self.router)
        self.assertFalse(ri.snat_enabled)


class TestBasicRoutingOperations(base.BaseTestCase):

    def setUp(self):
        super(TestBasicRoutingOperations, self).setUp()
        self.conf = cfg.ConfigOpts()
        self.conf.register_opts(base_config.core_opts)
        self.conf.register_opts(cfg_agent.CiscoCfgAgent.OPTS)
        self.ex_gw_port = {'id': _uuid(),
                           'network_id': _uuid(),
                           'fixed_ips': [{'ip_address': '19.4.4.4',
                                         'subnet_id': _uuid()}],
                           'subnet': {'cidr': '19.4.4.0/24',
                                      'gateway_ip': '19.4.4.1'}}
        self.hosting_device = {'id': "100",
                               'name': "CSR1kv_template",
                               'booting_time': 300,
                               'host_category': "VM",
                               'management_ip_address': '20.0.0.5',
                               'protocol_port': 22,
                               'credentials': {'username': 'user',
                                               "password": '4getme'},
                               }
        self.router = {
            'id': _uuid(),
            'enable_snat': True,
            'routes': [],
            'gw_port': self.ex_gw_port,
            'hosting_device': self.hosting_device}

        self.agent = mock.Mock()

        #Patches & Mocks

        self.l3pluginApi_cls_p = mock.patch(
            'neutron.plugins.cisco.cfg_agent.service_helpers.'
            'routing_svc_helper.CiscoRoutingPluginApi')
        l3plugin_api_cls = self.l3pluginApi_cls_p.start()
        self.plugin_api = mock.Mock()
        l3plugin_api_cls.return_value = self.plugin_api
        self.plugin_api.get_routers = mock.MagicMock()
        self.looping_call_p = mock.patch(
            'neutron.openstack.common.loopingcall.FixedIntervalLoopingCall')
        self.looping_call_p.start()
        mock.patch('neutron.common.rpc.create_connection').start()

        self.routing_helper = RoutingServiceHelper(
            HOST, self.conf, self.agent)
        self.routing_helper._internal_network_added = mock.Mock()
        self.routing_helper._external_gateway_added = mock.Mock()
        self.routing_helper._internal_network_removed = mock.Mock()
        self.routing_helper._external_gateway_removed = mock.Mock()
        self.driver = self._mock_driver_and_hosting_device(
            self.routing_helper)

    def _mock_driver_and_hosting_device(self, svc_helper):
        svc_helper._dev_status.is_hosting_device_reachable = mock.MagicMock(
            return_value=True)
        driver = mock.MagicMock()
        svc_helper._drivermgr.get_driver = mock.Mock(return_value=driver)
        svc_helper._drivermgr.set_driver = mock.Mock(return_value=driver)
        return driver

    def _reset_mocks(self):
        self.routing_helper._process_router_floating_ips.reset_mock()
        self.routing_helper._internal_network_added.reset_mock()
        self.routing_helper._external_gateway_added.reset_mock()
        self.routing_helper._internal_network_removed.reset_mock()
        self.routing_helper._external_gateway_removed.reset_mock()

    def test_process_router_throw_config_error(self):
        snip_name = 'CREATE_SUBINTERFACE'
        e_type = 'Fake error'
        e_tag = 'Fake error tag'
        params = {'snippet': snip_name, 'type': e_type, 'tag': e_tag}
        self.routing_helper._internal_network_added.side_effect = (
            cfg_exceptions.CSR1kvConfigException(**params))
        router, ports = prepare_router_data()
        ri = RouterInfo(router['id'], router)
        self.assertRaises(cfg_exceptions.CSR1kvConfigException,
                          self.routing_helper._process_router, ri)

    def test_process_router(self):
        router, ports = prepare_router_data()
        #Setup mock for call to proceess floating ips
        self.routing_helper._process_router_floating_ips = mock.Mock()
        fake_floatingips1 = {'floatingips': [
            {'id': _uuid(),
             'floating_ip_address': '8.8.8.8',
             'fixed_ip_address': '7.7.7.7',
             'port_id': _uuid()}]}
        ri = RouterInfo(router['id'], router=router)
        # Process with initial values
        self.routing_helper._process_router(ri)
        ex_gw_port = ri.router.get('gw_port')
        # Assert that process_floating_ips, internal_network & external network
        # added were all called with the right params
        self.routing_helper._process_router_floating_ips.assert_called_with(
            ri, ex_gw_port)
        self.routing_helper._internal_network_added.assert_called_with(
            ri, ports[0], ex_gw_port)
        self.routing_helper._external_gateway_added.assert_called_with(
            ri, ex_gw_port)
        self._reset_mocks()
        # remap floating IP to a new fixed ip
        fake_floatingips2 = copy.deepcopy(fake_floatingips1)
        fake_floatingips2['floatingips'][0]['fixed_ip_address'] = '7.7.7.8'
        router[l3_constants.FLOATINGIP_KEY] = fake_floatingips2['floatingips']

        # Process again and check that this time only the process_floating_ips
        # was only called.
        self.routing_helper._process_router(ri)
        ex_gw_port = ri.router.get('gw_port')
        self.routing_helper._process_router_floating_ips.assert_called_with(
            ri, ex_gw_port)
        self.assertFalse(self.routing_helper._internal_network_added.called)
        self.assertFalse(self.routing_helper._external_gateway_added.called)
        self._reset_mocks()
        # remove just the floating ips
        del router[l3_constants.FLOATINGIP_KEY]
        # Process again and check that this time also only the
        # process_floating_ips and external_network remove was called
        self.routing_helper._process_router(ri)
        ex_gw_port = ri.router.get('gw_port')
        self.routing_helper._process_router_floating_ips.assert_called_with(
            ri, ex_gw_port)
        self.assertFalse(self.routing_helper._internal_network_added.called)
        self.assertFalse(self.routing_helper._external_gateway_added.called)
        self._reset_mocks()
        # now no ports so state is torn down
        del router[l3_constants.INTERFACE_KEY]
        del router['gw_port']
        # Update router_info object
        ri.router = router
        # Keep a copy of the ex_gw_port before its gone after processing.
        ex_gw_port = ri.ex_gw_port
        # Process router and verify that internal and external network removed
        # were called and floating_ips_process was called
        self.routing_helper._process_router(ri)
        self.assertFalse(self.routing_helper.
                         _process_router_floating_ips.called)
        self.assertFalse(self.routing_helper._external_gateway_added.called)
        self.assertTrue(self.routing_helper._internal_network_removed.called)
        self.assertTrue(self.routing_helper._external_gateway_removed.called)
        self.routing_helper._internal_network_removed.assert_called_with(
            ri, ports[0], ex_gw_port)
        self.routing_helper._external_gateway_removed.assert_called_with(
            ri, ex_gw_port)

    def test_routing_table_update(self):
        router = self.router
        fake_route1 = {'destination': '135.207.0.0/16',
                       'nexthop': '1.2.3.4'}
        fake_route2 = {'destination': '135.207.111.111/32',
                       'nexthop': '1.2.3.4'}

        # First we set the routes to fake_route1 and see if the
        # driver.routes_updated was called with 'replace'(==add or replace)
        # and fake_route1
        router['routes'] = [fake_route1]
        ri = RouterInfo(router['id'], router)
        self.routing_helper._process_router(ri)

        self.driver.routes_updated.assert_called_with(ri, 'replace',
                                                      fake_route1)

        # Now we replace fake_route1 with fake_route2. This should cause driver
        # to be invoked to delete fake_route1 and 'replace'(==add or replace)
        self.driver.reset_mock()
        router['routes'] = [fake_route2]
        ri.router = router
        self.routing_helper._process_router(ri)

        self.driver.routes_updated.assert_called_with(ri, 'delete',
                                                      fake_route1)
        self.driver.routes_updated.assert_any_call(ri, 'replace', fake_route2)

        # Now we add back fake_route1 as a new route, this should cause driver
        # to be invoked to 'replace'(==add or replace) fake_route1
        self.driver.reset_mock()
        router['routes'] = [fake_route2, fake_route1]
        ri.router = router
        self.routing_helper._process_router(ri)

        self.driver.routes_updated.assert_any_call(ri, 'replace', fake_route1)

        # Now we delete all routes. This should cause driver
        # to be invoked to delete fake_route1 and fake-route2
        self.driver.reset_mock()
        router['routes'] = []
        ri.router = router
        self.routing_helper._process_router(ri)

        self.driver.routes_updated.assert_any_call(ri, 'delete', fake_route2)
        self.driver.routes_updated.assert_any_call(ri, 'delete', fake_route1)

    def test_process_router_internal_network_added_unexpected_error(self):
        router, ports = prepare_router_data()
        ri = RouterInfo(router['id'], router=router)
        # raise RuntimeError to simulate that an unexpected exception occurrs
        self.routing_helper._internal_network_added.side_effect = RuntimeError
        self.assertRaises(RuntimeError,
                          self.routing_helper._process_router,
                          ri)
        self.assertNotIn(
            router[l3_constants.INTERFACE_KEY][0], ri.internal_ports)

        # The unexpected exception has been fixed manually
        self.routing_helper._internal_network_added.side_effect = None

        # Failure will cause a retry next time, then were able to add the
        # port to ri.internal_ports
        self.routing_helper._process_router(ri)
        self.assertIn(
            router[l3_constants.INTERFACE_KEY][0], ri.internal_ports)

    def test_process_router_internal_network_removed_unexpected_error(self):
        router, ports = prepare_router_data()
        ri = RouterInfo(router['id'], router=router)
        # add an internal port
        self.routing_helper._process_router(ri)

        # raise RuntimeError to simulate that an unexpected exception occurrs

        self.routing_helper._internal_network_removed.side_effect = mock.Mock(
            side_effect=RuntimeError)
        ri.internal_ports[0]['admin_state_up'] = False
        # The above port is set to down state, remove it.
        self.assertRaises(RuntimeError,
                          self.routing_helper._process_router,
                          ri)
        self.assertIn(
            router[l3_constants.INTERFACE_KEY][0], ri.internal_ports)

        # The unexpected exception has been fixed manually
        self.routing_helper._internal_network_removed.side_effect = None

        # Failure will cause a retry next time,
        # We were able to add the port to ri.internal_ports
        self.routing_helper._process_router(ri)
        # We were able to remove the port from ri.internal_ports
        self.assertNotIn(
            router[l3_constants.INTERFACE_KEY][0], ri.internal_ports)

    def test_routers_with_admin_state_down(self):
        self.plugin_api.get_external_network_id.return_value = None

        routers = [
            {'id': _uuid(),
             'admin_state_up': False,
             'external_gateway_info': {}}]
        self.routing_helper._process_routers(routers, None)
        self.assertNotIn(routers[0]['id'], self.routing_helper.router_info)

    def test_router_deleted(self):
        self.routing_helper.router_deleted(None, [FAKE_ID])
        self.assertIn(FAKE_ID, self.routing_helper.removed_routers)

    def test_routers_updated(self):
        self.routing_helper.routers_updated(None, [FAKE_ID])
        self.assertIn(FAKE_ID, self.routing_helper.updated_routers)

    def test_removed_from_agent(self):
        self.routing_helper.router_removed_from_agent(None,
                                                      {'router_id': FAKE_ID})
        self.assertIn(FAKE_ID, self.routing_helper.removed_routers)

    def test_added_to_agent(self):
        self.routing_helper.router_added_to_agent(None, [FAKE_ID])
        self.assertIn(FAKE_ID, self.routing_helper.updated_routers)

    def test_process_router_delete(self):
        router = self.router
        router['gw_port'] = self.ex_gw_port
        self.routing_helper._router_added(router['id'], router)
        self.assertIn(router['id'], self.routing_helper.router_info)
        # Now we remove the router
        self.routing_helper._router_removed(router['id'], deconfigure=True)
        self.assertNotIn(router['id'], self.routing_helper.router_info)

    def test_collect_state(self):
        router, ports = prepare_router_data(enable_snat=True,
                                            num_internal_ports=2)
        self.routing_helper._router_added(router['id'], router)

        configurations = {}
        configurations = self.routing_helper.collect_state(configurations)
        hd_exp_result = {
            router['hosting_device']['id']: {'routers': 1}}
        self.assertEqual(1, configurations['total routers'])
        self.assertEqual(1, configurations['total ex_gw_ports'])
        self.assertEqual(2, configurations['total interfaces'])
        self.assertEqual(0, configurations['total floating_ips'])
        self.assertEqual(hd_exp_result, configurations['hosting_devices'])
        self.assertEqual([], configurations['non_responding_hosting_devices'])

    def test_sort_resources_per_hosting_device(self):
        router1, port = prepare_router_data()
        router2, port = prepare_router_data()
        router3, port = prepare_router_data()
        router4, port = prepare_router_data()

        hd1_id = router1['hosting_device']['id']
        hd2_id = router4['hosting_device']['id']
        #Setting router2 and router3 device id same as router1's device id
        router2['hosting_device']['id'] = hd1_id
        router3['hosting_device']['id'] = hd1_id

        resources = {'routers': [router1, router2, router4],
                     'removed_routers': [router3]}
        devices = self.routing_helper._sort_resources_per_hosting_device(
            resources)

        self.assertEqual(2, len(devices.keys()))  # Two devices
        hd1_routers = [router1, router2]
        self.assertEqual(hd1_routers, devices[hd1_id]['routers'])
        self.assertEqual([router3], devices[hd1_id]['removed_routers'])
        self.assertEqual([router4], devices[hd2_id]['routers'])

    def test_get_router_ids_from_removed_devices_info(self):
        removed_devices_info = {
            'hosting_data': {'device_1': {'routers': ['id1', 'id2']},
                             'device_2': {'routers': ['id3', 'id4'],
                                          'other_key': ['value1', 'value2']}}
        }
        resp = self.routing_helper._get_router_ids_from_removed_devices_info(
            removed_devices_info)
        self.assertEqual(sorted(resp), sorted(['id1', 'id2', 'id3', 'id4']))

    @mock.patch("eventlet.GreenPool.spawn_n")
    def test_process_services_full_sync_different_devices(self, mock_spawn):
        router1, port = prepare_router_data()
        router2, port = prepare_router_data()
        self.plugin_api.get_routers = mock.Mock(
            return_value=[router1, router2])
        self.routing_helper.process_service()
        self.assertEqual(2, mock_spawn.call_count)
        call1 = mock.call(self.routing_helper._process_routers, [router1],
                          None, router1['hosting_device']['id'],
                          all_routers=True)
        call2 = mock.call(self.routing_helper._process_routers, [router2],
                          None, router2['hosting_device']['id'],
                          all_routers=True)
        mock_spawn.assert_has_calls([call1, call2], any_order=True)

    @mock.patch("eventlet.GreenPool.spawn_n")
    def test_process_services_full_sync_same_device(self, mock_spawn):
        router1, port = prepare_router_data()
        router2, port = prepare_router_data()
        router2['hosting_device']['id'] = router1['hosting_device']['id']
        self.plugin_api.get_routers = mock.Mock(return_value=[router1,
                                                              router2])
        self.routing_helper.process_service()
        self.assertEqual(1, mock_spawn.call_count)
        mock_spawn.assert_called_with(self.routing_helper._process_routers,
                                      [router1, router2],
                                      None,
                                      router1['hosting_device']['id'],
                                      all_routers=True)

    @mock.patch("eventlet.GreenPool.spawn_n")
    def test_process_services_with_updated_routers(self, mock_spawn):

        router1, port = prepare_router_data()

        def routers_data(context, router_ids=None, hd_ids=None):
            if router_ids:
                return [router1]
        self.plugin_api.get_routers.side_effect = routers_data

        self.routing_helper.fullsync = False
        self.routing_helper.updated_routers.add(router1['id'])
        self.routing_helper.process_service()
        self.assertEqual(1, self.plugin_api.get_routers.call_count)
        self.plugin_api.get_routers.assert_called_with(
            self.routing_helper.context,
            router_ids=[router1['id']])
        self.assertEqual(1, mock_spawn.call_count)
        mock_spawn.assert_called_with(self.routing_helper._process_routers,
                                      [router1],
                                      None,
                                      router1['hosting_device']['id'],
                                      all_routers=False)

    @mock.patch("eventlet.GreenPool.spawn_n")
    def test_process_services_with_deviceid(self, mock_spawn):

        router, port = prepare_router_data()
        device_id = router['hosting_device']['id']

        def routers_data(context, router_ids=None, hd_ids=None):
            if hd_ids:
                self.assertEqual([device_id], hd_ids)
                return [router]

        self.plugin_api.get_routers.side_effect = routers_data
        self.routing_helper.fullsync = False
        self.routing_helper.process_service(device_ids=[device_id])
        self.assertEqual(1, self.plugin_api.get_routers.call_count)
        self.plugin_api.get_routers.assert_called_with(
            self.routing_helper.context,
            hd_ids=[device_id])
        self.assertEqual(1, mock_spawn.call_count)
        mock_spawn.assert_called_with(self.routing_helper._process_routers,
                                      [router],
                                      None,
                                      device_id,
                                      all_routers=False)

    @mock.patch("eventlet.GreenPool.spawn_n")
    def test_process_services_with_removed_routers(self, mock_spawn):
        router, port = prepare_router_data()
        device_id = router['hosting_device']['id']

        self._mock_driver_and_hosting_device(self.routing_helper)
        self.routing_helper.fullsync = False
        # Emulate router added for setting up internal structures
        self.routing_helper._router_added(router['id'], router)
        # Add router to removed routers list and process it
        self.routing_helper.removed_routers.add(router['id'])
        self.routing_helper.process_service()

        self.assertEqual(1, mock_spawn.call_count)
        mock_spawn.assert_called_with(self.routing_helper._process_routers,
                                      None,
                                      [router],
                                      device_id,
                                      all_routers=False)

    @mock.patch("eventlet.GreenPool.spawn_n")
    def test_process_services_with_removed_routers_info(self, mock_spawn):
        router1, port = prepare_router_data()
        device_id = router1['hosting_device']['id']
        router2, port = prepare_router_data()
        router2['hosting_device']['id'] = _uuid()

        removed_devices_info = {
            'hosting_data': {device_id: {'routers': [router1['id']]}},
            'deconfigure': True
        }

        self._mock_driver_and_hosting_device(self.routing_helper)
        self.routing_helper.fullsync = False
        # Emulate router added for setting up internal structures
        self.routing_helper._router_added(router1['id'], router1)
        self.routing_helper._router_added(router2['id'], router2)
        # Add router to removed routers list and process it
        self.routing_helper.removed_routers.add(router2['id'])
        self.routing_helper.process_service(
            removed_devices_info=removed_devices_info)

        self.assertEqual(2, mock_spawn.call_count)
        call1 = mock.call(self.routing_helper._process_routers,
                          None,
                          [router1],
                          router1['hosting_device']['id'],
                          all_routers=False)
        call2 = mock.call(self.routing_helper._process_routers,
                          None,
                          [router2],
                          router2['hosting_device']['id'],
                          all_routers=False)
        mock_spawn.assert_has_calls([call1, call2], any_order=True)

    @mock.patch("eventlet.GreenPool.spawn_n")
    def test_process_services_with_rpc_error(self, mock_spawn):
        router, port = prepare_router_data()
        self.plugin_api.get_routers.side_effect = n_rpc.RPCException
        self.routing_helper.fullsync = False
        self.routing_helper.updated_routers.add(router['id'])
        self.routing_helper.process_service()
        self.assertEqual(1, self.plugin_api.get_routers.call_count)
        self.plugin_api.get_routers.assert_called_with(
            self.routing_helper.context,
            router_ids=[router['id']])
        self.assertFalse(mock_spawn.called)
        self.assertTrue(self.routing_helper.fullsync)

    def test_process_routers(self):
        router, port = prepare_router_data()
        driver = self._mock_driver_and_hosting_device(self.routing_helper)
        self.routing_helper._process_router = mock.Mock()
        self.routing_helper._process_routers([router], None)
        ri = self.routing_helper.router_info[router['id']]
        driver.router_added.assert_called_with(ri)
        self.routing_helper._process_router.assert_called_with(ri)

    def _process_routers_floatingips(self, action='add'):
        router, port = prepare_router_data()
        driver = self._mock_driver_and_hosting_device(self.routing_helper)
        ex_gw_port = router['gw_port']
        floating_ip_address = '19.4.4.10'
        fixed_ip_address = '35.4.1.10'
        fixed_ip_address_2 = '35.4.1.15'
        port_id = 'fake_port_id'
        floating_ip = {'fixed_ip_address': fixed_ip_address,
                       'floating_ip_address': floating_ip_address,
                       'id': 'floating_ip_id',
                       'port_id': port_id,
                       'status': 'ACTIVE', }
        router[l3_constants.FLOATINGIP_KEY] = [floating_ip]
        ri = RouterInfo(router['id'], router=router)

        # Default add action
        self.routing_helper._process_router_floating_ips(ri, ex_gw_port)
        driver.floating_ip_added.assert_called_with(
            ri, ex_gw_port, floating_ip_address, fixed_ip_address)

        if action == 'remove':
            router[l3_constants.FLOATINGIP_KEY] = []
            self.routing_helper._process_router_floating_ips(ri, ex_gw_port)
            driver.floating_ip_removed.assert_called_with(
                ri, ri.ex_gw_port, floating_ip_address, fixed_ip_address)

        if action == 'remap':
            driver.reset_mock()
            floating_ip_2 = copy.deepcopy(floating_ip)
            floating_ip_2['fixed_ip_address'] = fixed_ip_address_2
            ri.router[l3_constants.FLOATINGIP_KEY] = [floating_ip_2]

            self.routing_helper._process_router_floating_ips(ri, ex_gw_port)
            driver.floating_ip_added.assert_called_with(
                ri, ri.ex_gw_port, floating_ip_address, fixed_ip_address_2)

            driver.floating_ip_removed.assert_called_with(
                ri, ri.ex_gw_port, floating_ip_address, fixed_ip_address)

    def test_process_routers_floatingips_add(self):
        self._process_routers_floatingips(action="add")

    def test_process_routers_floatingips_remove(self):
        self._process_routers_floatingips(action="remove")

    def test_process_routers_floatingips_remap(self):
        self._process_routers_floatingips(action="remap")
