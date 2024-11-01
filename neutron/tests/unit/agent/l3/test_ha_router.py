# Copyright (c) 2015 OpenStack Foundation
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
import signal
from unittest import mock

from neutron_lib import constants as n_consts
from neutron_lib import fixture as lib_fixtures
from oslo_utils import uuidutils

from neutron.agent.l3 import ha_router
from neutron.agent.l3 import router_info
from neutron.common import utils as common_utils
from neutron.tests import base
from neutron.tests.common import l3_test_common

_uuid = uuidutils.generate_uuid


class TestBasicRouterOperations(base.BaseTestCase):
    def setUp(self):
        super().setUp()
        self.device_exists_p = mock.patch(
            'neutron.agent.linux.ip_lib.device_exists')
        self.device_exists = self.device_exists_p.start()
        self.delete_if_exists_p = mock.patch(
            'neutron.agent.linux.utils.delete_if_exists')
        self.delete_if_exists = self.delete_if_exists_p.start()

    def _create_router(self, router=None, **kwargs):
        if not router:
            router = mock.MagicMock()
        self.agent_conf = mock.Mock()
        self.router_id = _uuid()
        return ha_router.HaRouter(mock.sentinel.agent,
                                  self.router_id,
                                  router,
                                  self.agent_conf,
                                  mock.sentinel.driver,
                                  **kwargs)

    def test_get_router_cidrs_returns_ha_cidrs(self):
        ri = self._create_router()
        device = mock.MagicMock()
        device.name.return_value = 'eth2'
        addresses = ['15.1.2.2/24', '15.1.2.3/32']
        ri._get_cidrs_from_keepalived = mock.MagicMock(return_value=addresses)
        self.assertEqual(set(addresses), ri.get_router_cidrs(device))

    def test_routes_updated_with_dvr(self):
        ri = self._create_router(router={'distributed': True})
        ri.keepalived_manager = mock.Mock()
        base_routes_updated = mock.patch(
            'neutron.agent.l3.router_info.'
            'RouterInfo.routes_updated').start()
        mock_instance = mock.Mock()
        mock_instance.virtual_routes.gateway_routes = []
        ri._get_keepalived_instance = mock.Mock(
            return_value=mock_instance)
        ri.routes_updated([], [])
        self.assertTrue(base_routes_updated.called)

    def test_routes_updated_with_non_dvr(self):
        ri = self._create_router(router={'distributed': False})
        ri.keepalived_manager = mock.Mock()
        base_routes_updated = mock.patch(
            'neutron.agent.l3.router_info.'
            'RouterInfo.routes_updated').start()
        mock_instance = mock.Mock()
        mock_instance.virtual_routes.gateway_routes = []
        ri._get_keepalived_instance = mock.Mock(return_value=mock_instance)
        ri.routes_updated([], [])
        self.assertFalse(base_routes_updated.called)

    def test__add_default_gw_virtual_route(self):
        ri = self._create_router()
        mock_instance = mock.Mock()
        mock_instance.virtual_routes.gateway_routes = []
        ri._get_keepalived_instance = mock.Mock(return_value=mock_instance)
        subnets = [{'id': _uuid(),
                    'cidr': '20.0.0.0/24',
                    'gateway_ip': None}]
        ex_gw_port = {'fixed_ips': [],
                      'subnets': subnets,
                      'extra_subnets': [],
                      'id': _uuid(),
                      'network_id': _uuid(),
                      'mac_address': 'ca:fe:de:ad:be:ef'}
        # Make sure no exceptional code
        ri._add_default_gw_virtual_route(ex_gw_port, 'qg-abc')
        self.assertEqual(0, len(mock_instance.virtual_routes.gateway_routes))

        subnets.append({'id': _uuid(),
                        'cidr': '30.0.0.0/24',
                        'gateway_ip': '30.0.0.1'})
        ri._add_default_gw_virtual_route(ex_gw_port, 'qg-abc')
        self.assertEqual(1, len(mock_instance.virtual_routes.gateway_routes))

        subnets[1]['gateway_ip'] = None
        ri._add_default_gw_virtual_route(ex_gw_port, 'qg-abc')
        self.assertEqual(0, len(mock_instance.virtual_routes.gateway_routes))

        subnets[1]['gateway_ip'] = '30.0.1.1'
        ri._add_default_gw_virtual_route(ex_gw_port, 'qg-abc')
        self.assertEqual(2, len(mock_instance.virtual_routes.gateway_routes))

    @mock.patch.object(router_info.RouterInfo, 'remove_floating_ip')
    def test_remove_floating_ip(self, super_remove_floating_ip):
        ri = self._create_router(mock.MagicMock())
        mock_instance = mock.Mock()
        ri._get_keepalived_instance = mock.Mock(return_value=mock_instance)
        device = mock.Mock()
        fip_cidr = '15.1.2.3/32'

        ri.remove_floating_ip(device, fip_cidr)
        self.assertTrue(super_remove_floating_ip.called)

    @mock.patch.object(ha_router.LOG, 'debug')
    def test_spawn_state_change_monitor(self, mock_log):
        ri = self._create_router(mock.MagicMock())
        with mock.patch.object(ri,
                               '_get_state_change_monitor_process_manager')\
                as m_get_state:
            mock_pm = m_get_state.return_value
            mock_pm.active = True
            mock_pm.pid = 1234
            ri.spawn_state_change_monitor(mock_pm)

        mock_pm.enable.assert_called_once()
        mock_log.assert_called_once()

    @mock.patch.object(ha_router.LOG, 'warning')
    def test_spawn_state_change_monitor_no_pid(self, mock_log):
        ri = self._create_router(mock.MagicMock())
        with mock.patch.object(ri,
                               '_get_state_change_monitor_process_manager')\
                as m_get_state:
            mock_pm = m_get_state.return_value
            mock_pm.active = True
            mock_pm.pid = None
            ri.spawn_state_change_monitor(mock_pm)

        mock_pm.enable.assert_called_once()
        mock_log.assert_called_once()

    def test_destroy_state_change_monitor_ok(self):
        ri = self._create_router(mock.MagicMock())
        # need a port for destroy_state_change_monitor() to call PM code
        ri.ha_port = {'id': _uuid()}
        with mock.patch.object(ri,
                               '_get_state_change_monitor_process_manager')\
                as m_get_state:
            mock_pm = m_get_state.return_value
            mock_pm.active = False
            ri.destroy_state_change_monitor(mock_pm)

        mock_pm.disable.assert_called_once_with(
            sig=str(int(signal.SIGTERM)))

    @mock.patch.object(common_utils, 'wait_until_true')
    @mock.patch.object(ha_router.HaRouter,
                       '_get_state_change_monitor_process_manager')
    def test_destroy_state_change_monitor_force(self, m_get_state,
                                                mock_wait_until):
        ri = self._create_router(mock.MagicMock())
        # need a port for destroy_state_change_monitor() to call PM code
        ri.ha_port = {'id': _uuid()}
        mock_pm = m_get_state.return_value
        mock_pm.active = False
        mock_wait_until.side_effect = common_utils.WaitTimeout

        ri.destroy_state_change_monitor(mock_pm)

        m_get_state.assert_called_once_with()
        mock_pm.unregister.assert_called_once_with(
            self.router_id, ha_router.IP_MONITOR_PROCESS_SERVICE)
        mock_wait_until.assert_called_once_with(mock.ANY, timeout=10)
        mock_pm.disable.assert_has_calls([
            mock.call(sig=str(int(signal.SIGTERM))),
            mock.call(sig=str(int(signal.SIGKILL)))])

    def _test_ha_state(self, read_return, expected):
        ri = self._create_router(mock.MagicMock())
        ri.keepalived_manager = mock.Mock()
        ri.keepalived_manager.get_full_config_file_path.return_value = (
            'ha_state')
        self.mock_open = self.useFixture(
            lib_fixtures.OpenFixture('ha_state', read_return)).mock_open
        self.assertEqual(expected, ri.ha_state)

    def test_ha_state_primary(self):
        self._test_ha_state('primary', 'primary')

    def test_ha_state_unknown(self):
        # an empty state file should yield 'unknown'
        self._test_ha_state('', 'unknown')

    def test_ha_state_ioerror(self):
        # an error reading the state file should yield 'unknown'
        ri = self._create_router(mock.MagicMock())
        ri.keepalived_manager = mock.Mock()
        ri.keepalived_manager.get_full_config_file_path.return_value = (
            'ha_state')
        self.mock_open = IOError
        self.assertEqual('unknown', ri.ha_state)

    def test_gateway_ports_equal(self):
        ri = self._create_router(mock.MagicMock())
        ri.driver = mock.MagicMock()
        subnet_id, qos_policy_id = _uuid(), _uuid()
        _, old_gw_port = l3_test_common.prepare_ext_gw_test(
            self, ri, True)
        old_gw_port['qos_policy_id'] = qos_policy_id
        new_gw_port = copy.deepcopy(old_gw_port)
        new_gw_port.update({'binding:host_id': 'node02',
                            'updated_at': '2018-11-02T14:07:00',
                            'revision_number': 101,
                            'qos_policy_id': qos_policy_id})
        self.assertTrue(ri._gateway_ports_equal(old_gw_port, new_gw_port))

        fixed_ip = {'ip_address': '10.10.10.3', 'subnet_id': subnet_id}
        new_gw_port['fixed_ips'].append(fixed_ip)
        self.assertFalse(ri._gateway_ports_equal(old_gw_port, new_gw_port))

        new_gw_port['fixed_ips'].remove(fixed_ip)
        new_gw_port['qos_policy_id'] = _uuid()
        self.assertFalse(ri._gateway_ports_equal(old_gw_port, new_gw_port))

    def test_set_ha_port(self):
        ri = self._create_router()
        self.assertIsNone(ri.ha_port)

        ri.router = {}
        ri.set_ha_port()
        self.assertIsNone(ri.ha_port)

        # HA_INTERFACE_KEY from None to some value
        ri.router = {n_consts.HA_INTERFACE_KEY: {"id": _uuid(),
                                                 "status": "DOWN"}}
        ri.set_ha_port()
        self.assertIsNotNone(ri.ha_port)
        self.assertEqual('DOWN', ri.ha_port["status"])

        # HA port state change
        ri.router = {n_consts.HA_INTERFACE_KEY: {"id": _uuid(),
                                                 "status": "ACTIVE"}}
        ri.set_ha_port()
        self.assertIsNotNone(ri.ha_port)
        self.assertEqual('ACTIVE', ri.ha_port["status"])

        ri.router = {}
        ri.set_ha_port()
        # neutron server return empty HA_INTERFACE_KEY, but
        # agent side router info should remain the original value.
        self.assertIsNotNone(ri.ha_port)
