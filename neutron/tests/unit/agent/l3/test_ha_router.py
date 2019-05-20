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

import signal

import mock
from neutron_lib import constants as n_consts
from oslo_utils import uuidutils

from neutron.agent.l3 import ha_router
from neutron.agent.l3 import router_info
from neutron.tests import base

_uuid = uuidutils.generate_uuid


class TestBasicRouterOperations(base.BaseTestCase):

    def _create_router(self, router=None, **kwargs):
        if not router:
            router = mock.MagicMock()
        self.agent_conf = mock.Mock()
        self.router_id = _uuid()
        return ha_router.HaRouter(mock.sentinel.enqueue_state,
                                  mock.sentinel.agent,
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

    @mock.patch.object(router_info.RouterInfo, 'remove_floating_ip')
    def test_remove_floating_ip(self, super_remove_floating_ip):
        ri = self._create_router(mock.MagicMock())
        mock_instance = mock.Mock()
        ri._get_keepalived_instance = mock.Mock(return_value=mock_instance)
        device = mock.Mock()
        fip_cidr = '15.1.2.3/32'

        ri.remove_floating_ip(device, fip_cidr)
        self.assertTrue(super_remove_floating_ip.called)

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

    def test_destroy_state_change_monitor_force(self):
        ri = self._create_router(mock.MagicMock())
        # need a port for destroy_state_change_monitor() to call PM code
        ri.ha_port = {'id': _uuid()}
        with mock.patch.object(ri,
                               '_get_state_change_monitor_process_manager')\
                as m_get_state:
            mock_pm = m_get_state.return_value
            mock_pm.active = False
            with mock.patch.object(ha_router, 'SIGTERM_TIMEOUT', 0):
                ri.destroy_state_change_monitor(mock_pm)

        calls = ["sig='str(%d)'" % signal.SIGTERM,
                 "sig='str(%d)'" % signal.SIGKILL]
        mock_pm.disable.has_calls(calls)

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
