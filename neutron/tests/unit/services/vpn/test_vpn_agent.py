# Copyright 2013, Nachi Ueno, NTT I3, Inc.
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

import mock
from oslo.config import cfg

from neutron.agent.common import config as agent_config
from neutron.agent import l3_agent
from neutron.agent import l3_ha_agent
from neutron.agent.linux import interface
from neutron.common import config as base_config
from neutron.openstack.common import uuidutils
from neutron.services.vpn import agent
from neutron.services.vpn import device_drivers
from neutron.tests import base

_uuid = uuidutils.generate_uuid
NOOP_DEVICE_CLASS = 'NoopDeviceDriver'
NOOP_DEVICE = ('neutron.tests.unit.services.'
               'vpn.test_vpn_agent.%s' % NOOP_DEVICE_CLASS)


class NoopDeviceDriver(device_drivers.DeviceDriver):
    def sync(self, context, processes):
        pass

    def create_router(self, process_id):
        pass

    def destroy_router(self, process_id):
        pass


class TestVPNAgent(base.BaseTestCase):
    def setUp(self):
        super(TestVPNAgent, self).setUp()
        self.conf = cfg.CONF
        self.conf.register_opts(base_config.core_opts)
        self.conf.register_opts(l3_agent.L3NATAgent.OPTS)
        self.conf.register_opts(l3_ha_agent.OPTS)
        self.conf.register_opts(interface.OPTS)
        agent_config.register_interface_driver_opts_helper(self.conf)
        agent_config.register_use_namespaces_opts_helper(self.conf)
        agent_config.register_agent_state_opts_helper(self.conf)
        agent_config.register_root_helper(self.conf)

        self.conf.set_override('interface_driver',
                               'neutron.agent.linux.interface.NullDriver')
        self.conf.set_override(
            'vpn_device_driver',
            [NOOP_DEVICE],
            'vpnagent')

        for clazz in [
            'neutron.agent.linux.ip_lib.device_exists',
            'neutron.agent.linux.ip_lib.IPWrapper',
            'neutron.agent.linux.interface.NullDriver',
            'neutron.agent.linux.utils.execute'
        ]:
            mock.patch(clazz).start()

        l3pluginApi_cls = mock.patch(
            'neutron.agent.l3_agent.L3PluginApi').start()
        self.plugin_api = mock.MagicMock()
        l3pluginApi_cls.return_value = self.plugin_api

        looping_call_p = mock.patch(
            'neutron.openstack.common.loopingcall.FixedIntervalLoopingCall')
        looping_call_p.start()

        self.fake_host = 'fake_host'
        self.agent = agent.VPNAgent(self.fake_host)

    def test_setup_drivers(self):
        self.assertEqual(1, len(self.agent.devices))
        device = self.agent.devices[0]
        self.assertEqual(
            NOOP_DEVICE_CLASS,
            device.__class__.__name__
        )

    def test_get_namespace(self):
        router_id = _uuid()
        ri = l3_agent.RouterInfo(router_id, self.conf.root_helper,
                                 self.conf.use_namespaces, {})
        self.agent.router_info = {router_id: ri}
        namespace = self.agent.get_namespace(router_id)
        self.assertTrue(namespace.endswith(router_id))
        self.assertFalse(self.agent.get_namespace('fake_id'))

    def test_add_nat_rule(self):
        router_id = _uuid()
        ri = l3_agent.RouterInfo(router_id, self.conf.root_helper,
                                 self.conf.use_namespaces, {})
        iptables = mock.Mock()
        ri.iptables_manager.ipv4['nat'] = iptables
        self.agent.router_info = {router_id: ri}
        self.agent.add_nat_rule(router_id, 'fake_chain', 'fake_rule', True)
        iptables.add_rule.assert_called_once_with(
            'fake_chain', 'fake_rule', top=True)

    def test_add_nat_rule_with_no_router(self):
        self.agent.router_info = {}
        #Should do nothing
        self.agent.add_nat_rule(
            'fake_router_id',
            'fake_chain',
            'fake_rule',
            True)

    def test_remove_rule(self):
        router_id = _uuid()
        ri = l3_agent.RouterInfo(router_id, self.conf.root_helper,
                                 self.conf.use_namespaces, {})
        iptables = mock.Mock()
        ri.iptables_manager.ipv4['nat'] = iptables
        self.agent.router_info = {router_id: ri}
        self.agent.remove_nat_rule(router_id, 'fake_chain', 'fake_rule', True)
        iptables.remove_rule.assert_called_once_with(
            'fake_chain', 'fake_rule', top=True)

    def test_remove_rule_with_no_router(self):
        self.agent.router_info = {}
        #Should do nothing
        self.agent.remove_nat_rule(
            'fake_router_id',
            'fake_chain',
            'fake_rule')

    def test_iptables_apply(self):
        router_id = _uuid()
        ri = l3_agent.RouterInfo(router_id, self.conf.root_helper,
                                 self.conf.use_namespaces, {})
        iptables = mock.Mock()
        ri.iptables_manager = iptables
        self.agent.router_info = {router_id: ri}
        self.agent.iptables_apply(router_id)
        iptables.apply.assert_called_once_with()

    def test_iptables_apply_with_no_router(self):
        #Should do nothing
        self.agent.router_info = {}
        self.agent.iptables_apply('fake_router_id')

    def test_router_added(self):
        mock.patch(
            'neutron.agent.linux.iptables_manager.IptablesManager').start()
        router_id = _uuid()
        router = {'id': router_id}
        device = mock.Mock()
        self.agent.devices = [device]
        self.agent._router_added(router_id, router)
        device.create_router.assert_called_once_with(router_id)

    def test_router_removed(self):
        self.plugin_api.get_external_network_id.return_value = None
        mock.patch(
            'neutron.agent.linux.iptables_manager.IptablesManager').start()
        router_id = _uuid()
        ri = l3_agent.RouterInfo(router_id, self.conf.root_helper,
                                 self.conf.use_namespaces, {})
        ri.router = {
            'id': _uuid(),
            'admin_state_up': True,
            'routes': [],
            'external_gateway_info': {},
            'distributed': False}
        device = mock.Mock()
        self.agent.router_info = {router_id: ri}
        self.agent.devices = [device]
        self.agent._router_removed(router_id)
        device.destroy_router.assert_called_once_with(router_id)

    def test_process_routers(self):
        self.plugin_api.get_external_network_id.return_value = None
        routers = [
            {'id': _uuid(),
             'admin_state_up': True,
             'routes': [],
             'external_gateway_info': {}}]

        device = mock.Mock()
        self.agent.devices = [device]
        self.agent._process_routers(routers, False)
        device.sync.assert_called_once_with(mock.ANY, routers)
