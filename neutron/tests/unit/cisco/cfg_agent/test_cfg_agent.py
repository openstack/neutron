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

import mock
from oslo_config import cfg
import testtools

from neutron.agent.common import config
from neutron.common import config as base_config
from neutron.common import constants as l3_constants
from neutron.openstack.common import uuidutils
from neutron.plugins.cisco.cfg_agent import cfg_agent
from neutron.tests import base

_uuid = uuidutils.generate_uuid
HOSTNAME = 'myhost'
FAKE_ID = _uuid()


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
                      'host_type': 'CSR1kv',
                      'ip_address': '20.0.0.5',
                      'port': '23'}

    router = {
        'id': router_id,
        l3_constants.INTERFACE_KEY: int_ports,
        'routes': [],
        'gw_port': ex_gw_port,
        'hosting_device': hosting_device}
    if enable_snat is not None:
        router['enable_snat'] = enable_snat
    return router, int_ports


class TestCiscoCfgAgentWIthStateReporting(base.BaseTestCase):

    def setUp(self):
        self.conf = cfg.ConfigOpts()
        config.register_agent_state_opts_helper(cfg.CONF)
        self.conf.register_opts(base_config.core_opts)
        self.conf.register_opts(cfg_agent.CiscoCfgAgent.OPTS, "cfg_agent")
        cfg.CONF.set_override('report_interval', 0, 'AGENT')
        super(TestCiscoCfgAgentWIthStateReporting, self).setUp()
        self.devmgr_plugin_api_cls_p = mock.patch(
            'neutron.plugins.cisco.cfg_agent.cfg_agent.'
            'CiscoDeviceManagementApi')
        devmgr_plugin_api_cls = self.devmgr_plugin_api_cls_p.start()
        self.devmgr_plugin_api = mock.Mock()
        devmgr_plugin_api_cls.return_value = self.devmgr_plugin_api
        self.devmgr_plugin_api.register_for_duty.return_value = True

        self.plugin_reportstate_api_cls_p = mock.patch(
            'neutron.agent.rpc.PluginReportStateAPI')
        plugin_reportstate_api_cls = self.plugin_reportstate_api_cls_p.start()
        self.plugin_reportstate_api = mock.Mock()
        plugin_reportstate_api_cls.return_value = self.plugin_reportstate_api

        self.looping_call_p = mock.patch(
            'neutron.openstack.common.loopingcall.FixedIntervalLoopingCall')
        self.looping_call_p.start()

        mock.patch('neutron.common.rpc.create_connection').start()

    def test_agent_registration_success(self):
        agent = cfg_agent.CiscoCfgAgentWithStateReport(HOSTNAME, self.conf)
        self.assertTrue(agent.devmgr_rpc.register_for_duty(agent.context))

    def test_agent_registration_success_after_2_tries(self):
        self.devmgr_plugin_api.register_for_duty = mock.Mock(
            side_effect=[False, False, True])
        cfg_agent.REGISTRATION_RETRY_DELAY = 0.01
        agent = cfg_agent.CiscoCfgAgentWithStateReport(HOSTNAME, self.conf)
        self.assertEqual(agent.devmgr_rpc.register_for_duty.call_count, 3)

    def test_agent_registration_fail_always(self):
        self.devmgr_plugin_api.register_for_duty = mock.Mock(
            return_value=False)
        cfg_agent.REGISTRATION_RETRY_DELAY = 0.01
        cfg_agent.MAX_REGISTRATION_ATTEMPTS = 3
        with testtools.ExpectedException(SystemExit):
            cfg_agent.CiscoCfgAgentWithStateReport(HOSTNAME, self.conf)

    def test_agent_registration_no_device_mgr(self):
        self.devmgr_plugin_api.register_for_duty = mock.Mock(
            return_value=None)
        cfg_agent.REGISTRATION_RETRY_DELAY = 0.01
        cfg_agent.MAX_REGISTRATION_ATTEMPTS = 3
        with testtools.ExpectedException(SystemExit):
            cfg_agent.CiscoCfgAgentWithStateReport(HOSTNAME, self.conf)

    def test_report_state(self):
        agent = cfg_agent.CiscoCfgAgentWithStateReport(HOSTNAME, self.conf)
        agent._report_state()
        self.assertIn('total routers', agent.agent_state['configurations'])
        self.assertEqual(0, agent.agent_state[
            'configurations']['total routers'])

    @mock.patch('neutron.plugins.cisco.cfg_agent.'
                'cfg_agent.CiscoCfgAgentWithStateReport._agent_registration')
    def test_report_state_attribute_error(self, agent_registration):
        cfg.CONF.set_override('report_interval', 1, 'AGENT')
        self.plugin_reportstate_api.report_state.side_effect = AttributeError
        agent = cfg_agent.CiscoCfgAgentWithStateReport(HOSTNAME, self.conf)
        agent.heartbeat = mock.Mock()
        agent.send_agent_report(None, None)
        self.assertTrue(agent.heartbeat.stop.called)
