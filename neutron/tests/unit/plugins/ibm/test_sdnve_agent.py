# Copyright 2014 IBM Corp.
#
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

import contextlib

import mock
from oslo_config import cfg

from neutron.agent.linux import ip_lib
from neutron.plugins.ibm.agent import sdnve_neutron_agent
from neutron.tests import base


NOTIFIER = ('neutron.plugins.ibm.'
            'sdnve_neutron_plugin.AgentNotifierApi')


class CreateAgentConfigMap(base.BaseTestCase):

    def test_create_agent_config_map_succeeds(self):
        self.assertTrue(sdnve_neutron_agent.create_agent_config_map(cfg.CONF))

    def test_create_agent_config_using_controller_ips(self):
        cfg.CONF.set_override('controller_ips',
                              ['10.10.10.1', '10.10.10.2'], group='SDNVE')
        cfgmap = sdnve_neutron_agent.create_agent_config_map(cfg.CONF)
        self.assertEqual(cfgmap['controller_ip'], '10.10.10.1')

    def test_create_agent_config_using_interface_mappings(self):
        cfg.CONF.set_override('interface_mappings',
                              ['interface1 : eth1', 'interface2 : eth2'],
                              group='SDNVE')
        cfgmap = sdnve_neutron_agent.create_agent_config_map(cfg.CONF)
        self.assertEqual(cfgmap['interface_mappings'],
                         {'interface1': 'eth1', 'interface2': 'eth2'})


class TestSdnveNeutronAgent(base.BaseTestCase):

    def setUp(self):
        super(TestSdnveNeutronAgent, self).setUp()
        notifier_p = mock.patch(NOTIFIER)
        notifier_cls = notifier_p.start()
        self.notifier = mock.Mock()
        notifier_cls.return_value = self.notifier
        cfg.CONF.set_override('integration_bridge',
                              'br_int', group='SDNVE')
        kwargs = sdnve_neutron_agent.create_agent_config_map(cfg.CONF)

        class MockFixedIntervalLoopingCall(object):
            def __init__(self, f):
                self.f = f

            def start(self, interval=0):
                self.f()

        with contextlib.nested(
            mock.patch('neutron.plugins.ibm.agent.sdnve_neutron_agent.'
                       'SdnveNeutronAgent.setup_integration_br',
                       return_value=mock.Mock()),
            mock.patch('neutron.openstack.common.loopingcall.'
                       'FixedIntervalLoopingCall',
                       new=MockFixedIntervalLoopingCall)):
            self.agent = sdnve_neutron_agent.SdnveNeutronAgent(**kwargs)

    def test_setup_physical_interfaces(self):
        with mock.patch.object(self.agent.int_br,
                               'add_port') as add_port_func:
            with mock.patch.object(ip_lib,
                                   'device_exists',
                                   return_valxue=True):
                self.agent.setup_physical_interfaces({"interface1": "eth1"})
        add_port_func.assert_called_once_with('eth1')

    def test_setup_physical_interfaces_none(self):
        with mock.patch.object(self.agent.int_br,
                               'add_port') as add_port_func:
            with mock.patch.object(ip_lib,
                                   'device_exists',
                                   return_valxue=True):
                self.agent.setup_physical_interfaces({})
        self.assertFalse(add_port_func.called)

    def test_get_info_set_controller(self):
        with mock.patch.object(self.agent.int_br,
                               'set_controller') as set_controller_func:
            kwargs = {}
            kwargs['info'] = {'new_controller': '10.10.10.1'}
            self.agent.info_update('dummy', **kwargs)
        set_controller_func.assert_called_once_with(['tcp:10.10.10.1'])

    def test_get_info(self):
        with mock.patch.object(self.agent.int_br,
                               'set_controller') as set_controller_func:
            kwargs = {}
            self.agent.info_update('dummy', **kwargs)
        self.assertFalse(set_controller_func.called)
