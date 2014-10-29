# Copyright (c) 2013 OpenStack Foundation
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

from neutron.common import constants
from neutron.common import topics
from neutron import context
from neutron.db import agents_db
from neutron.extensions import portbindings
from neutron.extensions import providernet as pnet
from neutron import manager
from neutron.openstack.common import timeutils
from neutron.plugins.ml2 import config as config
from neutron.plugins.ml2.drivers.l2pop import mech_driver as l2pop_mech_driver
from neutron.plugins.ml2 import managers
from neutron.plugins.ml2 import rpc
from neutron.tests.unit import test_db_plugin as test_plugin

HOST = 'my_l2_host'
L2_AGENT = {
    'binary': 'neutron-openvswitch-agent',
    'host': HOST,
    'topic': constants.L2_AGENT_TOPIC,
    'configurations': {'tunneling_ip': '20.0.0.1',
                       'tunnel_types': ['vxlan']},
    'agent_type': constants.AGENT_TYPE_OVS,
    'tunnel_type': [],
    'start_flag': True
}

L2_AGENT_2 = {
    'binary': 'neutron-openvswitch-agent',
    'host': HOST + '_2',
    'topic': constants.L2_AGENT_TOPIC,
    'configurations': {'tunneling_ip': '20.0.0.2',
                       'tunnel_types': ['vxlan']},
    'agent_type': constants.AGENT_TYPE_OVS,
    'tunnel_type': [],
    'start_flag': True
}

L2_AGENT_3 = {
    'binary': 'neutron-openvswitch-agent',
    'host': HOST + '_3',
    'topic': constants.L2_AGENT_TOPIC,
    'configurations': {'tunneling_ip': '20.0.0.3',
                       'tunnel_types': []},
    'agent_type': constants.AGENT_TYPE_OVS,
    'tunnel_type': [],
    'start_flag': True
}

L2_AGENT_4 = {
    'binary': 'neutron-openvswitch-agent',
    'host': HOST + '_4',
    'topic': constants.L2_AGENT_TOPIC,
    'configurations': {'tunneling_ip': '20.0.0.4',
                       'tunnel_types': ['vxlan']},
    'agent_type': constants.AGENT_TYPE_OVS,
    'tunnel_type': [],
    'start_flag': True
}

L2_AGENT_5 = {
    'binary': 'neutron-ofagent-agent',
    'host': HOST + '_5',
    'topic': constants.L2_AGENT_TOPIC,
    'configurations': {'tunneling_ip': '20.0.0.5',
                       'tunnel_types': [],
                       'bridge_mappings': {'phys1': 'br'},
                       'l2pop_network_types': ['vlan']},
    'agent_type': constants.AGENT_TYPE_OFA,
    'tunnel_type': [],
    'start_flag': True
}

PLUGIN_NAME = 'neutron.plugins.ml2.plugin.Ml2Plugin'
NOTIFIER = 'neutron.plugins.ml2.rpc.AgentNotifierApi'
DEVICE_OWNER_COMPUTE = 'compute:None'


class TestL2PopulationRpcTestCase(test_plugin.NeutronDbPluginV2TestCase):

    def setUp(self):
        # Enable the test mechanism driver to ensure that
        # we can successfully call through to all mechanism
        # driver apis.
        config.cfg.CONF.set_override('mechanism_drivers',
                                     ['openvswitch', 'linuxbridge',
                                      'ofagent', 'l2population'],
                                     'ml2')
        config.cfg.CONF.set_override('network_vlan_ranges',
                                     ['phys1:1:100'],
                                     'ml2_type_vlan')
        super(TestL2PopulationRpcTestCase, self).setUp(PLUGIN_NAME)

        self.adminContext = context.get_admin_context()

        self.type_manager = managers.TypeManager()
        self.notifier = rpc.AgentNotifierApi(topics.AGENT)
        self.callbacks = rpc.RpcCallbacks(self.notifier, self.type_manager)

        net_arg = {pnet.NETWORK_TYPE: 'vxlan',
                   pnet.SEGMENTATION_ID: '1'}
        self._network = self._make_network(self.fmt, 'net1', True,
                                           arg_list=(pnet.NETWORK_TYPE,
                                                     pnet.SEGMENTATION_ID,),
                                           **net_arg)

        net_arg = {pnet.NETWORK_TYPE: 'vlan',
                   pnet.PHYSICAL_NETWORK: 'phys1',
                   pnet.SEGMENTATION_ID: '2'}
        self._network2 = self._make_network(self.fmt, 'net2', True,
                                            arg_list=(pnet.NETWORK_TYPE,
                                                      pnet.PHYSICAL_NETWORK,
                                                      pnet.SEGMENTATION_ID,),
                                            **net_arg)

        notifier_patch = mock.patch(NOTIFIER)
        notifier_patch.start()

        self.fanout_topic = topics.get_topic_name(topics.AGENT,
                                                  topics.L2POPULATION,
                                                  topics.UPDATE)
        fanout = ('neutron.common.rpc.RpcProxy.fanout_cast')
        fanout_patch = mock.patch(fanout)
        self.mock_fanout = fanout_patch.start()

        cast = ('neutron.common.rpc.RpcProxy.cast')
        cast_patch = mock.patch(cast)
        self.mock_cast = cast_patch.start()

        uptime = ('neutron.plugins.ml2.drivers.l2pop.db.L2populationDbMixin.'
                  'get_agent_uptime')
        uptime_patch = mock.patch(uptime, return_value=190)
        uptime_patch.start()

    def _register_ml2_agents(self):
        callback = agents_db.AgentExtRpcCallback()
        callback.report_state(self.adminContext,
                              agent_state={'agent_state': L2_AGENT},
                              time=timeutils.strtime())
        callback.report_state(self.adminContext,
                              agent_state={'agent_state': L2_AGENT_2},
                              time=timeutils.strtime())
        callback.report_state(self.adminContext,
                              agent_state={'agent_state': L2_AGENT_3},
                              time=timeutils.strtime())
        callback.report_state(self.adminContext,
                              agent_state={'agent_state': L2_AGENT_4},
                              time=timeutils.strtime())
        callback.report_state(self.adminContext,
                              agent_state={'agent_state': L2_AGENT_5},
                              time=timeutils.strtime())

    def test_fdb_add_called(self):
        self._register_ml2_agents()

        with self.subnet(network=self._network) as subnet:
            host_arg = {portbindings.HOST_ID: HOST}
            with self.port(subnet=subnet,
                           device_owner=DEVICE_OWNER_COMPUTE,
                           arg_list=(portbindings.HOST_ID,),
                           **host_arg) as port1:
                with self.port(subnet=subnet,
                               arg_list=(portbindings.HOST_ID,),
                               **host_arg):
                    p1 = port1['port']

                    device = 'tap' + p1['id']

                    self.mock_fanout.reset_mock()
                    self.callbacks.update_device_up(self.adminContext,
                                                    agent_id=HOST,
                                                    device=device)

                    p1_ips = [p['ip_address'] for p in p1['fixed_ips']]
                    expected = {'args':
                                {'fdb_entries':
                                 {p1['network_id']:
                                  {'ports':
                                   {'20.0.0.1': [constants.FLOODING_ENTRY,
                                                 [p1['mac_address'],
                                                  p1_ips[0]]]},
                                   'network_type': 'vxlan',
                                   'segment_id': 1}}},
                                'namespace': None,
                                'method': 'add_fdb_entries'}

                    self.mock_fanout.assert_called_with(
                        mock.ANY, expected, topic=self.fanout_topic)

    def test_fdb_add_not_called_type_local(self):
        self._register_ml2_agents()

        with self.subnet(network=self._network) as subnet:
            host_arg = {portbindings.HOST_ID: HOST + '_3'}
            with self.port(subnet=subnet,
                           arg_list=(portbindings.HOST_ID,),
                           **host_arg) as port1:
                with self.port(subnet=subnet,
                               arg_list=(portbindings.HOST_ID,),
                               **host_arg):
                    p1 = port1['port']

                    device = 'tap' + p1['id']

                    self.mock_fanout.reset_mock()
                    self.callbacks.update_device_up(self.adminContext,
                                                    agent_id=HOST,
                                                    device=device)

                    self.assertFalse(self.mock_fanout.called)

    def test_fdb_add_called_for_l2pop_network_types(self):
        self._register_ml2_agents()

        host = HOST + '_5'
        with self.subnet(network=self._network2) as subnet:
            host_arg = {portbindings.HOST_ID: host}
            with self.port(subnet=subnet,
                           device_owner=DEVICE_OWNER_COMPUTE,
                           arg_list=(portbindings.HOST_ID,),
                           **host_arg) as port1:
                with self.port(subnet=subnet,
                               arg_list=(portbindings.HOST_ID,),
                               **host_arg):
                    p1 = port1['port']

                    device = 'tap' + p1['id']

                    self.mock_fanout.reset_mock()
                    self.callbacks.update_device_up(self.adminContext,
                                                    agent_id=host,
                                                    device=device)

                    p1_ips = [p['ip_address'] for p in p1['fixed_ips']]
                    expected = {'args':
                                {'fdb_entries':
                                 {p1['network_id']:
                                  {'ports':
                                   {'20.0.0.5': [constants.FLOODING_ENTRY,
                                                 [p1['mac_address'],
                                                  p1_ips[0]]]},
                                   'network_type': 'vlan',
                                   'segment_id': 2}}},
                                'namespace': None,
                                'method': 'add_fdb_entries'}

                    self.mock_fanout.assert_called_with(
                        mock.ANY, expected, topic=self.fanout_topic)

    def test_fdb_add_two_agents(self):
        self._register_ml2_agents()

        with self.subnet(network=self._network) as subnet:
            host_arg = {portbindings.HOST_ID: HOST,
                        'admin_state_up': True}
            with self.port(subnet=subnet,
                           device_owner=DEVICE_OWNER_COMPUTE,
                           arg_list=(portbindings.HOST_ID, 'admin_state_up',),
                           **host_arg) as port1:
                host_arg = {portbindings.HOST_ID: HOST + '_2',
                            'admin_state_up': True}
                with self.port(subnet=subnet,
                               device_owner=DEVICE_OWNER_COMPUTE,
                               arg_list=(portbindings.HOST_ID,
                                         'admin_state_up',),
                               **host_arg) as port2:
                    p1 = port1['port']
                    p2 = port2['port']

                    device = 'tap' + p1['id']

                    self.mock_cast.reset_mock()
                    self.mock_fanout.reset_mock()
                    self.callbacks.update_device_up(self.adminContext,
                                                    agent_id=HOST,
                                                    device=device)

                    p1_ips = [p['ip_address'] for p in p1['fixed_ips']]
                    p2_ips = [p['ip_address'] for p in p2['fixed_ips']]

                    expected1 = {'args':
                                 {'fdb_entries':
                                  {p1['network_id']:
                                   {'ports':
                                    {'20.0.0.2': [constants.FLOODING_ENTRY,
                                                  [p2['mac_address'],
                                                   p2_ips[0]]]},
                                    'network_type': 'vxlan',
                                    'segment_id': 1}}},
                                 'namespace': None,
                                 'method': 'add_fdb_entries'}

                    topic = topics.get_topic_name(topics.AGENT,
                                                  topics.L2POPULATION,
                                                  topics.UPDATE,
                                                  HOST)

                    self.mock_cast.assert_called_with(mock.ANY,
                                                      expected1,
                                                      topic=topic)

                    expected2 = {'args':
                                 {'fdb_entries':
                                  {p1['network_id']:
                                   {'ports':
                                    {'20.0.0.1': [constants.FLOODING_ENTRY,
                                                  [p1['mac_address'],
                                                   p1_ips[0]]]},
                                    'network_type': 'vxlan',
                                    'segment_id': 1}}},
                                 'namespace': None,
                                 'method': 'add_fdb_entries'}

                    self.mock_fanout.assert_called_with(
                        mock.ANY, expected2, topic=self.fanout_topic)

    def test_fdb_add_called_two_networks(self):
        self._register_ml2_agents()

        with self.subnet(network=self._network) as subnet:
            host_arg = {portbindings.HOST_ID: HOST + '_2'}
            with self.port(subnet=subnet,
                           device_owner=DEVICE_OWNER_COMPUTE,
                           arg_list=(portbindings.HOST_ID,),
                           **host_arg) as port1:
                with self.subnet(cidr='10.1.0.0/24') as subnet2:
                    with self.port(subnet=subnet2,
                                   device_owner=DEVICE_OWNER_COMPUTE,
                                   arg_list=(portbindings.HOST_ID,),
                                   **host_arg):
                        host_arg = {portbindings.HOST_ID: HOST}
                        with self.port(subnet=subnet,
                                       device_owner=DEVICE_OWNER_COMPUTE,
                                       arg_list=(portbindings.HOST_ID,),
                                       **host_arg) as port3:
                            p1 = port1['port']
                            p3 = port3['port']

                            device = 'tap' + p3['id']

                            self.mock_cast.reset_mock()
                            self.mock_fanout.reset_mock()
                            self.callbacks.update_device_up(
                                self.adminContext, agent_id=HOST,
                                device=device)

                            p1_ips = [p['ip_address']
                                      for p in p1['fixed_ips']]
                            expected1 = {'args':
                                         {'fdb_entries':
                                          {p1['network_id']:
                                           {'ports':
                                            {'20.0.0.2':
                                             [constants.FLOODING_ENTRY,
                                              [p1['mac_address'],
                                               p1_ips[0]]]},
                                            'network_type': 'vxlan',
                                            'segment_id': 1}}},
                                         'namespace': None,
                                         'method': 'add_fdb_entries'}

                            topic = topics.get_topic_name(topics.AGENT,
                                                          topics.L2POPULATION,
                                                          topics.UPDATE,
                                                          HOST)

                            self.mock_cast.assert_called_with(mock.ANY,
                                                              expected1,
                                                              topic=topic)

                            p3_ips = [p['ip_address']
                                      for p in p3['fixed_ips']]
                            expected2 = {'args':
                                         {'fdb_entries':
                                          {p1['network_id']:
                                           {'ports':
                                            {'20.0.0.1':
                                             [constants.FLOODING_ENTRY,
                                              [p3['mac_address'],
                                               p3_ips[0]]]},
                                            'network_type': 'vxlan',
                                            'segment_id': 1}}},
                                         'namespace': None,
                                         'method': 'add_fdb_entries'}

                            self.mock_fanout.assert_called_with(
                                mock.ANY, expected2,
                                topic=self.fanout_topic)

    def test_update_port_down(self):
        self._register_ml2_agents()

        with self.subnet(network=self._network) as subnet:
            host_arg = {portbindings.HOST_ID: HOST}
            with self.port(subnet=subnet,
                           device_owner=DEVICE_OWNER_COMPUTE,
                           arg_list=(portbindings.HOST_ID,),
                           **host_arg) as port1:
                with self.port(subnet=subnet,
                               device_owner=DEVICE_OWNER_COMPUTE,
                               arg_list=(portbindings.HOST_ID,),
                               **host_arg) as port2:
                    p2 = port2['port']
                    device2 = 'tap' + p2['id']

                    self.mock_fanout.reset_mock()
                    self.callbacks.update_device_up(self.adminContext,
                                                    agent_id=HOST,
                                                    device=device2)

                    p1 = port1['port']
                    device1 = 'tap' + p1['id']

                    self.callbacks.update_device_up(self.adminContext,
                                                    agent_id=HOST,
                                                    device=device1)
                    self.mock_fanout.reset_mock()
                    self.callbacks.update_device_down(self.adminContext,
                                                      agent_id=HOST,
                                                      device=device2)

                    p2_ips = [p['ip_address'] for p in p2['fixed_ips']]
                    expected = {'args':
                                {'fdb_entries':
                                 {p2['network_id']:
                                  {'ports':
                                   {'20.0.0.1': [[p2['mac_address'],
                                                  p2_ips[0]]]},
                                   'network_type': 'vxlan',
                                   'segment_id': 1}}},
                                'namespace': None,
                                'method': 'remove_fdb_entries'}

                    self.mock_fanout.assert_called_with(
                        mock.ANY, expected, topic=self.fanout_topic)

    def test_update_port_down_last_port_up(self):
        self._register_ml2_agents()

        with self.subnet(network=self._network) as subnet:
            host_arg = {portbindings.HOST_ID: HOST}
            with self.port(subnet=subnet,
                           device_owner=DEVICE_OWNER_COMPUTE,
                           arg_list=(portbindings.HOST_ID,),
                           **host_arg):
                with self.port(subnet=subnet,
                               device_owner=DEVICE_OWNER_COMPUTE,
                               arg_list=(portbindings.HOST_ID,),
                               **host_arg) as port2:
                    p2 = port2['port']
                    device2 = 'tap' + p2['id']

                    self.mock_fanout.reset_mock()
                    self.callbacks.update_device_up(self.adminContext,
                                                    agent_id=HOST,
                                                    device=device2)

                    self.callbacks.update_device_down(self.adminContext,
                                                      agent_id=HOST,
                                                      device=device2)

                    p2_ips = [p['ip_address'] for p in p2['fixed_ips']]
                    expected = {'args':
                                {'fdb_entries':
                                 {p2['network_id']:
                                  {'ports':
                                   {'20.0.0.1': [constants.FLOODING_ENTRY,
                                                 [p2['mac_address'],
                                                  p2_ips[0]]]},
                                   'network_type': 'vxlan',
                                   'segment_id': 1}}},
                                'namespace': None,
                                'method': 'remove_fdb_entries'}

                    self.mock_fanout.assert_called_with(
                        mock.ANY, expected, topic=self.fanout_topic)

    def test_delete_port(self):
        self._register_ml2_agents()

        with self.subnet(network=self._network) as subnet:
            host_arg = {portbindings.HOST_ID: HOST}
            with self.port(subnet=subnet,
                           device_owner=DEVICE_OWNER_COMPUTE,
                           arg_list=(portbindings.HOST_ID,),
                           **host_arg) as port:
                p1 = port['port']
                device = 'tap' + p1['id']

                self.mock_fanout.reset_mock()
                self.callbacks.update_device_up(self.adminContext,
                                                agent_id=HOST,
                                                device=device)

                with self.port(subnet=subnet,
                               device_owner=DEVICE_OWNER_COMPUTE,
                               arg_list=(portbindings.HOST_ID,),
                               **host_arg) as port2:
                    p2 = port2['port']
                    device1 = 'tap' + p2['id']

                    self.mock_fanout.reset_mock()
                    self.callbacks.update_device_up(self.adminContext,
                                                    agent_id=HOST,
                                                    device=device1)
                self._delete('ports', port2['port']['id'])
                p2_ips = [p['ip_address'] for p in p2['fixed_ips']]
                expected = {'args':
                            {'fdb_entries':
                             {p2['network_id']:
                              {'ports':
                               {'20.0.0.1': [[p2['mac_address'],
                                              p2_ips[0]]]},
                               'network_type': 'vxlan',
                               'segment_id': 1}}},
                            'namespace': None,
                            'method': 'remove_fdb_entries'}

                self.mock_fanout.assert_any_call(
                    mock.ANY, expected, topic=self.fanout_topic)

    def test_delete_port_last_port_up(self):
        self._register_ml2_agents()

        with self.subnet(network=self._network) as subnet:
            host_arg = {portbindings.HOST_ID: HOST}
            with self.port(subnet=subnet,
                           device_owner=DEVICE_OWNER_COMPUTE,
                           arg_list=(portbindings.HOST_ID,),
                           **host_arg):
                with self.port(subnet=subnet,
                               device_owner=DEVICE_OWNER_COMPUTE,
                               arg_list=(portbindings.HOST_ID,),
                               **host_arg) as port:
                    p1 = port['port']

                    device = 'tap' + p1['id']

                    self.callbacks.update_device_up(self.adminContext,
                                                    agent_id=HOST,
                                                    device=device)
                self._delete('ports', port['port']['id'])
                p1_ips = [p['ip_address'] for p in p1['fixed_ips']]
                expected = {'args':
                            {'fdb_entries':
                             {p1['network_id']:
                              {'ports':
                               {'20.0.0.1': [constants.FLOODING_ENTRY,
                                             [p1['mac_address'],
                                              p1_ips[0]]]},
                               'network_type': 'vxlan',
                               'segment_id': 1}}},
                            'namespace': None,
                            'method': 'remove_fdb_entries'}

                self.mock_fanout.assert_any_call(
                    mock.ANY, expected, topic=self.fanout_topic)

    def test_fixed_ips_changed(self):
        self._register_ml2_agents()

        with self.subnet(network=self._network) as subnet:
            host_arg = {portbindings.HOST_ID: HOST}
            with self.port(subnet=subnet, cidr='10.0.0.0/24',
                           device_owner=DEVICE_OWNER_COMPUTE,
                           arg_list=(portbindings.HOST_ID,),
                           **host_arg) as port1:
                p1 = port1['port']

                device = 'tap' + p1['id']

                self.callbacks.update_device_up(self.adminContext,
                                                agent_id=HOST,
                                                device=device)

                self.mock_fanout.reset_mock()

                data = {'port': {'fixed_ips': [{'ip_address': '10.0.0.2'},
                                               {'ip_address': '10.0.0.10'}]}}
                req = self.new_update_request('ports', data, p1['id'])
                res = self.deserialize(self.fmt, req.get_response(self.api))
                ips = res['port']['fixed_ips']
                self.assertEqual(len(ips), 2)

                add_expected = {'args':
                                {'fdb_entries':
                                 {'chg_ip':
                                  {p1['network_id']:
                                   {'20.0.0.1':
                                    {'after': [[p1['mac_address'],
                                                '10.0.0.10']]}}}}},
                                'namespace': None,
                                'method': 'update_fdb_entries'}

                self.mock_fanout.assert_any_call(
                    mock.ANY, add_expected, topic=self.fanout_topic)

                self.mock_fanout.reset_mock()

                data = {'port': {'fixed_ips': [{'ip_address': '10.0.0.2'},
                                               {'ip_address': '10.0.0.16'}]}}
                req = self.new_update_request('ports', data, p1['id'])
                res = self.deserialize(self.fmt, req.get_response(self.api))
                ips = res['port']['fixed_ips']
                self.assertEqual(len(ips), 2)

                upd_expected = {'args':
                                {'fdb_entries':
                                 {'chg_ip':
                                  {p1['network_id']:
                                   {'20.0.0.1':
                                    {'before': [[p1['mac_address'],
                                                 '10.0.0.10']],
                                     'after': [[p1['mac_address'],
                                                '10.0.0.16']]}}}}},
                                'namespace': None,
                                'method': 'update_fdb_entries'}

                self.mock_fanout.assert_any_call(
                    mock.ANY, upd_expected, topic=self.fanout_topic)

                self.mock_fanout.reset_mock()

                data = {'port': {'fixed_ips': [{'ip_address': '10.0.0.16'}]}}
                req = self.new_update_request('ports', data, p1['id'])
                res = self.deserialize(self.fmt, req.get_response(self.api))
                ips = res['port']['fixed_ips']
                self.assertEqual(len(ips), 1)

                del_expected = {'args':
                                {'fdb_entries':
                                 {'chg_ip':
                                  {p1['network_id']:
                                   {'20.0.0.1':
                                    {'before': [[p1['mac_address'],
                                                 '10.0.0.2']]}}}}},
                                'namespace': None,
                                'method': 'update_fdb_entries'}

                self.mock_fanout.assert_any_call(
                    mock.ANY, del_expected, topic=self.fanout_topic)

    def test_no_fdb_updates_without_port_updates(self):
        self._register_ml2_agents()

        with self.subnet(network=self._network) as subnet:
            host_arg = {portbindings.HOST_ID: HOST}
            with self.port(subnet=subnet, cidr='10.0.0.0/24',
                           device_owner=DEVICE_OWNER_COMPUTE,
                           arg_list=(portbindings.HOST_ID,),
                           **host_arg) as port1:
                p1 = port1['port']

                device = 'tap' + p1['id']

                self.callbacks.update_device_up(self.adminContext,
                                                agent_id=HOST,
                                                device=device)
                p1['status'] = 'ACTIVE'
                self.mock_fanout.reset_mock()

                fanout = ('neutron.plugins.ml2.drivers.l2pop.rpc.'
                          'L2populationAgentNotifyAPI._notification_fanout')
                fanout_patch = mock.patch(fanout)
                mock_fanout = fanout_patch.start()

                plugin = manager.NeutronManager.get_plugin()
                plugin.update_port(self.adminContext, p1['id'], port1)

                self.assertFalse(mock_fanout.called)
                fanout_patch.stop()

    def test_host_changed(self):
        self._register_ml2_agents()
        with self.subnet(network=self._network) as subnet:
            host_arg = {portbindings.HOST_ID: L2_AGENT['host']}
            host2_arg = {portbindings.HOST_ID: L2_AGENT_2['host']}
            with self.port(subnet=subnet, cidr='10.0.0.0/24',
                           device_owner=DEVICE_OWNER_COMPUTE,
                           arg_list=(portbindings.HOST_ID,),
                           **host_arg) as port1:
                with self.port(subnet=subnet, cidr='10.0.0.0/24',
                               device_owner=DEVICE_OWNER_COMPUTE,
                               arg_list=(portbindings.HOST_ID,),
                               **host2_arg) as port2:
                    p1 = port1['port']
                    device1 = 'tap' + p1['id']
                    self.callbacks.update_device_up(
                        self.adminContext,
                        agent_id=L2_AGENT['host'],
                        device=device1)
                    p2 = port2['port']
                    device2 = 'tap' + p2['id']
                    self.callbacks.update_device_up(
                        self.adminContext,
                        agent_id=L2_AGENT_2['host'],
                        device=device2)
                    data2 = {'port': {'binding:host_id': L2_AGENT_2['host']}}
                    req = self.new_update_request('ports', data2, p1['id'])
                    res = self.deserialize(self.fmt,
                                           req.get_response(self.api))
                    self.assertEqual(res['port']['binding:host_id'],
                                     L2_AGENT_2['host'])
                    self.mock_fanout.reset_mock()
                    self.callbacks.get_device_details(
                        self.adminContext,
                        device=device1,
                        agent_id=L2_AGENT_2['host'])
                    p1_ips = [p['ip_address'] for p in p1['fixed_ips']]
                    expected = {'args':
                                {'fdb_entries':
                                 {p1['network_id']:
                                  {'ports':
                                   {'20.0.0.1': [constants.FLOODING_ENTRY,
                                                 [p1['mac_address'],
                                                  p1_ips[0]]]},
                                   'network_type': 'vxlan',
                                   'segment_id': 1}}},
                                'namespace': None,
                                'method': 'remove_fdb_entries'}

                    self.mock_fanout.assert_called_with(
                        mock.ANY, expected, topic=self.fanout_topic)

    def test_host_changed_twice(self):
        self._register_ml2_agents()
        with self.subnet(network=self._network) as subnet:
            host_arg = {portbindings.HOST_ID: L2_AGENT['host']}
            host2_arg = {portbindings.HOST_ID: L2_AGENT_2['host']}
            with self.port(subnet=subnet, cidr='10.0.0.0/24',
                           device_owner=DEVICE_OWNER_COMPUTE,
                           arg_list=(portbindings.HOST_ID,),
                           **host_arg) as port1:
                with self.port(subnet=subnet, cidr='10.0.0.0/24',
                               device_owner=DEVICE_OWNER_COMPUTE,
                               arg_list=(portbindings.HOST_ID,),
                               **host2_arg) as port2:
                    p1 = port1['port']
                    device1 = 'tap' + p1['id']
                    self.callbacks.update_device_up(
                        self.adminContext,
                        agent_id=L2_AGENT['host'],
                        device=device1)
                    p2 = port2['port']
                    device2 = 'tap' + p2['id']
                    self.callbacks.update_device_up(
                        self.adminContext,
                        agent_id=L2_AGENT_2['host'],
                        device=device2)
                    data2 = {'port': {'binding:host_id': L2_AGENT_2['host']}}
                    req = self.new_update_request('ports', data2, p1['id'])
                    res = self.deserialize(self.fmt,
                                           req.get_response(self.api))
                    self.assertEqual(res['port']['binding:host_id'],
                                     L2_AGENT_2['host'])
                    data4 = {'port': {'binding:host_id': L2_AGENT_4['host']}}
                    req = self.new_update_request('ports', data4, p1['id'])
                    res = self.deserialize(self.fmt,
                                           req.get_response(self.api))
                    self.assertEqual(res['port']['binding:host_id'],
                                     L2_AGENT_4['host'])
                    self.mock_fanout.reset_mock()
                    self.callbacks.get_device_details(
                        self.adminContext,
                        device=device1,
                        agent_id=L2_AGENT_4['host'])
                    p1_ips = [p['ip_address'] for p in p1['fixed_ips']]
                    expected = {'args':
                                {'fdb_entries':
                                 {p1['network_id']:
                                  {'ports':
                                   {'20.0.0.1': [constants.FLOODING_ENTRY,
                                                 [p1['mac_address'],
                                                  p1_ips[0]]]},
                                   'network_type': 'vxlan',
                                   'segment_id': 1}}},
                                'namespace': None,
                                'method': 'remove_fdb_entries'}

                    self.mock_fanout.assert_called_with(
                        mock.ANY, expected, topic=self.fanout_topic)

    def test_delete_port_invokes_update_device_down(self):
        l2pop_mech = l2pop_mech_driver.L2populationMechanismDriver()
        l2pop_mech.L2PopulationAgentNotify = mock.Mock()
        l2pop_mech.rpc_ctx = mock.Mock()
        with contextlib.nested(
                mock.patch.object(l2pop_mech,
                           '_update_port_down',
                           return_value=None),
                mock.patch.object(l2pop_mech.L2PopulationAgentNotify,
                                  'remove_fdb_entries')) as (upd_port_down,
                                                             rem_fdb_entries):
            l2pop_mech.delete_port_postcommit(mock.Mock())
            self.assertTrue(upd_port_down.called)