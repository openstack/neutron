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

import testtools

import mock

from neutron.agent import l2population_rpc
from neutron.common import constants
from neutron.common import topics
from neutron import context
from neutron.extensions import portbindings
from neutron.extensions import providernet as pnet
from neutron import manager
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.plugins.ml2 import driver_context
from neutron.plugins.ml2.drivers.l2pop import db as l2pop_db
from neutron.plugins.ml2.drivers.l2pop import mech_driver as l2pop_mech_driver
from neutron.plugins.ml2.drivers.l2pop import rpc as l2pop_rpc
from neutron.plugins.ml2 import managers
from neutron.plugins.ml2 import rpc
from neutron.tests import base
from neutron.tests.common import helpers
from neutron.tests.unit.plugins.ml2 import test_plugin

HOST = 'my_l2_host'
HOST_2 = HOST + '_2'
HOST_3 = HOST + '_3'
HOST_4 = HOST + '_4'
HOST_5 = HOST + '_5'


NOTIFIER = 'neutron.plugins.ml2.rpc.AgentNotifierApi'
DEVICE_OWNER_COMPUTE = 'compute:None'


class TestL2PopulationRpcTestCase(test_plugin.Ml2PluginV2TestCase):
    _mechanism_drivers = ['openvswitch', 'fake_agent', 'l2population']

    def setUp(self):
        super(TestL2PopulationRpcTestCase, self).setUp()

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
                   pnet.PHYSICAL_NETWORK: 'physnet1',
                   pnet.SEGMENTATION_ID: '2'}
        self._network2 = self._make_network(self.fmt, 'net2', True,
                                            arg_list=(pnet.NETWORK_TYPE,
                                                      pnet.PHYSICAL_NETWORK,
                                                      pnet.SEGMENTATION_ID,),
                                            **net_arg)

        net_arg = {pnet.NETWORK_TYPE: 'flat',
                   pnet.PHYSICAL_NETWORK: 'noagent'}
        self._network3 = self._make_network(self.fmt, 'net3', True,
                                            arg_list=(pnet.NETWORK_TYPE,
                                                      pnet.PHYSICAL_NETWORK,),
                                            **net_arg)

        notifier_patch = mock.patch(NOTIFIER)
        notifier_patch.start()

        self.fanout_topic = topics.get_topic_name(topics.AGENT,
                                                  topics.L2POPULATION,
                                                  topics.UPDATE)
        fanout = ('neutron.plugins.ml2.drivers.l2pop.rpc.'
                  'L2populationAgentNotifyAPI._notification_fanout')
        fanout_patch = mock.patch(fanout)
        self.mock_fanout = fanout_patch.start()

        cast = ('neutron.plugins.ml2.drivers.l2pop.rpc.'
                'L2populationAgentNotifyAPI._notification_host')
        cast_patch = mock.patch(cast)
        self.mock_cast = cast_patch.start()

        uptime = ('neutron.plugins.ml2.drivers.l2pop.db.L2populationDbMixin.'
                  'get_agent_uptime')
        uptime_patch = mock.patch(uptime, return_value=190)
        uptime_patch.start()

    def _register_ml2_agents(self):
        helpers.register_ovs_agent(host=HOST, tunneling_ip='20.0.0.1')
        helpers.register_ovs_agent(host=HOST_2, tunneling_ip='20.0.0.2')
        helpers.register_ovs_agent(host=HOST_3, tunneling_ip='20.0.0.3',
                                   tunnel_types=[])
        helpers.register_ovs_agent(host=HOST_4, tunneling_ip='20.0.0.4')
        helpers.register_ovs_agent(host=HOST_5, tunneling_ip='20.0.0.5',
                                   binary='neutron-fake-agent',
                                   tunnel_types=[],
                                   interface_mappings={'physnet1': 'eth9'},
                                   agent_type=constants.AGENT_TYPE_OFA,
                                   l2pop_network_types=['vlan'])

    def test_port_info_compare(self):
        # An assumption the code makes is that PortInfo compares equal to
        # equivalent regular tuples.
        self.assertEqual(("mac", "ip"), l2pop_rpc.PortInfo("mac", "ip"))

        flooding_entry = l2pop_rpc.PortInfo(*constants.FLOODING_ENTRY)
        self.assertEqual(constants.FLOODING_ENTRY, flooding_entry)

    def test__unmarshall_fdb_entries(self):
        entries = {'foouuid': {
            'segment_id': 1001,
            'ports': {'192.168.0.10': [['00:00:00:00:00:00', '0.0.0.0'],
                                       ['fa:16:3e:ff:8c:0f', '10.0.0.6']]},
            'network_type': 'vxlan'}}

        mixin = l2population_rpc.L2populationRpcCallBackMixin
        entries = mixin._unmarshall_fdb_entries(entries)

        port_info_list = entries['foouuid']['ports']['192.168.0.10']
        # Check that the lists have been properly converted to PortInfo
        self.assertIsInstance(port_info_list[0], l2pop_rpc.PortInfo)
        self.assertIsInstance(port_info_list[1], l2pop_rpc.PortInfo)
        self.assertEqual(('00:00:00:00:00:00', '0.0.0.0'), port_info_list[0])
        self.assertEqual(('fa:16:3e:ff:8c:0f', '10.0.0.6'), port_info_list[1])

    def test__marshall_fdb_entries(self):
        entries = {'foouuid': {
            'segment_id': 1001,
            'ports': {'192.168.0.10': [('00:00:00:00:00:00', '0.0.0.0'),
                                       ('fa:16:3e:ff:8c:0f', '10.0.0.6')]},
            'network_type': 'vxlan'}}

        entries = l2pop_rpc.L2populationAgentNotifyAPI._marshall_fdb_entries(
            entries)

        port_info_list = entries['foouuid']['ports']['192.168.0.10']
        # Check that the PortInfo tuples have been converted to list
        self.assertIsInstance(port_info_list[0], list)
        self.assertIsInstance(port_info_list[1], list)
        self.assertEqual(['00:00:00:00:00:00', '0.0.0.0'], port_info_list[0])
        self.assertEqual(['fa:16:3e:ff:8c:0f', '10.0.0.6'], port_info_list[1])

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
                    expected = {p1['network_id']:
                                {'ports':
                                 {'20.0.0.1': [constants.FLOODING_ENTRY,
                                               l2pop_rpc.PortInfo(
                                                   p1['mac_address'],
                                                   p1_ips[0])]},
                                 'network_type': 'vxlan',
                                 'segment_id': 1}}

                    self.mock_fanout.assert_called_with(
                        mock.ANY, 'add_fdb_entries', expected)

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
                    expected = {p1['network_id']:
                                {'ports':
                                 {'20.0.0.5': [constants.FLOODING_ENTRY,
                                               l2pop_rpc.PortInfo(
                                                   p1['mac_address'],
                                                   p1_ips[0])]},
                                 'network_type': 'vlan',
                                 'segment_id': 2}}

                    self.mock_fanout.assert_called_with(
                        mock.ANY, 'add_fdb_entries', expected)

    def test_fdb_called_for_active_ports(self):
        self._register_ml2_agents()

        with self.subnet(network=self._network) as subnet:
            host_arg = {portbindings.HOST_ID: HOST}
            with self.port(subnet=subnet,
                           device_owner=DEVICE_OWNER_COMPUTE,
                           arg_list=(portbindings.HOST_ID,),
                           **host_arg) as port1:
                host_arg = {portbindings.HOST_ID: HOST + '_2'}
                with self.port(subnet=subnet,
                               device_owner=DEVICE_OWNER_COMPUTE,
                               arg_list=(portbindings.HOST_ID,),
                               **host_arg):
                    p1 = port1['port']

                    device1 = 'tap' + p1['id']

                    self.mock_cast.reset_mock()
                    self.mock_fanout.reset_mock()
                    self.callbacks.update_device_up(self.adminContext,
                                                    agent_id=HOST,
                                                    device=device1)

                    p1_ips = [p['ip_address'] for p in p1['fixed_ips']]

                    self.assertFalse(self.mock_cast.called)

                    expected2 = {p1['network_id']:
                                 {'ports':
                                  {'20.0.0.1': [constants.FLOODING_ENTRY,
                                                l2pop_rpc.PortInfo(
                                                    p1['mac_address'],
                                                    p1_ips[0])]},
                                  'network_type': 'vxlan',
                                  'segment_id': 1}}

                    self.mock_fanout.assert_called_with(
                        mock.ANY, 'add_fdb_entries', expected2)

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

                    device1 = 'tap' + p1['id']
                    device2 = 'tap' + p2['id']

                    self.mock_cast.reset_mock()
                    self.mock_fanout.reset_mock()
                    self.callbacks.update_device_up(self.adminContext,
                                                    agent_id=HOST + '_2',
                                                    device=device2)
                    self.callbacks.update_device_up(self.adminContext,
                                                    agent_id=HOST,
                                                    device=device1)

                    p1_ips = [p['ip_address'] for p in p1['fixed_ips']]
                    p2_ips = [p['ip_address'] for p in p2['fixed_ips']]

                    expected1 = {p1['network_id']:
                                 {'ports':
                                  {'20.0.0.2': [constants.FLOODING_ENTRY,
                                                l2pop_rpc.PortInfo(
                                                    p2['mac_address'],
                                                    p2_ips[0])]},
                                  'network_type': 'vxlan',
                                  'segment_id': 1}}

                    self.mock_cast.assert_called_with(mock.ANY,
                                                      'add_fdb_entries',
                                                      expected1, HOST)

                    expected2 = {p1['network_id']:
                                 {'ports':
                                  {'20.0.0.1': [constants.FLOODING_ENTRY,
                                                l2pop_rpc.PortInfo(
                                                    p1['mac_address'],
                                                    p1_ips[0])]},
                                  'network_type': 'vxlan',
                                  'segment_id': 1}}

                    self.mock_fanout.assert_called_with(
                        mock.ANY, 'add_fdb_entries', expected2)

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

                            device1 = 'tap' + p1['id']
                            device3 = 'tap' + p3['id']

                            self.mock_cast.reset_mock()
                            self.mock_fanout.reset_mock()
                            self.callbacks.update_device_up(
                                self.adminContext, agent_id=HOST + '_2',
                                device=device1)
                            self.callbacks.update_device_up(
                                self.adminContext, agent_id=HOST,
                                device=device3)

                            p1_ips = [p['ip_address']
                                      for p in p1['fixed_ips']]
                            expected1 = {p1['network_id']:
                                         {'ports':
                                          {'20.0.0.2':
                                           [constants.FLOODING_ENTRY,
                                            l2pop_rpc.PortInfo(
                                                p1['mac_address'],
                                                p1_ips[0])]},
                                         'network_type': 'vxlan',
                                         'segment_id': 1}}

                            self.mock_cast.assert_called_with(
                                    mock.ANY, 'add_fdb_entries', expected1,
                                    HOST)

                            p3_ips = [p['ip_address']
                                      for p in p3['fixed_ips']]
                            expected2 = {p1['network_id']:
                                         {'ports':
                                          {'20.0.0.1':
                                           [constants.FLOODING_ENTRY,
                                            l2pop_rpc.PortInfo(
                                                p3['mac_address'],
                                                p3_ips[0])]},
                                         'network_type': 'vxlan',
                                         'segment_id': 1}}

                            self.mock_fanout.assert_called_with(
                                mock.ANY, 'add_fdb_entries', expected2)

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
                    expected = {p2['network_id']:
                                {'ports':
                                 {'20.0.0.1': [l2pop_rpc.PortInfo(
                                               p2['mac_address'],
                                               p2_ips[0])]},
                                 'network_type': 'vxlan',
                                 'segment_id': 1}}

                    self.mock_fanout.assert_called_with(
                        mock.ANY, 'remove_fdb_entries', expected)

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
                    expected = {p2['network_id']:
                                {'ports':
                                 {'20.0.0.1': [constants.FLOODING_ENTRY,
                                               l2pop_rpc.PortInfo(
                                                    p2['mac_address'],
                                                    p2_ips[0])]},
                                 'network_type': 'vxlan',
                                 'segment_id': 1}}

                    self.mock_fanout.assert_called_with(
                        mock.ANY, 'remove_fdb_entries', expected)

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
                expected = {p2['network_id']:
                            {'ports':
                             {'20.0.0.1': [l2pop_rpc.PortInfo(
                                           p2['mac_address'],
                                           p2_ips[0])]},
                             'network_type': 'vxlan',
                             'segment_id': 1}}

                self.mock_fanout.assert_any_call(
                    mock.ANY, 'remove_fdb_entries', expected)

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
                expected = {p1['network_id']:
                            {'ports':
                             {'20.0.0.1': [constants.FLOODING_ENTRY,
                                           l2pop_rpc.PortInfo(
                                               p1['mac_address'],
                                               p1_ips[0])]},
                             'network_type': 'vxlan',
                             'segment_id': 1}}

                self.mock_fanout.assert_any_call(
                    mock.ANY, 'remove_fdb_entries', expected)

    def test_mac_addr_changed(self):
        self._register_ml2_agents()

        with self.subnet(network=self._network) as subnet:
            host_arg = {portbindings.HOST_ID: HOST + '_5'}
            with self.port(subnet=subnet,
                           device_owner=DEVICE_OWNER_COMPUTE,
                           arg_list=(portbindings.HOST_ID,),
                           **host_arg) as port1:
                p1 = port1['port']

                self.mock_fanout.reset_mock()
                device = 'tap' + p1['id']

                old_mac = p1['mac_address']
                mac = old_mac.split(':')
                mac[5] = '01' if mac[5] != '01' else '00'
                new_mac = ':'.join(mac)
                data = {'port': {'mac_address': new_mac,
                                 portbindings.HOST_ID: HOST}}
                req = self.new_update_request('ports', data, p1['id'])
                res = self.deserialize(self.fmt, req.get_response(self.api))
                self.assertIn('port', res)
                self.assertEqual(new_mac, res['port']['mac_address'])

                # port was not bound before, so no fdb call expected yet
                self.assertFalse(self.mock_fanout.called)

                self.callbacks.update_device_up(self.adminContext,
                                                agent_id=HOST,
                                                device=device)

                self.assertEqual(1, self.mock_fanout.call_count)
                add_expected = {
                    p1['network_id']: {
                        'segment_id': 1,
                        'network_type': 'vxlan',
                        'ports': {
                            '20.0.0.1': [
                                l2pop_rpc.PortInfo('00:00:00:00:00:00',
                                                   '0.0.0.0'),
                                l2pop_rpc.PortInfo(new_mac, '10.0.0.2')
                            ]
                        }
                    }
                }
                self.mock_fanout.assert_called_with(
                    mock.ANY, 'add_fdb_entries', add_expected)

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

                add_expected = {'chg_ip':
                                {p1['network_id']:
                                 {'20.0.0.1':
                                  {'after': [(p1['mac_address'],
                                              '10.0.0.10')]}}}}

                self.mock_fanout.assert_any_call(
                    mock.ANY, 'update_fdb_entries', add_expected)

                self.mock_fanout.reset_mock()

                data = {'port': {'fixed_ips': [{'ip_address': '10.0.0.2'},
                                               {'ip_address': '10.0.0.16'}]}}
                req = self.new_update_request('ports', data, p1['id'])
                res = self.deserialize(self.fmt, req.get_response(self.api))
                ips = res['port']['fixed_ips']
                self.assertEqual(len(ips), 2)

                upd_expected = {'chg_ip':
                                {p1['network_id']:
                                 {'20.0.0.1':
                                  {'before': [(p1['mac_address'],
                                               '10.0.0.10')],
                                   'after': [(p1['mac_address'],
                                              '10.0.0.16')]}}}}

                self.mock_fanout.assert_any_call(
                    mock.ANY, 'update_fdb_entries', upd_expected)

                self.mock_fanout.reset_mock()

                data = {'port': {'fixed_ips': [{'ip_address': '10.0.0.16'}]}}
                req = self.new_update_request('ports', data, p1['id'])
                res = self.deserialize(self.fmt, req.get_response(self.api))
                ips = res['port']['fixed_ips']
                self.assertEqual(len(ips), 1)

                del_expected = {'chg_ip':
                                {p1['network_id']:
                                 {'20.0.0.1':
                                  {'before': [(p1['mac_address'],
                                               '10.0.0.2')]}}}}

                self.mock_fanout.assert_any_call(
                    mock.ANY, 'update_fdb_entries', del_expected)

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

    def test_get_device_details_port_id(self):
        self._register_ml2_agents()
        host_arg = {portbindings.HOST_ID: HOST}
        with self.port(arg_list=(portbindings.HOST_ID,),
                       **host_arg) as port:
            port_id = port['port']['id']
            # ensure various formats all result in correct port_id
            formats = ['tap' + port_id[0:8], port_id,
                       port['port']['mac_address']]
            for device in formats:
                details = self.callbacks.get_device_details(
                    self.adminContext, device=device,
                    agent_id=HOST_2)
                self.assertEqual(port_id, details['port_id'])

    def _update_and_check_portbinding(self, port_id, host_id):
        data = {'port': {'binding:host_id': host_id}}
        req = self.new_update_request('ports', data, port_id)
        res = self.deserialize(self.fmt,
                               req.get_response(self.api))
        self.assertEqual(host_id, res['port']['binding:host_id'])

    def _test_host_changed(self, twice):
        self._register_ml2_agents()
        with self.subnet(network=self._network) as subnet:
            host_arg = {portbindings.HOST_ID: HOST}
            with self.port(subnet=subnet, cidr='10.0.0.0/24',
                           device_owner=DEVICE_OWNER_COMPUTE,
                           arg_list=(portbindings.HOST_ID,),
                           **host_arg) as port1:
                p1 = port1['port']
                device1 = 'tap' + p1['id']
                self.callbacks.update_device_up(
                    self.adminContext,
                    agent_id=HOST,
                    device=device1)
                if twice:
                    self._update_and_check_portbinding(p1['id'], HOST_4)
                self._update_and_check_portbinding(p1['id'], HOST_2)
                self.mock_fanout.reset_mock()
                # NOTE(yamamoto): see bug #1441488
                self.adminContext.session.expire_all()
                self.callbacks.get_device_details(
                    self.adminContext,
                    device=device1,
                    agent_id=HOST_2)
                p1_ips = [p['ip_address'] for p in p1['fixed_ips']]
                expected = {p1['network_id']:
                            {'ports':
                             {'20.0.0.1': [constants.FLOODING_ENTRY,
                                           l2pop_rpc.PortInfo(
                                               p1['mac_address'],
                                               p1_ips[0])]},
                             'network_type': 'vxlan',
                             'segment_id': 1}}

                self.mock_fanout.assert_called_with(
                    mock.ANY, 'remove_fdb_entries', expected)

    def test_host_changed(self):
        self._test_host_changed(twice=False)

    def test_host_changed_twice(self):
        self._test_host_changed(twice=True)

    def test_delete_port_invokes_update_device_down(self):
        l2pop_mech = l2pop_mech_driver.L2populationMechanismDriver()
        l2pop_mech.L2PopulationAgentNotify = mock.Mock()
        l2pop_mech.rpc_ctx = mock.Mock()
        with mock.patch.object(l2pop_mech,
                               '_update_port_down',
                               return_value=None) as upd_port_down,\
                mock.patch.object(l2pop_mech.L2PopulationAgentNotify,
                                  'remove_fdb_entries'):
            l2pop_mech.delete_port_postcommit(mock.Mock())
            self.assertTrue(upd_port_down.called)


class TestL2PopulationMechDriver(base.BaseTestCase):

    def _test_get_tunnels(self, agent_ip, exclude_host=True):
        mech_driver = l2pop_mech_driver.L2populationMechanismDriver()
        agent = mock.Mock()
        agent.host = HOST
        network_ports = ((None, agent),)
        with mock.patch.object(l2pop_db.L2populationDbMixin,
                               'get_agent_ip',
                               return_value=agent_ip):
            excluded_host = HOST + '-EXCLUDE' if exclude_host else HOST
            return mech_driver._get_tunnels(network_ports, excluded_host)

    def test_get_tunnels(self):
        tunnels = self._test_get_tunnels('20.0.0.1')
        self.assertTrue('20.0.0.1' in tunnels)

    def test_get_tunnels_no_ip(self):
        tunnels = self._test_get_tunnels(None)
        self.assertEqual(0, len(tunnels))

    def test_get_tunnels_dont_exclude_host(self):
        tunnels = self._test_get_tunnels(None, exclude_host=False)
        self.assertEqual(0, len(tunnels))

    def _test_create_agent_fdb(self, fdb_network_ports_query, agent_ips):
        mech_driver = l2pop_mech_driver.L2populationMechanismDriver()
        tunnel_network_ports_query, tunnel_agent = (
            self._mock_network_ports_query(HOST + '1', None))
        agent_ips[tunnel_agent] = '10.0.0.1'

        def agent_ip_side_effect(agent):
            return agent_ips[agent]

        with mock.patch.object(l2pop_db.L2populationDbMixin,
                               'get_agent_ip',
                               side_effect=agent_ip_side_effect),\
                mock.patch.object(l2pop_db.L2populationDbMixin,
                                  'get_nondvr_active_network_ports',
                                  new=fdb_network_ports_query),\
                mock.patch.object(l2pop_db.L2populationDbMixin,
                                  'get_dvr_active_network_ports',
                                  new=tunnel_network_ports_query):
            session = mock.Mock()
            agent = mock.Mock()
            agent.host = HOST
            segment = {'segmentation_id': 1, 'network_type': 'vxlan'}
            return mech_driver._create_agent_fdb(session,
                                                 agent,
                                                 segment,
                                                 'network_id')

    def _mock_network_ports_query(self, host_name, binding):
        agent = mock.Mock()
        agent.host = host_name
        result = [(binding, agent)]
        all_mock = mock.Mock()
        all_mock.all = mock.Mock(return_value=result)
        mock_query = mock.Mock(return_value=all_mock)
        return mock_query, agent

    def test_create_agent_fdb(self):
        binding = mock.Mock()
        binding.port = {'mac_address': '00:00:DE:AD:BE:EF',
                        'fixed_ips': [{'ip_address': '1.1.1.1'}]}
        fdb_network_ports_query, fdb_agent = (
            self._mock_network_ports_query(HOST + '2', binding))
        agent_ips = {fdb_agent: '20.0.0.1'}

        agent_fdb = self._test_create_agent_fdb(fdb_network_ports_query,
                                                agent_ips)
        result = agent_fdb['network_id']

        expected_result = {'segment_id': 1,
                           'network_type': 'vxlan',
                           'ports':
                           {'10.0.0.1':
                            [constants.FLOODING_ENTRY],
                            '20.0.0.1':
                            [constants.FLOODING_ENTRY,
                             l2pop_rpc.PortInfo(
                                 mac_address='00:00:DE:AD:BE:EF',
                                 ip_address='1.1.1.1')]}}
        self.assertEqual(expected_result, result)

    def test_create_agent_fdb_only_tunnels(self):
        all_mock = mock.Mock()
        all_mock.all = mock.Mock(return_value=[])
        fdb_network_ports_query = mock.Mock(return_value=all_mock)
        agent_fdb = self._test_create_agent_fdb(fdb_network_ports_query, {})
        result = agent_fdb['network_id']

        expected_result = {'segment_id': 1,
                           'network_type': 'vxlan',
                           'ports':
                           {'10.0.0.1':
                            [constants.FLOODING_ENTRY]}}
        self.assertEqual(expected_result, result)

    def test_update_port_postcommit_mac_address_changed_raises(self):
        port = {'status': u'ACTIVE',
                'device_owner': u'compute:None',
                'mac_address': u'12:34:56:78:4b:0e',
                'id': u'1'}

        original_port = port.copy()
        original_port['mac_address'] = u'12:34:56:78:4b:0f'

        with mock.patch.object(driver_context.db, 'get_network_segments'):
            ctx = driver_context.PortContext(mock.Mock(),
                                             mock.Mock(),
                                             port,
                                             mock.MagicMock(),
                                             mock.Mock(),
                                             None,
                                             original_port=original_port)

        mech_driver = l2pop_mech_driver.L2populationMechanismDriver()
        with testtools.ExpectedException(ml2_exc.MechanismDriverError):
            mech_driver.update_port_postcommit(ctx)
