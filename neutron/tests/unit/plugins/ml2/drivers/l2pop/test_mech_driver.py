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

import mock

from neutron_lib.agent import topics
from neutron_lib.api.definitions import port as port_def
from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib import constants
from neutron_lib import context
from neutron_lib import exceptions
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from oslo_serialization import jsonutils
import testtools

from neutron.db import agents_db
from neutron.db import l3_agentschedulers_db
from neutron.db import l3_hamode_db
from neutron.plugins.ml2 import driver_context
from neutron.plugins.ml2.drivers.l2pop import db as l2pop_db
from neutron.plugins.ml2.drivers.l2pop import mech_driver as l2pop_mech_driver
from neutron.plugins.ml2.drivers.l2pop import rpc as l2pop_rpc
from neutron.plugins.ml2.drivers.l2pop.rpc_manager import l2population_rpc
from neutron.plugins.ml2 import managers
from neutron.plugins.ml2 import models
from neutron.plugins.ml2 import rpc
from neutron.scheduler import l3_agent_scheduler
from neutron.tests import base
from neutron.tests.common import helpers
from neutron.tests.unit.plugins.ml2 import test_plugin

HOST = 'my_l2_host'
HOST_2 = HOST + '_2'
HOST_3 = HOST + '_3'
HOST_4 = HOST + '_4'
HOST_5 = HOST + '_5'
TEST_ROUTER_ID = 'router_id'


NOTIFIER = 'neutron.plugins.ml2.rpc.AgentNotifierApi'
DEVICE_OWNER_COMPUTE = constants.DEVICE_OWNER_COMPUTE_PREFIX + 'fake'
DEVICE_OWNER_ROUTER_HA_INTF = constants.DEVICE_OWNER_ROUTER_HA_INTF + 'fake'


class FakeL3PluginWithAgents(l3_hamode_db.L3_HA_NAT_db_mixin,
                             l3_agentschedulers_db.L3AgentSchedulerDbMixin,
                             agents_db.AgentDbMixin):
    pass


class TestL2PopulationRpcTestCase(test_plugin.Ml2PluginV2TestCase):
    _mechanism_drivers = ['openvswitch', 'fake_agent', 'l2population']
    tenant = 'tenant'

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

        uptime = ('neutron.plugins.ml2.drivers.l2pop.db.get_agent_uptime')
        uptime_patch = mock.patch(uptime, return_value=190)
        uptime_patch.start()

    def _setup_l3(self):
        notif_p = mock.patch.object(l3_hamode_db.L3_HA_NAT_db_mixin,
                                    '_notify_router_updated')
        self.notif_m = notif_p.start()
        self.plugin = FakeL3PluginWithAgents()
        self._register_ml2_agents()
        self._register_l3_agents()

    def _register_l3_agents(self):
        self.agent1 = helpers.register_l3_agent(host=HOST)
        self.agent2 = helpers.register_l3_agent(host=HOST_2)

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
        entries['chg_ip'] = {
            'foouuid': {
                '192.168.0.1': {'before': [['fa:16:3e:ff:8c:0f', '10.0.0.6']],
                                'after': [['fa:16:3e:ff:8c:0f', '10.0.0.7']]},
                '192.168.0.2': {'before': [['fa:16:3e:ff:8c:0e', '10.0.0.8']]}
            },
            'foouuid2': {
                '192.168.0.1': {'before': [['ff:16:3e:ff:8c:0e', '1.0.0.8']]}
            }
        }

        mixin = l2population_rpc.L2populationRpcCallBackMixin
        entries = mixin._unmarshall_fdb_entries(entries)

        port_info_list = entries['foouuid']['ports']['192.168.0.10']
        # Check that the lists have been properly converted to PortInfo
        self.assertIsInstance(port_info_list[0], l2pop_rpc.PortInfo)
        self.assertIsInstance(port_info_list[1], l2pop_rpc.PortInfo)
        self.assertEqual(('00:00:00:00:00:00', '0.0.0.0'), port_info_list[0])
        self.assertEqual(('fa:16:3e:ff:8c:0f', '10.0.0.6'), port_info_list[1])
        agt1 = entries['chg_ip']['foouuid']['192.168.0.1']
        self.assertIsInstance(agt1['before'][0], l2pop_rpc.PortInfo)
        self.assertIsInstance(agt1['after'][0], l2pop_rpc.PortInfo)
        self.assertEqual(('fa:16:3e:ff:8c:0f', '10.0.0.6'), agt1['before'][0])
        self.assertEqual(('fa:16:3e:ff:8c:0f', '10.0.0.7'), agt1['after'][0])
        agt1_net2 = entries['chg_ip']['foouuid2']['192.168.0.1']
        self.assertEqual(('ff:16:3e:ff:8c:0e', '1.0.0.8'),
                         agt1_net2['before'][0])
        self.assertIsInstance(agt1_net2['before'][0], l2pop_rpc.PortInfo)
        agt2 = entries['chg_ip']['foouuid']['192.168.0.2']
        self.assertIsInstance(agt2['before'][0], l2pop_rpc.PortInfo)
        self.assertEqual(('fa:16:3e:ff:8c:0e', '10.0.0.8'), agt2['before'][0])

    def test_portinfo_marshalled_as_list(self):
        entry = ['fa:16:3e:ff:8c:0f', '10.0.0.6']
        payload = {'netuuid': {'ports': {'1': [l2pop_rpc.PortInfo(*entry)]}}}
        result = jsonutils.loads(jsonutils.dumps(payload))
        self.assertEqual(entry, result['netuuid']['ports']['1'][0])

    def _create_router(self, ha=True, tenant_id='tenant1',
                       distributed=None, ctx=None):
        if ctx is None:
            ctx = self.adminContext
        ctx.tenant_id = tenant_id
        router = {'name': TEST_ROUTER_ID, 'admin_state_up': True,
                  'tenant_id': ctx.tenant_id}
        if ha is not None:
            router['ha'] = ha
        if distributed is not None:
            router['distributed'] = distributed
        return self.plugin.create_router(ctx, {'router': router})

    def _bind_router(self, router_id, tenant_id):
        scheduler = l3_agent_scheduler.ChanceScheduler()
        filters = {'agent_type': [constants.AGENT_TYPE_L3]}
        agents_object = self.plugin.get_agent_objects(
            self.adminContext, filters=filters)
        for agent_obj in agents_object:
            scheduler.create_ha_port_and_bind(
                self.plugin,
                self.adminContext,
                router_id,
                tenant_id,
                agent_obj)
        self._bind_ha_network_ports(router_id)

    def _bind_ha_network_ports(self, router_id):
        port_bindings = self.plugin.get_ha_router_port_bindings(
            self.adminContext, [router_id])
        plugin = directory.get_plugin()

        for port_binding in port_bindings:
            filters = {'id': [port_binding.port_id]}
            port = plugin.get_ports(self.adminContext, filters=filters)[0]
            if port_binding.l3_agent_id == self.agent1['id']:
                port[portbindings.HOST_ID] = self.agent1['host']
            else:
                port[portbindings.HOST_ID] = self.agent2['host']
            plugin.update_port(self.adminContext, port['id'],
                               {port_def.RESOURCE_NAME: port})

    def _get_first_interface(self, net_id, router):
        plugin = directory.get_plugin()
        if router['distributed']:
            device_filter = {'device_id': [router['id']],
                             'device_owner':
                             [constants.DEVICE_OWNER_DVR_INTERFACE]}
        else:
            device_filter = {'device_id': [router['id']],
                             'device_owner':
                             [constants.DEVICE_OWNER_HA_REPLICATED_INT]}
        ports = plugin.get_ports(self.adminContext, filters=device_filter)
        if ports:
            return ports[0]

    def _add_router_interface(self, subnet, router, host):
        interface_info = {'subnet_id': subnet['id']}
        self.plugin.add_router_interface(self.adminContext,
                                         router['id'], interface_info)
        self.plugin.update_routers_states(
            self.adminContext,
            {router['id']: constants.HA_ROUTER_STATE_ACTIVE}, host)

        port = self._get_first_interface(subnet['network_id'], router)

        self.mock_cast.reset_mock()
        self.mock_fanout.reset_mock()
        self.callbacks.update_device_up(self.adminContext, agent_id=host,
                                        device=port['id'], host=host)
        return port

    def _create_ha_router(self):
        self._setup_l3()
        router = self._create_router()
        self._bind_router(router['id'], router['tenant_id'])
        return router

    def _create_dvr_router(self):
        self._setup_l3()
        router = self._create_router(distributed=True)
        self._bind_router(router['id'], router['tenant_id'])
        return router

    def _verify_remove_fdb(self, expected, agent_id, device, host=None):
        self.mock_fanout.reset_mock()
        self.callbacks.update_device_down(self.adminContext, agent_id=host,
                                          device=device, host=host)
        self.mock_fanout.assert_called_with(
            mock.ANY, 'remove_fdb_entries', expected)

    def test_other_agents_get_flood_entries_for_ha_agents(self):
        # First HA router port is added on HOST and HOST2, then network port
        # is added on HOST4.
        # HOST4 should get flood entries for HOST1 and HOST2
        router = self._create_ha_router()
        directory.add_plugin(plugin_constants.L3, self.plugin)
        with self.subnet(network=self._network, enable_dhcp=False) as snet:
            subnet = snet['subnet']
            port = self._add_router_interface(subnet, router, HOST)

            host_arg = {portbindings.HOST_ID: HOST_4, 'admin_state_up': True}
            with self.port(subnet=snet,
                           device_owner=DEVICE_OWNER_COMPUTE,
                           arg_list=(portbindings.HOST_ID,),
                           **host_arg) as port1:
                p1 = port1['port']
                device1 = 'tap' + p1['id']

                self.mock_cast.reset_mock()
                self.mock_fanout.reset_mock()
                self.callbacks.update_device_up(
                    self.adminContext, agent_id=HOST_4, device=device1)

                cast_expected = {
                    port['network_id']: {
                        'ports': {'20.0.0.1': [constants.FLOODING_ENTRY],
                                  '20.0.0.2': [constants.FLOODING_ENTRY]},
                        'network_type': 'vxlan', 'segment_id': 1}}
                self.assertEqual(1, self.mock_cast.call_count)
                self.mock_cast.assert_called_with(
                    mock.ANY, 'add_fdb_entries', cast_expected, HOST_4)

    def test_delete_ha_port(self):
        # First network port is added on HOST, and then HA router port
        # is added on HOST and HOST2.
        # Remove_fdb should carry flood entry of only HOST2 and not HOST
        router = self._create_ha_router()

        directory.add_plugin(plugin_constants.L3, self.plugin)
        with self.subnet(network=self._network, enable_dhcp=False) as snet:
            host_arg = {portbindings.HOST_ID: HOST, 'admin_state_up': True}
            with self.port(subnet=snet,
                           device_owner=DEVICE_OWNER_COMPUTE,
                           arg_list=(portbindings.HOST_ID,),
                           **host_arg) as port1:
                p1 = port1['port']
                device1 = 'tap' + p1['id']
                self.callbacks.update_device_up(self.adminContext,
                                                agent_id=HOST, device=device1)

                subnet = snet['subnet']
                port = self._add_router_interface(subnet, router, HOST)

                expected = {port['network_id']:
                    {'ports': {'20.0.0.2': [constants.FLOODING_ENTRY]},
                     'network_type': 'vxlan', 'segment_id': 1}}

                self.mock_fanout.reset_mock()
                interface_info = {'subnet_id': subnet['id']}
                self.plugin.remove_router_interface(self.adminContext,
                                         router['id'], interface_info)
                self.mock_fanout.assert_called_with(
                    mock.ANY, 'remove_fdb_entries', expected)

    def test_ovs_agent_restarted_with_dvr_port(self):
        plugin = directory.get_plugin()
        router = self._create_dvr_router()
        with self.subnet(network=self._network,
                         enable_dhcp=False) as snet:
            with self.port(
                    subnet=snet,
                    project_id=self.tenant,
                    device_owner=constants.DEVICE_OWNER_DVR_INTERFACE)\
                        as port:
                port_id = port['port']['id']
                plugin.update_distributed_port_binding(self.adminContext,
                    port_id, {'port': {portbindings.HOST_ID: HOST_4,
                    'device_id': router['id']}})
                port = self._show('ports', port_id,
                                  neutron_context=self.adminContext)
                self.assertEqual(portbindings.VIF_TYPE_DISTRIBUTED,
                                 port['port'][portbindings.VIF_TYPE])
                self.callbacks.update_device_up(self.adminContext,
                                                agent_id=HOST_4,
                                                device=port_id,
                                                host=HOST_4,
                                                agent_restarted=True)
                fanout_expected = {port['port']['network_id']: {
                    'network_type': u'vxlan',
                    'ports': {u'20.0.0.4': [('00:00:00:00:00:00', '0.0.0.0')]},
                    'segment_id': 1}}
                self.mock_fanout.assert_called_with(mock.ANY,
                                                    'add_fdb_entries',
                                                    fanout_expected)

    def test_ha_agents_with_dvr_rtr_does_not_get_other_fdb(self):
        router = self._create_dvr_router()
        directory.add_plugin(plugin_constants.L3, self.plugin)
        with self.subnet(network=self._network, enable_dhcp=False) as snet:
            host_arg = {portbindings.HOST_ID: HOST_4, 'admin_state_up': True}
            with self.port(subnet=snet,
                           device_owner=DEVICE_OWNER_COMPUTE,
                           arg_list=(portbindings.HOST_ID,),
                           **host_arg) as port1:
                p1 = port1['port']
                device1 = 'tap' + p1['id']
                self.callbacks.update_device_up(
                    self.adminContext, agent_id=HOST_4, device=device1)

                subnet = snet['subnet']
                port = self._add_router_interface(subnet, router, HOST)

                self.mock_cast.assert_not_called()
                self.mock_fanout.assert_not_called()

                self.mock_cast.reset_mock()
                self.mock_fanout.reset_mock()

                self.callbacks.update_device_up(
                    self.adminContext, agent_id=HOST_2,
                    device=port['id'], host=HOST_2)

                self.mock_cast.assert_not_called()
                self.mock_fanout.assert_not_called()

    def test_ha_agents_get_other_fdb(self):
        # First network port is added on HOST4, then HA router port is
        # added on HOST and HOST2.
        # Both HA agents should create tunnels to HOST4 and among themselves.
        # Both HA agents should be notified to other agents.
        router = self._create_ha_router()

        directory.add_plugin(plugin_constants.L3, self.plugin)
        with self.subnet(network=self._network, enable_dhcp=False) as snet:
            host_arg = {portbindings.HOST_ID: HOST_4, 'admin_state_up': True}
            with self.port(subnet=snet,
                           device_owner=DEVICE_OWNER_COMPUTE,
                           arg_list=(portbindings.HOST_ID,),
                           **host_arg) as port1:
                p1 = port1['port']
                device1 = 'tap' + p1['id']
                self.callbacks.update_device_up(
                    self.adminContext, agent_id=HOST_4, device=device1)
                p1_ips = [p['ip_address'] for p in p1['fixed_ips']]

                subnet = snet['subnet']
                port = self._add_router_interface(subnet, router, HOST)
                fanout_expected = {port['network_id']: {
                    'ports': {'20.0.0.1': [constants.FLOODING_ENTRY]},
                    'network_type': 'vxlan', 'segment_id': 1}}

                cast_expected_host = {port['network_id']: {
                    'ports': {
                        '20.0.0.4': [constants.FLOODING_ENTRY,
                                     l2pop_rpc.PortInfo(p1['mac_address'],
                                                        p1_ips[0])],
                        '20.0.0.2': [constants.FLOODING_ENTRY]},
                    'network_type': 'vxlan', 'segment_id': 1}}
                self.mock_cast.assert_called_with(
                    mock.ANY, 'add_fdb_entries', cast_expected_host, HOST)
                self.mock_fanout.assert_called_with(
                    mock.ANY, 'add_fdb_entries', fanout_expected)

                self.mock_cast.reset_mock()
                self.mock_fanout.reset_mock()

                self.callbacks.update_device_up(
                    self.adminContext, agent_id=HOST_2,
                    device=port['id'], host=HOST_2)

                cast_expected_host2 = {port['network_id']: {
                    'ports': {
                        '20.0.0.4': [constants.FLOODING_ENTRY,
                                     l2pop_rpc.PortInfo(p1['mac_address'],
                                                        p1_ips[0])],
                        '20.0.0.1': [constants.FLOODING_ENTRY]},
                    'network_type': 'vxlan', 'segment_id': 1}}
                fanout_expected = {port['network_id']: {
                    'ports': {'20.0.0.2': [constants.FLOODING_ENTRY]},
                    'network_type': 'vxlan', 'segment_id': 1}}
                self.mock_cast.assert_called_with(
                    mock.ANY, 'add_fdb_entries', cast_expected_host2, HOST_2)
                self.mock_fanout.assert_called_with(
                    mock.ANY, 'add_fdb_entries', fanout_expected)

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

    def test_fdb_add_called_dualstack(self):
        self._register_ml2_agents()

        host_arg = {portbindings.HOST_ID: HOST,
                    'admin_state_up': True}
        with self.subnet(self._network) as subnet,\
            self.subnet(
                self._network,
                cidr='2001:db8::/64',
                ip_version=constants.IP_VERSION_6,
                gateway_ip='fe80::1',
                ipv6_address_mode=constants.IPV6_SLAAC) as subnet2:
            with self.port(
                subnet,
                fixed_ips=[{'subnet_id': subnet['subnet']['id']},
                           {'subnet_id': subnet2['subnet']['id']}],
                device_owner=DEVICE_OWNER_COMPUTE,
                arg_list=(portbindings.HOST_ID,),
                **host_arg
            ) as port:
                p1 = port['port']

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
                                               p1_ips[0]),
                                           l2pop_rpc.PortInfo(
                                               p1['mac_address'],
                                               p1_ips[1])]},
                             'network_type': 'vxlan',
                             'segment_id': 1}}

                self.mock_fanout.assert_called_with(
                    mock.ANY, 'add_fdb_entries', expected)

    def test_update_port_up_two_active_ports(self):
        '''The test will check that even with 2 active ports on the host,
        agent will be provided with the whole list of fdb entries. Bug 1789846
        '''
        self._register_ml2_agents()

        with self.subnet(network=self._network) as subnet:
            host_arg = {portbindings.HOST_ID: HOST}
            # 2 ports on host 1
            with self.port(subnet=subnet,
                           device_owner=DEVICE_OWNER_COMPUTE,
                           arg_list=(portbindings.HOST_ID,),
                           **host_arg) as port1:
                with self.port(subnet=subnet,
                               device_owner=DEVICE_OWNER_COMPUTE,
                               arg_list=(portbindings.HOST_ID,),
                               **host_arg) as port2:
                    # 1 port on another host to have fdb entree to update
                    # agent on host 1
                    host_arg = {portbindings.HOST_ID: HOST + '_2'}
                    with self.port(subnet=subnet,
                                   device_owner=DEVICE_OWNER_COMPUTE,
                                   arg_list=(portbindings.HOST_ID,),
                                   **host_arg) as port3:
                        p1 = port1['port']
                        p2 = port2['port']
                        p3 = port3['port']

                        # only ACTIVE ports count
                        plugin = directory.get_plugin()
                        p2['status'] = 'ACTIVE'
                        plugin.update_port(self.adminContext, p2['id'], port2)
                        p3['status'] = 'ACTIVE'
                        plugin.update_port(self.adminContext, p3['id'], port3)

                        self.mock_cast.reset_mock()
                        p1['status'] = 'ACTIVE'
                        plugin.update_port(self.adminContext, p1['id'], port1)

                        # agent on host 1 should be updated with entry from
                        # another host
                        expected = {p3['network_id']:
                            {'ports':
                             {'20.0.0.2': [
                                 constants.FLOODING_ENTRY,
                                 l2pop_rpc.PortInfo(
                                     p3['mac_address'],
                                     p3['fixed_ips'][0]['ip_address'])]},
                             'network_type': 'vxlan',
                             'segment_id': 1}}

                        self.mock_cast.assert_called_once_with(
                            mock.ANY, 'add_fdb_entries', expected, HOST)

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

    def test_update_port_down_ha_router_port(self):
        router = self._create_ha_router()
        directory.add_plugin(plugin_constants.L3, self.plugin)
        with self.subnet(network=self._network, enable_dhcp=False) as snet:
            subnet = snet['subnet']
            router_port = self._add_router_interface(subnet, router, HOST)
            router_port_device = 'tap' + router_port['id']

            host_arg = {portbindings.HOST_ID: HOST_4, 'admin_state_up': True}
            with self.port(subnet=snet,
                           device_owner=DEVICE_OWNER_COMPUTE,
                           arg_list=(portbindings.HOST_ID,),
                           **host_arg) as port1:
                p1 = port1['port']
                device1 = 'tap' + p1['id']

                self.callbacks.update_device_up(self.adminContext,
                                                agent_id=HOST,
                                                device=device1)
                self.mock_fanout.reset_mock()
                self.callbacks.update_device_down(self.adminContext,
                                                  agent_id=HOST,
                                                  device=router_port_device,
                                                  host=HOST)

                router_port_ips = [
                    p['ip_address'] for p in router_port['fixed_ips']]
                expected = {
                    router_port['network_id']: {
                        'ports': {
                            '20.0.0.1': [
                                l2pop_rpc.PortInfo(router_port['mac_address'],
                                                   router_port_ips[0])]},
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
                p1_ip = p1['fixed_ips'][0]['ip_address']
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
                                l2pop_rpc.PortInfo(new_mac, p1_ip)
                            ]
                        }
                    }
                }
                self.mock_fanout.assert_called_with(
                    mock.ANY, 'add_fdb_entries', add_expected)

    def test_fixed_ips_changed_vlan(self):
        self._register_ml2_agents()

        with self.subnet(network=self._network2) as subnet:
            host_arg = {portbindings.HOST_ID: HOST}
            fixed_ips = [{'subnet_id': subnet['subnet']['id'],
                          'ip_address': '10.0.0.2'}]
            with self.port(subnet=subnet, cidr='10.0.0.0/24',
                           device_owner=DEVICE_OWNER_COMPUTE,
                           arg_list=(portbindings.HOST_ID,),
                           fixed_ips=fixed_ips,
                           **host_arg) as port:
                p = port['port']

                device = 'tap' + p['id']

                self.callbacks.update_device_up(self.adminContext,
                                                agent_id=HOST,
                                                device=device)

                data = {'port': {'fixed_ips': [{'ip_address': '10.0.0.2'},
                                               {'ip_address': '10.0.0.10'}]}}
                self.new_update_request('ports', data, p['id'])
                l2pop_mech = l2pop_mech_driver.L2populationMechanismDriver()
                l2pop_mech.L2PopulationAgentNotify = mock.Mock()
                l2notify = l2pop_mech.L2PopulationAgentNotify
                l2notify.update_fdb_entries = mock.Mock()
                self.assertFalse(l2notify.update_fdb_entries.called)

    def test_fixed_ips_changed(self):
        self._register_ml2_agents()

        with self.subnet(network=self._network) as subnet:
            host_arg = {portbindings.HOST_ID: HOST}
            fixed_ips = [{'subnet_id': subnet['subnet']['id'],
                          'ip_address': '10.0.0.2'}]
            with self.port(subnet=subnet, cidr='10.0.0.0/24',
                           device_owner=DEVICE_OWNER_COMPUTE,
                           arg_list=(portbindings.HOST_ID,),
                           fixed_ips=fixed_ips,
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
                self.assertEqual(2, len(ips))

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
                self.assertEqual(2, len(ips))

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
                self.assertEqual(1, len(ips))

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

                plugin = directory.get_plugin()
                plugin.update_port(self.adminContext, p1['id'], port1)

                self.assertFalse(self.mock_fanout.called)

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
        data = {'port': {portbindings.HOST_ID: host_id}}
        req = self.new_update_request('ports', data, port_id)
        res = self.deserialize(self.fmt,
                               req.get_response(self.api))
        self.assertEqual(host_id, res['port'][portbindings.HOST_ID])

    def _test_host_changed(self, twice):
        self._register_ml2_agents()
        with self.subnet(network=self._network) as subnet:
            host_arg = {portbindings.HOST_ID: HOST}
            with self.port(subnet=subnet, cidr='10.0.0.0/24',
                           device_owner=DEVICE_OWNER_COMPUTE,
                           arg_list=(portbindings.HOST_ID,),
                           **host_arg) as port1:
                tunnel_ip = '20.0.0.1'
                p1 = port1['port']
                device1 = 'tap' + p1['id']
                self.callbacks.update_device_up(
                    self.adminContext,
                    agent_id=HOST,
                    device=device1)
                if twice:
                    tunnel_ip = '20.0.0.4'
                    self._update_and_check_portbinding(p1['id'], HOST_4)
                    self.callbacks.update_device_up(self.adminContext,
                                                    agent_id=HOST_4,
                                                    device=device1)

                self.mock_fanout.reset_mock()
                self._update_and_check_portbinding(p1['id'], HOST_2)
                p1_ips = [p['ip_address'] for p in p1['fixed_ips']]
                expected = {p1['network_id']:
                            {'ports':
                             {tunnel_ip: [constants.FLOODING_ENTRY,
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

    def test_delete_port_no_fdb_entries_with_ha_port(self):
        l2pop_mech = l2pop_mech_driver.L2populationMechanismDriver()
        l2pop_mech.L2PopulationAgentNotify = mock.Mock()
        l2pop_mech.rpc_ctx = mock.Mock()
        port = {'device_owner': l2pop_db.HA_ROUTER_PORTS[0]}
        context = mock.Mock()
        context.current = port
        with mock.patch.object(l2pop_mech,
                               '_get_agent_fdb',
                               return_value=None) as upd_port_down,\
                mock.patch.object(l2pop_mech.L2PopulationAgentNotify,
                                  'remove_fdb_entries'):
            l2pop_mech.delete_port_postcommit(context)
            self.assertTrue(upd_port_down.called)

    def test_delete_port_invokes_update_device_down(self):
        l2pop_mech = l2pop_mech_driver.L2populationMechanismDriver()
        l2pop_mech.L2PopulationAgentNotify = mock.Mock()
        l2pop_mech.rpc_ctx = mock.Mock()
        port = {'device_owner': ''}
        context = mock.Mock()
        context.current = port
        with mock.patch.object(l2pop_mech,
                               '_get_agent_fdb',
                               return_value=None) as upd_port_down,\
                mock.patch.object(l2pop_mech.L2PopulationAgentNotify,
                                  'remove_fdb_entries'):
            l2pop_mech.delete_port_postcommit(context)
            self.assertTrue(upd_port_down.called)

    def test_delete_unbound_port(self):
        self._test_delete_port_handles_agentless_host_id(None)

    def test_delete_port_bound_to_agentless_host(self):
        self._test_delete_port_handles_agentless_host_id('test')

    def _test_delete_port_handles_agentless_host_id(self, host):
        l2pop_mech = l2pop_mech_driver.L2populationMechanismDriver()
        l2pop_mech.initialize()

        with self.port() as port:
            port['port'][portbindings.HOST_ID] = host
            bindings = [models.PortBindingLevel()]
            port_context = driver_context.PortContext(
                self.driver, self.context, port['port'],
                self.driver.get_network(
                    self.context, port['port']['network_id']),
                models.PortBinding(), bindings)
            # The point is to provide coverage and to assert that no exceptions
            # are raised.
            l2pop_mech.delete_port_postcommit(port_context)

    def test_delete_dvr_snat_port_fdb_entries(self):
        l2pop_mech = l2pop_mech_driver.L2populationMechanismDriver()
        l2pop_mech.initialize()

        self._setup_l3()

        with self.subnet(network=self._network, enable_dhcp=False) as snet:
            host_arg = {portbindings.HOST_ID: HOST, 'admin_state_up': True}
            with self.port(subnet=snet,
                           device_owner=constants.DEVICE_OWNER_ROUTER_SNAT,
                           arg_list=(portbindings.HOST_ID,),
                           **host_arg) as p:
                device = 'tap' + p['port']['id']
                self.callbacks.update_device_up(self.adminContext,
                                                agent_id=HOST, device=device)
                self.mock_fanout.reset_mock()

                p['port'][portbindings.HOST_ID] = HOST
                bindings = [models.PortBindingLevel()]
                port_context = driver_context.PortContext(
                    self.driver, self.context, p['port'],
                    self.driver.get_network(
                        self.context, p['port']['network_id']),
                    models.PortBinding(), bindings)
                fdbs = {
                    p['port']['network_id']: {
                        'segment_id': 'fakeid',
                        'ports': {},
                    }
                }
                mock.patch.object(
                    l2pop_mech, '_get_agent_fdb', return_value=fdbs).start()
                # The point is to provide coverage and to assert that
                # no exceptions are raised.
                l2pop_mech.delete_port_postcommit(port_context)

    def test_fixed_ips_change_unbound_port_no_rpc(self):
        l2pop_mech = l2pop_mech_driver.L2populationMechanismDriver()
        l2pop_mech.initialize()
        l2pop_mech.L2populationAgentNotify = mock.Mock()

        with self.port() as port:
            port_context = driver_context.PortContext(
                self.driver, self.context, port['port'],
                self.driver.get_network(
                    self.context, port['port']['network_id']),
                models.PortBinding(), None)
            l2pop_mech._fixed_ips_changed(
                port_context, None, port['port'], (set(['10.0.0.1']), set()))

        # There's no need to send an RPC update if the IP address for an
        # unbound port changed.
        self.assertFalse(
            l2pop_mech.L2populationAgentNotify.update_fdb_entries.called)


class TestL2PopulationMechDriver(base.BaseTestCase):

    def _test_get_tunnels(self, agent_ip, exclude_host=True):
        mech_driver = l2pop_mech_driver.L2populationMechanismDriver()
        agent = mock.Mock()
        agent.host = HOST
        network_ports = ((None, agent),)
        with mock.patch.object(l2pop_db, 'get_agent_ip',
                               return_value=agent_ip):
            excluded_host = HOST + '-EXCLUDE' if exclude_host else HOST
            return mech_driver._get_tunnels(network_ports, excluded_host)

    def test_get_tunnels(self):
        tunnels = self._test_get_tunnels('20.0.0.1')
        self.assertIn('20.0.0.1', tunnels)

    def test_get_tunnels_no_ip(self):
        tunnels = self._test_get_tunnels(None)
        self.assertEqual(0, len(tunnels))

    def test_get_tunnels_dont_exclude_host(self):
        tunnels = self._test_get_tunnels(None, exclude_host=False)
        self.assertEqual(0, len(tunnels))

    def _test_create_agent_fdb(self, fdb_network_ports, agent_ips):
        mech_driver = l2pop_mech_driver.L2populationMechanismDriver()
        tunnel_network_ports, tunnel_agent = (
            self._mock_network_ports(HOST + '1', [None]))
        agent_ips[tunnel_agent] = '10.0.0.1'

        def agent_ip_side_effect(agent):
            return agent_ips[agent]

        with mock.patch.object(l2pop_db, 'get_agent_ip',
                               side_effect=agent_ip_side_effect),\
                mock.patch.object(l2pop_db,
                                  'get_nondistributed_active_network_ports',
                                  return_value=fdb_network_ports),\
                mock.patch.object(l2pop_db,
                                  'get_distributed_active_network_ports',
                                  return_value=tunnel_network_ports):
            agent = mock.Mock()
            agent.host = HOST
            segment = {'segmentation_id': 1, 'network_type': 'vxlan'}
            return mech_driver._create_agent_fdb(context,
                                                 agent,
                                                 segment,
                                                 'network_id')

    def _mock_network_ports(self, host_name, bindings):
        agent = mock.Mock()
        agent.host = host_name
        return [(binding, agent) for binding in bindings], agent

    def test_create_agent_fdb(self):
        binding = mock.Mock()
        binding.port = {'mac_address': '00:00:DE:AD:BE:EF',
                        'fixed_ips': [{'ip_address': '1.1.1.1'}]}
        fdb_network_ports, fdb_agent = (
            self._mock_network_ports(HOST + '2', [binding]))
        agent_ips = {fdb_agent: '20.0.0.1'}

        agent_fdb = self._test_create_agent_fdb(fdb_network_ports,
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
        agent_fdb = self._test_create_agent_fdb([], {})
        result = agent_fdb['network_id']

        expected_result = {'segment_id': 1,
                           'network_type': 'vxlan',
                           'ports':
                           {'10.0.0.1':
                            [constants.FLOODING_ENTRY]}}
        self.assertEqual(expected_result, result)

    def test_create_agent_fdb_concurrent_port_deletion(self):
        binding = mock.Mock()
        binding.port = {'mac_address': '00:00:DE:AD:BE:EF',
                        'fixed_ips': [{'ip_address': '1.1.1.1'}]}
        binding2 = mock.Mock()
        # the port was deleted
        binding2.port = None
        fdb_network_ports, fdb_agent = (
            self._mock_network_ports(HOST + '2', [binding, binding2]))
        agent_ips = {fdb_agent: '20.0.0.1'}

        agent_fdb = self._test_create_agent_fdb(fdb_network_ports,
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

    def test_update_port_precommit_mac_address_changed_raises(self):
        port = {'status': u'ACTIVE',
                'device_owner': DEVICE_OWNER_COMPUTE,
                'mac_address': u'12:34:56:78:4b:0e',
                'id': u'1'}

        original_port = port.copy()
        original_port['mac_address'] = u'12:34:56:78:4b:0f'

        with mock.patch.object(driver_context.segments_db,
                               'get_network_segments'):
            ctx = driver_context.PortContext(mock.Mock(),
                                             mock.Mock(),
                                             port,
                                             mock.MagicMock(),
                                             models.PortBinding(),
                                             [models.PortBindingLevel()],
                                             original_port=original_port)

        mech_driver = l2pop_mech_driver.L2populationMechanismDriver()
        with testtools.ExpectedException(exceptions.InvalidInput):
            mech_driver.update_port_precommit(ctx)
