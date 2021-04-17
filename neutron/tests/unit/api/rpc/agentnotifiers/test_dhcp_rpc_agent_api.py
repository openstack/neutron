# Copyright (c) 2013 Red Hat, Inc.
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

import copy
import datetime
from unittest import mock

from neutron_lib.api import extensions
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib.plugins import directory
from oslo_utils import timeutils
from oslo_utils import uuidutils

from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.db.agentschedulers_db import cfg
from neutron.objects import agent as agent_obj
from neutron.tests import base


class TestDhcpAgentNotifyAPI(base.BaseTestCase):

    def setUp(self):
        super(TestDhcpAgentNotifyAPI, self).setUp()
        self.notifier = (
            dhcp_rpc_agent_api.DhcpAgentNotifyAPI(plugin=mock.Mock()))

        mock_util_p = mock.patch.object(extensions, 'is_extension_supported')
        mock_log_p = mock.patch.object(dhcp_rpc_agent_api, 'LOG')
        mock_fanout_p = mock.patch.object(self.notifier, '_fanout_message')
        mock_cast_p = mock.patch.object(self.notifier, '_cast_message')
        self.mock_util = mock_util_p.start()
        self.mock_log = mock_log_p.start()
        self.mock_fanout = mock_fanout_p.start()
        self.mock_cast = mock_cast_p.start()

    def _test__schedule_network(self, network,
                                new_agents=None, existing_agents=None,
                                expected_casts=0, expected_warnings=0):
        self.notifier.plugin.schedule_network.return_value = new_agents
        agents = self.notifier._schedule_network(
            mock.ANY, network, existing_agents)
        if new_agents is None:
            new_agents = []
        self.assertEqual(new_agents + existing_agents, agents)
        self.assertEqual(expected_casts, self.mock_cast.call_count)
        self.assertEqual(expected_warnings, self.mock_log.warning.call_count)

    def test__schedule_network(self):
        agent = agent_obj.Agent(mock.ANY, id=uuidutils.generate_uuid(),
                                host='host')
        agent.admin_state_up = True
        agent.heartbeat_timestamp = timeutils.utcnow()
        network = {'id': 'foo_net_id'}
        self._test__schedule_network(network,
                                     new_agents=[agent], existing_agents=[],
                                     expected_casts=1, expected_warnings=0)

    def test__schedule_network_no_existing_agents(self):
        agent = agent_obj.Agent(mock.ANY, id=uuidutils.generate_uuid())
        agent.admin_state_up = True
        agent.heartbeat_timestamp = timeutils.utcnow()
        network = {'id': 'foo_net_id'}
        self._test__schedule_network(network,
                                     new_agents=None, existing_agents=[agent],
                                     expected_casts=0, expected_warnings=0)

    def test__schedule_network_no_new_agents(self):
        network = {'id': 'foo_net_id'}
        self._test__schedule_network(network,
                                     new_agents=None, existing_agents=[],
                                     expected_casts=0, expected_warnings=1)

    def _test__get_enabled_agents(self, network_id,
                                  agents=None, port_count=0,
                                  expected_warnings=0, expected_errors=0):
        self.notifier.plugin.get_ports_count.return_value = port_count
        enabled_agents = self.notifier._get_enabled_agents(
            mock.Mock(), network_id, None, agents, mock.ANY, mock.ANY)
        if not cfg.CONF.enable_services_on_agents_with_admin_state_down:
            agents = [x for x in agents if x.admin_state_up]
        self.assertEqual(agents, enabled_agents)
        self.assertEqual(expected_warnings, self.mock_log.warning.call_count)
        self.assertEqual(expected_errors, self.mock_log.error.call_count)

    def test__get_enabled_agents(self):
        agent1 = agent_obj.Agent(mock.ANY, id=uuidutils.generate_uuid())
        agent1.admin_state_up = True
        agent1.heartbeat_timestamp = timeutils.utcnow()
        agent2 = agent_obj.Agent(mock.ANY, id=uuidutils.generate_uuid())
        agent2.admin_state_up = False
        agent2.heartbeat_timestamp = timeutils.utcnow()
        self._test__get_enabled_agents(network_id='foo_network_id',
                                       agents=[agent1])

    def test__get_enabled_agents_with_inactive_ones(self):
        agent1 = agent_obj.Agent(mock.ANY, id=uuidutils.generate_uuid())
        agent1.admin_state_up = True
        agent1.heartbeat_timestamp = timeutils.utcnow()
        agent2 = agent_obj.Agent(mock.ANY, id=uuidutils.generate_uuid())
        agent2.admin_state_up = True
        # This is effectively an inactive agent
        agent2.heartbeat_timestamp = datetime.datetime(2000, 1, 1, 0, 0)
        self._test__get_enabled_agents(network_id='foo_network_id',
                                       agents=[agent1, agent2],
                                       expected_warnings=1, expected_errors=0)

    def test__get_enabled_agents_with_notification_required(self):
        network = {'id': 'foo_network_id', 'subnets': ['foo_subnet_id']}
        self.notifier.plugin.get_network.return_value = network
        agent = agent_obj.Agent(mock.ANY, id=uuidutils.generate_uuid())
        agent.admin_state_up = False
        agent.heartbeat_timestamp = timeutils.utcnow()
        self._test__get_enabled_agents('foo_network_id',
                                       [agent], port_count=20,
                                       expected_warnings=0, expected_errors=1)

    def test__get_enabled_agents_with_admin_state_down(self):
        cfg.CONF.set_override(
            'enable_services_on_agents_with_admin_state_down', True)
        agent1 = agent_obj.Agent(mock.ANY, id=uuidutils.generate_uuid())
        agent1.admin_state_up = True
        agent1.heartbeat_timestamp = timeutils.utcnow()
        agent2 = agent_obj.Agent(mock.ANY, id=uuidutils.generate_uuid())
        agent2.admin_state_up = False
        agent2.heartbeat_timestamp = timeutils.utcnow()
        self._test__get_enabled_agents(network_id='foo_network_id',
                                       agents=[agent1, agent2])

    def test__notify_agents_allocate_priority(self):
        mock_context = mock.MagicMock()
        mock_context.is_admin = True
        methods = ['network_create_end', 'network_update_end',
                  'network_delete_end', 'subnet_create_end',
                  'subnet_update_end', 'subnet_delete_end',
                  'port_create_end', 'port_update_end', 'port_delete_end']
        with mock.patch.object(self.notifier, '_schedule_network') as f:
            with mock.patch.object(self.notifier, '_get_enabled_agents') as g:
                for method in methods:
                    f.return_value = [mock.MagicMock()]
                    g.return_value = [mock.MagicMock()]
                    payload = {}
                    if method.startswith('port'):
                        payload['port'] = \
                            {'device_id':
                             constants.DEVICE_ID_RESERVED_DHCP_PORT}
                    expected_payload = copy.deepcopy(payload)
                    expected_payload['priority'] = \
                        dhcp_rpc_agent_api.METHOD_PRIORITY_MAP.get(method)
                    self.notifier._notify_agents(mock_context, method, payload,
                                                 'fake_network_id')
                    if method == 'network_delete_end':
                        self.mock_fanout.assert_called_with(mock.ANY, method,
                                                            expected_payload)
                    elif method != 'network_create_end':
                        if method == 'port_create_end':
                            expected_payload['priority'] = \
                                dhcp_rpc_agent_api.PRIORITY_PORT_CREATE_HIGH
                        self.mock_cast.assert_called_with(mock.ANY, method,
                                                          expected_payload,
                                                          mock.ANY, mock.ANY)

    def test__notify_agents_fanout_required(self):
        self.notifier._notify_agents(mock.ANY,
                                     'network_delete_end',
                                     {}, 'foo_network_id')
        self.assertEqual(1, self.mock_fanout.call_count)

    def _test__notify_agents_with_function(self, function,
                                           expected_scheduling=0,
                                           expected_casts=0):
        with mock.patch.object(self.notifier, '_schedule_network') as f:
            with mock.patch.object(self.notifier, '_get_enabled_agents') as g:
                agent = agent_obj.Agent(mock.ANY, id=uuidutils.generate_uuid(),
                                        host='host', topic='topic')
                agent.admin_state_up = True
                agent.heartbeat_timestamp = timeutils.utcnow()
                g.return_value = [agent]
                function()
                self.assertEqual(expected_scheduling, f.call_count)
                self.assertEqual(expected_casts, self.mock_cast.call_count)

    def _test__notify_agents(self, method,
                             expected_scheduling=0, expected_casts=0,
                             payload=None):
        payload = payload or {'port': {}}
        self._test__notify_agents_with_function(
            lambda: self.notifier._notify_agents(
                mock.Mock(), method, payload, 'foo_network_id'),
            expected_scheduling, expected_casts)

    def test__notify_agents_cast_required_with_scheduling(self):
        self._test__notify_agents('port_create_end',
                                  expected_scheduling=1, expected_casts=1)

    def test__notify_agents_cast_required_wo_scheduling_on_port_update(self):
        self._test__notify_agents('port_update_end',
                                  expected_scheduling=0, expected_casts=1)

    def test__notify_agents_cast_required_with_scheduling_subnet_create(self):
        self._test__notify_agents('subnet_create_end',
                                  expected_scheduling=1, expected_casts=1,
                                  payload={'subnet': {}})

    def test__notify_agents_cast_required_with_scheduling_segment(self):
        network_id = 'foo_network_id'
        segment_id = 'foo_segment_id'
        subnet = {'subnet': {'segment_id': segment_id}}
        segment = {'id': segment_id, 'network_id': network_id,
                   'hosts': ['host-a']}
        self.notifier.plugin.get_network.return_value = {'id': network_id}
        segment_sp = mock.Mock()
        segment_sp.get_segment.return_value = segment
        directory.add_plugin('segments', segment_sp)
        self._test__notify_agents('subnet_create_end',
                                  expected_scheduling=1, expected_casts=1,
                                  payload=subnet)
        get_agents = self.notifier.plugin.get_dhcp_agents_hosting_networks
        get_agents.assert_called_once_with(
            mock.ANY, [network_id], hosts=segment['hosts'])

    def test__notify_agents_no_action(self):
        self._test__notify_agents('network_create_end',
                                  expected_scheduling=0, expected_casts=0)

    def test__notify_agents_with_router_interface_add(self):
        self._test__notify_agents_with_function(
            lambda: self.notifier._after_router_interface_created(
                mock.ANY, mock.ANY, mock.ANY, context=mock.Mock(),
                port={'id': 'foo_port_id', 'network_id': 'foo_network_id'}),
            expected_scheduling=1, expected_casts=1)

    def test__notify_agents_with_router_interface_delete(self):
        self._test__notify_agents_with_function(
            lambda: self.notifier._after_router_interface_deleted(
                mock.ANY, mock.ANY, mock.ANY, context=mock.Mock(),
                port={'id': 'foo_port_id', 'network_id': 'foo_network_id',
                      'fixed_ips': {'subnet_id': 'subnet1',
                                    'ip_address': '10.0.0.1'}}),
            expected_scheduling=0, expected_casts=1)

    def test__fanout_message(self):
        self.notifier._fanout_message(mock.ANY, mock.ANY, mock.ANY)
        self.assertEqual(1, self.mock_fanout.call_count)

    def test__cast_message(self):
        self.notifier._cast_message(mock.ANY, mock.ANY, mock.ANY, mock.ANY)
        self.assertEqual(1, self.mock_cast.call_count)

    def test__native_notification_unsubscribes(self):
        self.assertFalse(self.notifier._unsubscribed_resources)
        for res in (resources.PORT, resources.NETWORK, resources.SUBNET):
            self.notifier._unsubscribed_resources = []
            kwargs = {res: {}}
            registry.notify(res, events.AFTER_CREATE, self,
                            context=mock.Mock(), **kwargs)
            # don't unsubscribe until all three types are observed
            self.assertEqual([], self.notifier._unsubscribed_resources)
            registry.notify(res, events.AFTER_UPDATE, self,
                            context=mock.Mock(), **kwargs)
            self.assertEqual([], self.notifier._unsubscribed_resources)
            registry.notify(res, events.AFTER_DELETE, self,
                            context=mock.Mock(), **kwargs)
            self.assertEqual([res], self.notifier._unsubscribed_resources)
            # after first time, no further unsubscribing should happen
            registry.notify(res, events.AFTER_CREATE, self,
                            context=mock.Mock(), **kwargs)
            self.assertEqual([res], self.notifier._unsubscribed_resources)

    def test__only_status_changed(self):
        p1 = {'id': 1, 'status': 'DOWN', 'updated_at': '10:00:00',
              'revision_number': 1}
        p2 = dict(p1)
        p2['status'] = 'ACTIVE'
        p2['revision_number'] = 2
        p2['updated_at'] = '10:00:01'
        self.assertTrue(self.notifier._only_status_changed(p1, p2))
        p2['name'] = 'test'
        self.assertFalse(self.notifier._only_status_changed(p1, p2))
        p1['name'] = 'test'
        self.assertTrue(self.notifier._only_status_changed(p1, p2))
        p1['name'] = 'test1'
        self.assertFalse(self.notifier._only_status_changed(p1, p2))
