# Copyright (c) 2012 OpenStack Foundation.
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

import datetime

import mock
import netaddr
from neutron_lib.agent import topics as lib_topics
from neutron_lib.callbacks import events
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib import rpc as n_rpc
from oslo_context import context as oslo_context
from oslo_utils import uuidutils

from neutron.agent import rpc
from neutron.common import constants as n_const
from neutron.objects import network
from neutron.objects import ports
from neutron.tests import base


class AgentRPCPluginApi(base.BaseTestCase):
    def _test_rpc_call(self, method):
        agent = rpc.PluginApi('fake_topic')
        ctxt = oslo_context.RequestContext(user_id='fake_user',
                                           project_id='fake_project')
        expect_val = 'foo'
        with mock.patch.object(agent.client, 'call') as mock_call,\
                mock.patch.object(agent.client, 'prepare') as mock_prepare:
            mock_prepare.return_value = agent.client
            mock_call.return_value = expect_val
            func_obj = getattr(agent, method)
            if method == 'tunnel_sync':
                actual_val = func_obj(ctxt, 'fake_tunnel_ip')
            else:
                actual_val = func_obj(ctxt, 'fake_device', 'fake_agent_id')
        self.assertEqual(actual_val, expect_val)

    def test_get_device_details(self):
        self._test_rpc_call('get_device_details')

    def test_get_devices_details_list(self):
        self._test_rpc_call('get_devices_details_list')

    def test_update_device_down(self):
        self._test_rpc_call('update_device_down')

    def test_tunnel_sync(self):
        self._test_rpc_call('tunnel_sync')


class AgentPluginReportState(base.BaseTestCase):
    def test_plugin_report_state_use_call(self):
        topic = 'test'
        reportStateAPI = rpc.PluginReportStateAPI(topic)
        expected_agent_state = {'agent': 'test'}
        with mock.patch.object(reportStateAPI.client, 'call') as mock_call, \
                mock.patch.object(reportStateAPI.client, 'cast'), \
                mock.patch.object(reportStateAPI.client, 'prepare'
                                  ) as mock_prepare:
            mock_prepare.return_value = reportStateAPI.client
            ctxt = oslo_context.RequestContext(user_id='fake_user',
                                               project_id='fake_project')
            reportStateAPI.report_state(ctxt, expected_agent_state,
                                        use_call=True)
            self.assertEqual(mock_call.call_args[0][0], ctxt)
            self.assertEqual(mock_call.call_args[0][1], 'report_state')
            self.assertEqual(mock_call.call_args[1]['agent_state'],
                             {'agent_state': expected_agent_state})
            self.assertIsInstance(mock_call.call_args[1]['time'], str)

    def test_plugin_report_state_cast(self):
        topic = 'test'
        reportStateAPI = rpc.PluginReportStateAPI(topic)
        expected_agent_state = {'agent': 'test'}
        with mock.patch.object(reportStateAPI.client, 'call'), \
                mock.patch.object(reportStateAPI.client, 'cast'
                                  ) as mock_cast, \
                mock.patch.object(reportStateAPI.client, 'prepare'
                                  ) as mock_prepare:
            mock_prepare.return_value = reportStateAPI.client
            ctxt = oslo_context.RequestContext(user_id='fake_user',
                                               project_id='fake_project')
            reportStateAPI.report_state(ctxt, expected_agent_state)
            self.assertEqual(mock_cast.call_args[0][0], ctxt)
            self.assertEqual(mock_cast.call_args[0][1], 'report_state')
            self.assertEqual(mock_cast.call_args[1]['agent_state'],
                             {'agent_state': expected_agent_state})
            self.assertIsInstance(mock_cast.call_args[1]['time'], str)

    def test_plugin_report_state_microsecond_is_0(self):
        topic = 'test'
        expected_time = datetime.datetime(2015, 7, 27, 15, 33, 30, 0)
        expected_time_str = '2015-07-27T15:33:30.000000'
        expected_agent_state = {'agent': 'test'}
        with mock.patch('neutron.agent.rpc.datetime') as mock_datetime:
            reportStateAPI = rpc.PluginReportStateAPI(topic)
            mock_datetime.utcnow.return_value = expected_time
            with mock.patch.object(reportStateAPI.client, 'call'), \
                    mock.patch.object(reportStateAPI.client, 'cast'
                                      ) as mock_cast, \
                    mock.patch.object(reportStateAPI.client, 'prepare'
                                      ) as mock_prepare:
                mock_prepare.return_value = reportStateAPI.client
                ctxt = oslo_context.RequestContext(user_id='fake_user',
                                                   project_id='fake_project')
                reportStateAPI.report_state(ctxt, expected_agent_state)
                self.assertEqual(expected_time_str,
                                 mock_cast.call_args[1]['time'])


class AgentRPCMethods(base.BaseTestCase):

    def _test_create_consumers(
        self, endpoints, method, expected, topics, listen):
        with mock.patch.object(n_rpc, 'Connection') as create_connection:
            rpc.create_consumers(
                endpoints, method, topics, start_listening=listen)
            create_connection.assert_has_calls(expected)

    def test_create_consumers_start_listening(self):
        endpoints = [mock.Mock()]
        expected = [
            mock.call(),
            mock.call().create_consumer('foo-topic-op', endpoints,
                                        fanout=True),
            mock.call().consume_in_threads()
        ]
        method = 'foo'
        topics = [('topic', 'op')]
        self._test_create_consumers(
            endpoints, method, expected, topics, True)

    def test_create_consumers_do_not_listen(self):
        endpoints = [mock.Mock()]
        expected = [
            mock.call(),
            mock.call().create_consumer('foo-topic-op', endpoints,
                                        fanout=True),
        ]
        method = 'foo'
        topics = [('topic', 'op')]
        self._test_create_consumers(
            endpoints, method, expected, topics, False)

    def test_create_consumers_with_node_name(self):
        endpoints = [mock.Mock()]
        expected = [
            mock.call(),
            mock.call().create_consumer('foo-topic-op', endpoints,
                                        fanout=True),
            mock.call().create_consumer('foo-topic-op.node1', endpoints,
                                        fanout=False),
            mock.call().consume_in_threads()
        ]

        with mock.patch.object(n_rpc, 'Connection') as create_connection:
            rpc.create_consumers(endpoints, 'foo', [('topic', 'op', 'node1')])
            create_connection.assert_has_calls(expected)


class TestCacheBackedPluginApi(base.BaseTestCase):

    def setUp(self):
        super(TestCacheBackedPluginApi, self).setUp()
        self._api = rpc.CacheBackedPluginApi(lib_topics.PLUGIN)
        self._api._legacy_interface = mock.Mock()
        self._api.remote_resource_cache = mock.Mock()
        self._network_id = uuidutils.generate_uuid()
        self._segment_id = uuidutils.generate_uuid()
        self._segment = network.NetworkSegment(
            id=self._segment_id, network_id=self._network_id,
            network_type=constants.TYPE_FLAT)
        self._port_id = uuidutils.generate_uuid()
        self._network = network.Network(id=self._network_id,
                                        segments=[self._segment])
        self._port = ports.Port(
            id=self._port_id, network_id=self._network_id,
            mac_address=netaddr.EUI('fa:16:3e:ec:c7:d9'), admin_state_up=True,
            security_group_ids=set([uuidutils.generate_uuid()]),
            fixed_ips=[], allowed_address_pairs=[],
            device_owner=constants.DEVICE_OWNER_COMPUTE_PREFIX,
            bindings=[ports.PortBinding(port_id=self._port_id,
                                        host='host1',
                                        status=constants.ACTIVE,
                                        profile={})],
            binding_levels=[ports.PortBindingLevel(port_id=self._port_id,
                                                   host='host1',
                                                   level=0,
                                                   segment=self._segment)])

    def test__legacy_notifier_resource_delete(self):
        self._api._legacy_notifier(resources.PORT, events.AFTER_DELETE, self,
                                   mock.ANY, resource_id=self._port_id,
                                   existing=self._port)
        self._api._legacy_interface.port_update.assert_not_called()
        self._api._legacy_interface.port_delete.assert_called_once_with(
            mock.ANY, port={'id': self._port_id}, port_id=self._port_id)
        self._api._legacy_interface.binding_deactivate.assert_not_called()

    def test__legacy_notifier_resource_update(self):
        updated_port = ports.Port(id=self._port_id, name='updated_port')
        self._api._legacy_notifier(resources.PORT, events.AFTER_UPDATE, self,
                                   mock.ANY, changed_fields=set(['name']),
                                   resource_id=self._port_id,
                                   existing=self._port, updated=updated_port)
        self._api._legacy_interface.port_delete.assert_not_called()
        self._api._legacy_interface.port_update.assert_called_once_with(
            mock.ANY, port={'id': self._port_id}, port_id=self._port_id)
        self._api._legacy_interface.binding_deactivate.assert_not_called()

    def _test__legacy_notifier_binding_activated(self):
        updated_port = ports.Port(
            id=self._port_id, name='updated_port',
            bindings=[ports.PortBinding(port_id=self._port_id,
                                        host='host2',
                                        status=constants.ACTIVE),
                      ports.PortBinding(port_id=self._port_id,
                                        host='host1',
                                        status=constants.INACTIVE)])
        self._api._legacy_notifier(resources.PORT, events.AFTER_UPDATE, self,
                                   mock.ANY,
                                   changed_fields=set(['name', 'bindings']),
                                   resource_id=self._port_id,
                                   existing=self._port, updated=updated_port)
        self._api._legacy_interface.port_update.assert_not_called()
        self._api._legacy_interface.port_delete.assert_not_called()

    def test__legacy_notifier_new_binding_activated(self):
        self._test__legacy_notifier_binding_activated()
        self._api._legacy_interface.binding_deactivate.assert_called_once_with(
            mock.ANY, host='host1', port_id=self._port_id)
        self._api._legacy_interface.binding_activate.assert_called_once_with(
            mock.ANY, host='host2', port_id=self._port_id)

    def test__legacy_notifier_no_new_binding_activated(self):
        updated_port = ports.Port(
            id=self._port_id, name='updated_port',
            bindings=[ports.PortBinding(port_id=self._port_id,
                                        host='host2',
                                        status=constants.ACTIVE)])
        self._api._legacy_notifier(resources.PORT, events.AFTER_UPDATE, self,
                                   mock.ANY,
                                   changed_fields=set(['name', 'bindings']),
                                   resource_id=self._port_id,
                                   existing=self._port, updated=updated_port)
        self._api._legacy_interface.port_update.assert_called_once_with(
            mock.ANY, port={'id': self._port_id}, port_id=self._port_id)
        self._api._legacy_interface.port_delete.assert_not_called()
        self._api._legacy_interface.binding_deactivate.assert_not_called()

    def test__legacy_notifier_existing_or_updated_is_none(self):
        self._api._legacy_notifier(resources.PORT, events.AFTER_UPDATE,
                                   self, mock.ANY,
                                   changed_fields=set(['name', 'bindings']),
                                   resource_id=self._port_id,
                                   existing=None, updated=None)
        self._api._legacy_notifier(resources.PORT, events.AFTER_UPDATE, self,
                                   mock.ANY,
                                   changed_fields=set(['name', 'bindings']),
                                   resource_id=self._port_id,
                                   existing=self._port, updated=None)
        call = mock.call(mock.ANY, port={'id': self._port_id},
                         port_id=self._port_id)
        self._api._legacy_interface.port_update.assert_has_calls([call, call])
        self._api._legacy_interface.port_delete.assert_not_called()
        self._api._legacy_interface.binding_deactivate.assert_not_called()

    def test__legacy_notifier_binding_activated_not_supported(self):
        del self._api._legacy_interface.binding_deactivate
        self._test__legacy_notifier_binding_activated()

    def test_get_device_details_binding_in_host(self):
        self._api.remote_resource_cache.get_resource_by_id.side_effect = [
            self._port, self._network]
        entry = self._api.get_device_details(mock.ANY, self._port_id, mock.ANY,
                                             'host1')
        self.assertEqual(self._port_id, entry['device'])
        self.assertEqual(self._port_id, entry['port_id'])
        self.assertEqual(self._network_id, entry['network_id'])
        self.assertNotIn(n_const.NO_ACTIVE_BINDING, entry)

    def test_get_device_details_binding_not_in_host(self):
        self._api.remote_resource_cache.get_resource_by_id.side_effect = [
            self._port, self._network]
        entry = self._api.get_device_details(mock.ANY, self._port_id, mock.ANY,
                                             'host2')
        self.assertEqual(self._port_id, entry['device'])
        self.assertNotIn('port_id', entry)
        self.assertNotIn('network_id', entry)
        self.assertIn(n_const.NO_ACTIVE_BINDING, entry)
