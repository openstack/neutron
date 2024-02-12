# Copyright (c) 2012 OpenStack Foundation.
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

import operator
from unittest import mock

from neutron_lib.api.definitions import portbindings
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib import exceptions
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from oslo_db import exception as db_exc
from oslo_messaging.rpc import dispatcher as rpc_dispatcher
from oslo_utils import uuidutils

from neutron.api.rpc.handlers import dhcp_rpc
from neutron.common import utils
from neutron.db import provisioning_blocks
from neutron.objects import network as network_obj
from neutron.tests import base


class TestDhcpRpcCallback(base.BaseTestCase):

    def setUp(self):
        super(TestDhcpRpcCallback, self).setUp()
        self.plugin = mock.MagicMock()
        directory.add_plugin(plugin_constants.CORE, self.plugin)
        self.callbacks = dhcp_rpc.DhcpRpcCallback()
        self.log_p = mock.patch('neutron.api.rpc.handlers.dhcp_rpc.LOG')
        self.log = self.log_p.start()
        set_dirty_p = mock.patch('neutron.quota.resource_registry.'
                                 'set_resources_dirty')
        self.mock_set_dirty = set_dirty_p.start()
        self.utils_p = mock.patch('neutron_lib.plugins.utils.create_port')
        self.utils = self.utils_p.start()
        self.agent_hosting_network_p = mock.patch.object(self.callbacks,
            '_is_dhcp_agent_hosting_network')
        self.mock_agent_hosting_network = self.agent_hosting_network_p.start()
        self.mock_agent_hosting_network.return_value = True
        self.segment_plugin = mock.MagicMock()
        directory.add_plugin('segments', self.segment_plugin)

    def test_group_by_network_id(self):
        port1 = {'network_id': 'a'}
        port2 = {'network_id': 'b'}
        port3 = {'network_id': 'a'}
        grouped_ports = self.callbacks._group_by_network_id(
                                                        [port1, port2, port3])
        expected = {'a': [port1, port3], 'b': [port2]}
        self.assertEqual(expected, grouped_ports)

    def test_get_active_networks_info(self):
        networks = [mock.Mock(id='net1'), mock.Mock(id='net2'),
                    mock.Mock(id='net3')]
        ports = [{'id': 'port1', 'network_id': 'net1'},
                 {'id': 'port2', 'network_id': 'net2'},
                 {'id': 'port3', 'network_id': 'net3'}]
        self.plugin.get_ports.return_value = ports
        iter_kwargs = iter([{'enable_dhcp_filter': True, 'host': 'test-host'},
                            {'enable_dhcp_filter': False, 'host': 'test-host'},
                            {'host': 'test-host'}])
        with mock.patch.object(self.callbacks, '_get_active_networks') as \
                mock_get_networks, \
                mock.patch.object(self.callbacks, 'get_network_info') as \
                mock_get_network_info:
            mock_get_networks.return_value = networks
            mock_get_network_info.side_effect = networks
            kwargs = next(iter_kwargs)
            ret = self.callbacks.get_active_networks_info('ctx', **kwargs)
            self.assertEqual(networks, ret)
            enable_dhcp = (True if kwargs.get('enable_dhcp_filter', True) else
                           None)
            mock_get_network_info.assert_has_calls([
                mock.call('ctx', network=networks[0], enable_dhcp=enable_dhcp,
                          host='test-host', ports=[ports[0]]),
                mock.call('ctx', network=networks[1], enable_dhcp=enable_dhcp,
                          host='test-host', ports=[ports[1]]),
                mock.call('ctx', network=networks[2], enable_dhcp=enable_dhcp,
                          host='test-host', ports=[ports[2]])
            ])

    def _test__port_action_with_failures(self, exc=None, action=None):
        port = {
            'network_id': 'foo_network_id',
            'device_owner': constants.DEVICE_OWNER_DHCP,
            'fixed_ips': [{'subnet_id': 'foo_subnet_id'}]
        }
        self.plugin.create_port.side_effect = exc
        self.utils.side_effect = exc
        self.assertIsNone(self.callbacks._port_action(self.plugin,
                                                      mock.Mock(),
                                                      {'port': port},
                                                      action))

    def _test__port_action_good_action(self, action, port, expected_call):
        self.callbacks._port_action(self.plugin, mock.Mock(),
                                    port, action)
        if action == 'create_port':
            self.utils.assert_called_once_with(mock.ANY, mock.ANY, mock.ANY)
        else:
            self.plugin.assert_has_calls([expected_call])

    def test_port_action_create_port(self):
        self._test__port_action_good_action(
            'create_port', mock.Mock(),
            mock.call.create_port(mock.ANY, mock.ANY))

    def test_port_action_update_port(self):
        fake_port = {'id': 'foo_port_id', 'port': mock.Mock()}
        self._test__port_action_good_action(
            'update_port', fake_port,
            mock.call.update_port(mock.ANY, 'foo_port_id', mock.ANY))

    def test__port_action_bad_action(self):
        self.assertRaises(
            exceptions.Invalid,
            self._test__port_action_with_failures,
            exc=None,
            action='foo_action')

    def test_create_port_catch_network_not_found(self):
        self._test__port_action_with_failures(
            exc=exceptions.NetworkNotFound(net_id='foo_network_id'),
            action='create_port')

    def test_create_port_catch_subnet_not_found(self):
        self._test__port_action_with_failures(
            exc=exceptions.SubnetNotFound(subnet_id='foo_subnet_id'),
            action='create_port')

    def test_create_port_catch_db_reference_error(self):
        self._test__port_action_with_failures(
            exc=db_exc.DBReferenceError('a', 'b', 'c', 'd'),
            action='create_port')

    def test_create_port_catch_ip_generation_failure_reraise(self):
        self.assertRaises(
            exceptions.IpAddressGenerationFailure,
            self._test__port_action_with_failures,
            exc=exceptions.IpAddressGenerationFailure(net_id='foo_network_id'),
            action='create_port')

    def test_create_port_catch_and_handle_ip_generation_failure(self):
        self.plugin.get_subnet.side_effect = (
            exceptions.SubnetNotFound(subnet_id='foo_subnet_id'))
        self._test__port_action_with_failures(
            exc=exceptions.IpAddressGenerationFailure(net_id='foo_network_id'),
            action='create_port')
        self._test__port_action_with_failures(
            exc=exceptions.InvalidInput(error_message='sorry'),
            action='create_port')

    def test_update_port_missing_port_on_get(self):
        self.plugin.get_port.side_effect = exceptions.PortNotFound(
            port_id='66')
        self.assertIsNone(self.callbacks.update_dhcp_port(
            context='ctx', host='host', port_id='66',
            port={'port': {'network_id': 'a'}}))

    def test_update_port_missing_port_on_update(self):
        self.plugin.get_port.return_value = {
            'device_id': constants.DEVICE_ID_RESERVED_DHCP_PORT}
        self.plugin.update_port.side_effect = exceptions.PortNotFound(
            port_id='66')
        self.assertIsNone(self.callbacks.update_dhcp_port(
            context='ctx', host='host', port_id='66',
            port={'port': {'network_id': 'a'}}))

    @mock.patch.object(network_obj.Network, 'get_object', return_value=None)
    def test_get_network_info_return_none_on_not_found(self, *args):
        retval = self.callbacks.get_network_info(mock.Mock(), network_id='a')
        self.assertIsNone(retval)

    @mock.patch.object(network_obj.Network, 'get_object')
    def _test_get_network_info(self, mock_net_get_object,
                               segmented_network=False, routed_network=False,
                               network_info=False, enable_dhcp=True):
        def _network_to_dict(network, ports, enable_dhcp):
            segment_ids = ['1']
            if enable_dhcp is None:
                subnets = [_make_subnet_dict(sn) for sn in
                           network.db_obj.subnets]
            else:
                subnets = [_make_subnet_dict(sn) for sn in
                           network.db_obj.subnets if
                           sn.enable_dhcp == enable_dhcp]
            if routed_network:
                non_local_subnets = [subnet for subnet in subnets
                                     if subnet.get('segment_id') not in
                                     segment_ids]
                subnets = [subnet for subnet in subnets
                           if subnet.get('segment_id') in segment_ids]
            else:
                non_local_subnets = []
            ret = {'id': network.id,
                   'project_id': network.project_id,
                   'tenant_id': network.project_id,
                   'admin_state_up': network.admin_state_up,
                   'ports': ports,
                   'subnets': sorted(subnets, key=operator.itemgetter('id')),
                   'non_local_subnets': sorted(non_local_subnets,
                                               key=operator.itemgetter('id')),
                   'mtu': network.mtu}
            # Plugin segment is activated globally, the tests is asserting the
            # return.
            ret['segments'] = [{'id': segment.id,
                                'network_id': segment.network_id,
                                'name': segment.name,
                                'network_type': segment.network_type,
                                'physical_network': segment.physical_network,
                                'segmentation_id': segment.segmentation_id,
                                'is_dynamic': segment.is_dynamic,
                                'segment_index': segment.segment_index,
                                'hosts': segment.hosts
                                } for segment in network.segments]
            return ret

        def _make_subnet_dict(subnet):
            ret = {'id': subnet.id}
            if isinstance(subnet.segment_id, str):
                ret['segment_id'] = subnet.segment_id
            return ret

        if not routed_network:
            subnets = [mock.Mock(id='a', enable_dhcp=True),
                       mock.Mock(id='c', enable_dhcp=True),
                       mock.Mock(id='b', enable_dhcp=False)]
        else:
            subnets = [mock.Mock(id='a', segment_id='1', enable_dhcp=True),
                       mock.Mock(id='c', segment_id='2', enable_dhcp=True),
                       mock.Mock(id='b', segment_id='1', enable_dhcp=False)]
        db_obj = mock.Mock(subnets=subnets)
        project_id = uuidutils.generate_uuid()
        network = mock.Mock(id='a', admin_state_up=True, db_obj=db_obj,
                            project_id=project_id, mtu=1234)
        ports = mock.Mock()
        if not network_info:
            mock_net_get_object.return_value = network
            self.plugin.get_ports.return_value = ports
        self.plugin._make_subnet_dict = _make_subnet_dict

        if segmented_network:
            network.segments = [mock.Mock(id='1', hosts=['host1']),
                                mock.Mock(id='2', hosts=['host2'])]
        else:
            network.segments = []

        _kwargs = {'network_id': 'a', 'host': 'host1'}
        if network_info:
            _kwargs.update({'network': network,
                            'enable_dhcp': enable_dhcp,
                            'ports': ports})
        retval = self.callbacks.get_network_info(mock.Mock(), **_kwargs)
        reference = _network_to_dict(network, ports, enable_dhcp)
        self.assertEqual(reference, retval)

    def test_get_network_info(self):
        self._test_get_network_info()

    def test_get_network_info_with_routed_network(self):
        self._test_get_network_info(segmented_network=True,
                                    routed_network=True)

    def test_get_network_info_with_segmented_network_but_not_routed(self):
        self._test_get_network_info(segmented_network=True)

    def test_get_network_info_with_non_segmented_network(self):
        self._test_get_network_info()

    def test_get_network_info_with_network_info_provided(self):
        self._test_get_network_info(network_info=True)
        self._test_get_network_info(network_info=True, enable_dhcp=True)
        self._test_get_network_info(network_info=True, enable_dhcp=False)
        self._test_get_network_info(network_info=True, enable_dhcp=None)

    def test_update_dhcp_port_verify_port_action_port_dict(self):
        port = {'port': {'network_id': 'foo_network_id',
                         'device_owner': constants.DEVICE_OWNER_DHCP,
                         'fixed_ips': [{'subnet_id': 'foo_subnet_id'}]}
                }
        expected_port = {'port': {'network_id': 'foo_network_id',
                                  'device_owner': constants.DEVICE_OWNER_DHCP,
                                  portbindings.HOST_ID: 'foo_host',
                                  'fixed_ips': [{'subnet_id': 'foo_subnet_id'}]
                                  },
                         'id': 'foo_port_id'
                         }

        def _fake_port_action(plugin, context, port, action):
            self.assertEqual(expected_port, port)

        self.plugin.get_port.return_value = {
            'device_id': constants.DEVICE_ID_RESERVED_DHCP_PORT}
        self.callbacks._port_action = _fake_port_action
        self.callbacks.update_dhcp_port(mock.Mock(),
                                        host='foo_host',
                                        port_id='foo_port_id',
                                        port=port)

    def test_update_reserved_dhcp_port(self):
        port = {'port': {'network_id': 'foo_network_id',
                         'device_owner': constants.DEVICE_OWNER_DHCP,
                         'fixed_ips': [{'subnet_id': 'foo_subnet_id'}]}
                }
        expected_port = {'port': {'network_id': 'foo_network_id',
                                  'device_owner': constants.DEVICE_OWNER_DHCP,
                                  portbindings.HOST_ID: 'foo_host',
                                  'fixed_ips': [{'subnet_id': 'foo_subnet_id'}]
                                  },
                         'id': 'foo_port_id'
                         }

        def _fake_port_action(plugin, context, port, action):
            self.assertEqual(expected_port, port)

        self.plugin.get_port.return_value = {
            'device_id': utils.get_dhcp_agent_device_id('foo_network_id',
                                                        'foo_host')}
        self.callbacks._port_action = _fake_port_action
        self.callbacks.update_dhcp_port(
            mock.Mock(), host='foo_host', port_id='foo_port_id', port=port)

        self.plugin.get_port.return_value = {
            'device_id': 'other_id'}
        res = self.callbacks.update_dhcp_port(mock.Mock(), host='foo_host',
                                        port_id='foo_port_id', port=port)
        self.assertIsNone(res)

    def test_update_dhcp_port(self):
        port = {'port': {'network_id': 'foo_network_id',
                         'device_owner': constants.DEVICE_OWNER_DHCP,
                         'fixed_ips': [{'subnet_id': 'foo_subnet_id'}]}
                }
        expected_port = {'port': {'network_id': 'foo_network_id',
                                  'device_owner': constants.DEVICE_OWNER_DHCP,
                                  portbindings.HOST_ID: 'foo_host',
                                  'fixed_ips': [{'subnet_id': 'foo_subnet_id'}]
                                  },
                         'id': 'foo_port_id'
                         }
        self.plugin.get_port.return_value = {
            'device_id': constants.DEVICE_ID_RESERVED_DHCP_PORT}
        self.callbacks.update_dhcp_port(mock.Mock(),
                                        host='foo_host',
                                        port_id='foo_port_id',
                                        port=port)
        self.plugin.assert_has_calls([
            mock.call.update_port(mock.ANY, 'foo_port_id', expected_port)])

    def test_update_dhcp_port_with_agent_not_hosting_network(self):
        port = {'port': {'network_id': 'foo_network_id',
                         'device_owner': constants.DEVICE_OWNER_DHCP,
                         'fixed_ips': [{'subnet_id': 'foo_subnet_id'}]}
                }
        self.plugin.get_port.return_value = {
            'device_id': constants.DEVICE_ID_RESERVED_DHCP_PORT}
        self.mock_agent_hosting_network.return_value = False
        self.assertRaises(rpc_dispatcher.ExpectedException,
                          self.callbacks.update_dhcp_port,
                          mock.Mock(),
                          host='foo_host',
                          port_id='foo_port_id',
                          port=port)

    def test__is_dhcp_agent_hosting_network(self):
        self.agent_hosting_network_p.stop()
        agent = mock.Mock()
        with mock.patch.object(self.plugin, 'get_dhcp_agents_hosting_networks',
                               return_value=[agent]):
            ret = self.callbacks._is_dhcp_agent_hosting_network(self.plugin,
                mock.Mock(), host='foo_host', network_id='foo_network_id')
        self.assertTrue(ret)

    def test__is_dhcp_agent_hosting_network_false(self):
        self.agent_hosting_network_p.stop()
        with mock.patch.object(self.plugin, 'get_dhcp_agents_hosting_networks',
                               return_value=[]):
            ret = self.callbacks._is_dhcp_agent_hosting_network(self.plugin,
                mock.Mock(), host='foo_host', network_id='foo_network_id')
        self.assertFalse(ret)

    def test_release_dhcp_port(self):
        port_retval = dict(id='port_id', fixed_ips=[dict(subnet_id='a')])
        self.plugin.get_ports.return_value = [port_retval]

        self.callbacks.release_dhcp_port(mock.ANY, network_id='netid',
                                         device_id='devid')

        self.plugin.assert_has_calls([
            mock.call.delete_ports_by_device_id(mock.ANY, 'devid', 'netid')])

    def test_dhcp_ready_on_ports(self):
        context = mock.Mock()
        port_ids = range(10)
        with mock.patch.object(provisioning_blocks,
                               'provisioning_complete') as pc:
            self.callbacks.dhcp_ready_on_ports(context, port_ids)
        calls = [mock.call(context, port_id, resources.PORT,
                           provisioning_blocks.DHCP_ENTITY)
                 for port_id in port_ids]
        pc.assert_has_calls(calls)
