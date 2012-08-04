# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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

import unittest

import mock
from sqlalchemy.ext import sqlsoup

from quantum.agent import dhcp_agent
from quantum.agent.common import config
from quantum.agent.linux import interface


class FakeModel:
    def __init__(self, id_, **kwargs):
        self.id = id_
        self.__dict__.update(kwargs)

    def __str__(self):
        return str(self.__dict__)


class TestDhcpAgent(unittest.TestCase):
    def setUp(self):
        self.conf = config.setup_conf()
        self.conf.register_opts(dhcp_agent.DhcpAgent.OPTS)
        self.driver_cls_p = mock.patch(
            'quantum.agent.dhcp_agent.importutils.import_class')
        self.driver = mock.Mock(name='driver')
        self.driver_cls = self.driver_cls_p.start()
        self.driver_cls.return_value = self.driver
        self.dhcp = dhcp_agent.DhcpAgent(self.conf)
        self.dhcp.polling_interval = 0

    def tearDown(self):
        self.driver_cls_p.stop()

    def test_dhcp_agent_main(self):
        with mock.patch('quantum.agent.dhcp_agent.DeviceManager') as dev_mgr:
            with mock.patch('quantum.agent.dhcp_agent.DhcpAgent') as dhcp:
                with mock.patch('quantum.agent.dhcp_agent.sys') as mock_sys:
                    mock_sys.argv = []
                    dhcp_agent.main()
                    dev_mgr.assert_called_once(mock.ANY, 'sudo')
                    dhcp.assert_has_calls([
                        mock.call(mock.ANY),
                        mock.call().daemon_loop()])

    def test_daemon_loop_survives_get_network_state_delta_failure(self):
        def stop_loop(*args):
            self.dhcp._run = False
            return None

        with mock.patch.object(self.dhcp, 'get_network_state_delta') as state:
            state.side_effect = stop_loop
            self.dhcp.daemon_loop()

    def test_daemon_loop_completes_single_pass(self):
        with mock.patch.object(self.dhcp, 'get_network_state_delta') as state:
            with mock.patch.object(self.dhcp, 'call_driver') as call_driver:
                with mock.patch('quantum.agent.dhcp_agent.time') as time:
                    time.sleep = mock.Mock(side_effect=RuntimeError('stop'))
                    state.return_value = dict(new=['new_net'],
                                              updated=['updated_net'],
                                              deleted=['deleted_net'])

                    self.assertRaises(RuntimeError, self.dhcp.daemon_loop)
                    call_driver.assert_has_calls(
                        [mock.call('enable', 'new_net'),
                         mock.call('reload_allocations', 'updated_net'),
                         mock.call('disable', 'deleted_net')])

    def test_state_builder(self):
        fake_subnet = [
            FakeModel(1, network_id=1),
            FakeModel(2, network_id=2),
        ]

        fake_allocation = [
            FakeModel(2, subnet_id=1)
        ]

        db = mock.Mock()
        db.subnets.all = mock.Mock(return_value=fake_subnet)
        db.ipallocations.all = mock.Mock(return_value=fake_allocation)
        self.dhcp.db = db
        state = self.dhcp._state_builder()

        self.assertEquals(state.networks, set([1, 2]))

        expected_subnets = set([
            (hash(str(fake_subnet[0])), 1),
            (hash(str(fake_subnet[1])), 2)
        ])
        self.assertEquals(state.subnet_hashes, expected_subnets)

        expected_ipalloc = set([
            (hash(str(fake_allocation[0])), 1),
        ])
        self.assertEquals(state.ipalloc_hashes, expected_ipalloc)

    def _network_state_helper(self, before, after):
        with mock.patch.object(self.dhcp, '_state_builder') as state_builder:
            state_builder.return_value = after
            self.dhcp.prev_state = before
            return self.dhcp.get_network_state_delta()

    def test_get_network_state_fresh(self):
        new_state = dhcp_agent.State(set([1]), set([(3, 1)]), set([(11, 1)]))

        delta = self._network_state_helper(self.dhcp.prev_state, new_state)
        self.assertEqual(delta,
                         dict(new=set([1]), deleted=set(), updated=set()))

    def test_get_network_state_new_subnet_on_known_network(self):
        prev_state = dhcp_agent.State(set([1]), set([(3, 1)]), set([(11, 1)]))
        new_state = dhcp_agent.State(set([1]),
                                     set([(3, 1), (4, 1)]),
                                     set([(11, 1)]))

        delta = self._network_state_helper(prev_state, new_state)
        self.assertEqual(delta,
                         dict(new=set(), deleted=set(), updated=set([1])))

    def test_get_network_state_new_ipallocation(self):
        prev_state = dhcp_agent.State(set([1]),
                                      set([(3, 1)]),
                                      set([(11, 1)]))
        new_state = dhcp_agent.State(set([1]),
                                     set([(3, 1)]),
                                     set([(11, 1), (12, 1)]))

        delta = self._network_state_helper(prev_state, new_state)
        self.assertEqual(delta,
                         dict(new=set(), deleted=set(), updated=set([1])))

    def test_get_network_state_delete_subnet_on_known_network(self):
        prev_state = dhcp_agent.State(set([1]),
                                      set([(3, 1), (4, 1)]),
                                      set([(11, 1)]))
        new_state = dhcp_agent.State(set([1]),
                                     set([(3, 1)]),
                                     set([(11, 1)]))

        delta = self._network_state_helper(prev_state, new_state)
        self.assertEqual(delta,
                         dict(new=set(), deleted=set(), updated=set([1])))

    def test_get_network_state_deleted_ipallocation(self):
        prev_state = dhcp_agent.State(set([1]),
                                      set([(3, 1)]),
                                      set([(11, 1), (12, 1)]))
        new_state = dhcp_agent.State(set([1]),
                                     set([(3, 1)]),
                                     set([(11, 1)]))

        delta = self._network_state_helper(prev_state, new_state)
        self.assertEqual(delta,
                         dict(new=set(), deleted=set(), updated=set([1])))

    def test_get_network_state_deleted_network(self):
        prev_state = dhcp_agent.State(set([1]),
                                      set([(3, 1)]),
                                      set([(11, 1), (12, 1)]))
        new_state = dhcp_agent.State(set(), set(), set())

        delta = self._network_state_helper(prev_state, new_state)
        self.assertEqual(delta,
                         dict(new=set(), deleted=set([1]), updated=set()))

    def test_get_network_state_changed_subnet_and_deleted_network(self):
        prev_state = dhcp_agent.State(set([1, 2]),
                                      set([(3, 1), (2, 2)]),
                                      set([(11, 1), (12, 1)]))
        new_state = dhcp_agent.State(set([1]),
                                     set([(4, 1)]),
                                     set([(11, 1), (12, 1)]))

        delta = self._network_state_helper(prev_state, new_state)
        self.assertEqual(delta,
                         dict(new=set(), deleted=set([2]), updated=set([1])))

    def test_call_driver(self):
        with mock.patch.object(self.dhcp, 'db') as db:
            db.networks = mock.Mock()
            db.networks.filter_by = mock.Mock(
                return_value=mock.Mock(return_value=FakeModel('1')))
            with mock.patch.object(dhcp_agent, 'DeviceManager') as dev_mgr:
                self.dhcp.call_driver('foo', '1')
                dev_mgr.assert_called()
                self.driver.assert_called_once_with(self.conf,
                                                    mock.ANY,
                                                    'sudo',
                                                    mock.ANY)


class TestDeviceManager(unittest.TestCase):
    def setUp(self):
        self.conf = config.setup_conf()
        self.conf.register_opts(dhcp_agent.DeviceManager.OPTS)
        self.conf.set_override('interface_driver',
                               'quantum.agent.linux.interface.NullDriver')

        self.client_cls_p = mock.patch('quantumclient.v2_0.client.Client')
        client_cls = self.client_cls_p.start()
        self.client_inst = mock.Mock()
        client_cls.return_value = self.client_inst

        self.device_exists_p = mock.patch(
            'quantum.agent.linux.ip_lib.device_exists')
        self.device_exists = self.device_exists_p.start()

        self.dvr_cls_p = mock.patch('quantum.agent.linux.interface.NullDriver')
        driver_cls = self.dvr_cls_p.start()
        self.mock_driver = mock.MagicMock()
        self.mock_driver.DEV_NAME_LEN = (
            interface.LinuxInterfaceDriver.DEV_NAME_LEN)
        driver_cls.return_value = self.mock_driver

    def tearDown(self):
        self.dvr_cls_p.stop()
        self.device_exists_p.stop()
        self.client_cls_p.stop()

    def test_setup(self):
        fake_subnets = [FakeModel('12345678-aaaa-aaaa-1234567890ab'),
                        FakeModel('12345678-bbbb-bbbb-1234567890ab')]

        fake_network = FakeModel('12345678-1234-5678-1234567890ab',
                                 tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa',
                                 subnets=fake_subnets)

        fake_port = FakeModel('12345678-1234-aaaa-1234567890ab',
                              mac_address='aa:bb:cc:dd:ee:ff')

        port_dict = dict(mac_address='aa:bb:cc:dd:ee:ff', allocations=[], id=1)

        self.client_inst.create_port.return_value = dict(port=port_dict)
        self.device_exists.return_value = False

        # fake the db
        filter_by_result = mock.Mock()
        filter_by_result.one = mock.Mock(return_value=fake_port)

        self.filter_called = False

        def get_filter_results(*args, **kwargs):
            if self.filter_called:
                return filter_by_result
            else:
                self.filter_called = True
                raise sqlsoup.SQLAlchemyError()

        mock_db = mock.Mock()
        mock_db.ports = mock.Mock(name='ports2')
        mock_db.ports.filter_by = mock.Mock(
            name='filter_by',
            side_effect=get_filter_results)

        self.mock_driver.get_device_name.return_value = 'tap12345678-12'

        dh = dhcp_agent.DeviceManager(self.conf, mock_db)
        dh.setup(fake_network)

        self.client_inst.assert_has_calls([
            mock.call.create_port(mock.ANY)])

        self.mock_driver.assert_has_calls([
            mock.call.plug('12345678-1234-5678-1234567890ab',
                           '12345678-1234-aaaa-1234567890ab',
                           'tap12345678-12',
                           'aa:bb:cc:dd:ee:ff'),
            mock.call.init_l3(mock.ANY, 'tap12345678-12')]
        )

    def test_destroy(self):
        fake_subnets = [FakeModel('12345678-aaaa-aaaa-1234567890ab'),
                        FakeModel('12345678-bbbb-bbbb-1234567890ab')]

        fake_network = FakeModel('12345678-1234-5678-1234567890ab',
                                 tenant_id='aaaaaaaa-aaaa-aaaa-aaaaaaaaaaaa',
                                 subnets=fake_subnets)

        fake_port = FakeModel('12345678-1234-aaaa-1234567890ab',
                              mac_address='aa:bb:cc:dd:ee:ff')

        port_dict = dict(mac_address='aa:bb:cc:dd:ee:ff', allocations=[], id=1)

        self.client_inst.create_port.return_value = dict(port=port_dict)
        self.device_exists.return_value = False

        # fake the db
        filter_by_result = mock.Mock()
        filter_by_result.one = mock.Mock(return_value=fake_port)

        self.filter_called = False

        def get_filter_results(*args, **kwargs):
            if self.filter_called:
                return filter_by_result
            else:
                self.filter_called = True
                raise sqlsoup.SQLAlchemyError()

        mock_db = mock.Mock()
        mock_db.ports = mock.Mock(name='ports2')
        mock_db.ports.filter_by = mock.Mock(
            name='filter_by',
            side_effect=get_filter_results)

        with mock.patch('quantum.agent.linux.interface.NullDriver') as dvr_cls:
            mock_driver = mock.MagicMock()
            mock_driver.DEV_NAME_LEN = (
                interface.LinuxInterfaceDriver.DEV_NAME_LEN)
            mock_driver.port = fake_port
            mock_driver.get_device_name.return_value = 'tap12345678-12'
            dvr_cls.return_value = mock_driver

            dh = dhcp_agent.DeviceManager(self.conf, mock_db)
            dh.destroy(fake_network)

            dvr_cls.assert_called_once_with(self.conf)
            mock_driver.assert_has_calls(
                [mock.call.get_device_name(mock.ANY),
                 mock.call.unplug('tap12345678-12')])


class TestAugmentingWrapper(unittest.TestCase):
    def test_simple_wrap(self):
        net = mock.Mock()
        db = mock.Mock()
        net.name = 'foo'
        wrapped = dhcp_agent.AugmentingWrapper(net, db)
        self.assertEqual(wrapped.name, 'foo')
        self.assertEqual(repr(net), repr(wrapped))
