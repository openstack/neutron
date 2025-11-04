# Copyright 2022 Canonical
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

from unittest import mock

from neutron_lib.api.definitions import l3
from neutron_lib import constants as const
from neutron_lib import context as ncontext
from neutron_lib.services.logapi import constants as log_const
from neutron_lib.services.trunk import constants as trunk_const
from oslo_config import cfg

from neutron.common.ovn import constants
from neutron.conf.plugins.ml2 import config as ml2_conf
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from neutron.plugins.ml2 import db as ml2_db
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import ovn_client
from neutron.tests import base
from neutron.tests.unit import fake_resources as fakes
from neutron.tests.unit.services.logapi.drivers.ovn \
    import test_driver as test_log_driver

from tenacity import wait_none


class Test_has_separate_snat_per_subnet(base.BaseTestCase):

    def setUp(self):
        super().setUp()
        ovn_conf.register_opts()

    def test_snat_on_nested_off(self):
        fake_router = {
            'id': 'fake-id',
            'enable_snat': True,
            l3.EXTERNAL_GW_INFO: mock.Mock(),  # irrelevant value
        }
        # ovn_router_indirect_snat default is False
        self.assertTrue(ovn_client._has_separate_snat_per_subnet(fake_router))

    def test_snat_off_nested_off(self):
        fake_router = {
            'id': 'fake-id',
            'enable_snat': False,
            l3.EXTERNAL_GW_INFO: mock.Mock(),  # irrelevant value
        }
        # ovn_router_indirect_snat default is False
        self.assertFalse(ovn_client._has_separate_snat_per_subnet(fake_router))

    def test_snat_on_nested_on(self):
        fake_router = {
            'id': 'fake-id',
            'enable_snat': True,
            l3.EXTERNAL_GW_INFO: mock.Mock(),  # irrelevant value
        }
        cfg.CONF.set_override('ovn_router_indirect_snat', True, 'ovn')
        self.assertFalse(ovn_client._has_separate_snat_per_subnet(fake_router))

    def test_snat_off_nested_on(self):
        fake_router = {
            'id': 'fake-id',
            'enable_snat': False,
            l3.EXTERNAL_GW_INFO: mock.Mock(),  # irrelevant value
        }
        cfg.CONF.set_override('ovn_router_indirect_snat', True, 'ovn')
        self.assertFalse(ovn_client._has_separate_snat_per_subnet(fake_router))


class TestOVNClientBase(base.BaseTestCase):

    def setUp(self):
        ml2_conf.register_ml2_plugin_opts()
        ovn_conf.register_opts()
        super().setUp()
        self.nb_idl = mock.MagicMock()
        self.sb_idl = mock.MagicMock()
        self.ovn_client = ovn_client.OVNClient(self.nb_idl, self.sb_idl)


class TestOVNClient(TestOVNClientBase):

    def setUp(self):
        super().setUp()
        self.get_plugin = mock.patch(
            'neutron_lib.plugins.directory.get_plugin').start()

        # Disable tenacity wait for UT
        self.ovn_client._wait_for_port_bindings_host.retry.wait = wait_none()

    def test__add_router_ext_gw_default_route(self):
        plugin = mock.MagicMock()
        self.get_plugin.return_value = plugin
        subnet = {
            'id': 'fake-subnet-id',
            'gateway_ip': '10.42.0.1',
            'ip_version': const.IP_VERSION_4,
        }
        plugin.get_subnet.return_value = subnet
        plugin.get_subnets_by_network.return_value = [subnet]
        router = {
            'id': 'fake-router-id',
            'gw_port_id': 'fake-port-id',
            'enable_snat': True,
        }
        txn = mock.MagicMock()
        self.ovn_client._get_router_gw_ports = mock.MagicMock()
        gw_port = fakes.FakePort().create_one_port(
            attrs={
                'id': router['gw_port_id'],
                'fixed_ips': [{
                    'subnet_id': subnet.get('id'),
                    'ip_address': '10.42.0.42'}]
            })
        self.ovn_client._get_router_gw_ports.return_value = [gw_port]
        self.assertEqual(
            [self.get_plugin().get_port()],
            self.ovn_client._add_router_ext_gw(mock.Mock(), router, txn))
        self.nb_idl.add_static_route.assert_called_once_with(
            'neutron-' + router['id'],
            ip_prefix=const.IPv4_ANY,
            nexthop='10.42.0.1',
            maintain_bfd=False,
            external_ids={
                'neutron:is_ext_gw': 'true',
                'neutron:subnet_id': subnet['id'],
                constants.OVN_LRSR_EXT_ID_KEY: 'true'})

    def test__add_router_ext_gw_default_route_ecmp(self):
        plugin = mock.MagicMock()
        self.get_plugin.return_value = plugin
        subnet1 = {
            'id': 'fake-subnet-id-1',
            'gateway_ip': '10.42.0.1',
            'ip_version': const.IP_VERSION_4,
        }
        subnet2 = {
            'id': 'fake-subnet-id-2',
            'gateway_ip': '10.42.42.1',
            'ip_version': const.IP_VERSION_4,
        }
        plugin.get_subnet.side_effect = [subnet1, subnet2, subnet1, subnet2]
        plugin.get_subnets_by_network.return_value = [subnet1, subnet2]
        router = {
            'id': 'fake-router-id',
            'gw_port_id': 'fake-port-id',
            'enable_default_route_ecmp': True,
            'enable_snat': True,
        }
        txn = mock.MagicMock()
        self.ovn_client._get_router_gw_ports = mock.MagicMock()
        gw_port1 = fakes.FakePort().create_one_port(
            attrs={
                'id': router['gw_port_id'],
                'fixed_ips': [{
                    'subnet_id': subnet1.get('id'),
                    'ip_address': '10.42.0.42'}]
            })
        gw_port2 = fakes.FakePort().create_one_port(
            attrs={
                'id': 'gw-port-id-2',
                'fixed_ips': [{
                    'subnet_id': subnet2.get('id'),
                    'ip_address': '10.42.42.42'}]
            })
        self.ovn_client._get_router_gw_ports.return_value = [
            gw_port1, gw_port2]
        self.assertEqual(
            [self.get_plugin().get_port(), self.get_plugin().get_port()],
            self.ovn_client._add_router_ext_gw(mock.Mock(), router, txn))
        self.nb_idl.add_static_route.assert_has_calls([
            mock.call('neutron-' + router['id'],
                      ip_prefix=const.IPv4_ANY,
                      nexthop=subnet1['gateway_ip'],
                      maintain_bfd=False,
                      external_ids={
                         'neutron:is_ext_gw': 'true',
                         'neutron:subnet_id': subnet1['id'],
                         constants.OVN_LRSR_EXT_ID_KEY: 'true'},
                      ),
            mock.call('neutron-' + router['id'],
                      ip_prefix=const.IPv4_ANY,
                      nexthop=subnet2['gateway_ip'],
                      maintain_bfd=False,
                      external_ids={
                         'neutron:is_ext_gw': 'true',
                         'neutron:subnet_id': subnet2['id'],
                         constants.OVN_LRSR_EXT_ID_KEY: 'true'},
                      ),
        ])

    def test__add_router_ext_gw_no_default_route(self):
        plugin = mock.MagicMock()
        self.get_plugin.return_value = plugin
        subnet = {
            'id': 'fake-subnet-id',
            'gateway_ip': None,
            'ip_version': const.IP_VERSION_4
        }
        plugin.get_subnet.return_value = subnet
        plugin.get_subnets_by_network.return_value = [subnet]
        router = {
            'id': 'fake-router-id',
            l3.EXTERNAL_GW_INFO: {
                'external_fixed_ips': [{
                        'subnet_id': subnet.get('id'),
                        'ip_address': '10.42.0.42'}],
            },
            'gw_port_id': 'fake-port-id',
            'enable_snat': True,
        }
        txn = mock.MagicMock()
        self.ovn_client._get_router_gw_ports = mock.MagicMock()
        gw_port = fakes.FakePort().create_one_port(
            attrs={
                'id': router['gw_port_id'],
                'fixed_ips': [{
                    'subnet_id': subnet.get('id'),
                    'ip_address': '10.42.0.42'}]
            })
        self.ovn_client._get_router_gw_ports.return_value = [gw_port]
        self.assertEqual(
            [self.get_plugin().get_port()],
            self.ovn_client._add_router_ext_gw(mock.Mock(), router, txn))
        self.nb_idl.add_static_route.assert_not_called()

    def test_checkout_ip_list(self):
        addresses = ["192.168.2.2/32", "2001:db8::/32"]
        add_map = self.ovn_client._checkout_ip_list(addresses)
        self.assertEqual(["192.168.2.2/32"], add_map[const.IP_VERSION_4])
        self.assertEqual(["2001:db8::/32"], add_map[const.IP_VERSION_6])

    def test_update_lsp_host_info_up(self):
        context = mock.MagicMock()
        host_id = 'fake-binding-host-id'
        port_id = 'fake-port-id'
        db_port = mock.Mock(
            id=port_id, port_bindings=[mock.Mock(host=host_id)])

        self.ovn_client.update_lsp_host_info(context, db_port)

        self.nb_idl.db_set.assert_called_once_with(
            'Logical_Switch_Port', port_id,
            ('external_ids', {constants.OVN_HOST_ID_EXT_ID_KEY: host_id}))

    def test_update_lsp_host_info_up_retry(self):
        context = mock.MagicMock()
        host_id = 'fake-binding-host-id'
        port_id = 'fake-port-id'
        db_port_no_host = mock.Mock(
            id=port_id, port_bindings=[mock.Mock(host="")])
        db_port = mock.Mock(
            id=port_id, port_bindings=[mock.Mock(host=host_id)])

        with mock.patch.object(
                self.ovn_client, '_wait_for_port_bindings_host') as mock_wait:
            mock_wait.return_value = db_port
            self.ovn_client.update_lsp_host_info(context, db_port_no_host)

            # Assert _wait_for_port_bindings_host was called
            mock_wait.assert_called_once_with(context, port_id)

        # Assert host_id was set
        self.nb_idl.db_set.assert_called_once_with(
            'Logical_Switch_Port', port_id,
            ('external_ids', {constants.OVN_HOST_ID_EXT_ID_KEY: host_id}))

    def test_update_lsp_host_info_up_retry_fail(self):
        context = mock.MagicMock()
        port_id = 'fake-port-id'
        db_port_no_host = mock.Mock(
            id=port_id, port_bindings=[mock.Mock(host="")])

        with mock.patch.object(
                self.ovn_client, '_wait_for_port_bindings_host') as mock_wait:
            mock_wait.side_effect = RuntimeError("boom")
            self.ovn_client.update_lsp_host_info(context, db_port_no_host)

            # Assert _wait_for_port_bindings_host was called
            mock_wait.assert_called_once_with(context, port_id)

        # Assert host_id was NOT set
        self.assertFalse(self.nb_idl.db_set.called)

    def test_update_lsp_host_info_down(self):
        context = mock.MagicMock()
        port_id = 'fake-port-id'
        db_port = mock.Mock(id=port_id)
        self.nb_idl.lsp_get_up.return_value.execute.return_value = False

        self.ovn_client.update_lsp_host_info(context, db_port, up=False)

        self.nb_idl.db_remove.assert_called_once_with(
            'Logical_Switch_Port', port_id, 'external_ids',
            constants.OVN_HOST_ID_EXT_ID_KEY, if_exists=True)

    def test_update_lsp_host_info_trunk_subport(self):
        context = mock.MagicMock()
        db_port = mock.Mock(id='fake-port-id',
                            device_owner=trunk_const.TRUNK_SUBPORT_OWNER)

        self.ovn_client.update_lsp_host_info(context, db_port)
        self.nb_idl.db_remove.assert_not_called()
        self.nb_idl.db_set.assert_not_called()

    @mock.patch.object(ml2_db, 'get_port')
    def test__wait_for_port_bindings_host(self, mock_get_port):
        context = mock.MagicMock()
        host_id = 'fake-binding-host-id'
        port_id = 'fake-port-id'
        db_port_no_host = mock.Mock(
            id=port_id, port_bindings=[mock.Mock(host="")])
        db_port = mock.Mock(
            id=port_id, port_bindings=[mock.Mock(host=host_id)])

        mock_get_port.side_effect = (db_port_no_host, db_port)

        ret = self.ovn_client._wait_for_port_bindings_host(
            context, port_id)

        self.assertEqual(ret, db_port)

        expected_calls = [mock.call(context, port_id),
                          mock.call(context, port_id)]
        mock_get_port.assert_has_calls(expected_calls)

    @mock.patch.object(ml2_db, 'get_port')
    def test__wait_for_port_bindings_host_fail(self, mock_get_port):
        context = mock.MagicMock()
        port_id = 'fake-port-id'
        db_port_no_pb = mock.Mock(id=port_id, port_bindings=[])
        db_port_no_host = mock.Mock(
            id=port_id, port_bindings=[mock.Mock(host="")])

        mock_get_port.side_effect = (
            db_port_no_pb, db_port_no_host, db_port_no_host)

        self.assertRaises(
            RuntimeError, self.ovn_client._wait_for_port_bindings_host,
            context, port_id)

        expected_calls = [mock.call(context, port_id),
                          mock.call(context, port_id),
                          mock.call(context, port_id)]
        mock_get_port.assert_has_calls(expected_calls)

    def test__get_snat_cidrs_for_external_router_nested_snat_off(self):
        ctx = ncontext.Context()
        per_subnet_cidrs = ['10.0.0.0/24', '20.0.0.0/24']
        with mock.patch.object(
                self.ovn_client, '_get_v4_network_of_all_router_ports',
                return_value=per_subnet_cidrs):
            cidrs = self.ovn_client._get_snat_cidrs_for_external_router(
                ctx, 'fake-id')
        self.assertEqual(per_subnet_cidrs, cidrs)

    def test__get_snat_cidrs_for_external_router_nested_snat_on(self):
        ctx = ncontext.Context()
        cfg.CONF.set_override('ovn_router_indirect_snat', True, 'ovn')
        per_subnet_cidrs = ['10.0.0.0/24', '20.0.0.0/24']
        with mock.patch.object(
                self.ovn_client, '_get_v4_network_of_all_router_ports',
                return_value=per_subnet_cidrs):
            cidrs = self.ovn_client._get_snat_cidrs_for_external_router(
                ctx, 'fake-id')
        self.assertEqual([const.IPv4_ANY], cidrs)


class TestOVNClientFairMeter(TestOVNClientBase,
                             test_log_driver.TestOVNDriverBase):

    def test_create_ovn_fair_meter(self):
        mock_find_rows = mock.Mock()
        mock_find_rows.execute.return_value = None
        self.nb_idl.db_find_rows.return_value = mock_find_rows
        self.ovn_client.create_ovn_fair_meter(self._log_driver.meter_name)
        self.assertFalse(self.nb_idl.meter_del.called)
        self.assertTrue(self.nb_idl.meter_add.called)
        self.nb_idl.meter_add.assert_any_call(
            name=self._log_driver.meter_name + "_stateless",
            unit="pktps",
            rate=int(self.fake_cfg_network_log.rate_limit / 2),
            fair=True,
            burst_size=int(self.fake_cfg_network_log.burst_limit / 2),
            may_exist=False,
            external_ids={constants.OVN_DEVICE_OWNER_EXT_ID_KEY:
                          log_const.LOGGING_PLUGIN})
        self.nb_idl.meter_add.assert_any_call(
            name=self._log_driver.meter_name,
            unit="pktps",
            rate=self.fake_cfg_network_log.rate_limit,
            fair=True,
            burst_size=self.fake_cfg_network_log.burst_limit,
            may_exist=False,
            external_ids={constants.OVN_DEVICE_OWNER_EXT_ID_KEY:
                          log_const.LOGGING_PLUGIN})

    def test_create_ovn_fair_meter_unchanged(self):
        mock_find_rows = mock.Mock()
        fake_meter1 = [self._fake_meter()]
        fake_meter2 = [self._fake_meter(
            name=self._log_driver.meter_name + "_stateless",
            bands=[mock.Mock(uuid='tb_stateless')])]
        mock_find_rows.execute.side_effect = [fake_meter1, fake_meter1,
                                              fake_meter2, fake_meter2]
        self.nb_idl.db_find_rows.return_value = mock_find_rows
        self.nb_idl.lookup.side_effect = lambda table, key, default: (
            self._fake_meter_band() if key == "test_band" else
            self._fake_meter_band_stateless() if key == "tb_stateless" else
            default)
        self.ovn_client.create_ovn_fair_meter(self._log_driver.meter_name)
        self.assertFalse(self.nb_idl.meter_del.called)
        self.assertFalse(self.nb_idl.meter_add.called)

    def test_create_ovn_fair_meter_changed(self):
        mock_find_rows = mock.Mock()
        mock_find_rows.execute.return_value = [self._fake_meter(fair=[False])]
        self.nb_idl.db_find_rows.return_value = mock_find_rows
        self.nb_idl.lookup.return_value = self._fake_meter_band()
        self.ovn_client.create_ovn_fair_meter(self._log_driver.meter_name)
        self.assertTrue(self.nb_idl.meter_del.called)
        self.assertTrue(self.nb_idl.meter_add.called)

    def test_create_ovn_fair_meter_band_changed(self):
        mock_find_rows = mock.Mock()
        mock_find_rows.execute.return_value = [self._fake_meter()]
        self.nb_idl.db_find_rows.return_value = mock_find_rows
        self.nb_idl.lookup.return_value = self._fake_meter_band(rate=666)
        self.ovn_client.create_ovn_fair_meter(self._log_driver.meter_name)
        self.assertTrue(self.nb_idl.meter_del.called)
        self.assertTrue(self.nb_idl.meter_add.called)

    def test_create_ovn_fair_meter_band_missing(self):
        mock_find_rows = mock.Mock()
        mock_find_rows.execute.return_value = [self._fake_meter()]
        self.nb_idl.db_find_rows.return_value = mock_find_rows
        self.nb_idl.lookup.side_effect = None
        self.ovn_client.create_ovn_fair_meter(self._log_driver.meter_name)
        self.assertTrue(self.nb_idl.meter_del.called)
        self.assertTrue(self.nb_idl.meter_add.called)
