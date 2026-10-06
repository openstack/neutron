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
from neutron_lib import exceptions as n_exc
from neutron_lib.services.logapi import constants as log_const
from neutron_lib.services.trunk import constants as trunk_const
from oslo_config import cfg

from neutron.common.ovn import constants
from neutron.common.ovn import utils as ovn_utils
from neutron.conf.plugins.ml2 import config as ml2_conf
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from neutron.db import ovn_revision_numbers_db as db_rev
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
        cfg.CONF.set_override('ovn_router_indirect_snat', False, 'ovn')
        self.assertTrue(ovn_client._has_separate_snat_per_subnet(fake_router))

    def test_snat_off_nested_off(self):
        fake_router = {
            'id': 'fake-id',
            'enable_snat': False,
            l3.EXTERNAL_GW_INFO: mock.Mock(),  # irrelevant value
        }
        cfg.CONF.set_override('ovn_router_indirect_snat', False, 'ovn')
        self.assertFalse(ovn_client._has_separate_snat_per_subnet(fake_router))

    def test_snat_on_nested_on(self):
        fake_router = {
            'id': 'fake-id',
            'enable_snat': True,
            l3.EXTERNAL_GW_INFO: mock.Mock(),  # irrelevant value
        }
        # ovn_router_indirect_snat default is True
        self.assertFalse(ovn_client._has_separate_snat_per_subnet(fake_router))

    def test_snat_off_nested_on(self):
        fake_router = {
            'id': 'fake-id',
            'enable_snat': False,
            l3.EXTERNAL_GW_INFO: mock.Mock(),  # irrelevant value
        }
        # ovn_router_indirect_snat default is True
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
        self.get_pb_bsah = mock.patch(
            'neutron_lib.plugins.utils.'
            'get_port_binding_by_status_and_host').start()

        # Disable tenacity wait for UT
        self.ovn_client._wait_for_active_port_bindings_host.retry.wait = (
            wait_none())

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
        self.ovn_client._create_lrouter_port = mock.MagicMock()
        gw_port = fakes.FakePort().create_one_port(
            attrs={
                'id': router['gw_port_id'],
                'fixed_ips': [{
                    'subnet_id': subnet.get('id'),
                    'ip_address': '10.42.0.42'}]
            })
        self.ovn_client._get_router_gw_ports.return_value = [gw_port]
        result = self.ovn_client._add_router_ext_gw(mock.Mock(), router, txn)
        self.assertEqual([gw_port], result)
        plugin.get_port.assert_not_called()
        self.ovn_client._create_lrouter_port.assert_called_once()
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
        self.ovn_client._create_lrouter_port = mock.MagicMock()
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
        result = self.ovn_client._add_router_ext_gw(mock.Mock(), router, txn)
        self.assertEqual([gw_port1, gw_port2], result)
        plugin.get_port.assert_not_called()
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
        self.ovn_client._create_lrouter_port = mock.MagicMock()
        gw_port = fakes.FakePort().create_one_port(
            attrs={
                'id': router['gw_port_id'],
                'fixed_ips': [{
                    'subnet_id': subnet.get('id'),
                    'ip_address': '10.42.0.42'}]
            })
        self.ovn_client._get_router_gw_ports.return_value = [gw_port]
        result = self.ovn_client._add_router_ext_gw(mock.Mock(), router, txn)
        self.assertEqual([gw_port], result)
        plugin.get_port.assert_not_called()
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
        port_binding = mock.Mock(host=host_id)
        db_port = mock.Mock(id=port_id, port_bindings=[port_binding])
        self.get_pb_bsah.return_value = port_binding
        self.nb_idl.lookup.return_value = mock.Mock(up=[True])

        self.ovn_client.update_lsp_host_info(context, db_port)

        self.nb_idl.db_set.assert_called_once_with(
            'Logical_Switch_Port', port_id,
            ('external_ids', {constants.OVN_HOST_ID_EXT_ID_KEY: host_id}))
        self.nb_idl.lsp_get_up.assert_not_called()

    def test_update_lsp_host_info_up_retry(self):
        context = mock.MagicMock()
        host_id = 'fake-binding-host-id'
        port_id = 'fake-port-id'
        port_binding = mock.Mock(host=host_id)
        port_binding_no_host = mock.Mock(host="")
        db_port_no_host = mock.Mock(
            id=port_id, port_bindings=[port_binding_no_host])
        self.get_pb_bsah.return_value = None
        self.nb_idl.lookup.return_value = mock.Mock(up=[True])

        with mock.patch.object(
                self.ovn_client,
                '_wait_for_active_port_bindings_host') as mock_wait:
            mock_wait.return_value = port_binding
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
        self.get_pb_bsah.return_value = None
        self.nb_idl.lookup.return_value = mock.Mock(up=[True])

        with mock.patch.object(
                self.ovn_client,
                '_wait_for_active_port_bindings_host') as mock_wait:
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
        self.nb_idl.lookup.return_value = mock.Mock(up=[False])

        self.ovn_client.update_lsp_host_info(context, db_port, up=False)

        self.nb_idl.db_remove.assert_called_once_with(
            'Logical_Switch_Port', port_id, 'external_ids',
            constants.OVN_HOST_ID_EXT_ID_KEY, if_exists=True)
        self.nb_idl.lsp_get_up.assert_not_called()

    def test_update_lsp_host_info_trunk_subport(self):
        context = mock.MagicMock()
        db_port = mock.Mock(id='fake-port-id',
                            device_owner=trunk_const.TRUNK_SUBPORT_OWNER)

        self.ovn_client.update_lsp_host_info(context, db_port)
        self.nb_idl.db_remove.assert_not_called()
        self.nb_idl.db_set.assert_not_called()

    def test_update_lsp_host_info_router_port(self):
        context = mock.MagicMock()
        for device_owner in (const.DEVICE_OWNER_ROUTER_INTF,
                             const.DEVICE_OWNER_DVR_INTERFACE,
                             const.DEVICE_OWNER_ROUTER_HA_INTF,
                             const.DEVICE_OWNER_HA_REPLICATED_INT,
                             ):
            self.nb_idl.reset_mock()
            db_port = mock.Mock(id='fake-port-id',
                                device_owner=device_owner)
            self.ovn_client.update_lsp_host_info(context, db_port)
            self.nb_idl.lookup.assert_not_called()
            self.nb_idl.db_remove.assert_not_called()
            self.nb_idl.db_set.assert_not_called()

    @mock.patch.object(ml2_db, 'get_port')
    def test__wait_for_active_port_bindings_host(self, mock_get_port):
        context = mock.MagicMock()
        host_id = 'fake-binding-host-id'
        port_id = 'fake-port-id'
        port_binding = mock.Mock(host=host_id)
        port_binding_no_host = mock.Mock(host="")
        db_port_no_host = mock.Mock(
            id=port_id, port_bindings=[port_binding_no_host])
        db_port = mock.Mock(
            id=port_id, port_bindings=[port_binding])
        # no active binding, no binding with host, binding with host
        self.get_pb_bsah.side_effect = (None, port_binding_no_host,
                                        port_binding)

        mock_get_port.side_effect = (db_port_no_host, db_port_no_host, db_port)

        ret = self.ovn_client._wait_for_active_port_bindings_host(
            context, port_id)

        self.assertEqual(ret, port_binding)

        expected_calls = [mock.call(context, port_id),
                          mock.call(context, port_id)]
        mock_get_port.assert_has_calls(expected_calls)

    @mock.patch.object(ml2_db, 'get_port')
    def test__wait_for_active_port_bindings_host_fail(self, mock_get_port):
        context = mock.MagicMock()
        port_id = 'fake-port-id'
        db_port_no_pb = mock.Mock(id=port_id, port_bindings=[])
        db_port_no_host = mock.Mock(
            id=port_id, port_bindings=[mock.Mock(host="")])
        self.get_pb_bsah.return_value = None

        mock_get_port.side_effect = (
            db_port_no_pb, db_port_no_host, db_port_no_host)

        self.assertRaises(
            RuntimeError, self.ovn_client._wait_for_active_port_bindings_host,
            context, port_id)

        expected_calls = [mock.call(context, port_id),
                          mock.call(context, port_id),
                          mock.call(context, port_id)]
        mock_get_port.assert_has_calls(expected_calls)

    def test__get_snat_cidrs_for_external_router_nested_snat_off(self):
        ctx = ncontext.Context()
        cfg.CONF.set_override('ovn_router_indirect_snat', False, 'ovn')
        per_subnet_cidrs = ['10.0.0.0/24', '20.0.0.0/24']
        with mock.patch.object(
                self.ovn_client, '_get_v4_network_of_all_router_ports',
                return_value=per_subnet_cidrs):
            cidrs = self.ovn_client._get_snat_cidrs_for_external_router(
                ctx, 'fake-id')
        self.assertEqual(per_subnet_cidrs, cidrs)

    def test__get_snat_cidrs_for_external_router_nested_snat_on(self):
        ctx = ncontext.Context()
        # ovn_router_indirect_snat default is True
        per_subnet_cidrs = ['10.0.0.0/24', '20.0.0.0/24']
        with mock.patch.object(
                self.ovn_client, '_get_v4_network_of_all_router_ports',
                return_value=per_subnet_cidrs):
            cidrs = self.ovn_client._get_snat_cidrs_for_external_router(
                ctx, 'fake-id')
        self.assertEqual([const.IPv4_ANY], cidrs)

    def _make_ovn_lrp(self, port_id, network_name, subnet_ids='',
                      networks=None):
        lrp = mock.Mock()
        lrp.name = 'lrp-' + port_id
        lrp.networks = networks or []
        lrp.external_ids = {
            constants.OVN_NETWORK_NAME_EXT_ID_KEY: network_name,
            constants.OVN_ROUTER_IS_EXT_GW: 'True',
            constants.OVN_SUBNET_EXT_IDS_KEY: subnet_ids,
        }
        return lrp

    def test__check_external_ips_changed_no_change(self):
        """No change detected when new ports match OVN state."""
        plugin = mock.MagicMock()
        self.get_plugin.return_value = plugin
        subnet = {'id': 'sub1', 'gateway_ip': '10.0.0.1',
                  'ip_version': const.IP_VERSION_4}
        plugin.get_subnets_by_network.return_value = [subnet]
        gw_port = fakes.FakePort().create_one_port(
            attrs={'id': 'gw-port-1', 'network_id': 'ext-net',
                   'fixed_ips': [{'subnet_id': 'sub1',
                                  'ip_address': '10.0.0.5'}]})
        self.ovn_client._get_router_gw_ports = mock.Mock(
            return_value=[gw_port])

        ovn_snat = mock.Mock(external_ip='10.0.0.5')
        ovn_route = mock.Mock(
            external_ids={constants.OVN_SUBNET_EXT_ID_KEY: 'sub1'},
            bfd=[])
        ovn_lrp = self._make_ovn_lrp('gw-port-1', 'neutron-ext-net',
                                     subnet_ids='sub1')
        router = {'id': 'rtr1'}
        ctx = mock.MagicMock()

        result = self.ovn_client._check_external_ips_changed(
            ctx, [ovn_snat], [ovn_route], router, [ovn_lrp])
        self.assertFalse(result)
        self.nb_idl.get_lrouter_port.assert_not_called()

    def test__check_external_ips_changed_subnet_changed(self):
        """Detected when new port has a subnet not in OVN routes."""
        plugin = mock.MagicMock()
        self.get_plugin.return_value = plugin
        subnet = {'id': 'sub-new', 'gateway_ip': '10.0.0.1',
                  'ip_version': const.IP_VERSION_4}
        plugin.get_subnets_by_network.return_value = [subnet]
        gw_port = fakes.FakePort().create_one_port(
            attrs={'id': 'gw-port-1', 'network_id': 'ext-net',
                   'fixed_ips': [{'subnet_id': 'sub-new',
                                  'ip_address': '10.0.0.5'}]})
        self.ovn_client._get_router_gw_ports = mock.Mock(
            return_value=[gw_port])

        ovn_route = mock.Mock(
            external_ids={constants.OVN_SUBNET_EXT_ID_KEY: 'sub-old'},
            bfd=[])
        ovn_lrp = self._make_ovn_lrp('gw-port-1', 'neutron-ext-net')
        router = {'id': 'rtr1'}
        ctx = mock.MagicMock()

        result = self.ovn_client._check_external_ips_changed(
            ctx, [], [ovn_route], router, [ovn_lrp])
        self.assertTrue(result)

    def test__check_external_ips_changed_snat_ip_changed(self):
        """Detected when SNAT external_ip differs from new router IP."""
        plugin = mock.MagicMock()
        self.get_plugin.return_value = plugin
        subnet = {'id': 'sub1', 'gateway_ip': '10.0.0.1',
                  'ip_version': const.IP_VERSION_4}
        plugin.get_subnets_by_network.return_value = [subnet]
        gw_port = fakes.FakePort().create_one_port(
            attrs={'id': 'gw-port-1', 'network_id': 'ext-net',
                   'fixed_ips': [{'subnet_id': 'sub1',
                                  'ip_address': '10.0.0.99'}]})
        self.ovn_client._get_router_gw_ports = mock.Mock(
            return_value=[gw_port])

        ovn_snat = mock.Mock(external_ip='10.0.0.5')
        ovn_route = mock.Mock(
            external_ids={constants.OVN_SUBNET_EXT_ID_KEY: 'sub1'},
            bfd=[])
        ovn_lrp = self._make_ovn_lrp('gw-port-1', 'neutron-ext-net')
        router = {'id': 'rtr1'}
        ctx = mock.MagicMock()

        result = self.ovn_client._check_external_ips_changed(
            ctx, [ovn_snat], [ovn_route], router, [ovn_lrp])
        self.assertTrue(result)

    def test__check_external_ips_changed_no_subnet_network_changed(self):
        """No-subnet edge case uses passed-in LRP, not OVN re-fetch."""
        plugin = mock.MagicMock()
        self.get_plugin.return_value = plugin
        plugin.get_subnets_by_network.return_value = []
        gw_port = fakes.FakePort().create_one_port(
            attrs={'id': 'gw-port-1', 'network_id': 'new-ext-net',
                   'fixed_ips': []})
        self.ovn_client._get_router_gw_ports = mock.Mock(
            return_value=[gw_port])

        ovn_lrp = self._make_ovn_lrp(
            'gw-port-1', 'neutron-old-ext-net')
        router = {'id': 'rtr1'}
        ctx = mock.MagicMock()

        result = self.ovn_client._check_external_ips_changed(
            ctx, [], [], router, [ovn_lrp])
        self.assertTrue(result)
        self.nb_idl.get_lrouter_port.assert_not_called()

    def test__check_external_ips_changed_no_subnet_network_same(self):
        """No-subnet edge case returns False when network matches."""
        plugin = mock.MagicMock()
        self.get_plugin.return_value = plugin
        plugin.get_subnets_by_network.return_value = []
        gw_port = fakes.FakePort().create_one_port(
            attrs={'id': 'gw-port-1', 'network_id': 'ext-net',
                   'fixed_ips': []})
        self.ovn_client._get_router_gw_ports = mock.Mock(
            return_value=[gw_port])

        ovn_lrp = self._make_ovn_lrp('gw-port-1', 'neutron-ext-net')
        router = {'id': 'rtr1'}
        ctx = mock.MagicMock()

        result = self.ovn_client._check_external_ips_changed(
            ctx, [], [], router, [ovn_lrp])
        self.assertFalse(result)
        self.nb_idl.get_lrouter_port.assert_not_called()

    def test__check_external_ips_changed_bfd_mismatch(self):
        """BFD state change detected."""
        plugin = mock.MagicMock()
        self.get_plugin.return_value = plugin
        plugin.get_subnets_by_network.return_value = []
        self.ovn_client._get_router_gw_ports = mock.Mock(return_value=[])

        ovn_route = mock.Mock(
            external_ids={}, bfd=[])
        router = {'id': 'rtr1', 'enable_default_route_bfd': True}
        ctx = mock.MagicMock()

        result = self.ovn_client._check_external_ips_changed(
            ctx, [], [ovn_route], router, [])
        self.assertTrue(result)

    def test__get_nets_and_ipv6_ra_confs_ipv4_only(self):
        """Single bulk get_subnets call for all fixed IPs."""
        plugin = mock.MagicMock()
        self.get_plugin.return_value = plugin
        subnets = [
            {'id': 'sub1', 'cidr': '10.0.0.0/24',
             'network_id': 'net1', 'ipv6_address_mode': None},
            {'id': 'sub2', 'cidr': '20.0.0.0/16',
             'network_id': 'net1', 'ipv6_address_mode': None},
        ]
        plugin.get_subnets.return_value = subnets
        port = {
            'fixed_ips': [
                {'subnet_id': 'sub1', 'ip_address': '10.0.0.5'},
                {'subnet_id': 'sub2', 'ip_address': '20.0.1.5'},
            ],
            'device_owner': const.DEVICE_OWNER_ROUTER_INTF,
        }

        ctx = ncontext.Context()
        networks, ipv6_ra_configs = (
            self.ovn_client._get_nets_and_ipv6_ra_confs_for_router_port(
                ctx, port))

        self.assertEqual(sorted(networks), ['10.0.0.5/24', '20.0.1.5/16'])
        self.assertEqual({}, ipv6_ra_configs)
        plugin.get_subnets.assert_called_once_with(
            ctx, filters={'id': ['sub1', 'sub2']})
        plugin.get_network.assert_not_called()
        plugin.get_subnet.assert_not_called()

    def test__get_nets_and_ipv6_ra_confs_with_ipv6_ra(self):
        """IPv6 RA config is populated and network is fetched once."""
        plugin = mock.MagicMock()
        self.get_plugin.return_value = plugin
        subnets = [
            {'id': 'sub1', 'cidr': '10.0.0.0/24',
             'network_id': 'net1', 'ipv6_address_mode': None},
            {'id': 'sub-v6', 'cidr': 'fd00::/64',
             'network_id': 'net1', 'ipv6_address_mode': 'dhcpv6-stateful'},
        ]
        plugin.get_subnets.return_value = subnets
        network = {'id': 'net1', 'mtu': 1500,
                   'router:external': False}
        plugin.get_network.return_value = network
        port = {
            'fixed_ips': [
                {'subnet_id': 'sub1', 'ip_address': '10.0.0.5'},
                {'subnet_id': 'sub-v6', 'ip_address': 'fd00::5'},
            ],
            'device_owner': const.DEVICE_OWNER_ROUTER_INTF,
        }

        ctx = ncontext.Context()
        networks, ipv6_ra_configs = (
            self.ovn_client._get_nets_and_ipv6_ra_confs_for_router_port(
                ctx, port))

        self.assertIn('10.0.0.5/24', networks)
        self.assertIn('fd00::5/64', networks)
        self.assertEqual('true', ipv6_ra_configs['send_periodic'])
        self.assertEqual('1500', ipv6_ra_configs['mtu'])
        self.assertIn('address_mode', ipv6_ra_configs)
        plugin.get_subnets.assert_called_once()
        plugin.get_network.assert_called_once_with(ctx, 'net1')

    def test__get_nets_and_ipv6_ra_confs_gw_port_external_net(self):
        """Gateway port on external network sets send_periodic to false."""
        plugin = mock.MagicMock()
        self.get_plugin.return_value = plugin
        subnets = [
            {'id': 'sub-v6', 'cidr': 'fd00::/64',
             'network_id': 'ext-net', 'ipv6_address_mode': 'slaac'},
        ]
        plugin.get_subnets.return_value = subnets
        network = {'id': 'ext-net', 'mtu': 9000,
                   'router:external': True}
        plugin.get_network.return_value = network
        port = {
            'fixed_ips': [
                {'subnet_id': 'sub-v6', 'ip_address': 'fd00::1'},
            ],
            'device_owner': const.DEVICE_OWNER_ROUTER_GW,
        }

        ctx = ncontext.Context()
        networks, ipv6_ra_configs = (
            self.ovn_client._get_nets_and_ipv6_ra_confs_for_router_port(
                ctx, port))

        self.assertEqual(['fd00::1/64'], networks)
        self.assertEqual('false', ipv6_ra_configs['send_periodic'])
        self.assertEqual('9000', ipv6_ra_configs['mtu'])

    def test__get_nets_and_ipv6_ra_confs_only_first_ipv6_subnet(self):
        """Only the first IPv6 subnet with address_mode populates RA."""
        plugin = mock.MagicMock()
        self.get_plugin.return_value = plugin
        subnets = [
            {'id': 'sub-v6a', 'cidr': 'fd00::/64',
             'network_id': 'net1', 'ipv6_address_mode': 'slaac'},
            {'id': 'sub-v6b', 'cidr': 'fd01::/64',
             'network_id': 'net1', 'ipv6_address_mode': 'dhcpv6-stateful'},
        ]
        plugin.get_subnets.return_value = subnets
        network = {'id': 'net1', 'mtu': 1500,
                   'router:external': False}
        plugin.get_network.return_value = network
        port = {
            'fixed_ips': [
                {'subnet_id': 'sub-v6a', 'ip_address': 'fd00::5'},
                {'subnet_id': 'sub-v6b', 'ip_address': 'fd01::5'},
            ],
            'device_owner': const.DEVICE_OWNER_ROUTER_INTF,
        }

        ctx = ncontext.Context()
        _, ipv6_ra_configs = (
            self.ovn_client._get_nets_and_ipv6_ra_confs_for_router_port(
                ctx, port))

        plugin.get_network.assert_called_once()
        self.assertEqual('true', ipv6_ra_configs['send_periodic'])

    def test__get_nets_and_ipv6_ra_confs_missing_subnet(self):
        """Gracefully skip fixed IPs whose subnet was not found."""
        plugin = mock.MagicMock()
        self.get_plugin.return_value = plugin
        plugin.get_subnets.return_value = [
            {'id': 'sub1', 'cidr': '10.0.0.0/24',
             'network_id': 'net1', 'ipv6_address_mode': None},
        ]
        port = {
            'fixed_ips': [
                {'subnet_id': 'sub1', 'ip_address': '10.0.0.5'},
                {'subnet_id': 'sub-gone', 'ip_address': '10.1.0.5'},
            ],
            'device_owner': const.DEVICE_OWNER_ROUTER_INTF,
        }

        ctx = ncontext.Context()
        networks, ipv6_ra_configs = (
            self.ovn_client._get_nets_and_ipv6_ra_confs_for_router_port(
                ctx, port))

        self.assertEqual(['10.0.0.5/24'], networks)
        self.assertEqual({}, ipv6_ra_configs)

    def test__get_nets_and_ipv6_ra_confs_empty_fixed_ips(self):
        """No fixed IPs returns empty results."""
        plugin = mock.MagicMock()
        self.get_plugin.return_value = plugin
        plugin.get_subnets.return_value = []
        port = {
            'fixed_ips': [],
            'device_owner': const.DEVICE_OWNER_ROUTER_INTF,
        }

        ctx = ncontext.Context()
        networks, ipv6_ra_configs = (
            self.ovn_client._get_nets_and_ipv6_ra_confs_for_router_port(
                ctx, port))

        self.assertEqual([], networks)
        self.assertEqual({}, ipv6_ra_configs)
        plugin.get_subnets.assert_called_once_with(
            ctx, filters={'id': []})
        plugin.get_network.assert_not_called()

    def test__get_nets_and_ipv6_ra_confs_metadata_route_info(self):
        """route_info advertises metadata IPv6 address when enabled."""
        cfg.CONF.set_override('ovn_metadata_enabled', True, group='ovn')
        plugin = mock.MagicMock()
        self.get_plugin.return_value = plugin
        subnets = [
            {'id': 'sub-v6', 'cidr': 'fd00::/64',
             'network_id': 'net1', 'ipv6_address_mode': 'slaac'},
        ]
        plugin.get_subnets.return_value = subnets
        network = {'id': 'net1', 'mtu': 1500,
                   'router:external': False}
        plugin.get_network.return_value = network
        port = {
            'fixed_ips': [
                {'subnet_id': 'sub-v6', 'ip_address': 'fd00::5'},
            ],
            'device_owner': const.DEVICE_OWNER_ROUTER_INTF,
        }

        ctx = ncontext.Context()
        _, ipv6_ra_configs = (
            self.ovn_client._get_nets_and_ipv6_ra_confs_for_router_port(
                ctx, port))

        self.assertIn('route_info', ipv6_ra_configs)
        self.assertEqual('MEDIUM-%s' % const.METADATA_V6_CIDR,
                         ipv6_ra_configs['route_info'])

    def test__get_nets_and_ipv6_ra_confs_no_route_info_metadata_disabled(self):
        """route_info is absent when metadata is disabled."""
        cfg.CONF.set_override('ovn_metadata_enabled', False, group='ovn')
        plugin = mock.MagicMock()
        self.get_plugin.return_value = plugin
        subnets = [
            {'id': 'sub-v6', 'cidr': 'fd00::/64',
             'network_id': 'net1', 'ipv6_address_mode': 'slaac'},
        ]
        plugin.get_subnets.return_value = subnets
        network = {'id': 'net1', 'mtu': 1500,
                   'router:external': False}
        plugin.get_network.return_value = network
        port = {
            'fixed_ips': [
                {'subnet_id': 'sub-v6', 'ip_address': 'fd00::5'},
            ],
            'device_owner': const.DEVICE_OWNER_ROUTER_INTF,
        }

        ctx = ncontext.Context()
        _, ipv6_ra_configs = (
            self.ovn_client._get_nets_and_ipv6_ra_confs_for_router_port(
                ctx, port))

        self.assertNotIn('route_info', ipv6_ra_configs)

    def _make_fake_lsp(self, name, lsp_type='', options=None):
        lsp = mock.Mock()
        lsp.name = name
        lsp.type = lsp_type
        lsp.options = options or {}
        return lsp

    def _setup_delete_port_mocks(self, ovn_port, ls):
        def _lookup(table, name, **kwargs):
            if table == 'Logical_Switch_Port':
                return ovn_port
            if table == 'Logical_Switch':
                return ls
            raise ValueError("Unexpected lookup: %s %s" % (table, name))

        self.nb_idl.lookup.side_effect = _lookup
        self.ovn_client._qos_driver = mock.Mock()

    def test__delete_port_unsets_virtual_children(self):
        """Deleting a non-virtual port unsets it from virtual children."""
        port_id = 'parent-port'
        ovn_network_name = 'neutron-net1'

        ovn_port = self._make_fake_lsp(port_id)
        ovn_port.external_ids = {
            constants.OVN_NETWORK_NAME_EXT_ID_KEY: ovn_network_name}

        virtual_lsp = self._make_fake_lsp(
            'virtual-port', constants.LSP_TYPE_VIRTUAL,
            {constants.LSP_OPTIONS_VIRTUAL_PARENTS_KEY:
             'parent-port,other-port'})
        normal_lsp = self._make_fake_lsp('normal-port')
        ls = mock.Mock()
        ls.ports = [normal_lsp, virtual_lsp]

        self._setup_delete_port_mocks(ovn_port, ls)

        ctx = ncontext.Context()
        self.ovn_client._delete_port(ctx, port_id, None)

        self.nb_idl.unset_lswitch_port_to_virtual_type.assert_called_once_with(
            'virtual-port', port_id, if_exists=True)
        self.nb_idl.ls_get.assert_not_called()

    def test__delete_port_no_virtual_children(self):
        """No virtual ports on the LS means no unset call."""
        port_id = 'normal-port'
        ovn_network_name = 'neutron-net1'

        ovn_port = self._make_fake_lsp(port_id)
        ovn_port.external_ids = {
            constants.OVN_NETWORK_NAME_EXT_ID_KEY: ovn_network_name}

        other_lsp = self._make_fake_lsp('other-port')
        ls = mock.Mock()
        ls.ports = [other_lsp]

        self._setup_delete_port_mocks(ovn_port, ls)

        ctx = ncontext.Context()
        self.ovn_client._delete_port(ctx, port_id, None)

        self.nb_idl.unset_lswitch_port_to_virtual_type.assert_not_called()

    def test__delete_port_virtual_port_skips_parent_check(self):
        """Deleting a virtual port skips the parent check entirely."""
        port_id = 'virtual-port'
        ovn_network_name = 'neutron-net1'

        ovn_port = self._make_fake_lsp(
            port_id, constants.LSP_TYPE_VIRTUAL)
        ovn_port.external_ids = {
            constants.OVN_NETWORK_NAME_EXT_ID_KEY: ovn_network_name}

        self._setup_delete_port_mocks(ovn_port, ls=None)

        ctx = ncontext.Context()
        self.ovn_client._delete_port(ctx, port_id, None)

        calls = [c for c in self.nb_idl.lookup.call_args_list
                 if c[0][0] == 'Logical_Switch']
        self.assertEqual([], calls)
        self.nb_idl.unset_lswitch_port_to_virtual_type.assert_not_called()

    def test__delete_port_virtual_child_different_parent(self):
        """Virtual port referencing a different parent is not affected."""
        port_id = 'my-port'
        ovn_network_name = 'neutron-net1'

        ovn_port = self._make_fake_lsp(port_id)
        ovn_port.external_ids = {
            constants.OVN_NETWORK_NAME_EXT_ID_KEY: ovn_network_name}

        virtual_lsp = self._make_fake_lsp(
            'virtual-port', constants.LSP_TYPE_VIRTUAL,
            {constants.LSP_OPTIONS_VIRTUAL_PARENTS_KEY: 'other-parent'})
        ls = mock.Mock()
        ls.ports = [virtual_lsp]

        self._setup_delete_port_mocks(ovn_port, ls)

        ctx = ncontext.Context()
        self.ovn_client._delete_port(ctx, port_id, None)

        self.nb_idl.unset_lswitch_port_to_virtual_type.assert_not_called()

    @mock.patch('neutron.db.ovn_revision_numbers_db.bump_revision')
    def test_update_virtual_port_parent_host_with_chassis(self,
                                                          mock_bump_rev):
        """Updating a virtual port parent host resolves hostname from SB."""
        plugin = mock.MagicMock()
        self.get_plugin.return_value = plugin
        fake_port = {'id': 'vip-port', 'revision_number': 5}
        plugin.get_port.return_value = fake_port

        mock_db_get = mock.Mock()
        mock_db_get.execute.return_value = 'compute-0'
        self.sb_idl.db_get.return_value = mock_db_get

        check_rev_cmd = mock.Mock()
        check_rev_cmd.result = constants.TXN_COMMITTED
        self.nb_idl.check_revision_number.return_value = check_rev_cmd

        ctx = ncontext.Context()
        self.ovn_client.update_virtual_port_parent_host(
            ctx, 'vip-port', chassis_id='chassis-uuid')

        self.sb_idl.db_get.assert_called_once_with(
            'Chassis', 'chassis-uuid', 'hostname')
        plugin.update_virtual_port_parent_host.assert_called_once_with(
            ctx, 'vip-port', 'compute-0')
        plugin.get_port.assert_called_once_with(ctx, 'vip-port')
        self.nb_idl.db_set.assert_called_once_with(
            'Logical_Switch_Port', 'vip-port',
            ('external_ids',
             {constants.OVN_PARENT_HOSTNAME_EXT_ID_KEY: 'compute-0'}))
        mock_bump_rev.assert_called_once_with(
            ctx, fake_port, constants.TYPE_PORTS)

    @mock.patch('neutron.db.ovn_revision_numbers_db.bump_revision')
    def test_update_virtual_port_parent_host_with_hostname(self,
                                                           mock_bump_rev):
        """Updating a virtual port parent host with explicit hostname."""
        plugin = mock.MagicMock()
        self.get_plugin.return_value = plugin
        fake_port = {'id': 'vip-port', 'revision_number': 5}
        plugin.get_port.return_value = fake_port

        check_rev_cmd = mock.Mock()
        check_rev_cmd.result = constants.TXN_COMMITTED
        self.nb_idl.check_revision_number.return_value = check_rev_cmd

        ctx = ncontext.Context()
        self.ovn_client.update_virtual_port_parent_host(
            ctx, 'vip-port', hostname='compute-1')

        self.sb_idl.db_get.assert_not_called()
        plugin.update_virtual_port_parent_host.assert_called_once_with(
            ctx, 'vip-port', 'compute-1')
        plugin.get_port.assert_called_once_with(ctx, 'vip-port')
        mock_bump_rev.assert_called_once_with(
            ctx, fake_port, constants.TYPE_PORTS)

    @mock.patch('neutron.db.ovn_revision_numbers_db.bump_revision')
    def test_update_virtual_port_parent_host_no_chassis_no_hostname(
            self, mock_bump_rev):
        """Clearing virtual port parent host when no chassis/hostname."""
        plugin = mock.MagicMock()
        self.get_plugin.return_value = plugin
        fake_port = {'id': 'vip-port', 'revision_number': 5}
        plugin.get_port.return_value = fake_port

        check_rev_cmd = mock.Mock()
        check_rev_cmd.result = constants.TXN_COMMITTED
        self.nb_idl.check_revision_number.return_value = check_rev_cmd

        ctx = ncontext.Context()
        self.ovn_client.update_virtual_port_parent_host(ctx, 'vip-port')

        plugin.update_virtual_port_parent_host.assert_called_once_with(
            ctx, 'vip-port', '')
        self.nb_idl.db_set.assert_called_once_with(
            'Logical_Switch_Port', 'vip-port',
            ('external_ids',
             {constants.OVN_PARENT_HOSTNAME_EXT_ID_KEY: ''}))
        mock_bump_rev.assert_called_once_with(
            ctx, fake_port, constants.TYPE_PORTS)

    def test_update_virtual_port_parent_host_port_not_found(self):
        """PortNotFound is handled gracefully when port is already deleted."""
        plugin = mock.MagicMock()
        self.get_plugin.return_value = plugin
        plugin.get_port.side_effect = n_exc.PortNotFound(port_id='vip-port')

        ctx = ncontext.Context()
        self.ovn_client.update_virtual_port_parent_host(
            ctx, 'vip-port', hostname='compute-0')

        plugin.update_virtual_port_parent_host.assert_called_once_with(
            ctx, 'vip-port', 'compute-0')
        plugin.get_port.assert_called_once_with(ctx, 'vip-port')
        self.nb_idl.check_revision_number.assert_not_called()
        self.nb_idl.db_set.assert_not_called()

    # --- Multiple-segments-per-host tests ---

    def _make_segment(self, seg_id, network_type='vlan',
                      physical_network='physnet1', segmentation_id=100):
        return {'id': seg_id,
                'network_type': network_type,
                'physical_network': physical_network,
                'segmentation_id': segmentation_id}

    def _make_network(self, net_id='fake-net-id', name='test-net',
                      mtu=1500, project_id='fake-project'):
        return {'id': net_id,
                'name': name,
                'mtu': mtu,
                'project_id': project_id,
                'revision_number': 1}

    @mock.patch.object(db_rev, 'bump_revision')
    @mock.patch.object(ovn_utils, 'ovs_persist_uuid_supported',
                       return_value=True)
    @mock.patch.object(ovn_utils, 'network_needs_lswitch',
                       return_value=True)
    def test_create_port_without_segment_id(self, mock_needs_ls,
                                            mock_persist, mock_bump):
        """create_port without segment_id uses network logical switch."""
        port = fakes.FakePort.create_one_port(
            attrs={'name': 'test-port'}).info()
        port_info = mock.Mock(
            addresses=['aa:bb:cc:dd:ee:ff 10.0.0.5'],
            parent_name=[], tag=[], options={},
            type='', port_security=[],
            dhcpv4_options={}, dhcpv6_options={})
        with mock.patch.object(
                self.ovn_client, 'get_external_ids_from_port',
                return_value=(port_info, {})), \
            mock.patch.object(
                 self.ovn_client, 'is_dns_required_for_port',
                 return_value=False):
            self.ovn_client.create_port(mock.MagicMock(), port)

        create_call = self.nb_idl.create_lswitch_port.call_args
        self.assertEqual(
            ovn_utils.ovn_name(port['network_id']),
            create_call.kwargs['lswitch_name'])
        # No segment ext_id key
        self.assertNotIn(
            constants.OVN_PORT_SEGMENT_EXT_ID_KEY,
            create_call.kwargs['external_ids'])

    @mock.patch.object(db_rev, 'bump_revision')
    @mock.patch.object(ovn_utils, 'ovs_persist_uuid_supported',
                       return_value=True)
    @mock.patch.object(ovn_utils, 'network_needs_lswitch',
                       return_value=False)
    def test_create_port_with_segment_id(self, mock_needs_ls,
                                         mock_persist, mock_bump):
        """create_port with segment_id uses segment logical switch."""
        port = fakes.FakePort.create_one_port(
            attrs={'name': 'test-port'}).info()
        seg_id = 'fake-seg-id'
        port_info = mock.Mock(
            addresses=['aa:bb:cc:dd:ee:ff 10.0.0.5'],
            parent_name=[], tag=[], options={},
            type='', port_security=[],
            dhcpv4_options={}, dhcpv6_options={})
        with mock.patch.object(
                self.ovn_client, 'get_external_ids_from_port',
                return_value=(port_info, {})), \
            mock.patch.object(
                 self.ovn_client, 'is_dns_required_for_port',
                 return_value=False):
            self.ovn_client.create_port(
                mock.MagicMock(), port, segment_id=seg_id)

        create_call = self.nb_idl.create_lswitch_port.call_args
        self.assertEqual(
            ovn_utils.ovn_name(seg_id),
            create_call.kwargs['lswitch_name'])
        self.assertEqual(
            seg_id,
            create_call.kwargs['external_ids'][
                constants.OVN_PORT_SEGMENT_EXT_ID_KEY])

    @mock.patch.object(db_rev, 'bump_revision')
    @mock.patch.object(ovn_utils, 'ovs_persist_uuid_supported',
                       return_value=True)
    @mock.patch.object(ovn_utils, 'network_needs_lswitch',
                       return_value=False)
    def test_create_port_with_segment_id_skips_qos(self, mock_needs_ls,
                                                   mock_persist,
                                                   mock_bump):
        """create_port with segment_id does not create QoS."""
        port = fakes.FakePort.create_one_port(
            attrs={'name': 'test-port'}).info()
        port_info = mock.Mock(
            addresses=['aa:bb:cc:dd:ee:ff 10.0.0.5'],
            parent_name=[], tag=[], options={},
            type='', port_security=[],
            dhcpv4_options={}, dhcpv6_options={})
        with mock.patch.object(
                self.ovn_client, 'get_external_ids_from_port',
                return_value=(port_info, {})), \
            mock.patch.object(
                 self.ovn_client, 'is_dns_required_for_port',
                 return_value=False), \
            mock.patch.object(
                 self.ovn_client._qos_driver,
                 'create_port') as mock_qos_create:
            self.ovn_client.create_port(
                mock.MagicMock(), port, segment_id='seg-1')

        mock_qos_create.assert_not_called()

    @mock.patch.object(db_rev, 'bump_revision')
    @mock.patch.object(ovn_utils, 'network_needs_lswitch',
                       return_value=False)
    @mock.patch.object(ovn_utils, 'is_vlan_segment', return_value=True)
    def test_create_provnet_port_vlan_segment(self, mock_is_vlan,
                                              mock_needs_ls, mock_bump):
        """create_provnet_port for VLAN segment creates segment lswitch."""
        network = self._make_network()
        segment = self._make_segment('seg-1')
        ctx = mock.MagicMock()

        with mock.patch.object(
                self.ovn_client, 'create_metadata_port'):
            self.ovn_client.create_provnet_port(
                ctx, network['id'], segment, network=network)

        # Should create segment logical switch
        self.nb_idl.ls_add.assert_called_once()
        ls_call = self.nb_idl.ls_add.call_args
        self.assertEqual('seg-1', ls_call.kwargs['network_id'])

        # Localnet port tag should be [] (not VLAN tag) for segment switch
        create_port_call = self.nb_idl.create_lswitch_port.call_args
        self.assertEqual([], create_port_call.kwargs['tag_request'])

    @mock.patch.object(ovn_utils, 'network_needs_lswitch',
                       return_value=True)
    @mock.patch.object(ovn_utils, 'is_vlan_segment', return_value=False)
    def test_create_provnet_port_non_vlan_segment(self, mock_is_vlan,
                                                  mock_needs_ls):
        """create_provnet_port for non-VLAN uses network logical switch."""
        network = self._make_network()
        segment = self._make_segment('seg-1', network_type='geneve',
                                     physical_network='physnet1')
        ctx = mock.MagicMock()

        self.ovn_client.create_provnet_port(
            ctx, network['id'], segment, network=network)

        # Should NOT create segment logical switch
        self.nb_idl.ls_add.assert_not_called()
        # Localnet port should target network logical switch
        create_port_call = self.nb_idl.create_lswitch_port.call_args
        self.assertEqual(
            ovn_utils.ovn_name(network['id']),
            create_port_call.kwargs['lswitch_name'])

    @mock.patch.object(db_rev, 'delete_revision')
    @mock.patch.object(ovn_utils, 'network_needs_lswitch',
                       return_value=False)
    def test_delete_provnet_port_vlan_segment(self, mock_needs_ls,
                                              mock_del_rev):
        """delete_provnet_port for VLAN segment deletes segment lswitch."""
        segment = self._make_segment('seg-1')
        metadata_port = {'id': 'meta-port-id'}
        self.ovn_client._find_metadata_port = mock.Mock(
            return_value=metadata_port)

        self.ovn_client.delete_provnet_port('fake-net-id', segment)

        # Should delete the metadata port
        plugin = self.get_plugin.return_value
        plugin.delete_port.assert_called_once_with(
            mock.ANY, 'meta-port-id')
        # Should delete segment logical switch
        self.nb_idl.ls_del.assert_called_once_with(
            ovn_utils.ovn_name('seg-1'), if_exists=True)
        # Should delete segment revision
        mock_del_rev.assert_called_once_with(
            mock.ANY, 'seg-1', constants.TYPE_SEGMENTS)

    @mock.patch.object(db_rev, 'delete_revision')
    @mock.patch.object(ovn_utils, 'network_needs_lswitch',
                       return_value=False)
    def test_delete_provnet_port_for_net_delete(self, mock_needs_ls,
                                                mock_del_rev):
        """delete_provnet_port with for_net_delete skips metadata port."""
        segment = self._make_segment('seg-1')

        self.ovn_client.delete_provnet_port(
            'fake-net-id', segment, for_net_delete=True)

        # Should NOT delete metadata port
        plugin = self.get_plugin.return_value
        plugin.delete_port.assert_not_called()
        # Should delete segment logical switch
        self.nb_idl.ls_del.assert_called_once_with(
            ovn_utils.ovn_name('seg-1'), if_exists=True)
        # Should delete segment revision
        mock_del_rev.assert_called_once_with(
            mock.ANY, 'seg-1', constants.TYPE_SEGMENTS)

    @mock.patch.object(ovn_utils, 'network_needs_lswitch',
                       return_value=True)
    def test_delete_provnet_port_non_vlan(self, mock_needs_ls):
        """delete_provnet_port for non-VLAN deletes localnet port."""
        segment = self._make_segment('seg-1', network_type='geneve')

        self.ovn_client.delete_provnet_port('fake-net-id', segment)

        # Should delete localnet port from network logical switch
        self.nb_idl.delete_lswitch_port.assert_called_once_with(
            lport_name=ovn_utils.ovn_provnet_port_name('seg-1'),
            lswitch_name=ovn_utils.ovn_name('fake-net-id'))
        # Should NOT delete segment logical switch
        self.nb_idl.ls_del.assert_not_called()

    def test__find_metadata_port_with_segment(self):
        """_find_metadata_port with segment_id uses segment device_id."""
        ctx = mock.MagicMock()
        cfg.CONF.set_override('ovn_metadata_enabled', True, group='ovn')
        plugin = self.get_plugin.return_value
        plugin.get_ports.return_value = [{'id': 'meta-port'}]

        result = self.ovn_client._find_metadata_port(
            ctx, 'fake-net-id', segment_id='seg-1')

        self.assertEqual({'id': 'meta-port'}, result)
        plugin.get_ports.assert_called_once_with(
            ctx, filters={
                'network_id': ['fake-net-id'],
                'device_id': [constants.OVN_METADATA_PREFIX + 'seg-1'],
                'device_owner': [const.DEVICE_OWNER_DISTRIBUTED]},
            limit=1)

    def test__find_metadata_port_without_segment(self):
        """_find_metadata_port without segment_id uses network device_id."""
        ctx = mock.MagicMock()
        cfg.CONF.set_override('ovn_metadata_enabled', True, group='ovn')
        plugin = self.get_plugin.return_value
        plugin.get_ports.return_value = [{'id': 'meta-port'}]

        result = self.ovn_client._find_metadata_port(
            ctx, 'fake-net-id')

        self.assertEqual({'id': 'meta-port'}, result)
        plugin.get_ports.assert_called_once_with(
            ctx, filters={
                'network_id': ['fake-net-id'],
                'device_id': [constants.OVN_METADATA_PREFIX + 'fake-net-id'],
                'device_owner': [const.DEVICE_OWNER_DISTRIBUTED]},
            limit=1)

    @mock.patch.object(ovn_utils, 'network_needs_lswitch',
                       return_value=False)
    @mock.patch('neutron.plugins.ml2.plugin.Ml2Plugin.get_network',
                return_value={})
    def test_create_network_vlan_only(self, mock_get_net, mock_needs_ls):
        """create_network for VLAN-only skips network ls_add."""
        network = self._make_network()
        segments = [
            self._make_segment('seg-1', segmentation_id=100),
            self._make_segment('seg-2', segmentation_id=200),
        ]
        ctx = mock.MagicMock()

        with mock.patch(
                'neutron.db.segments_db.get_network_segments',
                return_value=segments), \
            mock.patch.object(
                 self.ovn_client, 'create_provnet_port') as mock_provnet, \
            mock.patch.object(db_rev, 'bump_revision') as mock_bump, \
            mock.patch.object(
                 self.ovn_client, 'create_metadata_port'):
            self.ovn_client.create_network(ctx, network)

        # Should NOT create network logical switch
        self.nb_idl.ls_add.assert_not_called()
        # Should create provnet port for each segment
        self.assertEqual(2, mock_provnet.call_count)
        # Should bump revision per segment (dependent_resource)
        self.assertEqual(2, mock_bump.call_count)
        for i, call in enumerate(mock_bump.call_args_list):
            self.assertEqual(
                segments[i], call.kwargs['dependent_resource'])
            self.assertEqual(
                constants.TYPE_SEGMENTS,
                call.kwargs['dependent_resource_type'])

    @mock.patch.object(ovn_utils, 'network_needs_lswitch',
                       return_value=True)
    @mock.patch('neutron.plugins.ml2.plugin.Ml2Plugin.get_network',
                return_value={})
    def test_create_network_regular(self, mock_get_net, mock_needs_ls):
        """create_network for regular network creates network ls_add."""
        network = self._make_network()
        segments = [self._make_segment('seg-1', network_type='geneve',
                                       physical_network='physnet1')]
        ctx = mock.MagicMock()

        with mock.patch(
                'neutron.db.segments_db.get_network_segments',
                return_value=segments), \
            mock.patch.object(
                 self.ovn_client, 'create_provnet_port'), \
            mock.patch.object(db_rev, 'bump_revision') as mock_bump, \
            mock.patch.object(
                 self.ovn_client, 'create_metadata_port'):
            self.ovn_client.create_network(ctx, network)

        # Should create network logical switch
        self.nb_idl.ls_add.assert_called_once()
        ls_call = self.nb_idl.ls_add.call_args
        self.assertEqual(network['id'], ls_call.kwargs['network_id'])
        # Should bump network revision (not per-segment)
        mock_bump.assert_called_once_with(
            ctx, network, constants.TYPE_NETWORKS)

    @mock.patch.object(ovn_utils, 'network_needs_lswitch',
                       return_value=False)
    def test_update_network_dispatches_vlan(self, mock_needs_ls):
        """update_network calls update_network_vlan_segments for VLAN."""
        network = self._make_network()
        segments = [self._make_segment('seg-1')]
        ctx = mock.MagicMock()

        with mock.patch(
                'neutron.db.segments_db.get_network_segments',
                return_value=segments), \
            mock.patch.object(
                 self.ovn_client,
                 'update_network_vlan_segments') as mock_vlan, \
            mock.patch.object(
                 self.ovn_client,
                 '_update_network_regular') as mock_regular:
            self.ovn_client.update_network(ctx, network)

        mock_vlan.assert_called_once_with(ctx, network, segments)
        mock_regular.assert_not_called()

    @mock.patch.object(ovn_utils, 'network_needs_lswitch',
                       return_value=True)
    def test_update_network_dispatches_regular(self, mock_needs_ls):
        """update_network calls _update_network_regular for mixed."""
        network = self._make_network()
        segments = [self._make_segment('seg-1', network_type='geneve')]
        ctx = mock.MagicMock()

        with mock.patch(
                'neutron.db.segments_db.get_network_segments',
                return_value=segments), \
            mock.patch.object(
                 self.ovn_client,
                 'update_network_vlan_segments') as mock_vlan, \
            mock.patch.object(
                 self.ovn_client,
                 '_update_network_regular') as mock_regular:
            self.ovn_client.update_network(ctx, network)

        mock_regular.assert_called_once_with(
            ctx, network, None, segments)
        mock_vlan.assert_not_called()

    def test_update_network_vlan_segments(self):
        """update_network_vlan_segments updates each segment switch."""
        network = self._make_network()
        segments = [
            self._make_segment('seg-1', segmentation_id=100),
            self._make_segment('seg-2', segmentation_id=200),
        ]
        ctx = mock.MagicMock()
        plugin = self.get_plugin.return_value
        plugin.get_subnets_by_network.return_value = []

        # Make check_revision_number return committed
        check_cmd = mock.MagicMock()
        check_cmd.result = constants.TXN_COMMITTED
        self.nb_idl.check_revision_number.return_value = check_cmd

        with mock.patch.object(db_rev, 'bump_revision') as mock_bump:
            self.ovn_client.update_network_vlan_segments(
                ctx, network, segments)

        # Should db_set each segment logical switch
        self.assertEqual(2, self.nb_idl.db_set.call_count)
        for i, call in enumerate(self.nb_idl.db_set.call_args_list):
            self.assertEqual(
                ovn_utils.ovn_name(segments[i]['id']),
                call.args[1])

        # Should bump revision per segment
        self.assertEqual(2, mock_bump.call_count)
        for i, call in enumerate(mock_bump.call_args_list):
            self.assertEqual(
                segments[i], call.kwargs['dependent_resource'])

    @mock.patch.object(ovn_utils, 'network_needs_lswitch',
                       return_value=False)
    def test_update_metadata_port_vlan_only(self, mock_needs_ls):
        """update_metadata_port for VLAN-only uses segment_id."""
        network = self._make_network()
        subnet = {'id': 'sub-1', 'segment_id': 'seg-1',
                  'enable_dhcp': True}
        ctx = mock.MagicMock()
        cfg.CONF.set_override('ovn_metadata_enabled', True, group='ovn')

        metadata_port = {'id': 'meta-port',
                         'fixed_ips': [{'subnet_id': 'sub-1',
                                        'ip_address': '10.0.0.2'}]}
        with mock.patch.object(
                self.ovn_client, 'create_metadata_port',
                return_value=metadata_port) as mock_create_meta:
            result = self.ovn_client.update_metadata_port(
                ctx, network, subnet=subnet)

        self.assertTrue(result)
        # Should call create_metadata_port with segment_id
        mock_create_meta.assert_called_once_with(
            ctx, network, subnet['segment_id'])

    @mock.patch.object(ovn_utils, 'network_needs_lswitch',
                       return_value=True)
    def test_update_metadata_port_regular(self, mock_needs_ls):
        """update_metadata_port for regular network uses no segment_id."""
        network = self._make_network()
        subnet = {'id': 'sub-1', 'segment_id': None,
                  'enable_dhcp': True}
        ctx = mock.MagicMock()
        cfg.CONF.set_override('ovn_metadata_enabled', True, group='ovn')

        metadata_port = {'id': 'meta-port',
                         'fixed_ips': [{'subnet_id': 'sub-1',
                                        'ip_address': '10.0.0.2'}]}
        with mock.patch.object(
                self.ovn_client, 'create_metadata_port',
                return_value=metadata_port) as mock_create_meta:
            result = self.ovn_client.update_metadata_port(
                ctx, network, subnet=subnet)

        self.assertTrue(result)
        # Should call create_metadata_port without segment_id
        mock_create_meta.assert_called_once_with(ctx, network)

    def test_create_metadata_port_with_segment(self):
        """create_metadata_port with segment_id creates segment port."""
        network = self._make_network()
        ctx = mock.MagicMock()
        cfg.CONF.set_override('ovn_metadata_enabled', True, group='ovn')

        # No existing metadata port
        self.ovn_client._find_metadata_port = mock.Mock(return_value=None)
        new_port = {'id': 'new-meta-port', 'network_id': network['id']}

        with mock.patch(
                'neutron_lib.plugins.utils.create_port',
                return_value=new_port) as mock_p_create, \
            mock.patch.object(
                self.ovn_client, 'create_port') as mock_create_port:
            result = self.ovn_client.create_metadata_port(
                ctx, network, segment_id='seg-1')

        self.assertEqual(new_port, result)
        # device_id should use segment_id
        port_arg = mock_p_create.call_args[0][2]
        self.assertEqual(
            constants.OVN_METADATA_PREFIX + 'seg-1',
            port_arg['port']['device_id'])
        # fixed_ips should be empty for segment metadata ports
        self.assertEqual([], port_arg['port']['fixed_ips'])
        # Should call create_port with segment_id
        mock_create_port.assert_called_once_with(
            ctx, new_port, segment_id='seg-1')

    def test_create_metadata_port_without_segment(self):
        """create_metadata_port without segment_id uses network_id."""
        network = self._make_network()
        ctx = mock.MagicMock()
        cfg.CONF.set_override('ovn_metadata_enabled', True, group='ovn')
        plugin = self.get_plugin.return_value
        plugin.get_subnets.return_value = [
            {'id': 'sub-1', 'enable_dhcp': True}]

        self.ovn_client._find_metadata_port = mock.Mock(return_value=None)
        new_port = {'id': 'new-meta-port', 'network_id': network['id']}

        with mock.patch(
                'neutron_lib.plugins.utils.create_port',
                return_value=new_port) as mock_p_create, \
            mock.patch.object(
                self.ovn_client, 'create_port') as mock_create_port:
            result = self.ovn_client.create_metadata_port(
                ctx, network)

        self.assertEqual(new_port, result)
        # device_id should use network_id
        port_arg = mock_p_create.call_args[0][2]
        self.assertEqual(
            constants.OVN_METADATA_PREFIX + network['id'],
            port_arg['port']['device_id'])
        # fixed_ips should include subnets
        self.assertEqual(
            [{'subnet_id': 'sub-1'}],
            port_arg['port']['fixed_ips'])
        # Should NOT call create_port (no segment_id)
        mock_create_port.assert_not_called()

    @mock.patch.object(db_rev, 'bump_revision')
    @mock.patch.object(ovn_utils, 'network_needs_lswitch',
                       return_value=False)
    def test_update_port_routed_network_filters_subnets(
            self, mock_needs_ls, mock_bump):
        """update_port metadata port only processes matching segment."""
        net_id = 'fake-net-id'
        # Metadata port bound to seg-1, with fixed_ips on two subnets
        port = {
            'id': 'meta-port-id',
            'name': '',
            'network_id': net_id,
            'device_owner': const.DEVICE_OWNER_DISTRIBUTED,
            'device_id': constants.OVN_METADATA_PREFIX + 'seg-1',
            'fixed_ips': [
                {'subnet_id': 'sub-1', 'ip_address': '10.0.0.2'},
                {'subnet_id': 'sub-2', 'ip_address': '10.0.1.2'},
            ],
            'admin_state_up': True,
            'allowed_address_pairs': [],
            'revision_number': 1,
        }
        ctx = mock.MagicMock()
        check_cmd = mock.MagicMock()
        check_cmd.result = constants.TXN_COMMITTED
        self.nb_idl.check_revision_number.return_value = check_cmd

        ovn_port = mock.MagicMock()
        ovn_port.type = ''
        ovn_port.external_ids = {
            constants.OVN_PORT_SEGMENT_EXT_ID_KEY: 'seg-1'}
        self.nb_idl.lookup.return_value = ovn_port

        plugin = self.get_plugin.return_value
        plugin.get_network.return_value = {'id': net_id}
        # sub-1 matches seg-1, sub-2 belongs to seg-2
        sub1 = {'id': 'sub-1', 'segment_id': 'seg-1',
                'enable_dhcp': True}
        sub2 = {'id': 'sub-2', 'segment_id': 'seg-2',
                'enable_dhcp': True}
        plugin.get_subnets.return_value = [sub1, sub2]

        with mock.patch.object(
                self.ovn_client, 'get_external_ids_from_port',
                return_value=(mock.Mock(
                    addresses=['aa:bb:cc:dd:ee:ff 10.0.0.2'],
                    parent_name=[], tag=[], options={},
                    type='', port_security=[],
                ), {})), \
            mock.patch.object(
                self.ovn_client, 'update_port_dhcp_options',
                return_value=([], [])), \
            mock.patch.object(
                self.ovn_client, 'is_dns_required_for_port',
                return_value=False), \
            mock.patch.object(
                self.ovn_client,
                '_update_subnet_dhcp_options') as mock_dhcp:
            self.ovn_client.update_port(ctx, port)

        # Only sub-1 (matching seg-1) should be processed
        mock_dhcp.assert_called_once()
        call_args = mock_dhcp.call_args
        self.assertEqual('sub-1', call_args[0][1]['id'])

    @mock.patch.object(ovn_utils, 'network_needs_lswitch',
                       return_value=False)
    def test__delete_port_with_segment(self, mock_needs_ls):
        """_delete_port in routed network uses segment logical switch."""
        ovn_port = mock.MagicMock()
        ovn_port.type = ''
        ovn_port.external_ids = {
            constants.OVN_NETWORK_NAME_EXT_ID_KEY:
                ovn_utils.ovn_name('fake-net-id'),
            constants.OVN_PORT_SEGMENT_EXT_ID_KEY: 'seg-1',
        }
        self.nb_idl.lookup.return_value = ovn_port
        ls = mock.MagicMock()
        ls.ports = []
        self.nb_idl.ls_get.return_value.execute.return_value = ls
        ctx = mock.MagicMock()

        self.ovn_client._delete_port(ctx, 'fake-port-id', None)

        # Should delete from segment logical switch
        self.nb_idl.delete_lswitch_port.assert_called_once_with(
            'fake-port-id', ovn_utils.ovn_name('seg-1'))

    def test__delete_port_no_check_rev_cmd(self):
        """_delete_port handles check_rev_cmd=None safely."""
        ovn_port = mock.MagicMock()
        ovn_port.type = ''
        ovn_port.external_ids = {
            constants.OVN_NETWORK_NAME_EXT_ID_KEY:
                ovn_utils.ovn_name('fake-net-id'),
        }
        self.nb_idl.lookup.return_value = ovn_port
        ls = mock.MagicMock()
        ls.ports = []
        self.nb_idl.ls_get.return_value.execute.return_value = ls
        ctx = mock.MagicMock()

        # Should not raise even with check_rev_cmd=None
        self.ovn_client._delete_port(ctx, 'fake-port-id', None)

    @mock.patch.object(db_rev, 'bump_revision')
    @mock.patch.object(db_rev, 'delete_revision')
    def test_delete_port_keep_revision(self, mock_del_rev, mock_bump):
        """delete_port with keep_revision bumps instead of deleting."""
        check_cmd = mock.MagicMock()
        check_cmd.result = constants.TXN_COMMITTED
        self.nb_idl.check_revision_number.return_value = check_cmd

        port_object = {'id': 'fake-port-id', 'network_id': 'fake-net-id'}
        ovn_port = mock.MagicMock()
        ovn_port.type = ''
        ovn_port.external_ids = {
            constants.OVN_NETWORK_NAME_EXT_ID_KEY:
                ovn_utils.ovn_name('fake-net-id'),
        }
        self.nb_idl.lookup.return_value = ovn_port
        ls = mock.MagicMock()
        ls.ports = []
        self.nb_idl.ls_get.return_value.execute.return_value = ls
        ctx = mock.MagicMock()

        self.ovn_client.delete_port(
            ctx, 'fake-port-id', port_object=port_object,
            keep_revision=True)

        mock_bump.assert_called_once_with(
            ctx, port_object, constants.TYPE_PORTS)
        mock_del_rev.assert_not_called()


class TestOVNClientGetPhysnet(TestOVNClientBase):

    def setUp(self):
        super().setUp()
        self.get_plugin = mock.patch(
            'neutron_lib.plugins.directory.get_plugin').start()
        self.mock_get_segments = mock.patch(
            'neutron.db.segments_db.get_network_segments').start()
        self.plugin = mock.MagicMock()
        self.get_plugin.return_value = self.plugin
        self.context = mock.MagicMock()

    def test_single_segment_flat(self):
        network = {
            'id': 'net-id',
            'provider:network_type': 'flat',
            'provider:physical_network': 'physnet1'}
        result = self.ovn_client._get_physnet(
            self.context, network)
        self.assertEqual('physnet1', result)
        self.mock_get_segments.assert_not_called()

    def test_single_segment_vlan(self):
        network = {
            'id': 'net-id',
            'provider:network_type': 'vlan',
            'provider:physical_network': 'physnet2'}
        result = self.ovn_client._get_physnet(
            self.context, network)
        self.assertEqual('physnet2', result)
        self.mock_get_segments.assert_not_called()

    def test_tunnelled_network(self):
        network = {
            'id': 'net-id',
            'provider:network_type': 'geneve'}
        self.mock_get_segments.return_value = [
            {'id': 'seg1', 'network_type': 'geneve',
             'physical_network': None}]
        result = self.ovn_client._get_physnet(
            self.context, network)
        self.assertIsNone(result)

    def test_multi_segment_flat_with_port(self):
        network = {'id': 'net-id'}
        port = {'fixed_ips': [{'subnet_id': 'subnet-1',
                               'ip_address': '10.0.0.5'}]}
        self.mock_get_segments.return_value = [
            {'id': 'seg-1', 'network_type': 'flat',
             'physical_network': 'physnet1'},
            {'id': 'seg-2', 'network_type': 'flat',
             'physical_network': 'physnet2'}]
        self.plugin.get_subnets.return_value = [
            {'id': 'subnet-1', 'segment_id': 'seg-2'}]
        result = self.ovn_client._get_physnet(
            self.context, network, port)
        self.assertEqual('physnet2', result)

    def test_multi_segment_flat_without_port(self):
        network = {'id': 'net-id'}
        self.mock_get_segments.return_value = [
            {'id': 'seg-1', 'network_type': 'flat',
             'physical_network': 'physnet1'},
            {'id': 'seg-2', 'network_type': 'flat',
             'physical_network': 'physnet2'}]
        result = self.ovn_client._get_physnet(
            self.context, network)
        self.assertEqual('physnet1', result)

    def test_multi_segment_mixed_types(self):
        network = {'id': 'net-id'}
        port = {'fixed_ips': [{'subnet_id': 'subnet-1',
                               'ip_address': '10.0.0.5'}]}
        self.mock_get_segments.return_value = [
            {'id': 'seg-1', 'network_type': 'geneve',
             'physical_network': None},
            {'id': 'seg-2', 'network_type': 'flat',
             'physical_network': 'physnet1'}]
        self.plugin.get_subnets.return_value = [
            {'id': 'subnet-1', 'segment_id': 'seg-2'}]
        result = self.ovn_client._get_physnet(
            self.context, network, port)
        self.assertEqual('physnet1', result)

    def test_multi_segment_all_tunnelled(self):
        network = {'id': 'net-id'}
        self.mock_get_segments.return_value = [
            {'id': 'seg-1', 'network_type': 'geneve',
             'physical_network': None},
            {'id': 'seg-2', 'network_type': 'vxlan',
             'physical_network': None}]
        result = self.ovn_client._get_physnet(
            self.context, network)
        self.assertIsNone(result)

    def test_multi_segment_no_segments_in_db(self):
        network = {'id': 'net-id'}
        self.mock_get_segments.return_value = []
        result = self.ovn_client._get_physnet(
            self.context, network)
        self.assertIsNone(result)

    def test_multi_segment_port_subnet_no_segment_id(self):
        network = {'id': 'net-id'}
        port = {'fixed_ips': [{'subnet_id': 'subnet-1',
                               'ip_address': '10.0.0.5'}]}
        self.mock_get_segments.return_value = [
            {'id': 'seg-1', 'network_type': 'flat',
             'physical_network': 'physnet1'},
            {'id': 'seg-2', 'network_type': 'flat',
             'physical_network': 'physnet2'}]
        self.plugin.get_subnets.return_value = [
            {'id': 'subnet-1', 'segment_id': None}]
        result = self.ovn_client._get_physnet(
            self.context, network, port)
        self.assertEqual('physnet1', result)


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
