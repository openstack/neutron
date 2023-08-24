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

from neutron.common.ovn import constants
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from neutron.plugins.ml2 import db as ml2_db
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import ovn_client
from neutron.tests import base
from neutron.tests.unit import fake_resources as fakes
from neutron.tests.unit.services.logapi.drivers.ovn \
    import test_driver as test_log_driver
from neutron_lib.api.definitions import portbindings
from neutron_lib.services.logapi import constants as log_const

from tenacity import wait_none


class TestOVNClientBase(base.BaseTestCase):

    def setUp(self):
        ovn_conf.register_opts()
        super(TestOVNClientBase, self).setUp()
        self.nb_idl = mock.MagicMock()
        self.sb_idl = mock.MagicMock()
        self.ovn_client = ovn_client.OVNClient(self.nb_idl, self.sb_idl)


class TestOVNClientDetermineBindHost(TestOVNClientBase):

    def setUp(self):
        super(TestOVNClientDetermineBindHost, self).setUp()
        self.get_chassis_by_card_serial_from_cms_options = (
            self.sb_idl.get_chassis_by_card_serial_from_cms_options)
        self.fake_smartnic_hostname = 'fake-chassis-hostname'
        self.get_chassis_by_card_serial_from_cms_options.return_value = (
            fakes.FakeChassis.create(
                attrs={'hostname': self.fake_smartnic_hostname}))

        # Disable tenacity wait for UT
        self.ovn_client._wait_for_port_bindings_host.retry.wait = wait_none()

    def test_vnic_normal_unbound_port(self):
        self.assertEqual(
            '',
            self.ovn_client.determine_bind_host({}))

    def test_vnic_normal_bound_port(self):
        port = {
            portbindings.HOST_ID: 'fake-binding-host-id',
        }
        self.assertEqual(
            'fake-binding-host-id',
            self.ovn_client.determine_bind_host(port))

    def test_vnic_normal_port_context(self):
        context = mock.MagicMock()
        context.host = 'fake-binding-host-id'
        self.assertEqual(
            'fake-binding-host-id',
            self.ovn_client.determine_bind_host({}, port_context=context))

    def test_vnic_remote_managed_unbound_port_no_binding_profile(self):
        port = {
            portbindings.VNIC_TYPE: portbindings.VNIC_REMOTE_MANAGED,
        }
        self.assertEqual(
            '',
            self.ovn_client.determine_bind_host(port))

    def test_vnic_remote_managed_unbound_port(self):
        port = {
            portbindings.VNIC_TYPE: portbindings.VNIC_REMOTE_MANAGED,
            constants.OVN_PORT_BINDING_PROFILE: {
                constants.VIF_DETAILS_PCI_VENDOR_INFO: 'fake-pci-vendor-info',
                constants.VIF_DETAILS_PCI_SLOT: 'fake-pci-slot',
                constants.VIF_DETAILS_PHYSICAL_NETWORK: None,
                constants.VIF_DETAILS_CARD_SERIAL_NUMBER: 'fake-serial',
                constants.VIF_DETAILS_PF_MAC_ADDRESS: 'fake-pf-mac',
                constants.VIF_DETAILS_VF_NUM: 42,
            },
        }
        self.assertEqual(
            self.fake_smartnic_hostname,
            self.ovn_client.determine_bind_host(port))

    def test_vnic_remote_managed_bound_port(self):
        port = {
            portbindings.VNIC_TYPE: portbindings.VNIC_REMOTE_MANAGED,
            portbindings.HOST_ID: 'fake-binding-host-id',
            constants.OVN_PORT_BINDING_PROFILE: {
                constants.VIF_DETAILS_PCI_VENDOR_INFO: 'fake-pci-vendor-info',
                constants.VIF_DETAILS_PCI_SLOT: 'fake-pci-slot',
                constants.VIF_DETAILS_PHYSICAL_NETWORK: None,
                constants.VIF_DETAILS_CARD_SERIAL_NUMBER: 'fake-serial',
                constants.VIF_DETAILS_PF_MAC_ADDRESS: 'fake-pf-mac',
                constants.VIF_DETAILS_VF_NUM: 42,
            },
        }
        self.assertEqual(
            self.fake_smartnic_hostname,
            self.ovn_client.determine_bind_host(port))

    def test_vnic_remote_managed_port_context(self):
        context = mock.MagicMock()
        context.current = {
            portbindings.VNIC_TYPE: portbindings.VNIC_REMOTE_MANAGED,
            constants.OVN_PORT_BINDING_PROFILE: {
                constants.VIF_DETAILS_PCI_VENDOR_INFO: 'fake-pci-vendor-info',
                constants.VIF_DETAILS_PCI_SLOT: 'fake-pci-slot',
                constants.VIF_DETAILS_PHYSICAL_NETWORK: None,
                constants.VIF_DETAILS_CARD_SERIAL_NUMBER: 'fake-serial',
                constants.VIF_DETAILS_PF_MAC_ADDRESS: 'fake-pf-mac',
                constants.VIF_DETAILS_VF_NUM: 42,
            },
        }
        context.host = 'fake-binding-host-id'
        self.assertEqual(
            self.fake_smartnic_hostname,
            self.ovn_client.determine_bind_host({}, port_context=context))

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

        self.ovn_client.update_lsp_host_info(context, db_port, up=False)

        self.nb_idl.db_remove.assert_called_once_with(
            'Logical_Switch_Port', port_id, 'external_ids',
            constants.OVN_HOST_ID_EXT_ID_KEY, if_exists=True)

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
