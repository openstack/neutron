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

from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.services.logapi import constants as log_const
from oslo_utils import uuidutils
from ovsdbapp.backend.ovs_idl import idlutils

from neutron.common import utils as neutron_utils

from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils as ovn_utils
from neutron.services.logapi.drivers.ovn import driver as ovn_driver
from neutron.tests import base
from neutron.tests.unit import fake_resources

FAKE_CFG_RATE = 123
FAKE_CFG_BURST = 321


class TestOVNDriver(base.BaseTestCase):

    def setUp(self):
        super().setUp()

        self.context = mock.Mock()
        self.plugin_driver = mock.Mock()
        self.plugin_driver.nb_ovn = fake_resources.FakeOvsdbNbOvnIdl()

        self.log_plugin = mock.Mock()
        get_mock_log_plugin = lambda alias: self.log_plugin if (
                alias == plugin_constants.LOG_API) else None
        self.fake_get_dir_object = mock.patch(
            "neutron_lib.plugins.directory.get_plugin",
            side_effect=get_mock_log_plugin).start()

        self.fake_get_sgs_attached_to_port = mock.patch(
            "neutron.services.logapi.common.db_api._get_sgs_attached_to_port",
            return_value=[]).start()

        self.fake_cfg_network_log = mock.patch(
            "oslo_config.cfg.CONF.network_log").start()
        self.fake_cfg_network_log.local_output_log_base = None
        self.fake_cfg_network_log.rate_limit = FAKE_CFG_RATE
        self.fake_cfg_network_log.burst_limit = FAKE_CFG_BURST

        self._log_driver_property = None

    @property
    def _nb_ovn(self):
        return self.plugin_driver.nb_ovn

    @property
    def _log_driver(self):
        if self._log_driver_property is None:
            self._log_driver_property = ovn_driver.OVNDriver.create(
                self.plugin_driver)
        return self._log_driver_property

    def _log_driver_reinit(self):
        self._log_driver_property = None
        return self._log_driver

    def _fake_meter(self, **kwargs):
        meter_defaults_dict = {
            'uuid': uuidutils.generate_uuid(),
            'bands': [mock.Mock(uuid='test_band')],
            'unit': 'pktps',
            'fair': [True],
        }
        meter_obj_dict = {**meter_defaults_dict, **kwargs}
        return mock.Mock(**meter_obj_dict)

    def _fake_meter_band(self, **kwargs):
        meter_band_defaults_dict = {
            'uuid': 'test_band',
            'rate': self.fake_cfg_network_log.rate_limit,
            'burst_size': self.fake_cfg_network_log.burst_limit,
        }
        meter_band_obj_dict = {**meter_band_defaults_dict, **kwargs}
        return mock.Mock(**meter_band_obj_dict)

    def test_create(self):
        driver = self._log_driver
        self.assertEqual(self.log_plugin, driver._log_plugin)
        self.assertEqual(self.plugin_driver, driver.plugin_driver)
        self.assertEqual(self.plugin_driver.nb_ovn, driver.ovn_nb)

    def test_create_meter_name(self):
        driver = self._log_driver
        self.assertEqual("acl_log_meter", driver.meter_name)

        test_log_base = neutron_utils.get_rand_name()
        self.fake_cfg_network_log.local_output_log_base = test_log_base
        driver2 = self._log_driver_reinit()
        self.assertEqual(test_log_base, driver2.meter_name)

    def test__create_ovn_fair_meter(self):
        mock_find_rows = mock.Mock()
        mock_find_rows.execute.return_value = None
        self._nb_ovn.db_find_rows.return_value = mock_find_rows
        self._log_driver._create_ovn_fair_meter(self._nb_ovn.transaction)
        self.assertFalse(self._nb_ovn.meter_del.called)
        self.assertTrue(self._nb_ovn.meter_add.called)
        self.assertFalse(
            self._nb_ovn.transaction.return_value.__enter__.called)
        self._nb_ovn.meter_add.assert_called_once_with(
            name="acl_log_meter",
            unit="pktps",
            rate=FAKE_CFG_RATE,
            fair=True,
            burst_size=FAKE_CFG_BURST,
            may_exist=False,
            external_ids={ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY:
                          log_const.LOGGING_PLUGIN})

    def test__create_ovn_fair_meter_unchanged(self):
        mock_find_rows = mock.Mock()
        mock_find_rows.execute.return_value = [self._fake_meter()]
        self._nb_ovn.db_find_rows.return_value = mock_find_rows
        self._nb_ovn.lookup.side_effect = lambda table, key: (
            self._fake_meter_band() if key == "test_band" else None)
        self._log_driver._create_ovn_fair_meter(self._nb_ovn.transaction)
        self.assertFalse(self._nb_ovn.meter_del.called)
        self.assertFalse(self._nb_ovn.meter_add.called)

    def test__create_ovn_fair_meter_changed(self):
        mock_find_rows = mock.Mock()
        mock_find_rows.execute.return_value = [self._fake_meter(fair=[False])]
        self._nb_ovn.db_find_rows.return_value = mock_find_rows
        self._nb_ovn.lookup.return_value = self._fake_meter_band()
        self._log_driver._create_ovn_fair_meter(self._nb_ovn.transaction)
        self.assertTrue(self._nb_ovn.meter_del.called)
        self.assertTrue(self._nb_ovn.meter_add.called)

    def test__create_ovn_fair_meter_band_changed(self):
        mock_find_rows = mock.Mock()
        mock_find_rows.execute.return_value = [self._fake_meter()]
        self._nb_ovn.db_find_rows.return_value = mock_find_rows
        self._nb_ovn.lookup.return_value = self._fake_meter_band(rate=666)
        self._log_driver._create_ovn_fair_meter(self._nb_ovn.transaction)
        self.assertTrue(self._nb_ovn.meter_del.called)
        self.assertTrue(self._nb_ovn.meter_add.called)

    def test__create_ovn_fair_meter_band_missing(self):
        mock_find_rows = mock.Mock()
        mock_find_rows.execute.return_value = [self._fake_meter()]
        self._nb_ovn.db_find_rows.return_value = mock_find_rows
        self._nb_ovn.lookup.side_effect = idlutils.RowNotFound
        self._log_driver._create_ovn_fair_meter(self._nb_ovn.transaction)
        self.assertTrue(self._nb_ovn.meter_del.called)
        self.assertTrue(self._nb_ovn.meter_add.called)

    class _fake_acl():
        def __init__(self, name=None, **acl_dict):
            acl_defaults_dict = {
                "name": [name] if name else [],
                "action": ovn_const.ACL_ACTION_ALLOW_RELATED,
            }
            self.__dict__ = {**acl_defaults_dict, **acl_dict}

    def _fake_pg_dict(self, **kwargs):
        pg_defaults_dict = {
            "name": ovn_utils.ovn_port_group_name(uuidutils.generate_uuid()),
            "acls": []
        }
        return {**pg_defaults_dict, **kwargs}

    def _fake_pg(self, **kwargs):
        pg_defaults_dict = {
            "name": ovn_utils.ovn_port_group_name(uuidutils.generate_uuid()),
            "acls": []
        }
        pg_dict = {**pg_defaults_dict, **kwargs}
        return mock.Mock(**pg_dict)

    def _fake_log_obj(self, **kwargs):
        log_obj_defaults_dict = {
            'uuid': uuidutils.generate_uuid(),
            'resource_id': None,
            'target_id': None,
            'event': log_const.ALL_EVENT,
        }
        log_obj_obj_dict = {**log_obj_defaults_dict, **kwargs}
        return mock.Mock(**log_obj_obj_dict)

    def test__pgs_from_log_obj_pg_all(self):
        expected_pgs = [self._fake_pg()]
        with mock.patch.object(self._log_driver, '_pgs_all',
                               return_value=expected_pgs) as mock_pgs_all:
            log_obj = self._fake_log_obj()
            pgs = self._log_driver._pgs_from_log_obj(self.context, log_obj)
            mock_pgs_all.assert_called_once()
            self.assertEqual(expected_pgs, pgs)

    def test__pgs_from_log_obj_empty(self):
        with mock.patch.object(self._log_driver, '_pgs_all',
                               return_value=[]) as mock_pgs_all:
            self._nb_ovn.lookup.side_effect = idlutils.RowNotFound
            log_obj = self._fake_log_obj(target_id='target_id')
            pgs = self._log_driver._pgs_from_log_obj(self.context, log_obj)
            mock_pgs_all.assert_not_called()
            self._nb_ovn.lookup.assert_called_once_with(
                "Port_Group", ovn_const.OVN_DROP_PORT_GROUP_NAME)
            self.fake_get_sgs_attached_to_port.assert_called_once_with(
                self.context, 'target_id')
            self.assertEqual([], pgs)

    def test__pgs_from_log_obj_pg_drop(self):
        with mock.patch.object(self._log_driver, '_pgs_all',
                               return_value=[]) as mock_pgs_all:
            pg = self._fake_pg()

            def _mock_lookup(_pg_table, pg_name):
                if pg_name == ovn_const.OVN_DROP_PORT_GROUP_NAME:
                    return pg
                raise idlutils.RowNotFound

            self._nb_ovn.lookup.side_effect = _mock_lookup
            log_obj = self._fake_log_obj(resource_id='resource_id')
            pgs = self._log_driver._pgs_from_log_obj(self.context, log_obj)
            mock_pgs_all.assert_not_called()
            self.assertEqual(2, self._nb_ovn.lookup.call_count)
            self.assertEqual([{'acls': [], 'name': pg.name}], pgs)

    def test__pgs_from_log_obj_pg(self):
        with mock.patch.object(self._log_driver, '_pgs_all',
                               return_value=[]) as mock_pgs_all:
            pg = self._fake_pg()
            self._nb_ovn.lookup.return_value = pg
            log_obj = self._fake_log_obj(resource_id='resource_id',
                                         target_id='target_id',
                                         event=log_const.ACCEPT_EVENT)
            pgs = self._log_driver._pgs_from_log_obj(self.context, log_obj)
            mock_pgs_all.assert_not_called()
            self._nb_ovn.lookup.assert_called_once_with(
                "Port_Group", ovn_utils.ovn_port_group_name('resource_id'))
            self.assertEqual([{'acls': [], 'name': pg.name}], pgs)

    def test__pgs_from_log_obj_port(self):
        with mock.patch.object(self._log_driver, '_pgs_all',
                               return_value=[]) as mock_pgs_all:
            sg_id = uuidutils.generate_uuid()
            pg_name = ovn_utils.ovn_port_group_name(sg_id)
            pg = self._fake_pg(name=pg_name)
            self._nb_ovn.lookup.return_value = pg
            log_obj = self._fake_log_obj(target_id='target_id',
                                         event=log_const.ACCEPT_EVENT)
            self.fake_get_sgs_attached_to_port.return_value = [sg_id]
            pgs = self._log_driver._pgs_from_log_obj(self.context, log_obj)
            mock_pgs_all.assert_not_called()
            self._nb_ovn.lookup.assert_called_once_with("Port_Group", pg_name)
            self.fake_get_sgs_attached_to_port.assert_called_once_with(
                self.context, 'target_id')
            self.assertEqual([{'acls': [], 'name': pg.name}], pgs)

    @mock.patch.object(ovn_driver.LOG, 'info')
    def test__remove_acls_log(self, m_info):
        pg_dict = self._fake_pg_dict(acls=['acl1', 'acl2'])
        self._log_driver._remove_acls_log([pg_dict], self._nb_ovn.transaction)
        info_args, _info_kwargs = m_info.call_args_list[0]
        self.assertIn('Cleared %d (out of %d visited) ACLs', info_args[0])
        self._nb_ovn.lookup.assert_not_called()
        self.assertEqual(len(pg_dict["acls"]), info_args[1])
        self.assertEqual(len(pg_dict["acls"]), info_args[2])
        self.assertEqual(len(pg_dict["acls"]), self._nb_ovn.db_set.call_count)

    @mock.patch.object(ovn_driver.LOG, 'info')
    def test__remove_acls_log_with_log_name(self, m_info):
        pg_dict = self._fake_pg_dict(acls=['acl1', 'acl2', 'acl3', 'acl4'])
        log_name = 'test_obj_name'
        used_name = 'test_used_name'

        def _mock_lookup(_pg_table, acl_uuid):
            if acl_uuid == 'acl2':
                return self._fake_acl(name=used_name)
            return self._fake_acl(name=log_name)

        self._nb_ovn.lookup.side_effect = _mock_lookup
        self._log_driver._remove_acls_log([pg_dict], self._nb_ovn.transaction,
                                          log_name)
        info_args, _info_kwargs = m_info.call_args_list[0]
        self.assertIn('Cleared %d (out of %d visited) ACLs', info_args[0])
        self.assertIn('for network log {}'.format(log_name), info_args[0])
        self.assertEqual(len(pg_dict["acls"]) - 1, info_args[1])
        self.assertEqual(len(pg_dict["acls"]), info_args[2])
        self.assertEqual(len(pg_dict["acls"]) - 1,
                         self._nb_ovn.db_set.call_count)

    @mock.patch.object(ovn_driver.LOG, 'info')
    def test__set_acls_log(self, m_info):
        pg_dict = self._fake_pg_dict(acls=['acl1', 'acl2', 'acl3', 'acl4'])
        log_name = 'test_obj_name'
        used_name = 'test_used_name'

        def _mock_lookup(_pg_table, acl_uuid):
            if acl_uuid == 'acl3':
                return self._fake_acl()
            return self._fake_acl(name=used_name)

        self._nb_ovn.lookup.side_effect = _mock_lookup
        actions_enabled = self._log_driver._acl_actions_enabled(
            self._fake_log_obj(event=log_const.ALL_EVENT))
        self._log_driver._set_acls_log([pg_dict], self._nb_ovn.transaction,
                                       actions_enabled, log_name)
        info_args, _info_kwargs = m_info.call_args_list[0]
        self.assertIn('Set %d (out of %d visited) ACLs for network log %s',
                      info_args[0])
        self.assertEqual(1, info_args[1])
        self.assertEqual(len(pg_dict["acls"]), info_args[2])
        self.assertEqual(log_name, info_args[3])
        self.assertEqual(1, self._nb_ovn.db_set.call_count)
