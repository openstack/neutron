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
from neutron.objects import securitygroup as sg_obj
from neutron.services.logapi.common import db_api
from neutron.services.logapi.drivers.ovn import driver as ovn_driver
from neutron.tests import base
from neutron.tests.unit import fake_resources

FAKE_CFG_RATE = 123
FAKE_CFG_BURST = 321
FAKE_LABEL = 1


class TestOVNDriverBase(base.BaseTestCase):

    def setUp(self):
        super().setUp()

        self.context = mock.Mock()
        self.plugin_driver = mock.Mock()
        self.plugin_driver.nb_ovn = fake_resources.FakeOvsdbNbOvnIdl()

        self.log_plugin = mock.Mock()

        def get_mock_log_plugin(alias):
            return self.log_plugin if (
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

    def _fake_meter_band_stateless(self, **kwargs):
        meter_band_defaults_dict = {
            'uuid': 'tb_stateless',
            'rate': int(self.fake_cfg_network_log.rate_limit / 2),
            'burst_size': int(self.fake_cfg_network_log.burst_limit / 2),
        }
        meter_band_obj_dict = {**meter_band_defaults_dict, **kwargs}
        return mock.Mock(**meter_band_obj_dict)


class TestOVNDriver(TestOVNDriverBase):
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

    class _fake_acl:
        def __init__(self, name=None, **acl_dict):
            acl_defaults_dict = {
                'name': [name] if name else [],
                'action': ovn_const.ACL_ACTION_ALLOW_RELATED,
                'label': FAKE_LABEL,
                'log': True,
            }
            self.__dict__ = {**acl_defaults_dict, **acl_dict}

    def _fake_pg_dict(self, **kwargs):
        uuid = uuidutils.generate_uuid()
        pg_defaults_dict = {
            "name": ovn_utils.ovn_port_group_name(uuid),
            "external_ids": {ovn_const.OVN_SG_EXT_ID_KEY: uuid},
            "acls": []
        }
        return {**pg_defaults_dict, **kwargs}

    def _fake_pg(self, **kwargs):
        pg_dict = self._fake_pg_dict(**kwargs)
        pg_name = pg_dict.pop('name', None)
        pg = mock.Mock(**pg_dict)
        pg.name = pg_name
        return pg

    def _fake_log_obj(self, **kwargs):
        log_id = uuidutils.generate_uuid()
        log_obj_defaults_dict = {
            'id': log_id,
            'uuid': log_id,
            'resource_id': None,
            'target_id': None,
            'event': log_const.ALL_EVENT,
            'enabled': True,
        }
        log_obj_obj_dict = {**log_obj_defaults_dict, **kwargs}
        return mock.Mock(**log_obj_obj_dict)

    def _fake_log_dict(self, **kwargs):
        log_id = uuidutils.generate_uuid()
        log_dict_defaults = {
            'id': log_id,
            'project_id': uuidutils.generate_uuid(),
            'name': 'test-log',
            'resource_type': log_const.SECURITY_GROUP,
            'resource_id': None,
            'target_id': None,
            'event': log_const.ALL_EVENT,
            'enabled': True,
        }
        return {**log_dict_defaults, **kwargs}

    def test__get_logs_with_filters(self):
        self.log_plugin.get_logs.return_value = [self._fake_log_dict()]

        log_objs = self._log_driver._get_logs(
            self.context, enabled=True, event=log_const.DROP_EVENT)

        self.log_plugin.get_logs.assert_called_once_with(
            self.context, filters={'enabled': True,
                                   'event': log_const.DROP_EVENT})
        self.assertEqual(1, len(log_objs))

    def test__get_other_sg_drop_logs_uses_filtered_queries(self):
        log_obj = self._fake_log_obj(id='current-log', resource_id='sg-id')
        self.log_plugin.get_logs.return_value = []

        with mock.patch.object(
                db_api, '_get_ports_attached_to_sg', return_value=[]):
            self.assertEqual(
                [], self._log_driver._get_other_sg_drop_logs(
                    self.context, log_obj))

        self.log_plugin.get_logs.assert_called_once_with(
            self.context, filters={'enabled': True,
                                   'resource_id': 'sg-id',
                                   'event': [log_const.DROP_EVENT,
                                             log_const.ALL_EVENT]})

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
            self.fake_get_sgs_attached_to_port.assert_called_once_with(
                self.context, 'target_id')
            self.assertEqual([], pgs)

    def test__pgs_from_log_obj_sg_not_found(self):
        with mock.patch.object(self._log_driver, '_pgs_all',
                               return_value=[]) as mock_pgs_all:
            self._nb_ovn.lookup.side_effect = idlutils.RowNotFound
            log_obj = self._fake_log_obj(resource_id='resource_id')
            pgs = self._log_driver._pgs_from_log_obj(self.context, log_obj)
            mock_pgs_all.assert_not_called()
            self.assertEqual([], pgs)

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
            self.assertEqual([{'acls': [],
                               'external_ids': pg.external_ids,
                               'name': pg.name}], pgs)

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
            self.assertEqual([{'acls': [],
                               'external_ids': pg.external_ids,
                               'name': pg.name}], pgs)

    @mock.patch.object(ovn_driver.LOG, 'info')
    def test__remove_acls_log(self, m_info):
        pg_dict = self._fake_pg_dict(acls=['acl1', 'acl2'])
        self._log_driver._remove_acls_log([pg_dict], self._nb_ovn.transaction)
        info_args, _info_kwargs = m_info.call_args_list[0]
        self.assertIn('Cleared %d, Not found %d (out of %d visited) ACLs',
                      info_args[0])
        self._nb_ovn.lookup.assert_has_calls([
            mock.call('ACL', 'acl1', default=None),
            mock.call('ACL', 'acl2', default=None)])
        self.assertEqual(len(pg_dict["acls"]), info_args[1])
        self.assertEqual(len(pg_dict["acls"]) - 2, info_args[2])
        self.assertEqual(len(pg_dict["acls"]), info_args[3])
        self.assertEqual(len(pg_dict["acls"]),
                         self._nb_ovn.db_set.call_count)
        self.assertEqual(len(pg_dict["acls"]),
                         self._nb_ovn.db_remove.call_count)

    @mock.patch.object(ovn_driver.LOG, 'info')
    def test__remove_acls_log_missing_acls(self, m_info):
        pg_dict = self._fake_pg_dict(acls=['acl1', 'acl2', 'acl3'])

        def _mock_lookup(_pg_table, acl_uuid, default):
            if acl_uuid == 'acl3':
                return None
            return self._fake_acl()

        self._nb_ovn.lookup.side_effect = _mock_lookup
        self._log_driver._remove_acls_log([pg_dict], self._nb_ovn.transaction)
        info_args, _info_kwargs = m_info.call_args_list[0]
        self.assertEqual(len(pg_dict["acls"]) - 1, info_args[1])
        self.assertEqual(len(pg_dict["acls"]) - 2, info_args[2])
        self.assertEqual(len(pg_dict["acls"]), info_args[3])
        self.assertEqual(len(pg_dict["acls"]) - 1,
                         self._nb_ovn.db_set.call_count)

    # This test is enforcing the use of if_exists so that we don't get
    # unexpected errors while doing parallel operations like erasing log
    # objects and security groups
    @mock.patch.object(ovn_driver.LOG, 'info')
    def test__remove_acls_log_only_if_exists(self, m_info):
        pg_dict = self._fake_pg_dict(acls=['acl1', 'acl2', 'acl3'])

        def _only_if_exists(_pg_table, acl_uuid, col, val, if_exists):
            self.assertTrue(if_exists)

        self._nb_ovn.db_remove.side_effect = _only_if_exists
        self._log_driver._remove_acls_log([pg_dict], self._nb_ovn.transaction)

    @mock.patch.object(ovn_driver.LOG, 'info')
    def test__remove_acls_log_with_log_name(self, m_info):
        pg_dict = self._fake_pg_dict(acls=['acl1', 'acl2', 'acl3', 'acl4'])
        log_name = 'test_obj_name'
        used_name = 'test_used_name'

        def _mock_lookup(_pg_table, acl_uuid, default):
            if acl_uuid == 'acl2':
                return self._fake_acl(name=used_name)
            return self._fake_acl(name=log_name)

        self._nb_ovn.lookup.side_effect = _mock_lookup
        self._log_driver._remove_acls_log([pg_dict], self._nb_ovn.transaction,
                                          log_name)
        info_args, _info_kwargs = m_info.call_args_list[0]
        self.assertIn('Cleared %d, Not found %d (out of %d visited) ACLs',
                      info_args[0])
        self.assertIn(f'for network log {log_name}', info_args[0])
        self.assertEqual(len(pg_dict["acls"]) - 1, info_args[1])
        self.assertEqual(len(pg_dict["acls"]) - 4, info_args[2])
        self.assertEqual(len(pg_dict["acls"]), info_args[3])
        self.assertEqual(len(pg_dict["acls"]) - 1,
                         self._nb_ovn.db_set.call_count)

    @mock.patch.object(ovn_driver.LOG, 'info')
    @mock.patch.object(sg_obj.SecurityGroup, 'get_sg_by_id')
    def test__set_acls_log(self, get_sg, m_info):
        pg_dict = self._fake_pg_dict(acls=['acl1', 'acl2', 'acl3', 'acl4'])
        log_name = 'test_obj_name'
        used_name = 'test_used_name'

        def _mock_lookup(_pg_table, acl_uuid):
            if acl_uuid == 'acl3':
                return self._fake_acl()
            return self._fake_acl(name=used_name)

        sg = fake_resources.FakeSecurityGroup.create_one_security_group(
            attrs={'stateful': True})
        get_sg.return_value = sg
        self._nb_ovn.lookup.side_effect = _mock_lookup
        actions_enabled = self._log_driver._acl_actions_enabled(
            self._fake_log_obj(event=log_const.ALL_EVENT))
        self._log_driver._set_acls_log([pg_dict], self.context,
                                       self._nb_ovn.transaction,
                                       actions_enabled, log_name)
        info_args, _info_kwargs = m_info.call_args_list[0]
        self.assertIn('Set %d (out of %d visited) ACLs for network log %s',
                      info_args[0])
        self.assertEqual(1, info_args[1])
        self.assertEqual(len(pg_dict["acls"]), info_args[2])
        self.assertEqual(log_name, info_args[3])
        self.assertEqual(1, self._nb_ovn.db_set.call_count)

    def test_add_label_related(self):
        mock.patch.object(self._log_driver, '_pgs_from_log_obj', return_value=[
                          {'name': 'neutron_pg_drop',
                           'external_ids': {},
                           'acls': [uuidutils.generate_uuid()]}]).start()
        neutron_acl = {'port_group': 'neutron_pg_drop',
                       'priority': 1000,
                       'action': 'drop',
                       'log': True,
                       'name': '',
                       'severity': 'info',
                       'direction': 'to-lport',
                       'match': 'outport == @neutron_pg_drop && ip'}
        log_objs = [self._fake_log_obj(event=log_const.DROP_EVENT)]
        with mock.patch.object(self._log_driver, '_get_logs',
                               return_value=log_objs):
            self._log_driver.add_label_related(neutron_acl, self.context)
            self.assertNotEqual(neutron_acl['label'], 0)

    def test__get_sg_port_groups_with_resource_id(self):
        sg_id = uuidutils.generate_uuid()
        pg_name = ovn_utils.ovn_port_group_name(sg_id)
        pg = self._fake_pg(name=pg_name,
                           external_ids={ovn_const.OVN_SG_EXT_ID_KEY: sg_id})
        self._nb_ovn.lookup.return_value = pg
        log_obj = self._fake_log_obj(resource_id=sg_id)
        pgs = self._log_driver._get_sg_port_groups(self.context, log_obj)
        self._nb_ovn.lookup.assert_called_once_with("Port_Group", pg_name)
        self.assertEqual(1, len(pgs))
        self.assertEqual(pg.name, pgs[0]["name"])

    def test__get_sg_port_groups_with_target_id(self):
        sg_id = uuidutils.generate_uuid()
        pg_name = ovn_utils.ovn_port_group_name(sg_id)
        pg = self._fake_pg(name=pg_name,
                           external_ids={ovn_const.OVN_SG_EXT_ID_KEY: sg_id})
        self._nb_ovn.lookup.return_value = pg
        self.fake_get_sgs_attached_to_port.return_value = [sg_id]
        log_obj = self._fake_log_obj(target_id='port_id')
        pgs = self._log_driver._get_sg_port_groups(self.context, log_obj)
        self.fake_get_sgs_attached_to_port.assert_called_once_with(
            self.context, 'port_id')
        self.assertEqual(1, len(pgs))

    def test__get_sg_port_groups_not_found(self):
        self._nb_ovn.lookup.side_effect = idlutils.RowNotFound
        log_obj = self._fake_log_obj(resource_id='missing_sg')
        pgs = self._log_driver._get_sg_port_groups(self.context, log_obj)
        self.assertEqual([], pgs)

    def test__create_sg_drop_acls(self):
        sg_id = uuidutils.generate_uuid()
        pg_name = ovn_utils.ovn_port_group_name(sg_id)
        pg = self._fake_pg(name=pg_name,
                           external_ids={ovn_const.OVN_SG_EXT_ID_KEY: sg_id})
        self._nb_ovn.lookup.return_value = pg
        log_obj = self._fake_log_obj(resource_id=sg_id,
                                     event=log_const.DROP_EVENT)
        log_name = ovn_utils.ovn_name(log_obj.id)
        with self._nb_ovn.transaction(check_error=True) as ovn_txn:
            self._log_driver._create_sg_drop_acls(
                self.context, log_obj, ovn_txn, log_name)
        # Should have called pg_acl_add twice (from-lport and to-lport)
        self.assertEqual(2, self._nb_ovn.pg_acl_add.call_count)
        calls = self._nb_ovn.pg_acl_add.call_args_list
        for call in calls:
            self.assertEqual(ovn_const.ACL_PRIORITY_LOG_DROP,
                             call.kwargs.get('priority',
                                             call.args[1] if len(call.args) > 1
                                             else None))

    def test__create_sg_drop_acls_accept_event_skipped(self):
        sg_id = uuidutils.generate_uuid()
        pg = self._fake_pg()
        self._nb_ovn.lookup.return_value = pg
        log_obj = self._fake_log_obj(resource_id=sg_id,
                                     event=log_const.ACCEPT_EVENT)
        with self._nb_ovn.transaction(check_error=True) as ovn_txn:
            self._log_driver._create_sg_drop_acls(
                self.context, log_obj, ovn_txn, 'log_name')
        self._nb_ovn.pg_acl_add.assert_not_called()

    def test__remove_sg_drop_acls(self):
        sg_id = uuidutils.generate_uuid()
        pg_name = ovn_utils.ovn_port_group_name(sg_id)
        pg = self._fake_pg(name=pg_name,
                           external_ids={ovn_const.OVN_SG_EXT_ID_KEY: sg_id})
        self._nb_ovn.lookup.return_value = pg
        log_obj = self._fake_log_obj(resource_id=sg_id,
                                     event=log_const.DROP_EVENT)
        with self._nb_ovn.transaction(check_error=True) as ovn_txn:
            self._log_driver._remove_sg_drop_acls(
                self.context, log_obj, ovn_txn)
        # Should have called pg_acl_del twice (from-lport and to-lport)
        self.assertEqual(2, self._nb_ovn.pg_acl_del.call_count)
        calls = self._nb_ovn.pg_acl_del.call_args_list
        directions = {call.args[1] for call in calls}
        self.assertEqual({'from-lport', 'to-lport'}, directions)
        for call in calls:
            self.assertEqual(ovn_const.ACL_PRIORITY_LOG_DROP, call.args[2])
            direction = call.args[1]
            p = 'inport' if direction == 'from-lport' else 'outport'
            expected_match = f'{p} == @{pg_name} && ip'
            self.assertEqual(expected_match, call.args[3])

    def test_update_log_disabled_drop_reassigns_sg_drop_acls(self):
        sg_id = uuidutils.generate_uuid()
        disabled_log = self._fake_log_obj(id='disabled-drop-log',
                                          resource_id=sg_id,
                                          event=log_const.DROP_EVENT,
                                          enabled=False)
        remaining_log = self._fake_log_obj(id='remaining-all-log',
                                           resource_id=sg_id,
                                           event=log_const.ALL_EVENT,
                                           enabled=True)

        with mock.patch.object(self._log_driver, '_get_logs',
                               return_value=[disabled_log, remaining_log]), \
                mock.patch.object(db_api, '_get_ports_attached_to_sg',
                                  return_value=[]), \
                mock.patch.object(self._log_driver, '_remove_sg_drop_acls'
                                  ) as remove_sg_drop_acls, \
                mock.patch.object(self._log_driver, '_create_sg_drop_acls'
                                  ) as create_sg_drop_acls:
            self._log_driver.update_log(self.context, disabled_log)

        remove_sg_drop_acls.assert_called_once_with(
            self.context, disabled_log, mock.ANY)
        create_sg_drop_acls.assert_called_once_with(
            self.context, remaining_log, mock.ANY,
            ovn_utils.ovn_name(remaining_log.id))

    def test__pgs_from_log_obj_drop_with_resource_uses_sg_pg(self):
        """When logging DROP for a specific SG, use per-SG port group."""
        sg_id = uuidutils.generate_uuid()
        pg_name = ovn_utils.ovn_port_group_name(sg_id)
        pg = self._fake_pg(name=pg_name,
                           external_ids={ovn_const.OVN_SG_EXT_ID_KEY: sg_id})
        self._nb_ovn.lookup.return_value = pg
        log_obj = self._fake_log_obj(resource_id=sg_id,
                                     event=log_const.DROP_EVENT)
        pgs = self._log_driver._pgs_from_log_obj(self.context, log_obj)
        self.assertEqual(1, len(pgs))
        self.assertEqual(pg.name, pgs[0]["name"])

    def test_add_logging_options_to_acls(self):
        mock.patch.object(self._log_driver, '_pgs_from_log_obj', return_value=[
                             {'name': 'neutron_pg_drop', 'external_ids': {},
                              'acls': [uuidutils.generate_uuid()]}]).start()
        n_acls = [{'port_group': 'neutron_pg_drop',
                   'priority': 1000,
                   'action': 'drop',
                   'log': False,
                   'name': '',
                   'severity': '',
                   'direction': 'to-lport',
                   'match': 'outport == @neutron_pg_drop && ip'}]
        log_objs = [self._fake_log_obj(event=log_const.DROP_EVENT,
                                       resource_id=None,
                                       id='1111')]

        with mock.patch.object(self._log_driver, '_get_logs',
                               return_value=log_objs):
            self._log_driver.add_logging_options_to_acls(n_acls, self.context)
            for acl in n_acls:
                self.assertEqual(acl['severity'], 'info')
                self.assertTrue(acl['log'])
                self.assertEqual(acl['name'],
                                 ovn_utils.ovn_name(log_objs[0].id))
                self.assertEqual(acl['meter'], self._log_driver.meter_name)
