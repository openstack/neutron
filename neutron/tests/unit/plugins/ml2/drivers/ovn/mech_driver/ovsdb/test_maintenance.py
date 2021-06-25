# Copyright 2019 Red Hat, Inc.
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

from futurist import periodics
from neutron_lib import context
from oslo_config import cfg

from neutron.common.ovn import constants
from neutron.common.ovn import utils
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from neutron.db import ovn_revision_numbers_db
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import maintenance
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import ovn_db_sync
from neutron.tests.unit import fake_resources as fakes
from neutron.tests.unit.plugins.ml2 import test_security_group as test_sg
from neutron.tests.unit import testlib_api


class TestSchemaAwarePeriodicsBase(testlib_api.SqlTestCaseLight):

    def test__set_schema_aware_periodics(self):

        class TestClass(maintenance.SchemaAwarePeriodicsBase):
            @periodics.periodic(spacing=1)
            @maintenance.rerun_on_schema_updates
            def test_method_0(self):
                pass

            @periodics.periodic(spacing=1)
            def test_method_1(self):
                pass

            @periodics.periodic(spacing=1)
            @maintenance.rerun_on_schema_updates
            def test_method_2(self):
                pass

        obj = TestClass(mock.Mock())
        # Assert that test_method_0 and test_method_2 are schema
        # aware periodics
        self.assertEqual([obj.test_method_0, obj.test_method_2],
                         obj._schema_aware_periodics)

    @mock.patch.object(maintenance.SchemaAwarePeriodicsBase,
                       'get_ovn_nbdb_version')
    def test_nbdb_schema_updated_hook(self, mock_get_ver):
        initial_ver = '1.0.0'
        obj = mock.Mock()
        obj.get_ovn_nbdb_version.side_effect = (initial_ver, '1.1.0')
        obj_evt = maintenance.OVNNBDBReconnectionEvent(obj, initial_ver)

        # First run() will be called with the initial version (see
        # side_effect), so the hook should not be invoked since the
        # versions didn't change
        obj_evt.run('update', mock.Mock(), mock.Mock())
        self.assertFalse(obj.nbdb_schema_updated_hook.called)

        # Second run() will be called with a different version, the
        # hook should now be invoked
        obj_evt.run('update', mock.Mock(), mock.Mock())
        self.assertTrue(obj.nbdb_schema_updated_hook.called)


@mock.patch.object(maintenance.DBInconsistenciesPeriodics,
                   'has_lock', mock.PropertyMock(return_value=True))
class TestDBInconsistenciesPeriodics(testlib_api.SqlTestCaseLight,
                                     test_sg.Ml2SecurityGroupsTestCase):

    def setUp(self):
        super(TestDBInconsistenciesPeriodics, self).setUp()
        self.net = self._make_network(
            self.fmt, name='net1', admin_state_up=True)['network']
        self.port = self._make_port(
            self.fmt, self.net['id'], name='port1')['port']
        self.fake_ovn_client = mock.MagicMock()
        self.periodic = maintenance.DBInconsistenciesPeriodics(
            self.fake_ovn_client)
        self.ctx = context.get_admin_context()

    @mock.patch.object(maintenance.DBInconsistenciesPeriodics,
                       '_fix_create_update')
    @mock.patch.object(ovn_revision_numbers_db, 'get_inconsistent_resources')
    def test_check_for_inconsistencies(self, mock_get_incon_res, mock_fix_net):
        fake_row = mock.Mock(resource_type=constants.TYPE_NETWORKS)
        mock_get_incon_res.return_value = [fake_row, ]
        self.periodic.check_for_inconsistencies()
        mock_fix_net.assert_called_once_with(mock.ANY, fake_row)

    def _test_migrate_to_port_groups_helper(self, a_sets, migration_expected,
                                            never_again):
        self.fake_ovn_client._nb_idl.get_address_sets.return_value = a_sets
        with mock.patch.object(ovn_db_sync.OvnNbSynchronizer,
                               'migrate_to_port_groups') as mtpg:
            if never_again:
                self.assertRaises(periodics.NeverAgain,
                                  self.periodic.migrate_to_port_groups)
            else:
                self.periodic.migrate_to_port_groups()

            if migration_expected:
                mtpg.assert_called_once_with(mock.ANY)
            else:
                mtpg.assert_not_called()

    def test_migrate_to_port_groups_not_needed(self):
        self._test_migrate_to_port_groups_helper(a_sets=None,
                                                 migration_expected=False,
                                                 never_again=True)

    def test_migrate_to_port_groups(self):
        # Check normal migration path: if the migration has to be done, it will
        # take place and won't be attempted in the future.
        self._test_migrate_to_port_groups_helper(a_sets=['as1', 'as2'],
                                                 migration_expected=True,
                                                 never_again=True)

    def test_migrate_to_port_groups_no_lock(self):
        with mock.patch.object(maintenance.DBInconsistenciesPeriodics,
                               'has_lock', mock.PropertyMock(
                                   return_value=False)):
            # Check that if this worker doesn't have the lock, it won't
            # perform the migration and it will try again later.
            self._test_migrate_to_port_groups_helper(a_sets=['as1', 'as2'],
                                                     migration_expected=False,
                                                     never_again=False)

    def _test_fix_create_update_network(self, ovn_rev, neutron_rev):
        self.net['revision_number'] = neutron_rev

        # Create an entry to the revision_numbers table and assert the
        # initial revision_number for our test object is the expected
        ovn_revision_numbers_db.create_initial_revision(
            self.ctx, self.net['id'], constants.TYPE_NETWORKS,
            revision_number=ovn_rev)
        row = ovn_revision_numbers_db.get_revision_row(self.ctx,
                                                       self.net['id'])
        self.assertEqual(ovn_rev, row.revision_number)

        if ovn_rev < 0:
            self.fake_ovn_client._nb_idl.get_lswitch.return_value = None
        else:
            fake_ls = mock.Mock(external_ids={
                constants.OVN_REV_NUM_EXT_ID_KEY: ovn_rev})
            self.fake_ovn_client._nb_idl.get_lswitch.return_value = fake_ls

        self.fake_ovn_client._plugin.get_network.return_value = self.net
        self.periodic._fix_create_update(self.ctx, row)

        # Since the revision number was < 0, make sure create_network()
        # is invoked with the latest version of the object in the neutron
        # database
        if ovn_rev < 0:
            self.fake_ovn_client.create_network.assert_called_once_with(
                self.ctx, self.net)
        # If the revision number is > 0 it means that the object already
        # exist and we just need to update to match the latest in the
        # neutron database so, update_network() should be called.
        else:
            self.fake_ovn_client.update_network.assert_called_once_with(
                self.ctx, self.net)

    def test_fix_network_create(self):
        self._test_fix_create_update_network(ovn_rev=-1, neutron_rev=2)

    def test_fix_network_update(self):
        self._test_fix_create_update_network(ovn_rev=5, neutron_rev=7)

    def _test_fix_create_update_port(self, ovn_rev, neutron_rev):
        self.port['revision_number'] = neutron_rev

        # Create an entry to the revision_numbers table and assert the
        # initial revision_number for our test object is the expected
        ovn_revision_numbers_db.create_initial_revision(
            self.ctx, self.port['id'], constants.TYPE_PORTS,
            revision_number=ovn_rev)
        row = ovn_revision_numbers_db.get_revision_row(self.ctx,
                                                       self.port['id'])
        self.assertEqual(ovn_rev, row.revision_number)

        if ovn_rev < 0:
            self.fake_ovn_client._nb_idl.get_lswitch_port.return_value = None
        else:
            fake_lsp = mock.Mock(external_ids={
                constants.OVN_REV_NUM_EXT_ID_KEY: ovn_rev})
            self.fake_ovn_client._nb_idl.get_lswitch_port.return_value = (
                fake_lsp)

        self.fake_ovn_client._plugin.get_port.return_value = self.port
        self.periodic._fix_create_update(self.ctx, row)

        # Since the revision number was < 0, make sure create_port()
        # is invoked with the latest version of the object in the neutron
        # database
        if ovn_rev < 0:
            self.fake_ovn_client.create_port.assert_called_once_with(
                self.ctx, self.port)
        # If the revision number is > 0 it means that the object already
        # exist and we just need to update to match the latest in the
        # neutron database so, update_port() should be called.
        else:
            self.fake_ovn_client.update_port.assert_called_once_with(
                self.ctx, self.port)

    def test_fix_port_create(self):
        self._test_fix_create_update_port(ovn_rev=-1, neutron_rev=2)

    def test_fix_port_update(self):
        self._test_fix_create_update_port(ovn_rev=5, neutron_rev=7)

    @mock.patch.object(ovn_revision_numbers_db, 'bump_revision')
    def _test_fix_security_group_create(self, mock_bump, revision_number):
        sg_name = utils.ovn_addrset_name('fake_id', 'ip4')
        sg = self._make_security_group(self.fmt, sg_name, '')['security_group']

        ovn_revision_numbers_db.create_initial_revision(
            self.ctx, sg['id'], constants.TYPE_SECURITY_GROUPS,
            revision_number=revision_number)
        row = ovn_revision_numbers_db.get_revision_row(self.ctx, sg['id'])
        self.assertEqual(revision_number, row.revision_number)

        if revision_number < 0:
            self.fake_ovn_client._nb_idl.get_address_set.return_value = None
            self.fake_ovn_client._nb_idl.get_port_group.return_value = None
        else:
            self.fake_ovn_client._nb_idl.get_address_set.return_value = (
                mock.sentinel.AddressSet)

        self.fake_ovn_client._plugin.get_security_group.return_value = sg
        self.periodic._fix_create_update(self.ctx, row)

        if revision_number < 0:
            self.fake_ovn_client.create_security_group.assert_called_once_with(
                self.ctx, sg)
        else:
            # If the object already exist let's make sure we just bump
            # the revision number in the ovn_revision_numbers table
            self.assertFalse(self.fake_ovn_client.create_security_group.called)
            mock_bump.assert_called_once_with(
                self.ctx, sg, constants.TYPE_SECURITY_GROUPS)

    def test_fix_security_group_create_doesnt_exist(self):
        self._test_fix_security_group_create(revision_number=-1)

    def test_fix_security_group_create_version_mismatch(self):
        self._test_fix_security_group_create(revision_number=2)

    def test__create_lrouter_port(self):
        port = {'id': 'port-id',
                'device_id': 'router-id'}
        self.periodic._create_lrouter_port(self.ctx, port)
        ovn_client_mock = self.periodic._ovn_client
        ovn_client_mock.create_router_port.assert_called_once_with(
            self.ctx, port['device_id'], mock.ANY)

    @mock.patch.object(maintenance.LOG, 'debug')
    def test__log_maintenance_inconsistencies(self, mock_log):
        ovn_conf.cfg.CONF.set_override('debug', True)

        # Create fake inconsistencies: 2 networks, 4 subnets and 8 ports
        incst = []
        incst += [mock.Mock(resource_type=constants.TYPE_NETWORKS)] * 2
        incst += [mock.Mock(resource_type=constants.TYPE_SUBNETS)] * 4
        incst += [mock.Mock(resource_type=constants.TYPE_PORTS)] * 8

        # Create fake inconsistencies for delete: 3 routers and 6 router ports
        incst_del = []
        incst_del += [mock.Mock(resource_type=constants.TYPE_ROUTERS)] * 3
        incst_del += [mock.Mock(resource_type=constants.TYPE_ROUTER_PORTS)] * 6

        self.periodic._log_maintenance_inconsistencies(incst, incst_del)

        # Assert LOG.debug was called twice
        self.assertEqual(2, len(mock_log.call_args_list))

        # Assert the log matches the number of inconsistencies
        fail_str_create_update = mock_log.call_args_list[0][0][1]['fail_str']
        self.assertIn('networks=2', fail_str_create_update)
        self.assertIn('subnets=4', fail_str_create_update)
        self.assertIn('ports=8', fail_str_create_update)

        fail_str_delete = mock_log.call_args_list[1][0][1]['fail_str']
        self.assertIn('routers=3', fail_str_delete)
        self.assertIn('router_ports=6', fail_str_delete)

    @mock.patch.object(maintenance.LOG, 'debug')
    def test__log_maintenance_inconsistencies_debug_disabled(self, mock_log):
        ovn_conf.cfg.CONF.set_override('debug', False)

        incst = [mock.Mock(resource_type=constants.TYPE_NETWORKS)] * 2
        self.periodic._log_maintenance_inconsistencies(incst, [])
        self.assertFalse(mock_log.called)

    def test_check_for_igmp_snoop_support(self):
        cfg.CONF.set_override('igmp_snooping_enable', True, group='OVS')
        nb_idl = self.fake_ovn_client._nb_idl
        ls0 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'ls0',
                   'other_config': {
                       constants.MCAST_SNOOP: 'false',
                       constants.MCAST_FLOOD_UNREGISTERED: 'false'}})
        ls1 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'ls1',
                   'other_config': {}})
        ls2 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'ls2',
                   'other_config': {
                        constants.MCAST_SNOOP: 'true',
                        constants.MCAST_FLOOD_UNREGISTERED: 'false'}})

        nb_idl.ls_list.return_value.execute.return_value = [ls0, ls1, ls2]

        self.assertRaises(periodics.NeverAgain,
                          self.periodic.check_for_igmp_snoop_support)

        # "ls2" is not part of the transaction because it already
        # have the right value set
        expected_calls = [
            mock.call('Logical_Switch', 'ls0',
                      ('other_config', {
                           constants.MCAST_SNOOP: 'true',
                           constants.MCAST_FLOOD_UNREGISTERED: 'false'})),
            mock.call('Logical_Switch', 'ls1',
                      ('other_config', {
                           constants.MCAST_SNOOP: 'true',
                           constants.MCAST_FLOOD_UNREGISTERED: 'false'})),
        ]
        nb_idl.db_set.assert_has_calls(expected_calls)

    def test_check_for_ha_chassis_group_address_not_supported(self):
        self.fake_ovn_client.is_external_ports_supported.return_value = False
        self.assertRaises(periodics.NeverAgain,
                          self.periodic.check_for_ha_chassis_group_address)
        self.assertFalse(
            self.fake_ovn_client._nb_idl.ha_chassis_group_add.called)

    def test_check_for_ha_chassis_group_address(self):
        self.fake_ovn_client.is_external_ports_supported.return_value = True
        nb_idl = self.fake_ovn_client._nb_idl
        sb_idl = self.fake_ovn_client._sb_idl

        gw_chassis_0 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'priority': 1,
                   'name': 'gw_chassis_0',
                   'chassis_name': 'gw_chassis_0'})
        gw_chassis_1 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'priority': 2,
                   'name': 'gw_chassis_1',
                   'chassis_name': 'gw_chassis_1'})
        non_gw_chassis_0 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'non_gw_chassis_0'})
        default_ha_group = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'ha_chassis': [gw_chassis_0, gw_chassis_1]})

        nb_idl.ha_chassis_group_add.return_value.execute.return_value = (
            default_ha_group)
        sb_idl.get_all_chassis.return_value = [
            non_gw_chassis_0.name, gw_chassis_0.name, gw_chassis_1.name]
        sb_idl.get_gateway_chassis_from_cms_options.return_value = [
            gw_chassis_0.name, gw_chassis_1.name]

        # Invoke the periodic method, it meant to run only once at startup
        # so NeverAgain will be raised at the end
        self.assertRaises(periodics.NeverAgain,
                          self.periodic.check_for_ha_chassis_group_address)

        # Make sure the non GW chassis has been removed from the
        # default HA_CHASSIS_GROUP
        nb_idl.ha_chassis_group_del_chassis.assert_called_once_with(
            constants.HA_CHASSIS_GROUP_DEFAULT_NAME, non_gw_chassis_0.name,
            if_exists=True)

        # Assert the GW chassis are being added to the
        # default HA_CHASSIS_GROUP
        expected_calls = [
            mock.call(constants.HA_CHASSIS_GROUP_DEFAULT_NAME,
                      gw_chassis_1.chassis_name,
                      priority=constants.HA_CHASSIS_GROUP_HIGHEST_PRIORITY),
            # Note that the second chassis is getting priority -1
            mock.call(constants.HA_CHASSIS_GROUP_DEFAULT_NAME,
                      gw_chassis_0.chassis_name,
                      priority=constants.HA_CHASSIS_GROUP_HIGHEST_PRIORITY - 1)
        ]
        nb_idl.ha_chassis_group_add_chassis.assert_has_calls(expected_calls)

    def test_check_for_mcast_flood_reports(self):
        nb_idl = self.fake_ovn_client._nb_idl
        lsp0 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'lsp0',
                   'options': {'mcast_flood_reports': 'true'},
                   'type': ""})
        lsp1 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'lsp1', 'options': {}, 'type': ""})
        lsp2 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'lsp2', 'options': {},
                   'type': "vtep"})
        lsp3 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'lsp3', 'options': {},
                   'type': "localport"})
        lsp4 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'lsp4', 'options': {},
                   'type': "router"})
        lsp5 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'lsp5', 'options': {}, 'type': 'localnet'})

        nb_idl.lsp_list.return_value.execute.return_value = [
            lsp0, lsp1, lsp2, lsp3, lsp4, lsp5]

        # Invoke the periodic method, it meant to run only once at startup
        # so NeverAgain will be raised at the end
        self.assertRaises(periodics.NeverAgain,
                          self.periodic.check_for_mcast_flood_reports)

        # Assert only lsp1 and lsp5 were called because they are the only
        # ones meeting the criteria ("mcast_flood_reports" not yet set,
        # and type "" or localnet)
        expected_calls = [
            mock.call('lsp1', mcast_flood_reports='true'),
            mock.call('lsp5', mcast_flood_reports='true', mcast_flood='false')]

        nb_idl.lsp_set_options.assert_has_calls(expected_calls)
