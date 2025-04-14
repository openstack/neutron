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
from neutron_lib.api.definitions import portbindings
from neutron_lib import constants as n_const
from neutron_lib import context
from neutron_lib.db import api as db_api
from oslo_config import cfg
from oslo_serialization import jsonutils
from oslo_utils import uuidutils

from neutron.common.ovn import constants
from neutron.common.ovn import utils
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from neutron.db.models import ovn as ovn_models
from neutron.db import ovn_revision_numbers_db
from neutron.objects import ports as ports_obj
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import maintenance
from neutron.tests import base
from neutron.tests.unit import fake_resources as fakes
from neutron.tests.unit.plugins.ml2 import test_security_group as test_sg
from neutron.tests.unit import testlib_api
from neutron_lib import exceptions as n_exc


class TestHasLockPeriodicDecorator(base.BaseTestCase):

    def test_decorator_no_limit_have_lock(self):
        run_counter = 0

        @maintenance.has_lock_periodic(
            periodic_run_limit=0, spacing=30)
        def test_maintenance_task(worker):
            nonlocal run_counter
            run_counter += 1

        worker_mock = mock.MagicMock()
        worker_mock.has_lock = True

        for _ in range(3):
            test_maintenance_task(worker_mock)
        self.assertEqual(3, run_counter)

    def test_decorator_no_lock_no_limit(self):
        run_counter = 0

        @maintenance.has_lock_periodic(
            periodic_run_limit=0, spacing=30)
        def test_maintenance_task(worker):
            nonlocal run_counter
            run_counter += 1

        worker_mock = mock.MagicMock()
        has_lock_values = [False, False, True]

        for has_lock in has_lock_values:
            worker_mock.has_lock = has_lock
            test_maintenance_task(worker_mock)
        self.assertEqual(1, run_counter)

    def test_decorator_no_lock_with_limit(self):
        run_counter = 0

        @maintenance.has_lock_periodic(
            periodic_run_limit=1, spacing=30)
        def test_maintenance_task(worker):
            nonlocal run_counter
            run_counter += 1

        worker_mock = mock.MagicMock()

        worker_mock.has_lock = False
        test_maintenance_task(worker_mock)
        self.assertEqual(0, run_counter)

        worker_mock.has_lock = False
        self.assertRaises(periodics.NeverAgain,
                          test_maintenance_task, worker_mock)
        self.assertEqual(0, run_counter)


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
        ovn_conf.register_opts()
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

    def _test_fix_create_update_network(self, ovn_rev, neutron_rev):
        with db_api.CONTEXT_WRITER.using(self.ctx):
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
        _nb_idl = self.fake_ovn_client._nb_idl
        with db_api.CONTEXT_WRITER.using(self.ctx):
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
                _nb_idl.get_lswitch_port.return_value = None
            else:
                fake_lsp = mock.Mock(external_ids={
                    constants.OVN_REV_NUM_EXT_ID_KEY: ovn_rev})
                _nb_idl.get_lswitch_port.return_value = fake_lsp

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
        with db_api.CONTEXT_WRITER.using(self.ctx):
            sg_name = utils.ovn_addrset_name('fake_id', 'ip4')
            sg = self._make_security_group(
                self.fmt, sg_name, '')['security_group']

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

    @mock.patch.object(maintenance, 'LOG')
    def test__fix_create_update_no_sttd_attr(self, mock_log):
        row_net = ovn_models.OVNRevisionNumbers(
            standard_attr_id=1, resource_uuid=2,
            resource_type=constants.TYPE_NETWORKS)
        self.fake_ovn_client._plugin.get_network.return_value = {
            'id': 'net_id', 'revision_number': 1}
        self.periodic._fix_create_update(self.ctx, row_net)
        mock_log.error.assert_called_once_with(
            'Standard attribute ID not found for object ID %s', 'net_id')

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
        ls3 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': '',
                   'other_config': {}})
        ls4 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': '',
                   'other_config': {constants.MCAST_SNOOP: 'false'}})

        nb_idl.ls_list.return_value.execute.return_value = [ls0, ls1, ls2, ls3,
                                                            ls4]

        self.assertRaises(periodics.NeverAgain,
                          self.periodic.check_for_igmp_snoop_support)

        # "ls2" is not part of the transaction because it already
        # have the right value set; "ls3" and "ls4" do not have a name set.
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

    def test_check_for_ha_chassis_group_not_supported(self):
        self.fake_ovn_client.is_external_ports_supported.return_value = False
        self.assertRaises(periodics.NeverAgain,
                          self.periodic.check_for_ha_chassis_group)
        self.assertFalse(
            self.fake_ovn_client._nb_idl.ha_chassis_group_add.called)

    @mock.patch.object(utils, 'sync_ha_chassis_group')
    def test_check_for_ha_chassis_group_no_external_ports(
            self, mock_sync_ha_chassis_group):
        self.fake_ovn_client.is_external_ports_supported.return_value = True
        nb_idl = self.fake_ovn_client._nb_idl
        nb_idl.db_find_rows.return_value.execute.return_value = []
        self.assertRaises(periodics.NeverAgain,
                          self.periodic.check_for_ha_chassis_group)
        self.assertFalse(mock_sync_ha_chassis_group.called)

    @mock.patch.object(utils, 'sync_ha_chassis_group')
    def test_check_for_ha_chassis_group(self, mock_sync_ha_chassis_group):
        self.fake_ovn_client.is_external_ports_supported.return_value = True
        nb_idl = self.fake_ovn_client._nb_idl

        hcg0 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'uuid': '1f4323db-fb58-48e9-adae-6c6e833c581d',
                   'name': 'test-ha-grp'})
        hcg1 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'uuid': 'e95ff98f-7f03-484b-a156-d8c7e366dd3d',
                   'name': 'another-test-ha-grp'})
        p0 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'type': constants.LSP_TYPE_EXTERNAL,
                   'name': 'p0',
                   'ha_chassis_group': [hcg0],
                   'external_ids': {
                       constants.OVN_NETWORK_NAME_EXT_ID_KEY: 'neutron-net0'}})
        p1 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'type': constants.LSP_TYPE_EXTERNAL,
                   'name': 'p1',
                   'ha_chassis_group': [hcg1],
                   'external_ids': {
                       constants.OVN_NETWORK_NAME_EXT_ID_KEY: 'neutron-net1'}})

        nb_idl.db_find_rows.return_value.execute.return_value = [p0, p1]
        mock_sync_ha_chassis_group.return_value = hcg0.uuid

        # Invoke the periodic method, it meant to run only once at startup
        # so NeverAgain will be raised at the end
        self.assertRaises(periodics.NeverAgain,
                          self.periodic.check_for_ha_chassis_group)

        # Assert sync_ha_chassis_group() is called for both networks
        expected_calls = [
            mock.call(mock.ANY, 'p0', 'net0',
                      self.fake_ovn_client._nb_idl,
                      self.fake_ovn_client._sb_idl, mock.ANY),
            mock.call(mock.ANY, 'p1', 'net1',
                      self.fake_ovn_client._nb_idl,
                      self.fake_ovn_client._sb_idl, mock.ANY),
        ]
        mock_sync_ha_chassis_group.assert_has_calls(expected_calls,
                                                    any_order=True)

        expected_calls = [
            mock.call('p0', ha_chassis_group=hcg0.uuid),
            mock.call('p1', ha_chassis_group=hcg0.uuid)]
        nb_idl.set_lswitch_port.assert_has_calls(expected_calls,
                                                 any_order=True)

    def test_check_port_has_address_scope(self):
        self.fake_ovn_client.is_external_ports_supported.return_value = True
        nb_idl = self.fake_ovn_client._nb_idl

        # Already has the address scope set but empty, nothing to do
        lsp0 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                "uuid": "1f4323db-fb58-48e9-adae-6c6e833c581f",
                "name": "lsp0",
                "external_ids": {
                    constants.OVN_SUBNET_POOL_EXT_ADDR_SCOPE4_KEY: "",
                    constants.OVN_SUBNET_POOL_EXT_ADDR_SCOPE6_KEY: "",
                },
            }
        )

        # address scope is missing, needs update
        lsp1 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                "uuid": "1f4323db-fb58-48e9-adae-6c6e833c581d",
                "name": "lsp1",
                "external_ids": {},
            }
        )

        # Already has the address scope set, nothing to do
        lsp2 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                "uuid": "1f4323db-fb58-48e9-adae-6c6e833c581a",
                "name": "lsp2",
                "external_ids": {
                    constants.OVN_SUBNET_POOL_EXT_ADDR_SCOPE4_KEY: "fakev4",
                    constants.OVN_SUBNET_POOL_EXT_ADDR_SCOPE6_KEY: "fakev6",
                },
            }
        )

        # address scope is missing, needs update but port is missing in ovn
        lsp4 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                "uuid": "1f4323db-fb58-48e9-adae-6c6e833c581c",
                "name": "lsp4",
                "external_ids": {},
            }
        )

        nb_idl.db_find_rows.return_value.execute.return_value = [
            lsp0,
            lsp1,
            lsp2,
            lsp4,
        ]

        self.fake_ovn_client._plugin.get_port.side_effect = [
            {"network_id": "net0"},
            n_exc.PortNotFound(port_id="port"),
        ]

        external_ids = {
            constants.OVN_SUBNET_POOL_EXT_ADDR_SCOPE4_KEY: "address_scope_v4",
            constants.OVN_SUBNET_POOL_EXT_ADDR_SCOPE6_KEY: "address_scope_v6",
        }

        self.fake_ovn_client.get_external_ids_from_port.return_value = (
            None,
            external_ids,
        )

        self.assertRaises(
            periodics.NeverAgain, self.periodic.check_port_has_address_scope
        )

        nb_idl.set_lswitch_port.assert_called_once_with(
            "lsp1", external_ids=external_ids
        )

    def test_check_for_mcast_flood_reports_broken(self):
        self.fake_ovn_client.is_mcast_flood_broken = True
        nb_idl = self.fake_ovn_client._nb_idl
        lsp0 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'lsp0',
                   'options': {
                       constants.LSP_OPTIONS_MCAST_FLOOD_REPORTS: 'true'},
                   'type': ""})
        lsp1 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'lsp1', 'options': {}, 'type': ""})
        lsp2 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'lsp2', 'options': {},
                   'type': "vtep"})
        lsp3 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'lsp3', 'options': {},
                   'type': constants.LSP_TYPE_LOCALPORT})
        lsp4 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'lsp4', 'options': {},
                   'type': "router"})
        lsp5 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'lsp5', 'options': {}, 'type': 'localnet'})
        lsp6 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'lsp6',
                   'options': {
                       constants.LSP_OPTIONS_MCAST_FLOOD_REPORTS: 'true',
                       constants.LSP_OPTIONS_MCAST_FLOOD: 'true'},
                   'type': 'localnet'})
        lsp7 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'lsp7',
                   'options': {
                       constants.LSP_OPTIONS_MCAST_FLOOD_REPORTS: 'true',
                       constants.LSP_OPTIONS_MCAST_FLOOD: 'false'},
                   'type': 'localnet'})

        nb_idl.lsp_list.return_value.execute.return_value = [
            lsp0, lsp1, lsp2, lsp3, lsp4, lsp5, lsp6, lsp7]

        # Invoke the periodic method, it meant to run only once at startup
        # so NeverAgain will be raised at the end
        self.assertRaises(periodics.NeverAgain,
                          self.periodic.check_for_mcast_flood_reports)

        # Assert only lsp1 and lsp5 were called because they are the
        # only ones meeting to set mcast_flood_reports to 'true'
        expected_calls = [
            mock.call('lsp1', mcast_flood_reports='true'),
            mock.call('lsp5', mcast_flood_reports='true')]

        nb_idl.lsp_set_options.assert_has_calls(expected_calls)
        self.assertEqual(2, nb_idl.lsp_set_options.call_count)

        # Assert only lsp6 and lsp7 were called because they are the
        # only ones meeting to remove mcast_flood
        expected_calls = [
            mock.call('Logical_Switch_Port', 'lsp6', 'options',
                      constants.LSP_OPTIONS_MCAST_FLOOD,
                      if_exists=True),
            mock.call('Logical_Switch_Port', 'lsp7', 'options',
                      constants.LSP_OPTIONS_MCAST_FLOOD,
                      if_exists=True)]

        nb_idl.db_remove.assert_has_calls(expected_calls)
        self.assertEqual(2, nb_idl.db_remove.call_count)

    def test_check_for_mcast_flood_reports(self):
        self.fake_ovn_client.is_mcast_flood_broken = False
        nb_idl = self.fake_ovn_client._nb_idl

        lsp0 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'lsp0',
                   'options': {
                       constants.LSP_OPTIONS_MCAST_FLOOD_REPORTS: 'true'},
                   'type': ""})
        lsp1 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'lsp1', 'options': {}, 'type': ""})
        lsp2 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'lsp2',
                   'options': {
                       constants.LSP_OPTIONS_MCAST_FLOOD_REPORTS: 'true'},
                   'type': "vtep"})
        lsp3 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'lsp3', 'options': {},
                   'type': constants.LSP_TYPE_LOCALPORT})
        lsp4 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'lsp4', 'options': {},
                   'type': "router"})
        lsp5 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'lsp5', 'options': {},
                   'type': constants.LSP_TYPE_LOCALNET})
        lsp6 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'lsp6',
                   'options': {
                       constants.LSP_OPTIONS_MCAST_FLOOD_REPORTS: 'true',
                       constants.LSP_OPTIONS_MCAST_FLOOD: 'true'},
                   'type': constants.LSP_TYPE_LOCALNET})
        lsp7 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'lsp7',
                   'options': {
                       constants.LSP_OPTIONS_MCAST_FLOOD_REPORTS: 'true',
                       constants.LSP_OPTIONS_MCAST_FLOOD: 'false'},
                   'type': constants.LSP_TYPE_LOCALNET})

        nb_idl.lsp_list.return_value.execute.return_value = [
            lsp0, lsp1, lsp2, lsp3, lsp4, lsp5, lsp6, lsp7]

        # Invoke the periodic method, it meant to run only once at startup
        # so NeverAgain will be raised at the end
        self.assertRaises(periodics.NeverAgain,
                          self.periodic.check_for_mcast_flood_reports)

        # Assert only lsp0 and lsp2 were called because they are the
        # only ones meeting the criteria
        expected_calls = [
            mock.call('Logical_Switch_Port', 'lsp0', 'options',
                      constants.LSP_OPTIONS_MCAST_FLOOD_REPORTS,
                      if_exists=True),
            mock.call('Logical_Switch_Port', 'lsp2', 'options',
                      constants.LSP_OPTIONS_MCAST_FLOOD_REPORTS,
                      if_exists=True)]

        nb_idl.db_remove.assert_has_calls(expected_calls)
        self.assertEqual(2, nb_idl.db_remove.call_count)

    def test_check_localnet_port_has_learn_fdb(self):
        cfg.CONF.set_override('localnet_learn_fdb', 'True',
                              group='ovn')
        nb_idl = self.fake_ovn_client._nb_idl

        # Already has the learn fdb option enabled
        lsp0 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                "name": "lsp0",
                "options": {
                    constants.LSP_OPTIONS_LOCALNET_LEARN_FDB: "true",
                },
            }
        )

        # learn fdb option missing, needs update
        lsp1 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                "name": "lsp1",
                "options": {},
            }
        )

        # learn fdb option set to false, needs update
        lsp2 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                "name": "lsp2",
                "options": {
                    constants.LSP_OPTIONS_LOCALNET_LEARN_FDB: "false",
                },
            }
        )

        nb_idl.db_find_rows.return_value.execute.return_value = [
            lsp0,
            lsp1,
            lsp2,
        ]

        self.assertRaises(
            periodics.NeverAgain,
            self.periodic.check_localnet_port_has_learn_fdb)

        options = {constants.LSP_OPTIONS_LOCALNET_LEARN_FDB: 'true'}
        expected_calls = [mock.call('Logical_Switch_Port', 'lsp1',
                                    ('options', options)),
                          mock.call('Logical_Switch_Port', 'lsp2',
                                    ('options', options))]
        nb_idl.db_set.assert_has_calls(expected_calls)

    def test_check_localnet_port_has_learn_fdb_disabled(self):
        nb_idl = self.fake_ovn_client._nb_idl

        # learn fdb option enabled, needs update
        lsp0 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                "name": "lsp0",
                "options": {
                    constants.LSP_OPTIONS_LOCALNET_LEARN_FDB: "true",
                },
            }
        )

        # learn fdb option missing, no update needed
        lsp1 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                "name": "lsp1",
                "options": {},
            }
        )

        # learn fdb option set to false, no update needed
        lsp2 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                "name": "lsp2",
                "options": {
                    constants.LSP_OPTIONS_LOCALNET_LEARN_FDB: "false",
                },
            }
        )

        nb_idl.db_find_rows.return_value.execute.return_value = [
            lsp0,
            lsp1,
            lsp2,
        ]

        self.assertRaises(
            periodics.NeverAgain,
            self.periodic.check_localnet_port_has_learn_fdb)

        options = {constants.LSP_OPTIONS_LOCALNET_LEARN_FDB: 'false'}
        expected_calls = [mock.call('Logical_Switch_Port', 'lsp0',
                                    ('options', options))]
        nb_idl.db_set.assert_has_calls(expected_calls)

    def _test_check_redirect_type_router_gateway_ports(self, networks,
                                                       redirect_value):
        self.fake_ovn_client._plugin.get_ports.return_value = [{
            'device_owner': n_const.DEVICE_OWNER_ROUTER_GW,
            'id': 'fake-id',
            'device_id': 'fake-device-id'}]
        self.fake_ovn_client._get_router_ports.return_value = []
        self.fake_ovn_client._plugin.get_networks.return_value = networks

        lrp_redirect = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                'options': {constants.LRP_OPTIONS_REDIRECT_TYPE: "bridged"}})
        lrp_no_redirect = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                'options': {}})

        # set the opossite so that the value is changed
        if redirect_value:
            self.fake_ovn_client._nb_idl.get_lrouter_port.return_value = (
                lrp_no_redirect)
        else:
            self.fake_ovn_client._nb_idl.get_lrouter_port.return_value = (
                lrp_redirect)

        self.assertRaises(
            periodics.NeverAgain,
            self.periodic.check_redirect_type_router_gateway_ports)

        if redirect_value:
            expected_calls = [
                mock.call.db_set('Logical_Router_Port',
                                 mock.ANY,
                                 ('options', {'redirect-type': 'bridged'}))
            ]
            self.fake_ovn_client._nb_idl.db_set.assert_has_calls(
                expected_calls)
        else:
            expected_calls = [
                mock.call.db_remove('Logical_Router_Port', mock.ANY,
                                    'options', 'redirect-type')
            ]
            self.fake_ovn_client._nb_idl.db_remove.assert_has_calls(
                expected_calls)

    def test_check_redirect_type_router_gateway_ports_enable_redirect(self):
        cfg.CONF.set_override('enable_distributed_floating_ip', 'True',
                              group='ovn')
        networks = [{'network_id': 'foo',
                     'provider:network_type': n_const.TYPE_VLAN}]
        self._test_check_redirect_type_router_gateway_ports(networks, True)

    def test_check_redirect_type_router_gateway_ports_disable_redirect(self):
        cfg.CONF.set_override('enable_distributed_floating_ip', 'True',
                              group='ovn')
        networks = [{'network_id': 'foo',
                     'provider:network_type': n_const.TYPE_GENEVE}]
        self._test_check_redirect_type_router_gateway_ports(networks, False)

    def _test_check_vlan_distributed_ports(self, opt_value=None):
        fake_net0 = {'id': 'net0'}
        fake_net1 = {'id': 'net1'}
        fake_port0 = {'id': 'port0', 'device_id': 'device0'}
        fake_port1 = {'id': 'port1', 'device_id': 'device1'}

        self.fake_ovn_client._plugin.get_networks.return_value = [
            fake_net0, fake_net1]
        self.fake_ovn_client._plugin.get_ports.return_value = [
            fake_port0, fake_port1]
        (self.fake_ovn_client._get_reside_redir_for_gateway_port
             .return_value) = 'true'

        fake_lrp = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                'name': 'lrp',
                'options': {constants.LRP_OPTIONS_RESIDE_REDIR_CH: opt_value}})
        self.fake_ovn_client._nb_idl.get_lrouter_port.return_value = fake_lrp

        # Invoke the periodic method, it meant to run only once at startup
        # so NeverAgain will be raised at the end
        self.assertRaises(periodics.NeverAgain,
                          self.periodic.check_vlan_distributed_ports)

    def test_check_vlan_distributed_ports_expected_value(self):
        self._test_check_vlan_distributed_ports(opt_value='true')

        # If the "reside-on-redirect-chassis" option value do match
        # the expected value, assert we do not update the database
        self.assertFalse(
            self.fake_ovn_client._nb_idl.db_set.called)

    def test_check_vlan_distributed_ports_non_expected_value(self):
        self._test_check_vlan_distributed_ports(opt_value='false')

        # If the "reside-on-redirect-chassis" option value does not match
        # the expected value, assert we update the database
        opt = {constants.LRP_OPTIONS_RESIDE_REDIR_CH: 'true'}
        expected_calls = [
            mock.call('Logical_Router_Port', 'lrp-port0', ('options', opt)),
            mock.call('Logical_Router_Port', 'lrp-port1', ('options', opt))]
        self.fake_ovn_client._nb_idl.db_set.assert_has_calls(
            expected_calls)

    def test_check_fdb_aging_settings(self):
        cfg.CONF.set_override('fdb_age_threshold', 5, group='ovn')
        networks = [{'id': 'foo',
                     'provider:physical_network': 'datacentre'}]
        self.fake_ovn_client._plugin.get_networks.return_value = networks
        fake_ls = mock.Mock(other_config={})
        self.fake_ovn_client._nb_idl.get_lswitch.return_value = fake_ls

        self.assertRaises(
            periodics.NeverAgain,
            self.periodic.check_fdb_aging_settings)

        self.fake_ovn_client._nb_idl.db_set.assert_has_calls([
            mock.call('NB_Global', '.',
                      options={'fdb_removal_limit':
                               ovn_conf.get_fdb_removal_limit()}),
            mock.call('Logical_Switch', 'neutron-foo',
                      ('other_config',
                      {constants.LS_OPTIONS_FDB_AGE_THRESHOLD: '5'}))])

    def test_check_fdb_aging_settings_with_threshold_set(self):
        cfg.CONF.set_override('fdb_age_threshold', 5, group='ovn')
        networks = [{'id': 'foo',
                     'provider:network_type': n_const.TYPE_VLAN}]
        self.fake_ovn_client._plugin.get_networks.return_value = networks
        fake_ls = mock.Mock(other_config={
            constants.LS_OPTIONS_FDB_AGE_THRESHOLD: '5'})
        self.fake_ovn_client._nb_idl.get_lswitch.return_value = fake_ls

        self.assertRaises(
            periodics.NeverAgain,
            self.periodic.check_fdb_aging_settings)

        # It doesn't really matter if db_set is called or not for the
        # ls. This is called one time at startup and python-ovs will
        # not send the transaction if it doesn't cause a change
        self.fake_ovn_client._nb_idl.db_set.assert_called_once_with(
            'NB_Global', '.',
            options={'fdb_removal_limit': ovn_conf.get_fdb_removal_limit()})

    def test_remove_gw_ext_ids_from_logical_router(self):
        nb_idl = self.fake_ovn_client._nb_idl
        # lr0: GW port ID, not GW network ID --> we need to remove port ID.
        lr0 = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={
            'name': 'lr0',
            'external_ids': {constants.OVN_GW_PORT_EXT_ID_KEY: 'port0'}})
        # lr1: GW port ID and GW network ID --> we need to remove both.
        lr1 = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={
                'name': 'lr1',
                'external_ids': {constants.OVN_GW_PORT_EXT_ID_KEY: 'port1',
                                 constants.OVN_GW_NETWORK_EXT_ID_KEY: 'net1'}})
        # lr2: no GW port ID (nor GW network ID) --> no action needed.
        lr2 = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={
                'name': 'lr2', 'external_ids': {}})
        nb_idl.lr_list.return_value.execute.return_value = (lr0, lr1, lr2)
        self.fake_ovn_client._plugin.get_port.return_value = {
            'network_id': 'net0'}

        self.assertRaises(
            periodics.NeverAgain,
            self.periodic.remove_gw_ext_ids_from_logical_router)
        expected_calls = [mock.call('Logical_Router', lr0.uuid,
                                    ('external_ids', {})),
                          mock.call('Logical_Router', lr1.uuid,
                                    ('external_ids', {}))]
        nb_idl.db_set.assert_has_calls(expected_calls)

    def _test_check_baremetal_ports_dhcp_options(self, dhcp_disabled=False):
        cfg.CONF.set_override('disable_ovn_dhcp_for_baremetal_ports',
                              dhcp_disabled, group='ovn')
        self.fake_ovn_client.is_external_ports_supported.return_value = True
        nb_idl = self.fake_ovn_client._nb_idl
        self.fake_ovn_client._get_port_options.return_value = 'fake-port-opts'

        port0 = {'id': 'port0'}
        port1 = {'id': 'port1'}
        port2 = {'id': 'port2'}
        port3 = {'id': 'port3'}

        self.fake_ovn_client._plugin.get_ports.return_value = [
            port0, port1, port2, port3]

        lsp0 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'type': constants.LSP_TYPE_EXTERNAL,
                   'name': 'lsp0',
                   'dhcpv4_options': ['fake-uuid'],
                   'dhcpv6_options': []})
        lsp1 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'type': constants.LSP_TYPE_EXTERNAL,
                   'name': 'lsp1',
                   'dhcpv4_options': [],
                   'dhcpv6_options': []})
        lsp2 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'type': constants.LSP_TYPE_EXTERNAL,
                   'name': 'lsp2',
                   'dhcpv4_options': [],
                   'dhcpv6_options': ['fake-uuid']})
        lsp3 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'type': constants.LSP_TYPE_EXTERNAL,
                   'name': 'lsp3',
                   'dhcpv4_options': ['fake-uuid'],
                   'dhcpv6_options': ['fake-uuid']})

        nb_idl.lsp_get.return_value.execute.side_effect = [
            lsp0, lsp1, lsp2, lsp3]

        self.fake_ovn_client.update_port_dhcp_options.side_effect = [
            (lsp0.dhcpv4_options, lsp0.dhcpv6_options),
            (lsp1.dhcpv4_options, lsp1.dhcpv6_options),
            (lsp2.dhcpv4_options, lsp2.dhcpv6_options),
            (lsp3.dhcpv4_options, lsp3.dhcpv6_options)]

        self.assertRaises(periodics.NeverAgain,
                          self.periodic.check_baremetal_ports_dhcp_options)

    def test_check_baremetal_ports_dhcp_options(self):
        self._test_check_baremetal_ports_dhcp_options()
        self.fake_ovn_client._nb_idl.set_lswitch_port.assert_called_once_with(
            lport_name='port1', dhcpv4_options=['fake-uuid'],
            dhcpv6_options=[], if_exists=False)

    def test_check_baremetal_ports_dhcp_options_dhcp_disabled(self):
        self._test_check_baremetal_ports_dhcp_options(dhcp_disabled=True)
        expected_calls = [
            mock.call(lport_name='port0',
                      dhcpv4_options=['fake-uuid'],
                      dhcpv6_options=[], if_exists=False),
            mock.call(lport_name='port2',
                      dhcpv4_options=[],
                      dhcpv6_options=[], if_exists=False),
            mock.call(lport_name='port3',
                      dhcpv4_options=[],
                      dhcpv6_options=['fake-uuid'], if_exists=False)]

        self.fake_ovn_client._nb_idl.set_lswitch_port.assert_has_calls(
            expected_calls)

    @mock.patch.object(utils, 'get_virtual_port_parents',
                       return_value=[mock.ANY])
    def test_update_port_virtual_type(self, *args):
        nb_idl = self.fake_ovn_client._nb_idl
        lsp0 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'lsp0', 'type': ''})
        lsp1 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'lsp1', 'type': constants.LSP_TYPE_VIRTUAL})
        lsp2 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'name': 'lsp2_not_present_in_neutron_db', 'type': ''})
        port0 = {'fixed_ips': [{'ip_address': mock.ANY}],
                 'network_id': mock.ANY, 'id': mock.ANY}
        nb_idl.lsp_list.return_value.execute.return_value = (lsp0, lsp1, lsp2)
        self.fake_ovn_client._plugin.get_port.side_effect = [
            port0, n_exc.PortNotFound(port_id=mock.ANY)]

        self.assertRaises(
            periodics.NeverAgain, self.periodic.update_port_virtual_type)
        expected_calls = [mock.call('Logical_Switch_Port', lsp0.uuid,
                                    ('type', constants.LSP_TYPE_VIRTUAL))]
        nb_idl.db_set.assert_has_calls(expected_calls)

    def test_add_gw_port_info_to_logical_router_port(self):
        nb_idl = self.fake_ovn_client._nb_idl
        ext_net_id = uuidutils.generate_uuid()
        internal_net_id = uuidutils.generate_uuid()
        routers_db = [{
            'id': uuidutils.generate_uuid(),
            'external_gateways': [{'network_id': ext_net_id}]}]
        ext_gw_lrp = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ids': {
                constants.OVN_NETWORK_NAME_EXT_ID_KEY:
                    'neutron-{}'.format(ext_net_id)}})
        internal_net_lrp = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ids': {
                constants.OVN_NETWORK_NAME_EXT_ID_KEY:
                    'neutron-{}'.format(internal_net_id)}})
        fake_router = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                'ports': [ext_gw_lrp, internal_net_lrp]})

        expected_new_ext_gw_lrp_ids = ext_gw_lrp.external_ids
        expected_new_ext_gw_lrp_ids[constants.OVN_ROUTER_IS_EXT_GW] = 'True'
        expected_new_internal_lrp_ids = internal_net_lrp.external_ids
        expected_new_internal_lrp_ids[constants.OVN_ROUTER_IS_EXT_GW] = 'False'

        self.fake_ovn_client._l3_plugin.get_routers.return_value = routers_db
        nb_idl.get_lrouter.return_value = fake_router
        self.assertRaises(
            periodics.NeverAgain,
            self.periodic.add_gw_port_info_to_logical_router_port)
        nb_idl.update_lrouter_port.assert_has_calls([
            mock.call(name=ext_gw_lrp.name,
                      external_ids=expected_new_ext_gw_lrp_ids),
            mock.call(name=internal_net_lrp.name,
                      external_ids=expected_new_internal_lrp_ids)],
            any_order=True)

    def test_add_gw_port_info_to_logical_router_port_no_action_needed(self):
        nb_idl = self.fake_ovn_client._nb_idl
        ext_net_id = uuidutils.generate_uuid()
        internal_net_id = uuidutils.generate_uuid()
        routers_db = [{
            'id': uuidutils.generate_uuid(),
            'external_gateways': [{'network_id': ext_net_id}]}]
        ext_gw_lrp = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ids': {
                constants.OVN_NETWORK_NAME_EXT_ID_KEY:
                    'neutron-{}'.format(ext_net_id),
                constants.OVN_ROUTER_IS_EXT_GW: 'True'}})
        internal_net_lrp = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'external_ids': {
                constants.OVN_NETWORK_NAME_EXT_ID_KEY:
                    'neutron-{}'.format(internal_net_id),
                constants.OVN_ROUTER_IS_EXT_GW: 'False'}})
        fake_router = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={
                'ports': [ext_gw_lrp, internal_net_lrp]})

        self.fake_ovn_client._l3_plugin.get_routers.return_value = routers_db
        nb_idl.get_lrouter.return_value = fake_router
        self.assertRaises(
            periodics.NeverAgain,
            self.periodic.add_gw_port_info_to_logical_router_port)
        nb_idl.update_lrouter_port.assert_not_called()

    def test_check_router_default_route_empty_dst_ip(self):
        nb_idl = self.fake_ovn_client._nb_idl
        route0 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'ip_prefix': n_const.IPv4_ANY,
                   'nexthop': '10.42.0.1'})
        route1 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'ip_prefix': n_const.IPv4_ANY,
                   'nexthop': ''})
        route2 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'ip_prefix': n_const.IPv6_ANY,
                   'nexthop': '2001:db8:42::1'})
        route3 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
            attrs={'ip_prefix': n_const.IPv6_ANY,
                   'nexthop': ''})
        router0 = fakes.FakeOvsdbRow.create_one_ovsdb_row()
        router1 = fakes.FakeOvsdbRow.create_one_ovsdb_row(
                attrs={
                    'external_ids': {constants.OVN_REV_NUM_EXT_ID_KEY: 1}
                })
        nb_idl.lr_list.return_value.execute.return_value = (router0, router1)
        nb_idl.lr_route_list.return_value.execute.return_value = (
            route0, route1, route2, route3)
        self.assertRaises(
            periodics.NeverAgain,
            self.periodic.check_router_default_route_empty_dst_ip)
        nb_idl.delete_static_route.assert_has_calls([
            mock.call(router1.name, route1.ip_prefix, route1.nexthop),
            mock.call(router1.name, route3.ip_prefix, route3.nexthop),
        ])
        self.assertEqual(
            2,
            nb_idl.delete_static_route.call_count)

    @mock.patch.object(ports_obj.PortBinding, 'get_port_binding_by_vnic_type')
    def test_add_vnic_type_and_pb_capabilities_to_lsp(self, mock_get_pb):
        nb_idl = self.fake_ovn_client._nb_idl
        profile = {'capabilities': ['switchdev']}
        pb1 = mock.Mock(profile=jsonutils.dumps(profile), port_id='port1')
        pb2 = mock.Mock(profile=jsonutils.dumps(profile), port_id='port2')
        pb3 = mock.Mock(profile='', port_id='port3')
        mock_get_pb.return_value = [pb1, pb2, pb3]

        self.assertRaises(
            periodics.NeverAgain,
            self.periodic.add_vnic_type_and_pb_capabilities_to_lsp)
        external_ids = {
            constants.OVN_PORT_VNIC_TYPE_KEY: portbindings.VNIC_DIRECT,
            constants.OVN_PORT_BP_CAPABILITIES_KEY: 'switchdev'}
        expected_calls = [mock.call(lport_name='port1', if_exists=True,
                                    external_ids=external_ids),
                          mock.call(lport_name='port2', if_exists=True,
                                    external_ids=external_ids)]
        nb_idl.set_lswitch_port.assert_has_calls(expected_calls)
        self.assertEqual(2, nb_idl.set_lswitch_port.call_count)

    def test_update_nat_floating_ip_with_gateway_port(self):
        _nb_idl = self.fake_ovn_client._nb_idl
        utils.is_nat_gateway_port_supported.return_value = True

        lrp = fakes.FakeOvsdbRow.create_one_ovsdb_row(attrs={'options': {}})
        _nb_idl.get_lrouter_port.return_value = lrp
        self.fake_external_fixed_ips = {
            'network_id': 'ext-network-id',
            'external_fixed_ips': [{'ip_address': '20.0.2.1',
                                    'subnet_id': 'ext-subnet-id'}]}
        lrouter = {
            'id': 'lr-id-b',
            'name': utils.ovn_name('lr-id-b'),
            'admin_state_up': True,
            'external_gateway_info': self.fake_external_fixed_ips,
            'gw_port_id': 'gw-port-id'
        }
        _nb_idl._l3_plugin.get_router.return_value = lrouter

        lra_nat = {'external_ip': '20.0.2.4', 'logical_ip': '10.0.0.4',
                   'type': 'dnat_and_snat', 'external_mac': [],
                   'logical_port': [],
                   'external_ids': {constants.OVN_FIP_EXT_ID_KEY: 'fip_id_1'},
                   'gateway_port': uuidutils.generate_uuid(),
                   'uuid': uuidutils.generate_uuid()}

        lrb_nat = {'external_ip': '20.0.2.5', 'logical_ip': '10.0.0.5',
                   'type': 'dnat_and_snat',
                   'external_mac': ['00:01:02:03:04:05'],
                   'logical_port': ['lsp-id-001'],
                   'external_ids': {constants.OVN_FIP_EXT_ID_KEY: 'fip_id_2'},
                   'gateway_port': [],
                   'uuid': uuidutils.generate_uuid()}

        expected = [{'name': 'lr-id-a',
                     'ports': {'orp-id-a1': ['10.0.1.0/24'],
                               'orp-id-a2': ['10.0.2.0/24'],
                               'orp-id-a3': ['10.0.3.0/24']},
                     'static_routes': [{'destination': '20.0.0.0/16',
                                        'nexthop': '10.0.3.253'}],
                     'snats': [{'external_ip': '10.0.3.1',
                                'logical_ip': '20.0.0.0/16',
                                'type': 'snat'}],
                     'dnat_and_snats': []},
                    {'name': 'lr-id-b',
                     'ports': {'xrp-id-b1': ['20.0.1.0/24'],
                               'orp-id-b2': ['20.0.2.0/24']},
                     'static_routes': [{'destination': '10.0.0.0/16',
                                        'nexthop': '20.0.2.253'}],
                     'snats': [{'external_ip': '20.0.2.1',
                                'logical_ip': '10.0.0.0/24',
                                'type': 'snat'}],
                     'dnat_and_snats': [lra_nat, lrb_nat]}]
        _nb_idl.get_all_logical_routers_with_rports.return_value = expected

        self.assertRaises(periodics.NeverAgain,
            self.periodic.update_nat_floating_ip_with_gateway_port_reference)

        _nb_idl.set_nat_rule_in_lrouter.assert_called_once_with(
            utils.ovn_name('lr-id-b'),
            lrb_nat['uuid'],
            gateway_port=lrp.uuid)
