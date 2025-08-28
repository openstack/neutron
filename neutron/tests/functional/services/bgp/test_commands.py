# Copyright 2025 Red Hat, Inc.
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

from collections import namedtuple

from oslo_config import cfg
from oslo_utils import uuidutils
from ovsdbapp.backend.ovs_idl import idlutils

from neutron.conf.services import bgp as bgp_config
from neutron.services.bgp import commands
from neutron.services.bgp import constants
from neutron.services.bgp import exceptions
from neutron.services.bgp import helpers
from neutron.tests.functional.services import bgp


def _get_unique_name(prefix="test"):
    return f"{prefix}_{uuidutils.generate_uuid()[:8]}"


def _create_fake_chassis():
    return _FakeChassis(_get_unique_name("chassis"))


class _FakeChassis:
    def __init__(self, name):
        self.uuid = uuidutils.generate_uuid()
        self.name = name
        self.external_ids = {constants.OVN_BGP_CHASSIS_INDEX_KEY: '5'}


class NbCommandsBase(bgp.BaseBgpNbIdlTestCase):
    def setUp(self):
        super().setUp()
        mm = helpers.LrpMacManager.get_instance()
        mm.known_routers.clear()


class BgpCommandsBase(bgp.BaseBgpTestCase):
    def setUp(self):
        super().setUp()
        mm = helpers.LrpMacManager.get_instance()
        mm.known_routers.clear()


class _AddBaseCommand:
    table = None
    command = None

    def _assert_table_row_exists(self, name, should_exist=True):
        try:
            row = self.nb_api.lookup(self.table, name)
            if should_exist:
                self.assertIsNotNone(row)
                self.assertEqual(row.name, name)
                return row
            self.fail(f"{self.table} {name} should not exist")
        except idlutils.RowNotFound:
            if should_exist:
                self.fail(f"{self.table} {name} not found")
            return None

    def create_row(self, name, **kwargs):
        self.command(self.nb_api, name, **kwargs).execute(check_error=True)

    def test_create_new_row(self):
        name = _get_unique_name()

        # Verify row doesn't exist initially
        self._assert_table_row_exists(name, should_exist=False)

        self.create_row(name)

        # Verify the row was created
        created_row = self._assert_table_row_exists(name)
        self.assertEqual(created_row.name, name)

    def test_create_existing_row(self):
        name = _get_unique_name()

        # Create row first time
        self.create_row(name)

        # Verify first creation worked
        row1 = self._assert_table_row_exists(name)

        # Create same row again - should be idempotent
        self.create_row(name)

        # Lookup should not fail with duplicated name
        row2 = self._assert_table_row_exists(name)
        self.assertEqual(row1.uuid, row2.uuid)

    def test_external_ids_update_on_create(self):
        name = _get_unique_name()
        self.create_row(name, external_ids={'id1': 'value1'})
        row = self._assert_table_row_exists(name)
        self.assertEqual(row.external_ids.get('id1'), 'value1')

        # Create same row again - should be idempotent
        self.create_row(name, external_ids={'id1': 'value2'})
        row = self._assert_table_row_exists(name)
        self.assertEqual(row.external_ids.get('id1'), 'value2')

        # Create with different name - should create a new row
        name = _get_unique_name()
        self.create_row(name, external_ids={'id1': 'value3'})
        row = self._assert_table_row_exists(name)


class LrAddCommandTestCase(NbCommandsBase, _AddBaseCommand):
    table = 'Logical_Router'
    command = commands._LrAddCommand



class LrpAddCommandTestCase(NbCommandsBase, _AddBaseCommand):
    table = 'Logical_Router_Port'
    command = commands._LrpAddCommand

    def setUp(self):
        super().setUp()
        self.lr_name = _get_unique_name()
        self.nb_api.lr_add(self.lr_name).execute(check_error=True)

    def create_row(self, name, **kwargs):
        if 'mac' not in kwargs:
            kwargs['mac'] = '00:00:00:00:00:00'
        return self.command(
            self.nb_api, self.lr_name, name, **kwargs).execute(
                check_error=True)

    def test_create_existing_with_different_attributes(self):
        name = _get_unique_name()
        self.create_row(name, mac='00:00:00:00:00:00',
                        networks=['192.168.1.0/24'], peer='lrp-peer-1')
        lrp = self._assert_table_row_exists(name)
        self.assertEqual(lrp.mac, '00:00:00:00:00:00')
        self.assertEqual(lrp.networks, ['192.168.1.0/24'])
        self.assertEqual(lrp.peer, ['lrp-peer-1'])

        # Should update the MAC address
        self.create_row(name, mac='00:00:00:00:00:01',
                        networks=['192.168.2.0/24'], peer='lrp-peer-2')
        lrp = self._assert_table_row_exists(name)
        self.assertEqual(lrp.mac, '00:00:00:00:00:01')
        self.assertEqual(lrp.networks, ['192.168.2.0/24'])
        self.assertEqual(lrp.peer, ['lrp-peer-2'])


class HAChassisGroupAddCommandTestCase(NbCommandsBase, _AddBaseCommand):
    table = 'HA_Chassis_Group'
    command = commands._HAChassisGroupAddCommand


class ReconcileRouterCommandTestCase(NbCommandsBase):
    def _validate_router_created(self, router_name):
        router = self.nb_api.lr_get(router_name).execute(check_error=True)
        self.assertEqual(router.name, router_name)
        mm = helpers.LrpMacManager.get_instance()
        self.assertIsNotNone(mm.known_routers.get(router_name))

    def test_reconcile_new_router(self):
        router_name = _get_unique_name()

        commands.ReconcileRouterCommand(
            self.nb_api, router_name).execute(check_error=True)

        self._validate_router_created(router_name)

    def test_reconcile_existing_router(self):
        router_name = _get_unique_name()

        self.nb_api.lr_add(router_name).execute(check_error=True)

        commands.ReconcileRouterCommand(
            self.nb_api, router_name).execute(check_error=True)

        router = self.nb_api.lr_get(router_name).execute(check_error=True)
        self.assertEqual(router.name, router_name)

    def test_reconcile_router_updates_existing_options(self):
        router_name = _get_unique_name()

        self.nb_api.lr_add(
            router_name, options={'wrong-option': 'value'}).execute(
                check_error=True)

        commands.ReconcileRouterCommand(
            self.nb_api, router_name).execute(check_error=True)

        router = self.nb_api.lr_get(router_name).execute(check_error=True)
        self.assertEqual(router.name, router_name)


class ReconcileMainRouterCommandTestCase(NbCommandsBase):
    def setUp(self):
        super().setUp()
        self.router_name = _get_unique_name()
        cfg.CONF.set_override('main_router_name', self.router_name, 'bgp')

    def _validate_main_router_options(self):
        router = self.nb_api.lr_get(self.router_name).execute(check_error=True)
        self.assertEqual(router.name, self.router_name)
        self.assertEqual(router.options.get('dynamic-routing'), 'true')
        self.assertEqual(router.options.get('dynamic-routing-redistribute'),
                         'connected-as-host,nat')

    def test_reconcile_main_router_with_dynamic_routing(self):
        commands.ReconcileMainRouterCommand(
            self.nb_api).execute(check_error=True)

        self._validate_main_router_options()

    def test_reconcile_updates_existing_main_router_options(self):
        self.nb_api.lr_add(
            self.router_name,
            options={'dynamic-routing': 'false', 'wrong-option': 'value'}
        ).execute(check_error=True)

        commands.ReconcileMainRouterCommand(
            self.nb_api).execute(check_error=True)

        self._validate_main_router_options()

    def test_registered_mac_prefix(self):
        cmd = commands.ReconcileMainRouterCommand(
            self.nb_api)
        cmd.execute(check_error=True)
        mm = helpers.LrpMacManager.get_instance()
        expected_prefix = cmd.router_mac_prefix
        self.assertEqual(
            expected_prefix,
            mm.known_routers[self.router_name].mac_prefix)


class ReconcileChassisRouterCommandTestCase(NbCommandsBase):
    def test_reconcile_chassis_router(self):
        chassis = _create_fake_chassis()
        router_name = helpers.get_chassis_router_name(chassis.name)

        commands.ReconcileChassisRouterCommand(
            self.nb_api, chassis).execute(check_error=True)

        router = self.nb_api.lr_get(router_name).execute(check_error=True)
        self.assertEqual(router.name, router_name)
        self.assertEqual(router.options.get('chassis'), chassis.name)

    def test_reconcile_updates_chassis_router_options(self):
        chassis = _create_fake_chassis()
        router_name = helpers.get_chassis_router_name(chassis.name)

        self.nb_api.lr_add(
            router_name,
            options={'chassis': 'wrong-chassis', 'other-option': 'value'}
        ).execute(check_error=True)

        commands.ReconcileChassisRouterCommand(
            self.nb_api, chassis).execute(check_error=True)

        router = self.nb_api.lr_get(router_name).execute(check_error=True)
        self.assertEqual(router.options.get('chassis'), chassis.name)

    def test_registered_mac_prefix(self):
        chassis = _create_fake_chassis()
        router_name = helpers.get_chassis_router_name(chassis.name)
        cmd = commands.ReconcileChassisRouterCommand(
            self.nb_api, chassis)
        cmd.execute(check_error=True)
        mm = helpers.LrpMacManager.get_instance()
        self.assertEqual(
            cmd.router_mac_prefix,
            mm.known_routers[router_name].mac_prefix)


class IndexAllChassisTestCase(bgp.BaseBgpSbIdlTestCase):
    def test_index_all_chassis(self):
        self.add_fake_chassis(_get_unique_name(), '192.168.1.100')
        self.add_fake_chassis(_get_unique_name(), '192.168.1.101')

        result = commands.IndexAllChassis(self.sb_api).execute(
            check_error=True)

        expected_indexes = [str(i) for i in range(2)]
        self.assertCountEqual(
            expected_indexes,
            [r.external_ids.get(constants.OVN_BGP_CHASSIS_INDEX_KEY)
             for r in result])

    def test_index_all_chassis_new_chassis_added(self):
        self.test_index_all_chassis()

        self.add_fake_chassis(_get_unique_name(), '192.168.1.102')

        result = commands.IndexAllChassis(self.sb_api).execute(
            check_error=True)

        expected_indexes = [str(i) for i in range(3)]
        self.assertCountEqual(
            expected_indexes,
            [r.external_ids[constants.OVN_BGP_CHASSIS_INDEX_KEY]
            for r in result])

    def test_index_all_chassis_with_existing_index(self):
        chassis_names = [_get_unique_name() for _ in range(2)]

        for i, chassis_name in enumerate(chassis_names):
            self.add_fake_chassis(chassis_name, f'192.168.1.10{i}')

        commands.IndexAllChassis(self.sb_api).execute(check_error=True)

        # remove chassis with index 0
        self.sb_api.chassis_del(chassis_names[0]).execute(check_error=True)

        for i in range(2):
            self.add_fake_chassis(_get_unique_name(), f'192.168.1.11{i}')

        result = commands.IndexAllChassis(self.sb_api).execute(
            check_error=True)

        expected_indexes = [str(i) for i in range(3)]
        self.assertCountEqual(
            expected_indexes,
            [r.external_ids[constants.OVN_BGP_CHASSIS_INDEX_KEY]
            for r in result])


class ConnectChassisRouterToMainRouterCommandTestCase(NbCommandsBase):
    def setUp(self):
        super().setUp()
        self.main_router_name = _get_unique_name()
        cfg.CONF.set_override('main_router_name', self.main_router_name, 'bgp')

        self.fake_chassis = _create_fake_chassis()
        self.chassis_router_name = helpers.get_chassis_router_name(
            self.fake_chassis.name)
        self.chassis_index = int(
            self.fake_chassis.external_ids[
                constants.OVN_BGP_CHASSIS_INDEX_KEY])

        hcg_name = f'bgp-hcg-{self.fake_chassis.name}'
        self.hcg_id = self._create_hcg(hcg_name)

        commands.ReconcileMainRouterCommand(
            self.nb_api).execute(check_error=True)
        commands.ReconcileChassisRouterCommand(
            self.nb_api,
            self.fake_chassis).execute(check_error=True)

    def _create_hcg(self, hcg_name):
        return commands._HAChassisGroupAddCommand(
            self.nb_api, hcg_name).execute(check_error=True).uuid

    def _validate_connection_created(self):
        lrp_main_name = helpers.get_lrp_name(
            self.main_router_name, self.chassis_router_name)
        lrp_chassis_name = helpers.get_lrp_name(
            self.chassis_router_name, self.main_router_name)

        lrp_main = self.nb_api.lrp_get(lrp_main_name).execute(check_error=True)
        lrp_chassis = self.nb_api.lrp_get(
            lrp_chassis_name).execute(check_error=True)

        # Check ports are connected
        self.assertEqual(lrp_main.peer, [lrp_chassis_name])
        self.assertEqual(lrp_chassis.peer, [lrp_main_name])

        # Check MAC addresses
        mm = helpers.LrpMacManager.get_instance()
        expected_main_mac = mm.get_mac_address(
            self.main_router_name, self.chassis_index)
        expected_chassis_mac = mm.get_mac_address(
            self.chassis_router_name, constants.LRP_CHASSIS_TO_MAIN_ROUTER)

        self.assertEqual(expected_main_mac, lrp_main.mac)
        self.assertEqual(expected_chassis_mac, lrp_chassis.mac)

        # Verify main router LRP has HA chassis group
        self.assertEqual(self.hcg_id, lrp_main.ha_chassis_group[0].uuid)

        # Verify main router LRP has dynamic routing option
        self.assertEqual(
            'true', lrp_main.options.get('dynamic-routing-maintain-vrf'))

        return lrp_main_name, lrp_chassis_name

    def test_connect_router_to_main_router_new(self):
        commands.ConnectChassisRouterToMainRouterCommand(
            self.nb_api, self.fake_chassis, self.hcg_id
        ).execute(check_error=True)

        self._validate_connection_created()

    def test_connect_existing_lrps_get_updated(self):
        lrp_main_name = helpers.get_lrp_name(
            self.main_router_name, self.chassis_router_name)
        lrp_chassis_name = helpers.get_lrp_name(
            self.chassis_router_name, self.main_router_name)

        self.nb_api.lrp_add(
            self.chassis_router_name, lrp_chassis_name,
            mac='00:00:00:00:00:01',  # wrong MAC
            networks=['10.0.0.1/24'],  # wrong IP
            peer='wrong-peer'  # wrong peer
        ).execute(check_error=True)

        self.nb_api.lrp_add(
            self.main_router_name, lrp_main_name,
            mac='00:00:00:00:00:02',  # wrong MAC
            networks=['10.0.0.2/24'],  # wrong IP
            peer='wrong-peer'  # wrong peer
        ).execute(check_error=True)

        commands.ConnectChassisRouterToMainRouterCommand(
            self.nb_api, self.fake_chassis, self.hcg_id
        ).execute(check_error=True)

        self._validate_connection_created()

    def test_connect_router_is_idempotent(self):
        commands.ConnectChassisRouterToMainRouterCommand(
            self.nb_api, self.fake_chassis, self.hcg_id
        ).execute(check_error=True)

        lrp_main1, lrp_chassis1 = self._validate_connection_created()

        commands.ConnectChassisRouterToMainRouterCommand(
            self.nb_api, self.fake_chassis, self.hcg_id
        ).execute(check_error=True)

        lrp_main2, lrp_chassis2 = self._validate_connection_created()

        self.assertEqual(lrp_main1, lrp_main2)
        self.assertEqual(lrp_chassis1, lrp_chassis2)

    def test_connect_router_to_non_existing_main_router(self):
        self.nb_api.lr_del(self.main_router_name).execute(check_error=True)
        cmd = commands.ConnectChassisRouterToMainRouterCommand(
            self.nb_api, self.fake_chassis, self.hcg_id)
        self.assertRaises(
            exceptions.ReconcileError,
            cmd.execute,
            check_error=True
        )

    def test_connect_non_existing_router_to_main_router(self):
        self.nb_api.lr_del(self.chassis_router_name).execute(check_error=True)
        cmd = commands.ConnectChassisRouterToMainRouterCommand(
            self.nb_api, self.fake_chassis, self.hcg_id)
        self.assertRaises(
            exceptions.ReconcileError,
            cmd.execute,
            check_error=True
        )


class ReconcileChassisCommandTestCase(BgpCommandsBase):
    PeerConnectionAttributes = namedtuple('PeerConnectionAttributes',
                                          ['lrp_name', 'lrp_ip', 'switch_ip'])

    def setUp(self):
        super().setUp()
        self.main_router_name = _get_unique_name()
        cfg.CONF.set_override('main_router_name', self.main_router_name, 'bgp')

    def _create_chassis(
            self, name=None, index=None):
        chassis_name = name or _get_unique_name("chassis")

        chassis_external_ids = {}
        if index is not None:
            chassis_external_ids[
                constants.OVN_BGP_CHASSIS_INDEX_KEY] = str(index)

        return self.add_fake_chassis(
            chassis_name, f'172.24.4.{index or 0}',
            external_ids=chassis_external_ids)

    def _validate_hcg_created(self, chassis_name):
        hcg_name = helpers.get_hcg_name(chassis_name)
        hcg = self.nb_api.db_find(
            'HA_Chassis_Group',
            ('name', '=', hcg_name)
        ).execute(check_error=True)
        self.assertTrue(hcg)
        return hcg[0]

    def _validate_chassis_router_created(self, chassis_name):
        router_name = helpers.get_chassis_router_name(chassis_name)
        router = self.nb_api.lr_get(router_name).execute(check_error=True)
        self.assertEqual(router_name, router.name)
        self.assertEqual(chassis_name, router.options.get('chassis'))
        return router

    def _validate_main_router_connection(self, chassis_name):
        chassis_router_name = helpers.get_chassis_router_name(chassis_name)

        lrp_main_name = helpers.get_lrp_name(
            self.main_router_name, chassis_router_name)
        lrp_chassis_name = helpers.get_lrp_name(
            chassis_router_name, self.main_router_name)

        lrp_main = self.nb_api.lrp_get(lrp_main_name).execute(check_error=True)
        lrp_chassis = self.nb_api.lrp_get(lrp_chassis_name).execute(
            check_error=True)

        self.assertEqual([lrp_chassis_name], lrp_main.peer)
        self.assertEqual([lrp_main_name], lrp_chassis.peer)

    def test_reconcile_chassis_basic(self):
        chassis = self._create_chassis(index=1)

        # Create main router first (prerequisite)
        commands.ReconcileMainRouterCommand(self.nb_api).execute(
            check_error=True)

        commands.ReconcileChassisCommand(
            self.nb_api, self.sb_api, chassis
        ).execute(check_error=True)


        # Validate all components were created
        self._validate_hcg_created(chassis.name)
        self._validate_chassis_router_created(chassis.name)
        self._validate_main_router_connection(chassis.name)

    def test_reconcile_chassis_idempotent(self):
        chassis = self._create_chassis(index=1)

        commands.ReconcileMainRouterCommand(self.nb_api).execute(
            check_error=True)

        cmd = commands.ReconcileChassisCommand(
            self.nb_api, self.sb_api, chassis)
        cmd.execute(check_error=True)
        # Run again to check idempotency
        cmd.execute(check_error=True)

        self._validate_hcg_created(chassis.name)
        self._validate_chassis_router_created(chassis.name)
        self._validate_main_router_connection(chassis.name)

    def test_reconcile_chassis_with_existing_components(self):
        chassis = self._create_chassis(index=1)
        hcg_name = helpers.get_hcg_name(chassis.name)
        router_name = helpers.get_chassis_router_name(chassis.name)

        # Create main router first
        commands.ReconcileMainRouterCommand(self.nb_api).execute(
            check_error=True)

        # Pre-create HCG with different settings
        self.nb_api.ha_chassis_group_add(hcg_name).execute(check_error=True)

        # Pre-create router with wrong chassis
        self.nb_api.lr_add(
            router_name,
            options={'chassis': 'wrong-chassis'}
        ).execute(check_error=True)

        # Execute command should update existing components
        commands.ReconcileChassisCommand(
            self.nb_api, self.sb_api, chassis
        ).execute(check_error=True)

        # Validate components were updated correctly
        router = self.nb_api.lr_get(router_name).execute(check_error=True)
        self.assertEqual(chassis.name, router.options.get('chassis'))

    def test_reconcile_chassis_missing_main_router(self):
        chassis = self._create_chassis(index=1)

        cmd = commands.ReconcileChassisCommand(
            self.nb_api, self.sb_api, chassis)
        self.assertRaises(
            exceptions.ReconcileError,
            cmd.execute,
            check_error=True
        )

    def test_reconcile_chassis_invalid_index(self):
        chassis = self._create_chassis(index=1)
        chassis.external_ids[constants.OVN_BGP_CHASSIS_INDEX_KEY] = 'invalid'

        cmd = commands.ReconcileChassisCommand(
            self.nb_api, self.sb_api, chassis)
        self.assertRaises(
            exceptions.ReconcileError,
            cmd.execute,
            check_error=True
        )

    def test_reconcile_chassis_missing_index(self):
        chassis = self._create_chassis()
        cmd = commands.ReconcileChassisCommand(
            self.nb_api, self.sb_api, chassis)

        self.assertRaises(
            exceptions.ReconcileError,
            cmd.execute,
            check_error=True
        )

    def test_reconcile_chassis_mac_manager_registration(self):
        chassis = self._create_chassis(index=1)

        # Create main router first
        commands.ReconcileMainRouterCommand(self.nb_api).execute(
            check_error=True)

        commands.ReconcileChassisCommand(
            self.nb_api, self.sb_api, chassis
        ).execute(check_error=True)

        # Verify router is registered with MAC manager
        mm = helpers.LrpMacManager.get_instance()
        router_name = helpers.get_chassis_router_name(chassis.name)
        self.assertIn(router_name, mm.known_routers)

        # Verify MAC prefix is correct based on chassis index
        expected_chassis_index = int(
            chassis.external_ids[constants.OVN_BGP_CHASSIS_INDEX_KEY])
        router_info = mm.known_routers[router_name]

        # MAC prefix should be based on chassis index
        base_mac = bgp_config.get_bgp_mac_base()
        hex_str = f"{expected_chassis_index:0{4}x}"
        expected_prefix = f'{base_mac}:{hex_str[0:2]}:{hex_str[2:4]}'
        self.assertEqual(expected_prefix, router_info.mac_prefix)
