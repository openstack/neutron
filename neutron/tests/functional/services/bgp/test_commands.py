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


from oslo_config import cfg
from oslo_utils import uuidutils
from ovsdbapp.backend.ovs_idl import idlutils

from neutron.agent.linux import ip_lib
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


class TestCaseWithOutputPort(bgp.BaseBgpNbIdlTestCase):
    def _is_bgp_supported(self):
        return bgp.is_policy_output_port_column_supported(self.nb_api.idl)


class LsAddCommandTestCase(bgp.BaseBgpNbIdlTestCase, _AddBaseCommand):
    table = 'Logical_Switch'
    command = commands._LsAddCommand


class LrAddCommandTestCase(bgp.BaseBgpNbIdlTestCase,
                           _AddBaseCommand):
    table = 'Logical_Router'
    command = commands._LrAddCommand


class LspAddCommandTestCase(bgp.BaseBgpNbIdlTestCase, _AddBaseCommand):
    table = 'Logical_Switch_Port'
    command = commands._LspAddCommand

    def setUp(self):
        super().setUp()
        self.ls_name = _get_unique_name()
        self.nb_api.ls_add(self.ls_name).execute(check_error=True)

    def create_row(self, name, **kwargs):
        return self.command(self.nb_api, self.ls_name, name, **kwargs).execute(
            check_error=True)

    def test_create_existing_with_different_attributes(self):
        name = _get_unique_name()
        self.create_row(
            name, options={'peer-port': 'lsp-peer-1'},
            external_ids={'id1': 'value1'})
        lsp = self._assert_table_row_exists(name)
        self.assertEqual(lsp.options.get('peer-port'), 'lsp-peer-1')
        self.assertEqual(lsp.external_ids.get('id1'), 'value1')

        # Should update the options
        self.create_row(name, options={'peer-port': 'lsp-peer-2'},
                        external_ids={'id1': 'value2'})
        lsp = self._assert_table_row_exists(name)
        self.assertEqual(lsp.options.get('peer-port'), 'lsp-peer-2')
        self.assertEqual(lsp.external_ids.get('id1'), 'value2')


class LrpAddCommandTestCase(bgp.BaseBgpNbIdlTestCase, _AddBaseCommand):
    table = 'Logical_Router_Port'
    command = commands._LrpAddCommand

    def setUp(self):
        super().setUp()
        self.lr_name = _get_unique_name()
        self.nb_api.lr_add(self.lr_name).execute(check_error=True)

    def create_row(self, name, **kwargs):
        return self.command(
            self.nb_api, self.lr_name, name, **kwargs).execute(
                check_error=True)

    def test_create_existing_with_different_attributes(self):
        name = _get_unique_name()
        self.create_row(name, networks=['192.168.1.0/24'], peer='lrp-peer-1')
        lrp = self._assert_table_row_exists(name)

        bad_mac = '00:00:00:00:00:00'

        # Set a different MAC address
        self.nb_api.db_set(
            'Logical_Router_Port', name,
            mac=bad_mac).execute(check_error=True)
        self.assertEqual(lrp.mac, bad_mac)
        self.assertEqual(lrp.networks, ['192.168.1.0/24'])
        self.assertEqual(lrp.peer, ['lrp-peer-1'])

        # Should update the MAC address
        self.create_row(name, networks=['192.168.2.0/24'], peer='lrp-peer-2')
        lrp = self._assert_table_row_exists(name)
        self.assertNotEqual(lrp.mac, bad_mac)
        self.assertEqual(lrp.networks, ['192.168.2.0/24'])
        self.assertEqual(lrp.peer, ['lrp-peer-2'])


class HAChassisGroupAddCommandTestCase(bgp.BaseBgpNbIdlTestCase,
                                       _AddBaseCommand):
    table = 'HA_Chassis_Group'
    command = commands._HAChassisGroupAddCommand


class CreateSwitchWithLocalnetCommandTestCase(bgp.BaseBgpNbIdlTestCase):
    def _validate_localnet_port(self, ls_name, network_name):
        """Validate localnet port was created correctly"""
        localnet_lsp_name = helpers.get_lsp_localnet_name(ls_name)
        lsp = self.nb_api.lookup('Logical_Switch_Port', localnet_lsp_name)
        self.assertEqual(lsp.type, 'localnet')
        self.assertEqual(lsp.options.get('network_name'), network_name)
        self.assertEqual(lsp.addresses, ['unknown'])

    def _create_lsp(self, ls_name, lsp_name, **attrs):
        """Helper to create LSP with wrong attributes"""
        self.nb_api.lsp_add(ls_name, lsp_name, **attrs).execute(
            check_error=True)

    def test_create_new_switch_with_localnet(self):
        ls_name = _get_unique_name()
        network_name = 'test-network'

        commands.CreateSwitchWithLocalnetCommand(
            self.nb_api, ls_name, network_name).execute(check_error=True)

        ls = self.nb_api.ls_get(ls_name).execute(check_error=True)
        self.assertEqual(ls.name, ls_name)

        self._validate_localnet_port(ls_name, network_name)

    def test_create_existing_switch_updates_localnet(self):
        ls_name = _get_unique_name()
        network_name = 'test-network'

        # Create switch first
        self.nb_api.ls_add(ls_name).execute(check_error=True)

        # Execute command
        commands.CreateSwitchWithLocalnetCommand(
            self.nb_api, ls_name, network_name).execute(check_error=True)

        # Verify localnet port was created even with existing switch
        self._validate_localnet_port(ls_name, network_name)

    def test_create_with_existing_localnet_wrong_attributes(self):
        """Test corner case where localnet port exists with wrong attributes"""
        ls_name = _get_unique_name()
        network_name = 'test-network'

        # Create switch and localnet port with wrong attributes
        self.nb_api.ls_add(ls_name).execute(check_error=True)
        localnet_lsp_name = helpers.get_lsp_localnet_name(ls_name)
        self._create_lsp(
            ls_name, localnet_lsp_name,
            type='patch',  # wrong type
            options={'wrong': 'value'},  # wrong options
            addresses=['00:00:00:00:00:01']  # wrong addresses
        )

        # Execute command should fix the attributes
        commands.CreateSwitchWithLocalnetCommand(
            self.nb_api, ls_name, network_name).execute(check_error=True)

        # Verify attributes were corrected
        self._validate_localnet_port(ls_name, network_name)


class CreateLspLocalnetCommandTestCase(bgp.BaseBgpNbIdlTestCase):
    def _validate_localnet_port(self, ls_name, network_name):
        """Validate localnet port was created correctly"""
        localnet_lsp_name = helpers.get_lsp_localnet_name(ls_name)
        lsp = self.nb_api.lookup('Logical_Switch_Port', localnet_lsp_name)
        self.assertEqual(lsp.type, 'localnet')
        self.assertEqual(lsp.options.get('network_name'), network_name)
        self.assertEqual(lsp.addresses, ['unknown'])
        return lsp

    def _create_lsp(self, ls_name, lsp_name, **attrs):
        self.nb_api.lsp_add(ls_name, lsp_name, **attrs).execute(
            check_error=True)

    def setUp(self):
        super().setUp()
        self.ls_name = _get_unique_name()
        self.nb_api.ls_add(self.ls_name).execute(check_error=True)

    def test_create_localnet_port(self):
        network_name = 'test-network'

        commands.CreateLspLocalnetCommand(
            self.nb_api, self.ls_name, network_name).execute(check_error=True)

        self._validate_localnet_port(self.ls_name, network_name)

    def test_update_existing_localnet_with_different_network(self):
        network_name1 = 'test-network-1'
        network_name2 = 'test-network-2'

        # Create first localnet port
        commands.CreateLspLocalnetCommand(
            self.nb_api, self.ls_name, network_name1).execute(check_error=True)

        # Update with different network name
        commands.CreateLspLocalnetCommand(
            self.nb_api, self.ls_name, network_name2).execute(check_error=True)

        # Verify network name was updated
        self._validate_localnet_port(self.ls_name, network_name2)

    def test_fix_localnet_with_wrong_type_and_options(self):
        network_name = 'test-network'
        localnet_lsp_name = helpers.get_lsp_localnet_name(self.ls_name)

        self._create_lsp(
            self.ls_name, localnet_lsp_name,
            type='router',  # wrong type
            options={'router-port': 'wrong'},  # wrong options
            addresses=['router']  # wrong addresses
        )

        commands.CreateLspLocalnetCommand(
            self.nb_api, self.ls_name, network_name).execute(check_error=True)

        lsp = self._validate_localnet_port(self.ls_name, network_name)
        self.assertNotIn('router-port', lsp.options)


class LrPolicyAddCommandTestCase(TestCaseWithOutputPort):
    table = 'Logical_Router_Policy'
    command = commands._LrPolicyAddCommand

    def setUp(self):
        super().setUp()
        self.router_name = _get_unique_name()
        self.lrp_inport_name = _get_unique_name()
        self.lrp_nexthop_name = _get_unique_name()
        with self.nb_api.transaction(check_error=True) as txn:
            txn.add(self.nb_api.lr_add(self.router_name))
            txn.add(self.nb_api.lrp_add(
                self.router_name,
                self.lrp_inport_name,
                mac="00:00:00:00:00:01",
                networks=["192.168.1.1/30"]))
            txn.add(self.nb_api.lrp_add(
                self.router_name,
                self.lrp_nexthop_name,
                mac="00:00:00:00:00:02",
                networks=["192.168.1.2/30"]))

    @bgp.requires_ovn_version_with_bgp()
    def test_create_new_policy(self):
        priority = 100
        match = 'inport==\"%s\"' % self.lrp_inport_name
        action = 'reroute'
        nexthop_port = self.nb_api.lrp_get(self.lrp_nexthop_name).execute(
            check_error=True)
        commands._LrPolicyAddCommand(
            self.nb_api,
            router=self.router_name,
            priority=priority,
            match=match,
            action=action,
            output_port=nexthop_port).execute(check_error=True)

        expected_exthops = [ip_lib.get_ipv6_lladdr(nexthop_port.mac)]
        policy = self.nb_api.lr_policy_list(
            self.router_name).execute(check_error=True)[0]
        self.assertEqual(priority, policy.priority)
        self.assertEqual(self.lrp_nexthop_name, policy.output_port[0].name)
        self.assertCountEqual(expected_exthops, policy.nexthops)

    @bgp.requires_ovn_version_with_bgp()
    def test_create_existing_policy(self):
        priority = 100
        match = 'inport==\"%s\"' % self.lrp_inport_name
        action = 'reroute'
        nexthop_port = self.nb_api.lrp_get(self.lrp_nexthop_name).execute(
            check_error=True)

        commands._LrPolicyAddCommand(
            self.nb_api,
            router=self.router_name,
            priority=priority,
            match=match,
            action=action,
            output_port=nexthop_port,
            nexthops=['192.168.1.2']).execute(check_error=True)

        commands._LrPolicyAddCommand(
            self.nb_api,
            router=self.router_name,
            priority=priority,
            match=match,
            action=action,
            output_port=nexthop_port).execute(check_error=True)

        expected_exthops = [ip_lib.get_ipv6_lladdr(nexthop_port.mac)]
        policy = self.nb_api.lr_policy_list(
            self.router_name).execute(check_error=True)[0]
        self.assertEqual(priority, policy.priority)
        self.assertEqual(self.lrp_nexthop_name, policy.output_port[0].name)
        self.assertCountEqual(expected_exthops, policy.nexthops)

        commands._LrPolicyAddCommand(
            self.nb_api,
            router=self.router_name,
            priority=priority,
            match=match,
            action=action,
            output_port=nexthop_port).execute(check_error=True)

        policies = self.nb_api.lr_policy_list(
            self.router_name).execute(check_error=True)
        self.assertEqual(1, len(policies))

    @bgp.requires_ovn_version_with_bgp()
    def test_create_policy_with_nexthops(self):
        priority = 100
        match = 'inport==\"%s\"' % self.lrp_inport_name
        action = 'reroute'
        output_port = self.nb_api.lrp_get(self.lrp_nexthop_name).execute(
            check_error=True)
        nexthops = ['192.168.1.2']
        commands._LrPolicyAddCommand(
            self.nb_api,
            router=self.router_name,
            priority=priority,
            match=match,
            action=action,
            output_port=output_port,
            nexthops=nexthops).execute(check_error=True)

        policy = self.nb_api.lr_policy_list(
            self.router_name).execute(check_error=True)[0]
        self.assertEqual(priority, policy.priority)
        self.assertEqual(match, policy.match)
        self.assertEqual(action, policy.action)
        self.assertEqual(self.lrp_nexthop_name, policy.output_port[0].name)
        self.assertCountEqual(nexthops, policy.nexthops)


class ReconcileRouterCommandTestCase(bgp.BaseBgpNbIdlTestCase):
    def _validate_router_created(self, router_name):
        router = self.nb_api.lr_get(router_name).execute(check_error=True)
        self.assertEqual(router.name, router_name)

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


class ReconcileMainRouterCommandTestCase(bgp.BaseBgpNbIdlTestCase):
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


class ReconcileChassisRouterCommandTestCase(bgp.BaseBgpNbIdlTestCase):
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


class ConnectChassisRouterToMainRouterCommandTestCase(
        bgp.BaseBgpNbIdlTestCase):
    def setUp(self):
        super().setUp()
        self.main_router_name = _get_unique_name()
        cfg.CONF.set_override('main_router_name', self.main_router_name, 'bgp')

        self.fake_chassis = _create_fake_chassis()
        self.chassis_router_name = helpers.get_chassis_router_name(
            self.fake_chassis.name)

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


class ConnectRouterToSwitchCommandTestCase(bgp.BaseBgpNbIdlTestCase):
    def setUp(self):
        super().setUp()
        self.lr_name = _get_unique_name()
        self.ls_name = _get_unique_name()

        self.nb_api.lr_add(self.lr_name).execute(check_error=True)
        self.nb_api.ls_add(self.ls_name).execute(check_error=True)

    @bgp.requires_ovn_version_with_bgp()
    def test_connect_router_to_switch_without_ip(self):
        commands.ConnectRouterToSwitchCommand(
            self.nb_api, self.lr_name, self.ls_name).execute(check_error=True)

        lrp_name = helpers.get_lrp_name(self.lr_name, self.ls_name)
        lrp = self.nb_api.lrp_get(lrp_name).execute(check_error=True)
        self.assertEqual([], lrp.networks)

        lsp_name = helpers.get_lsp_name(self.ls_name, self.lr_name)
        lsp = self.nb_api.lsp_get(lsp_name).execute(check_error=True)
        self.assertEqual('router', lsp.type)
        self.assertEqual(['router'], lsp.addresses)
        self.assertEqual(lrp_name, lsp.options.get('router-port'))

    def test_connect_router_to_switch_with_ip(self):
        lrp_ip = '192.168.1.1/24'

        commands.ConnectRouterToSwitchCommand(
            self.nb_api, self.lr_name, self.ls_name, [lrp_ip]
        ).execute(check_error=True)

        lrp_name = helpers.get_lrp_name(self.lr_name, self.ls_name)
        lrp = self.nb_api.lrp_get(lrp_name).execute(check_error=True)
        self.assertEqual([lrp_ip], lrp.networks)

    @bgp.requires_ovn_version_with_bgp()
    def test_connect_existing_with_different_attributes(self):
        lrp_name = helpers.get_lrp_name(self.lr_name, self.ls_name)
        lsp_name = helpers.get_lsp_name(self.ls_name, self.lr_name)

        # Create LRP and LSP with wrong attributes
        self.nb_api.lrp_add(
            self.lr_name, lrp_name,
            mac='00:00:00:00:00:01',  # wrong MAC
            networks=['10.0.0.1/24']  # wrong networks
        ).execute(check_error=True)

        self.nb_api.lsp_add(
            self.ls_name, lsp_name,
            type='patch',  # wrong type
            addresses=['00:00:00:00:00:01'],  # wrong addresses
            options={'peer': 'wrong-peer'}
        ).execute(check_error=True)

        commands.ConnectRouterToSwitchCommand(
            self.nb_api, self.lr_name, self.ls_name).execute(check_error=True)

        lrp = self.nb_api.lrp_get(lrp_name).execute(check_error=True)
        self.assertEqual([], lrp.networks)

        lsp = self.nb_api.lsp_get(lsp_name).execute(check_error=True)
        self.assertEqual('router', lsp.type)
        self.assertEqual(['router'], lsp.addresses)
        self.assertEqual(lrp_name, lsp.options.get('router-port'))


class ConnectChassisRouterToSwitchCommandTestCase(bgp.BaseBgpNbIdlTestCase):
    def setUp(self):
        super().setUp()
        self.lr_name = _get_unique_name()
        self.ls_name = _get_unique_name()

        self.nb_api.lr_add(self.lr_name).execute(check_error=True)
        self.nb_api.ls_add(self.ls_name).execute(check_error=True)

    def test_sets_external_ids(self):
        network_name = _get_unique_name()
        commands.ConnectChassisRouterToSwitchCommand(
            self.nb_api, self.lr_name, self.ls_name, network_name
        ).execute(check_error=True)

        lrp_name = helpers.get_lrp_name(self.lr_name, self.ls_name)
        lrp = self.nb_api.lrp_get(lrp_name).execute(check_error=True)
        self.assertEqual(
            network_name,
            lrp.external_ids[constants.LRP_NETWORK_NAME_EXT_ID_KEY])


class ReconcileChassisCommandTestCase(bgp.BaseBgpTestCase):
    def setUp(self):
        super().setUp()
        self.main_router_name = _get_unique_name()
        cfg.CONF.set_override('main_router_name', self.main_router_name, 'bgp')

    def _create_chassis(self, name=None, ip=1, network_names=None):
        chassis_name = name or _get_unique_name("chassis")
        ext_ids = {}
        if network_names:
            ext_ids[constants.CHASSIS_BGP_BRIDGES_EXT_ID_KEY] = ','.join(
                network_names)
        return self.add_fake_chassis(
            chassis_name, f'172.24.4.{ip}',
            external_ids=ext_ids)

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

    def _validate_chassis_router_policies(self, chassis_name, router, peers):
        def _check_policy(policy, peer):
            peer_switch_name = helpers.get_chassis_peer_switch_name(
                chassis_name, peer)
            output_lrp = helpers.get_lrp_name(router.name,
                                              self.main_router_name)
            inport_lrp = helpers.get_lrp_name(router.name, peer_switch_name)
            return (policy.match == f'inport==\"{inport_lrp}\"' and
                    policy.action == 'reroute' and
                    policy.output_port[0].name == output_lrp)

        checked_policies = []
        for peer in peers:
            for policy in router.policies:
                if _check_policy(policy, peer):
                    checked_policies.append(policy)
                    break
            else:
                self.fail(f"Policy for peer {peer} not found")

        self.assertEqual(len(router.policies), len(checked_policies))

    @bgp.requires_ovn_version_with_bgp()
    def test_reconcile_chassis_basic(self):
        peers = ["bgp1", "bgp2"]
        chassis = self._create_chassis(network_names=peers)

        # Create main router first (prerequisite)
        commands.ReconcileMainRouterCommand(self.nb_api).execute(
            check_error=True)

        commands.ReconcileChassisCommand(
            self.nb_api, chassis).execute(check_error=True)

        router = self.nb_api.lr_get(
            helpers.get_chassis_router_name(chassis.name)).execute(
                check_error=True)
        # Validate all components were created
        self._validate_hcg_created(chassis.name)
        self._validate_chassis_router_created(chassis.name)
        self._validate_main_router_connection(chassis.name)
        self._validate_chassis_router_policies(chassis.name, router, peers)

    @bgp.requires_ovn_version_with_bgp()
    def test_reconcile_chassis_idempotent(self):
        peers = ["bgp1", "bgp2"]
        chassis = self._create_chassis(network_names=peers)

        commands.ReconcileMainRouterCommand(self.nb_api).execute(
            check_error=True)

        cmd = commands.ReconcileChassisCommand(self.nb_api, chassis)
        cmd.execute(check_error=True)
        # Run again to check idempotency
        cmd.execute(check_error=True)

        router = self.nb_api.lr_get(
            helpers.get_chassis_router_name(chassis.name)).execute(
                check_error=True)
        self._validate_hcg_created(chassis.name)
        self._validate_chassis_router_created(chassis.name)
        self._validate_main_router_connection(chassis.name)
        self._validate_chassis_router_policies(chassis.name, router, peers)

    def test_reconcile_chassis_with_existing_components(self):
        chassis = self._create_chassis()
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
            self.nb_api, chassis).execute(check_error=True)

        # Validate components were updated correctly
        router = self.nb_api.lr_get(router_name).execute(check_error=True)
        self.assertEqual(chassis.name, router.options.get('chassis'))

    def test_reconcile_chassis_missing_main_router(self):
        chassis = self._create_chassis()

        cmd = commands.ReconcileChassisCommand(self.nb_api, chassis)
        self.assertRaises(
            exceptions.ReconcileError,
            cmd.execute,
            check_error=True
        )
