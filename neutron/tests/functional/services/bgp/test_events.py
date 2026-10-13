# Copyright 2025 Red Hat, LLC
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

from neutron_lib import constants as n_lib_const
from oslo_utils import uuidutils
import testtools

from neutron.common.ovn import constants as ovn_const
from neutron.common import utils as common_utils
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import (
    commands as ovn_commands)
from neutron.services.bgp import events
from neutron.tests.functional.services import bgp as bgp_base


class EventTestCaseBase(bgp_base.BaseBgpNbIdlTestCase):
    def setUp(self):
        super().setUp()
        self.reconciler = mock.Mock(nb_api=self.nb_api)
        self.event = self._create_event()
        self.nb_api.idl.notify_handler.watch_event(self.event)

    def _create_event(self):
        raise NotImplementedError

    def _create_provider_switch(self, net_id):
        ls_name = f'neutron-{net_id}'
        with self.nb_api.transaction(check_error=True) as txn:
            txn.add(self.nb_api.ls_add(ls_name))
            txn.add(self.nb_api.db_set(
                'Logical_Switch', ls_name,
                external_ids={
                    ovn_const.OVN_NETTYPE_EXT_ID_KEY: n_lib_const.TYPE_FLAT}))


class GatewayIPCreatedEventTestCase(EventTestCaseBase):
    def _create_event(self):
        return events.GatewayIPCreatedEvent(self.reconciler)

    def test_gateway_ip_created_event_fires_on_dhcp_options_create(self):
        net_id = uuidutils.generate_uuid()
        self._create_provider_switch(net_id)
        with self.nb_api.transaction(check_error=True) as txn:
            txn.add(ovn_commands.AddDHCPOptionsCommand(
                self.nb_api, net_id, may_exist=False,
                cidr='10.0.0.0/24',
                options={'router': '10.0.0.1'},
                external_ids={
                    ovn_const.OVN_NETWORK_ID_EXT_ID_KEY: net_id}))

        common_utils.wait_until_true(
            lambda: self.reconciler.reconcile.called,
            sleep=0.2,
            timeout=5,
            exception=AssertionError(
                'GatewayIPCreatedEvent did not trigger reconcile'))

        call_args = self.reconciler.reconcile.call_args[0]
        self.assertEqual('10.0.0.0/24', call_args[2].cidr)
        self.assertEqual({'router': '10.0.0.1'}, call_args[2].options)

    def test_gateway_ip_created_event_does_not_fire_without_router_option(
            self):
        net_id = uuidutils.generate_uuid()
        self._create_provider_switch(net_id)
        with self.nb_api.transaction(check_error=True) as txn:
            txn.add(ovn_commands.AddDHCPOptionsCommand(
                self.nb_api, net_id, may_exist=False,
                cidr='10.0.0.0/24',
                options={},
                external_ids={
                    ovn_const.OVN_NETWORK_ID_EXT_ID_KEY: net_id}))

        with testtools.ExpectedException(AssertionError):
            common_utils.wait_until_true(
                lambda: self.reconciler.reconcile.called,
                sleep=0.2,
                timeout=2,
                exception=AssertionError(
                    'Reconcile should not be called when DHCP options have '
                    'no router'))


class GatewayIPUpdatedEventTestCase(EventTestCaseBase):
    def _create_event(self):
        return events.GatewayIPUpdatedEvent(self.reconciler)

    def test_gateway_ip_updated_event_fires_when_router_option_changes(self):
        net_id = uuidutils.generate_uuid()
        self._create_provider_switch(net_id)
        with self.nb_api.transaction(check_error=True) as txn:
            txn.add(ovn_commands.AddDHCPOptionsCommand(
                self.nb_api, net_id, may_exist=False,
                cidr='10.0.0.0/24',
                options={'router': '10.0.0.1'},
                external_ids={
                    ovn_const.OVN_NETWORK_ID_EXT_ID_KEY: net_id}))

        # Clear so we only observe the update event
        self.reconciler.reconcile.reset_mock()

        rows = self.nb_api.db_find_rows(
            'DHCP_Options',
            ('external_ids', '=', {
                ovn_const.OVN_NETWORK_ID_EXT_ID_KEY: net_id}),
            ('cidr', '=', '10.0.0.0/24'),
        ).execute(check_error=True)

        self.nb_api.db_set(
            'DHCP_Options', rows[0].uuid,
            options={'router': '10.0.0.2'}).execute(check_error=True)

        common_utils.wait_until_true(
            lambda: self.reconciler.reconcile.called,
            sleep=0.2,
            timeout=5,
            exception=AssertionError(
                'GatewayIPUpdatedEvent did not trigger reconcile'))

        call_args = self.reconciler.reconcile.call_args[0]
        self.assertEqual({'router': '10.0.0.2'}, call_args[2].options)
        self.assertEqual('10.0.0.0/24', call_args[2].cidr)


class FIPChangedEventTestCase(EventTestCaseBase):
    def _create_event(self):
        return events.FIPChangedEvent(self.reconciler)

    def _create_router_with_fip(self, net_id, external_ip):
        router_name = 'neutron-' + uuidutils.generate_uuid()
        with self.nb_api.transaction(check_error=True) as txn:
            txn.add(self.nb_api.lr_add(router_name))
            txn.add(bgp_base.AddNATToRouterCommand(
                self.nb_api, router_name,
                type='dnat_and_snat',
                logical_ip='10.0.0.100',
                external_ip=external_ip,
                external_ids={ovn_const.OVN_FIP_NET_ID: net_id},
            ))
        return router_name

    def test_fip_changed_event_fires_on_nat_create(self):
        net_id = uuidutils.generate_uuid()
        self._create_provider_switch(net_id)

        self._create_router_with_fip(net_id, '172.24.4.10')

        common_utils.wait_until_true(
            lambda: self.reconciler.reconcile.called,
            sleep=0.2,
            timeout=5,
            exception=AssertionError(
                'FIPChangedEvent did not trigger reconcile on create'))

        passed_nat = self.reconciler.reconcile.call_args[0][2]
        self.assertEqual('dnat_and_snat', passed_nat.type)
        self.assertEqual('172.24.4.10', passed_nat.external_ip)

    def test_fip_changed_event_fires_on_nat_delete(self):
        net_id = uuidutils.generate_uuid()
        self._create_provider_switch(net_id)

        router_name = self._create_router_with_fip(net_id, '172.24.4.10')

        self.reconciler.reconcile.reset_mock()

        self.nb_api.lr_nat_del(
            router_name,
            nat_type='dnat_and_snat',
            match_ip='172.24.4.10',
        ).execute(check_error=True)

        common_utils.wait_until_true(
            lambda: self.reconciler.reconcile.called,
            sleep=0.2,
            timeout=5,
            exception=AssertionError(
                'FIPChangedEvent did not trigger reconcile on delete'))

    def test_fip_changed_event_does_not_fire_for_non_flat_network(self):
        net_id = uuidutils.generate_uuid()
        ls_name = f'neutron-{net_id}'
        with self.nb_api.transaction(check_error=True) as txn:
            txn.add(self.nb_api.ls_add(ls_name))
            txn.add(self.nb_api.db_set(
                'Logical_Switch', ls_name,
                external_ids={
                    ovn_const.OVN_NETTYPE_EXT_ID_KEY: 'vlan'}))

        self._create_router_with_fip(net_id, '172.24.4.10')

        with testtools.ExpectedException(AssertionError):
            common_utils.wait_until_true(
                lambda: self.reconciler.reconcile.called,
                sleep=0.2,
                timeout=2,
                exception=AssertionError(
                    'Reconcile should not be called for non-flat network'))

    def test_fip_changed_event_does_not_fire_for_snat(self):
        net_id = uuidutils.generate_uuid()
        self._create_provider_switch(net_id)

        router_name = 'neutron-' + uuidutils.generate_uuid()
        with self.nb_api.transaction(check_error=True) as txn:
            txn.add(self.nb_api.lr_add(router_name))
            txn.add(bgp_base.AddNATToRouterCommand(
                self.nb_api, router_name,
                type='snat',
                logical_ip='10.0.0.0/24',
                external_ip='172.24.4.10',
                external_ids={ovn_const.OVN_FIP_NET_ID: net_id},
            ))

        with testtools.ExpectedException(AssertionError):
            common_utils.wait_until_true(
                lambda: self.reconciler.reconcile.called,
                sleep=0.2,
                timeout=2,
                exception=AssertionError(
                    'Reconcile should not be called for snat'))


class VirtualPortChangedEventTestCase(EventTestCaseBase):
    def _create_event(self):
        return events.VirtualPortChangedEvent(self.reconciler)

    def _create_virtual_port(self, net_id, virtual_ip, vport_name=None):
        ls_name = f'neutron-{net_id}'
        vport_name = vport_name or uuidutils.generate_uuid()
        with self.nb_api.transaction(check_error=True) as txn:
            txn.add(self.nb_api.lsp_add(
                ls_name, vport_name,
                type=ovn_const.LSP_TYPE_VIRTUAL,
                options={
                    ovn_const.LSP_OPTIONS_VIRTUAL_IP_KEY: virtual_ip,
                    ovn_const.LSP_OPTIONS_VIRTUAL_PARENTS_KEY: 'parent-0',
                },
                external_ids={
                    ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY: ls_name},
            ))
        return vport_name

    def test_fires_on_virtual_port_create(self):
        net_id = uuidutils.generate_uuid()
        self._create_provider_switch(net_id)

        self._create_virtual_port(net_id, '10.0.0.100')

        common_utils.wait_until_true(
            lambda: self.reconciler.reconcile.called,
            sleep=0.2,
            timeout=5,
            exception=AssertionError(
                'VirtualPortChangedEvent did not trigger reconcile '
                'on create'))

        passed_lsp = self.reconciler.reconcile.call_args[0][2]
        self.assertEqual(ovn_const.LSP_TYPE_VIRTUAL, passed_lsp.type)
        self.assertEqual(
            '10.0.0.100',
            passed_lsp.options[ovn_const.LSP_OPTIONS_VIRTUAL_IP_KEY])

    def test_fires_on_virtual_port_delete(self):
        net_id = uuidutils.generate_uuid()
        self._create_provider_switch(net_id)

        vport_name = self._create_virtual_port(net_id, '10.0.0.100')

        self.reconciler.reconcile.reset_mock()

        self.nb_api.lsp_del(vport_name).execute(check_error=True)

        common_utils.wait_until_true(
            lambda: self.reconciler.reconcile.called,
            sleep=0.2,
            timeout=5,
            exception=AssertionError(
                'VirtualPortChangedEvent did not trigger reconcile '
                'on delete'))

    def test_does_not_fire_for_non_flat_network(self):
        net_id = uuidutils.generate_uuid()
        ls_name = f'neutron-{net_id}'
        with self.nb_api.transaction(check_error=True) as txn:
            txn.add(self.nb_api.ls_add(ls_name))
            txn.add(self.nb_api.db_set(
                'Logical_Switch', ls_name,
                external_ids={
                    ovn_const.OVN_NETTYPE_EXT_ID_KEY: 'vlan'}))

        self._create_virtual_port(net_id, '10.0.0.100')

        with testtools.ExpectedException(AssertionError):
            common_utils.wait_until_true(
                lambda: self.reconciler.reconcile.called,
                sleep=0.2,
                timeout=2,
                exception=AssertionError(
                    'Reconcile should not be called for non-flat network'))

    def test_does_not_fire_for_non_virtual_port(self):
        net_id = uuidutils.generate_uuid()
        self._create_provider_switch(net_id)

        ls_name = f'neutron-{net_id}'
        with self.nb_api.transaction(check_error=True) as txn:
            txn.add(self.nb_api.lsp_add(
                ls_name, uuidutils.generate_uuid(),
                external_ids={
                    ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY: ls_name},
            ))

        with testtools.ExpectedException(AssertionError):
            common_utils.wait_until_true(
                lambda: self.reconciler.reconcile.called,
                sleep=0.2,
                timeout=2,
                exception=AssertionError(
                    'Reconcile should not be called for non-virtual port'))


class VirtualPortTypeChangedEventTestCase(EventTestCaseBase):
    def _create_event(self):
        return events.VirtualPortTypeChangedEvent(self.reconciler)

    def test_fires_when_port_type_changes_to_virtual(self):
        net_id = uuidutils.generate_uuid()
        self._create_provider_switch(net_id)

        ls_name = f'neutron-{net_id}'
        port_name = uuidutils.generate_uuid()
        with self.nb_api.transaction(check_error=True) as txn:
            txn.add(self.nb_api.lsp_add(
                ls_name, port_name,
                external_ids={
                    ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY: ls_name},
            ))

        self.nb_api.db_set(
            'Logical_Switch_Port', port_name,
            type=ovn_const.LSP_TYPE_VIRTUAL,
            options={
                ovn_const.LSP_OPTIONS_VIRTUAL_IP_KEY: '10.0.0.100',
                ovn_const.LSP_OPTIONS_VIRTUAL_PARENTS_KEY: 'parent-0',
            },
        ).execute(check_error=True)

        common_utils.wait_until_true(
            lambda: self.reconciler.reconcile.called,
            sleep=0.2,
            timeout=5,
            exception=AssertionError(
                'VirtualPortTypeChangedEvent did not trigger reconcile '
                'when type changed to virtual'))

    def test_fires_when_port_type_changes_from_virtual(self):
        net_id = uuidutils.generate_uuid()
        self._create_provider_switch(net_id)

        ls_name = f'neutron-{net_id}'
        port_name = uuidutils.generate_uuid()
        with self.nb_api.transaction(check_error=True) as txn:
            txn.add(self.nb_api.lsp_add(
                ls_name, port_name,
                type=ovn_const.LSP_TYPE_VIRTUAL,
                options={
                    ovn_const.LSP_OPTIONS_VIRTUAL_IP_KEY: '10.0.0.100',
                    ovn_const.LSP_OPTIONS_VIRTUAL_PARENTS_KEY: 'parent-0',
                },
                external_ids={
                    ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY: ls_name},
            ))

        self.reconciler.reconcile.reset_mock()

        self.nb_api.db_set(
            'Logical_Switch_Port', port_name,
            type='',
        ).execute(check_error=True)

        common_utils.wait_until_true(
            lambda: self.reconciler.reconcile.called,
            sleep=0.2,
            timeout=5,
            exception=AssertionError(
                'VirtualPortTypeChangedEvent did not trigger reconcile '
                'when type changed from virtual'))

    def test_does_not_fire_for_non_virtual_type_change(self):
        net_id = uuidutils.generate_uuid()
        self._create_provider_switch(net_id)

        ls_name = f'neutron-{net_id}'
        port_name = uuidutils.generate_uuid()
        with self.nb_api.transaction(check_error=True) as txn:
            txn.add(self.nb_api.lsp_add(
                ls_name, port_name,
                type='localnet',
                external_ids={
                    ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY: ls_name},
            ))

        self.nb_api.db_set(
            'Logical_Switch_Port', port_name,
            type='',
        ).execute(check_error=True)

        with testtools.ExpectedException(AssertionError):
            common_utils.wait_until_true(
                lambda: self.reconciler.reconcile.called,
                sleep=0.2,
                timeout=2,
                exception=AssertionError(
                    'Reconcile should not be called for non-virtual '
                    'type change'))
