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


class GatewayIPEventTestCaseBase(bgp_base.BaseBgpNbIdlTestCase):
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


class GatewayIPCreatedEventTestCase(GatewayIPEventTestCaseBase):
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


class GatewayIPUpdatedEventTestCase(GatewayIPEventTestCaseBase):
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
