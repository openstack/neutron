# Copyright 2026 Red Hat, Inc.
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

import testtools

from neutron.agent.ovn.extensions.evpn import events as evpn_events
from neutron.agent.ovn.extensions.evpn import exceptions as evpn_exc
from neutron.agent.ovn.extensions.evpn import fsm as evpn_fsm
from neutron.agent.ovn.extensions.evpn import utils as evpn_utils
from neutron.common.ovn import constants as ovn_const
from neutron.common import utils as common_utils
from neutron.services.bgp import ovn as bgp_ovn
from neutron.services.evpn import constants as svc_const
from neutron.tests.functional.services import bgp as bgp_base

_OVN_SB_TABLES_WITH_PB = bgp_ovn.OVN_SB_TABLES + (
    'Datapath_Binding', 'Encap', 'Port_Binding')


class BaseEvpnEventsTestCase(bgp_base.BaseBgpIDLTestCase):
    schemas = ['OVN_Northbound', 'OVN_Southbound']

    def setUp(self):
        bgp_ovn.OvnSbIdl.tables = _OVN_SB_TABLES_WITH_PB
        try:
            super().setUp()
        finally:
            bgp_ovn.OvnSbIdl.tables = bgp_ovn.OVN_SB_TABLES
        self.mock_evpn_ext = mock.Mock()
        self.real_fsm = evpn_fsm.EvpnFSM(mock.Mock(), mock.Mock())
        self.mock_evpn_ext._evpn_fsm = mock.Mock(wraps=self.real_fsm)
        self.sb_api.idl.notify_handler.watch_event(
            evpn_events.PortBindingLrpEvpnCreateEvent(
                self.mock_evpn_ext._evpn_fsm))
        self.sb_api.idl.notify_handler.watch_event(
            evpn_events.PortBindingLrpEvpnDeleteEvent(
                self.mock_evpn_ext._evpn_fsm))

    def _create_evpn_lrp(self, vni, mac, vlan=100):
        lr_name = f'lr-evpn-{vni}'
        ls_name = f'ls-evpn-{vni}'
        lrp_name = f'lrp-to-evpn-{vni}'
        lsp_name = f'lsp-to-evpn-{vni}'
        lr = self.nb_api.lr_add(lr_name).execute(check_error=True)
        vrf = evpn_utils.evpn_vrf_name(lr.uuid)
        with self.nb_api.transaction(check_error=True) as txn:
            txn.add(self.nb_api.db_set(
                'Logical_Router', lr_name,
                options={
                    'dynamic-routing': 'true',
                    'chassis': 'fake-chassis',
                    ovn_const.LR_OPTIONS_DR_VRF_NAME: vrf,
                }))
            txn.add(self.nb_api.ls_add(ls_name))
            txn.add(self.nb_api.lrp_add(
                lr_name, lrp_name, mac, [],
                external_ids={
                    svc_const.EVPN_LRP_VNI_EXT_ID_KEY: str(vni),
                    svc_const.EVPN_LRP_VLAN_EXT_ID_KEY: str(vlan),
                },
                options={
                    'dynamic-routing-maintain-vrf': 'true',
                }))
            txn.add(self.nb_api.lsp_add(
                ls_name, lsp_name,
                type='router',
                options={'router-port': lrp_name}))
        return vrf

    def _create_lrp_without_evpn_match(self, vni, mac,
                                       set_vrf=True, set_vni=True,
                                       set_vlan=True):
        lr_name = f'lr-no-evpn-{vni}'
        ls_name = f'ls-no-evpn-{vni}'
        lrp_name = f'lrp-no-evpn-{vni}'
        lsp_name = f'lsp-no-evpn-{vni}'
        lr = self.nb_api.lr_add(lr_name).execute(check_error=True)
        options = {'dynamic-routing': 'true', 'chassis': 'fake-chassis'}
        if set_vrf:
            options[ovn_const.LR_OPTIONS_DR_VRF_NAME] = (
                evpn_utils.evpn_vrf_name(lr.uuid))
        external_ids = {}
        if set_vni:
            external_ids[svc_const.EVPN_LRP_VNI_EXT_ID_KEY] = str(vni)
        if set_vlan:
            external_ids[svc_const.EVPN_LRP_VLAN_EXT_ID_KEY] = '100'
        with self.nb_api.transaction(check_error=True) as txn:
            txn.add(self.nb_api.db_set(
                'Logical_Router', lr_name, options=options))
            txn.add(self.nb_api.ls_add(ls_name))
            txn.add(self.nb_api.lrp_add(
                lr_name, lrp_name, mac, [],
                external_ids=external_ids,
                options={'dynamic-routing-maintain-vrf': 'true'}))
            txn.add(self.nb_api.lsp_add(
                ls_name, lsp_name, type='router',
                options={'router-port': lrp_name}))

    def _delete_evpn_lrp(self, vni):
        lr_name = f'lr-evpn-{vni}'
        with self.nb_api.transaction(check_error=True) as txn:
            txn.add(self.nb_api.lr_del(lr_name))

    def _wait_for_advance(self, timeout=5):
        common_utils.wait_until_true(
            lambda: self.mock_evpn_ext._evpn_fsm.advance.called,
            sleep=0.2,
            timeout=timeout,
            exception=AssertionError('FSM advance was not called'))


class PortBindingLrpEvpnCreateEventTestCase(BaseEvpnEventsTestCase):

    def test_create_event_advances_fsm(self):
        vni = 10000
        vlan = 100
        mac = 'aa:bb:cc:dd:ee:ff'
        vrf = self._create_evpn_lrp(vni, mac, vlan=vlan)
        self._wait_for_advance()
        self.assertIn(vrf, self.real_fsm.instances)
        instance = self.real_fsm.instances[vrf]
        self.assertEqual(evpn_fsm.Evpn.WAITING_FOR_ROUTER, instance.state)
        self.assertEqual(mac, instance.mac)
        self.assertEqual(vni, instance.vni)
        self.assertEqual(vlan, instance.vid)

    def test_create_event_not_triggered_without_vrf_option(self):
        self._create_lrp_without_evpn_match(10001, 'aa:bb:cc:dd:ee:ff',
                                            set_vrf=False)
        with testtools.ExpectedException(AssertionError):
            self._wait_for_advance(timeout=2)

    def test_create_event_not_triggered_missing_vni(self):
        self._create_lrp_without_evpn_match(10002, 'aa:bb:cc:dd:ee:ff',
                                            set_vni=False)
        with testtools.ExpectedException(AssertionError):
            self._wait_for_advance(timeout=2)

    def test_create_event_not_triggered_missing_vlan(self):
        self._create_lrp_without_evpn_match(10003, 'aa:bb:cc:dd:ee:ff',
                                            set_vlan=False)
        with testtools.ExpectedException(AssertionError):
            self._wait_for_advance(timeout=2)

    def test_create_event_illegal_fsm_transition(self):
        self.mock_evpn_ext._evpn_fsm.advance.side_effect = \
            evpn_exc.FSMIllegalTransition("forced bad state")
        self._create_evpn_lrp(10004, 'aa:bb:cc:dd:ee:ff')
        self._wait_for_advance()


class PortBindingLrpEvpnDeleteEventTestCase(BaseEvpnEventsTestCase):

    def test_delete_event_advances_fsm(self):
        vni = 20000
        mac = 'cc:dd:ee:ff:00:11'
        vrf = self._create_evpn_lrp(vni, mac)
        self._wait_for_advance()
        self.mock_evpn_ext._evpn_fsm.advance.reset_mock()

        self._delete_evpn_lrp(vni)
        self._wait_for_advance()
        self.assertNotIn(vrf, self.real_fsm.instances)

    def test_delete_event_illegal_fsm_transition(self):
        vni = 20001
        mac = 'cc:dd:ee:ff:00:12'
        self._create_evpn_lrp(vni, mac)
        self._wait_for_advance()
        self.mock_evpn_ext._evpn_fsm.advance.reset_mock()
        self.mock_evpn_ext._evpn_fsm.advance.side_effect = \
            evpn_exc.FSMIllegalTransition("forced bad state")

        self._delete_evpn_lrp(vni)
        self._wait_for_advance()
