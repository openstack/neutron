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

import os
from unittest import mock

from oslo_config import cfg
from oslo_config import fixture as fixture_config
from ovsdbapp.backend.ovs_idl import event as ovs_idl_event
from ovsdbapp import venv as ovn_venv
import testtools

from neutron.agent.linux import nl_dispatcher
from neutron.agent.ovn.agent import ovn_neutron_agent
from neutron.agent.ovn.extensions.evpn import exceptions as evpn_exc
from neutron.agent.ovn.extensions.evpn import fsm as evpn_fsm
from neutron.agent.ovn.extensions.evpn import svd as evpn_svd
from neutron.agent.ovn.extensions.evpn import utils as evpn_utils
from neutron.common.ovn import constants as ovn_const
from neutron.common import utils as common_utils
from neutron.conf.agent.ovn.evpn import config as evpn_conf
from neutron.conf.agent.ovn.ovn_neutron_agent import config as config_ovn_agent
from neutron.privileged.agent.linux import svd as privileged_svd
from neutron.services.evpn import constants as svc_const
from neutron.tests.functional import base

EVPN_EXT = 'ovn-evpn'


class PreCheckWaitEvent(ovs_idl_event.WaitEvent):
    """WaitEvent that pre-checks current IDL state when wait() is called.

    Eliminates the race between registering the event and the condition
    already being true. Reuses conditions and match_fn with no duplication.
    """

    def __init__(self, api, *args, **kwargs):
        self.api = api
        super().__init__(*args, **kwargs)

    def pre_check(self):
        table = self.api.idl.tables.get(self.table)
        if not table:
            return False
        for row in table.rows.values():
            if (self.base_match(None, row, None) and
                    self.match_fn(None, row, None)):
                return True
        return False

    def wait(self):
        if not self.event.is_set() and self.pre_check():
            self.event.set()
        return self.event.wait(self.timeout)


class OvnControllerChassisEvent(PreCheckWaitEvent):
    """Fires when ovn-controller registers a chassis with the given name."""

    def __init__(self, api, chassis_name, timeout=15):
        super().__init__(
            api,
            (self.ROW_CREATE,),
            'Chassis',
            (('name', '=', chassis_name),),
            timeout=timeout)


class _EvpnOvsOvnVenvFixture(ovn_venv.OvsOvnVenvFixture):
    """Extends the ovsdbapp venv to pre-populate EVPN OVS external_ids."""

    def init_ovn_processes(self):
        super().init_ovn_processes()
        self.venv.call([
            'ovs-vsctl', f'--db={self.ovs_connection}',
            'set', 'open', '.',
            'external_ids:ovn-evpn-local-ip=10.0.0.1',
            'external_ids:ovn-evpn-vxlan-ports=49152',
        ])


class _VenvOvsdbServerMgr:
    """Minimal ovsdb_server_mgr shim backed by an ovsdbapp venv."""

    def __init__(self, nb_connection, sb_connection):
        self._nb = nb_connection
        self._sb = sb_connection
        self.private_key = ''
        self.certificate = ''
        self.ca_cert = ''

    def get_ovsdb_connection_path(self, db_type='nb'):
        return self._nb if db_type == 'nb' else self._sb


class BaseEvpnEventsTestCase(base.TestOVNFunctionalBase):

    def _start_ovsdb_server(self):
        self._ovn_venv = self.useFixture(
            _EvpnOvsOvnVenvFixture(
                self.temp_dir,
                ovsdir=os.getenv('OVS_SRCDIR'),
                ovndir=os.getenv('OVN_SRCDIR'),
                add_chassis=True,
                remove=False))
        set_cfg = cfg.CONF.set_override
        set_cfg('ovn_nb_connection', [self._ovn_venv.ovnnb_connection], 'ovn')
        set_cfg('ovn_sb_connection', [self._ovn_venv.ovnsb_connection], 'ovn')
        for key in ('ovn_nb_private_key', 'ovn_nb_certificate',
                    'ovn_nb_ca_cert', 'ovn_sb_private_key',
                    'ovn_sb_certificate', 'ovn_sb_ca_cert'):
            set_cfg(key, '', 'ovn')
        cfg.CONF.set_override('ovsdb_connection_timeout', 30, 'ovn')
        config_ovn_agent.register_opts()
        set_cfg('ovsdb_connection', self._ovn_venv.ovs_connection, 'OVS')
        self.ovsdb_server_mgr = _VenvOvsdbServerMgr(
            self._ovn_venv.ovnnb_connection,
            self._ovn_venv.ovnsb_connection)

    def _start_ovn_northd(self):
        pass  # already started by OvsOvnVenvFixture

    def setUp(self):
        super().setUp()
        evpn_conf.register_opts()
        system_id = self._ovn_venv.venv.call([
            'ovs-vsctl', f'--db={self._ovn_venv.ovs_connection}',
            'get', 'open', '.', 'external_ids:system-id',
        ]).decode().strip().strip('"')
        self.chassis_name = system_id
        event = OvnControllerChassisEvent(self.sb_api, self.chassis_name)
        self.sb_api.idl.notify_handler.watch_event(event)
        self.assertTrue(event.wait(),
                        'ovn-controller did not register chassis ' +
                        self.chassis_name)
        self.ovn_agent = self._start_evpn_agent()
        evpn_extension = self.ovn_agent[EVPN_EXT]
        self.fsm = evpn_extension._evpn_fsm
        self.fsm_advance = mock.patch.object(
            self.fsm, 'advance', wraps=self.fsm.advance).start()

    def _start_evpn_agent(self):
        conf = self.useFixture(fixture_config.Config()).conf
        conf.set_override('extensions', EVPN_EXT, group='agent')
        conf.set_override('ovn_nb_connection',
                          cfg.CONF.ovn.ovn_nb_connection, group='ovn')
        conf.set_override('ovn_sb_connection',
                          cfg.CONF.ovn.ovn_sb_connection, group='ovn')

        agt = ovn_neutron_agent.OVNNeutronAgent(conf)

        with mock.patch.object(ovn_neutron_agent.OVNNeutronAgent, 'wait'), \
                mock.patch.object(privileged_svd,
                                  'register_vxlan_vnifilter'), \
                mock.patch.object(evpn_svd.EvpnSvd, 'create'), \
                mock.patch('neutron.agent.ovn.extensions.evpn'
                           '.fsm_frr_driver.FsmFrrVtyshDriver',
                           return_value=mock.Mock()), \
                mock.patch.object(nl_dispatcher.NetlinkDispatcher, 'start'):
            agt.start()

        self.addCleanup(agt.ext_manager_api.sb_idl.ovsdb_connection.stop)
        if agt.ext_manager_api.nb_idl:
            self.addCleanup(agt.ext_manager_api.nb_idl.ovsdb_connection.stop)
        return agt

    def _create_evpn_lrp(self, vni, mac, vlan=100):
        lr_name = f'lr-evpn-{vni}'
        ls_name = f'ls-evpn-{vni}'
        lrp_name = f'lrp-to-evpn-{vni}'
        lsp_name = f'lsp-to-evpn-{vni}'
        hcg_name = f'hcg-evpn-{vni}'
        lr = self.nb_api.lr_add(lr_name).execute(check_error=True)
        vrf = evpn_utils.evpn_vrf_name(lr.uuid)
        # Create an HA_Chassis_Group for the LRP, matching the real EVPN
        # command which uses ha_chassis_group rather than options:chassis on
        # the LR (the latter produces l3gateway ports where the chassis column
        # is never persistently set).
        hcg = self.nb_api.ha_chassis_group_add(
            hcg_name).execute(check_error=True)
        self.nb_api.ha_chassis_group_add_chassis(
            hcg_name, self.chassis_name, 100).execute(check_error=True)
        with self.nb_api.transaction(check_error=True) as txn:
            txn.add(self.nb_api.db_set(
                'Logical_Router', lr_name,
                options={
                    'dynamic-routing': 'true',
                    ovn_const.LR_OPTIONS_DR_VRF_NAME: vrf,
                }))
            txn.add(self.nb_api.ls_add(ls_name))
            txn.add(self.nb_api.lrp_add(
                lr_name, lrp_name, mac, [],
                external_ids={
                    svc_const.EVPN_LRP_VNI_EXT_ID_KEY: str(vni),
                    svc_const.EVPN_LRP_VLAN_EXT_ID_KEY: str(vlan),
                },
                # Omit 'dynamic-routing-maintain-vrf: true' — that option
                # causes ovn-controller to create a kernel VRF device, which
                # requires CAP_NET_ADMIN and is not needed to test events.
                options={},
                ha_chassis_group=hcg.uuid))
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
        options = {'dynamic-routing': 'true'}
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
                # Omit 'dynamic-routing-maintain-vrf: true'
                # see _create_evpn_lrp
                options={}))
            txn.add(self.nb_api.lsp_add(
                ls_name, lsp_name, type='router',
                options={'router-port': lrp_name}))

    def _delete_evpn_lrp(self, vni):
        lr_name = f'lr-evpn-{vni}'
        with self.nb_api.transaction(check_error=True) as txn:
            txn.add(self.nb_api.lr_del(lr_name))

    def _wait_for_advance(self, timeout=5):
        common_utils.wait_until_true(
            lambda: self.fsm_advance.called,
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
        self.assertIn(vrf, self.fsm.instances)
        instance = self.fsm.instances[vrf]
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
        self.fsm_advance.side_effect = \
            evpn_exc.FSMIllegalTransition("forced bad state")
        self._create_evpn_lrp(10004, 'aa:bb:cc:dd:ee:ff')
        self._wait_for_advance()


class PortBindingLrpEvpnDeleteEventTestCase(BaseEvpnEventsTestCase):

    def test_delete_event_advances_fsm(self):
        vni = 20000
        mac = 'cc:dd:ee:ff:00:11'
        vrf = self._create_evpn_lrp(vni, mac)
        self._wait_for_advance()
        self.fsm_advance.reset_mock()

        self._delete_evpn_lrp(vni)
        self._wait_for_advance()
        self.assertNotIn(vrf, self.fsm.instances)

    def test_delete_event_illegal_fsm_transition(self):
        vni = 20001
        mac = 'cc:dd:ee:ff:00:12'
        self._create_evpn_lrp(vni, mac)
        self._wait_for_advance()
        self.fsm_advance.reset_mock()
        self.fsm_advance.side_effect = \
            evpn_exc.FSMIllegalTransition("forced bad state")

        self._delete_evpn_lrp(vni)
        self._wait_for_advance()
