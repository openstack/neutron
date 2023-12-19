# Copyright (c) 2023 Red Hat, Inc.
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

from oslo_utils import uuidutils

from neutron.agent.ovn.agent import ovsdb as agent_ovsdb
from neutron.agent.ovn.extensions import qos_hwol
from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils
from neutron.common import utils as n_utils
from neutron.tests import base as test_base
from neutron.tests.functional import base


class OVSInterfaceEventTestCase(base.TestOVNFunctionalBase):

    def _cleanup(self):
        self.ovs_idl.del_port(self.port_name, bridge=self.br_name).execute(
            check_error=False)
        self.ovs_idl.del_br(self.br_name).execute(check_error=False)

    @test_base.unstable_test('bug 2006603')
    def test_port_creation_and_deletion(self):
        def check_add_port_called():
            try:
                mock_agent[qos_hwol.EXT_NAME].add_port.assert_has_calls(
                    [mock.call(port_iface_id, self.port_name)])
                return True
            except AssertionError:
                return False

        def check_remove_egress_called():
            try:
                mock_agent.qos_hwol_ext.remove_egress.assert_has_calls(
                    [mock.call(port_iface_id)])
                return True
            except AssertionError:
                return False

        port_iface_id = 'port_iface-id'
        mock_agent = mock.MagicMock()
        events = [qos_hwol.OVSInterfaceEvent(mock_agent)]
        self.ovs_idl = agent_ovsdb.MonitorAgentOvsIdl(events=events).start()
        self.br_name = ('brtest-' + uuidutils.generate_uuid())[:13]
        self.port_name = ('port-' + uuidutils.generate_uuid())[:13]
        self.addCleanup(self._cleanup)
        with self.ovs_idl.transaction() as txn:
            txn.add(self.ovs_idl.add_br(self.br_name))
            txn.add(self.ovs_idl.add_port(self.br_name, self.port_name))
            txn.add(self.ovs_idl.iface_set_external_id(
                self.port_name, 'iface-id', port_iface_id))
            txn.add(self.ovs_idl.db_set(
                'Interface', self.port_name, ('type', 'internal')))

        exc = Exception('Port %s was not added to the bridge %s' %
                        (self.port_name, self.br_name))
        n_utils.wait_until_true(check_add_port_called, timeout=5,
                                exception=exc)

        self.ovs_idl.del_port(self.port_name).execute(check_error=True)
        exc = Exception('Port %s was not deleted from the bridge %s' %
                        (self.port_name, self.br_name))
        n_utils.wait_until_true(check_remove_egress_called, timeout=5,
                                exception=exc)


class QoSBandwidthLimitEventTestCase(base.TestOVNFunctionalBase):

    def setUp(self, **kwargs):
        super().setUp(**kwargs)
        self.net = self._make_network(self.fmt, 'n1', True)['network']
        res = self._create_subnet(self.fmt, self.net['id'], '10.0.0.0/24')
        self.subnet = self.deserialize(self.fmt, res)['subnet']
        res = self._create_port(self.fmt, self.net['id'])
        self.port = self.deserialize(self.fmt, res)['port']

    def test_qos_bw_limit_created_and_updated(self):
        def check_update_egress_called(rate):
            try:
                mock_agent[qos_hwol.EXT_NAME].update_egress.assert_has_calls(
                    [mock.call(port_id, rate, 0)])
                return True
            except AssertionError:
                return False

        mock_agent = mock.MagicMock(nb_idl=self.nb_api)
        events = [qos_hwol.QoSBandwidthLimitEvent(mock_agent)]
        agent_ovsdb.MonitorAgentOvnNbIdl(qos_hwol.NB_IDL_TABLES,
                                         events).start()
        lswitch_name = utils.ovn_name(self.net['id'])
        port_id = self.port['id']
        ovn_rule = {'switch': lswitch_name,
                    'priority': 1000,
                    'direction': 'from-lport',
                    'match': 'inport == ' + port_id,
                    'rate': 10000,
                    'external_ids': {ovn_const.OVN_PORT_EXT_ID_KEY: port_id}}
        self.nb_api.qos_add(**ovn_rule).execute(check_error=True)
        n_utils.wait_until_true(
            lambda: check_update_egress_called(ovn_rule['rate']), timeout=5)

        ovn_rule['rate'] = 15000
        self.nb_api.qos_add(**ovn_rule, may_exist=True).execute(
            check_error=True)
        n_utils.wait_until_true(
            lambda: check_update_egress_called(ovn_rule['rate']), timeout=5)


class QoSMinimumBandwidthEventTestCase(base.TestOVNFunctionalBase):

    def setUp(self, **kwargs):
        super().setUp(**kwargs)
        self.net = self._make_network(self.fmt, 'n1', True)['network']
        res = self._create_subnet(self.fmt, self.net['id'], '10.0.0.0/24')
        self.subnet = self.deserialize(self.fmt, res)['subnet']
        res = self._create_port(self.fmt, self.net['id'])
        self.port = self.deserialize(self.fmt, res)['port']

    def test_qos_min_bw_created_and_updated(self):
        def check_update_egress_called(max_kbps, min_kbps):
            try:
                mock_agent[qos_hwol.EXT_NAME].update_egress.assert_has_calls(
                    [mock.call(port_id, max_kbps, min_kbps)])
                return True
            except AssertionError:
                return False

        mock_agent = mock.MagicMock(nb_idl=self.nb_api)
        events = [qos_hwol.QoSMinimumBandwidthEvent(mock_agent)]
        agent_ovsdb.MonitorAgentOvnNbIdl(qos_hwol.NB_IDL_TABLES,
                                         events).start()
        port_id = self.port['id']
        min_kbps = 5000
        lsp = self.nb_api.lsp_get(port_id).execute(check_error=True)
        options = {ovn_const.LSP_OPTIONS_QOS_MIN_RATE: str(min_kbps)}
        self.nb_api.update_lswitch_qos_options(lsp, **options).execute(
            check_error=True)
        n_utils.wait_until_true(
            lambda: check_update_egress_called(0, min_kbps), timeout=5)


class PortBindingChassisCreatedEventTestCase(base.TestOVNFunctionalBase):

    def setUp(self, **kwargs):
        super().setUp(**kwargs)
        self.net = self._make_network(self.fmt, 'n1', True)['network']
        res = self._create_subnet(self.fmt, self.net['id'], '10.0.0.0/24')
        self.subnet = self.deserialize(self.fmt, res)['subnet']
        res = self._create_port(self.fmt, self.net['id'])
        self.port = self.deserialize(self.fmt, res)['port']

    @mock.patch.object(agent_ovsdb, 'get_ovs_port_name')
    @mock.patch.object(agent_ovsdb, 'get_port_qos')
    def test_port_binding_chassis_create_event(self, mock_get_port_qos,
                                               *args):
        def check_update_egress_called(max_kbps, min_kbps):
            try:
                mock_agent[qos_hwol.EXT_NAME].update_egress.assert_has_calls(
                    [mock.call(self.port['id'], max_kbps, min_kbps)])
                return True
            except AssertionError:
                return False

        max_kbps, min_kbps = 1000, 800
        mock_get_port_qos.return_value = max_kbps, min_kbps
        mock_agent = mock.MagicMock(nb_idl=self.nb_api)
        events = [qos_hwol.PortBindingChassisCreatedEvent(mock_agent)]
        chassis_name = self.add_fake_chassis('ovn-host-fake')
        mock_agent.chassis = chassis_name
        agent_ovsdb.MonitorAgentOvnSbIdl(qos_hwol.SB_IDL_TABLES, events,
                                         chassis=chassis_name).start()
        lsp_columns = {}
        lsp_name = self.port['id']
        ls_name = utils.ovn_name(self.net['id'])
        self.nb_api.create_lswitch_port(
            lsp_name, ls_name, **lsp_columns).execute(check_error=True)
        self.sb_api.lsp_bind(lsp_name, chassis_name).execute(check_error=True)
        n_utils.wait_until_true(
            lambda: check_update_egress_called(max_kbps, min_kbps), timeout=5)
