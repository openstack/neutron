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

import ddt
from neutron_lib import constants
from neutron_lib.services.qos import constants as qos_consts
from oslo_utils import uuidutils

from neutron.agent.ovn.agent import ovsdb as agent_ovsdb
from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils as ovn_utils
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb.extensions import qos \
    as ovn_qos
from neutron.tests.functional import base


@ddt.ddt
class GetPortQosTestCase(base.TestOVNFunctionalBase):

    def _set_lsp_qos(self, qos_param, qos_value, lsp_name):
        if qos_value is not None:
            options = {qos_param: str(qos_value * constants.SI_BASE)}
        else:
            options = {qos_param: None}
        lsp = self.nb_api.lsp_get(lsp_name).execute(check_error=True)
        self.nb_api.update_lswitch_qos_options(lsp.uuid, **options).execute(
            check_error=True)
        if qos_value is not None:
            self.assertEqual(qos_value,
                             int(lsp.options[qos_param]) // constants.SI_BASE)
        else:
            self.assertNotIn(qos_param, lsp.options)

    def _add_max_kbps_rule(self, max_qos_value, network_id, lsp_name,
                           network_type):
        if network_type in (constants.TYPE_VLAN, constants.TYPE_FLAT):
            self._set_lsp_qos(ovn_const.LSP_OPTIONS_QOS_MAX_RATE,
                              max_qos_value, lsp_name)
        else:
            qos_extension = ovn_qos.OVNClientQosExtension()
            rules = {qos_consts.RULE_TYPE_BANDWIDTH_LIMIT:
                     {'max_kbps': max_qos_value}}
            ovn_rules = qos_extension._ovn_qos_rule(
                constants.EGRESS_DIRECTION, rules, lsp_name, network_id)
            self.nb_api.qos_add(**ovn_rules, may_exist=True).execute(
                check_error=True)

    def _remove_max_kbps_rule(self, network_name, lsp_name, network_type):
        if network_type in (constants.TYPE_VLAN, constants.TYPE_FLAT):
            self._set_lsp_qos(ovn_const.LSP_OPTIONS_QOS_MAX_RATE, 0, lsp_name)
        else:
            ext_ids = {ovn_const.OVN_PORT_EXT_ID_KEY: lsp_name}
            self.nb_api.qos_del_ext_ids(
                network_name, ext_ids).execute(check_error=True)

    @ddt.data(constants.TYPE_VLAN, constants.TYPE_GENEVE)
    def test_get_port_qos(self, network_type):
        network_id = uuidutils.generate_uuid()
        network_name = ovn_utils.ovn_name(network_id)
        ext_ids = {ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY: network_name}
        ls = self.nb_api.ls_add(network_name).execute(check_error=True)
        lsp_name = ('port-' + uuidutils.generate_uuid())[:15]
        self.nb_api.create_lswitch_port(
            lsp_name, ls.name, external_ids=ext_ids).execute(check_error=True)
        lsp = self.nb_api.lsp_get(lsp_name).execute(check_error=True)
        self.assertIsNone(lsp.options.get(ovn_const.LSP_OPTIONS_QOS_MIN_RATE))

        # Set the max-bw rule
        max_qos_value = 50000
        self._add_max_kbps_rule(max_qos_value, network_id, lsp_name,
                                network_type)

        # Set min-bw rule in the LSP.
        min_qos_value = 30000
        self._set_lsp_qos(ovn_const.LSP_OPTIONS_QOS_MIN_RATE, min_qos_value,
                          lsp_name)

        # Retrieve the min-bw and max-bw egress rules associated to a port.
        max_kbps, min_kbps = agent_ovsdb.get_port_qos(self.nb_api, lsp.name)
        self.assertEqual((max_qos_value, min_qos_value), (max_kbps, min_kbps))

        # Remove the min-bw rule.
        self._set_lsp_qos(ovn_const.LSP_OPTIONS_QOS_MIN_RATE, None, lsp_name)
        max_kbps, min_kbps = agent_ovsdb.get_port_qos(self.nb_api, lsp.name)
        self.assertEqual((max_qos_value, 0), (max_kbps, min_kbps))

        # Remove the max-bw rule
        self._remove_max_kbps_rule(network_name, lsp_name, network_type)
        max_kbps, min_kbps = agent_ovsdb.get_port_qos(self.nb_api, lsp.name)
        self.assertEqual((0, 0), (max_kbps, min_kbps))

        # Remove the port, the default values returned by the method are (0, 0)
        lsp_name = lsp.name
        self.nb_api.lsp_del(lsp_name).execute(check_error=True)
        lsp = self.nb_api.lookup('Logical_Switch_Port', lsp_name, default=None)
        self.assertIsNone(lsp)
        max_kbps, min_kbps = agent_ovsdb.get_port_qos(self.nb_api, lsp_name)
        self.assertEqual((0, 0), (max_kbps, min_kbps))
