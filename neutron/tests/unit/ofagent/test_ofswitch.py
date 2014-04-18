# Copyright (C) 2014 VA Linux Systems Japan K.K.
# Copyright (C) 2014 YAMAMOTO Takashi <yamamoto at valinux co jp>
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


import mock

from neutron.openstack.common import importutils
from neutron.tests.unit.ofagent import ofa_test_base


class TestOFAgentFlows(ofa_test_base.OFATestBase):

    _MOD = 'neutron.plugins.ofagent.agent.ofswitch'

    def setUp(self):
        super(TestOFAgentFlows, self).setUp()
        self.mod = importutils.import_module(self._MOD)
        self.br = self.mod.OpenFlowSwitch()
        self.br.set_dp(self._mk_test_dp("dp"))

    def test_delete_flows(self):
        br = self.br
        with mock.patch.object(br, '_send_msg') as sendmsg:
            br.delete_flows()
        (dp, ofp, ofpp) = br._get_dp()
        call = mock.call
        expected_calls = [
            call(ofpp.OFPFlowMod(dp, command=ofp.OFPFC_DELETE,
                 match=ofpp.OFPMatch(), out_group=ofp.OFPG_ANY,
                 out_port=ofp.OFPP_ANY, priority=0, table_id=ofp.OFPTT_ALL)),
        ]
        sendmsg.assert_has_calls(expected_calls)

    def test_install_default_drop(self):
        br = self.br
        with mock.patch.object(br, '_send_msg') as sendmsg:
            br.install_default_drop(table_id=98)
        (dp, ofp, ofpp) = br._get_dp()
        call = mock.call
        expected_calls = [
            call(ofpp.OFPFlowMod(dp, priority=0, table_id=98)),
        ]
        sendmsg.assert_has_calls(expected_calls)

    def test_install_default_goto(self):
        br = self.br
        with mock.patch.object(br, '_send_msg') as sendmsg:
            br.install_default_goto(table_id=98, dest_table_id=150)
        (dp, ofp, ofpp) = br._get_dp()
        call = mock.call
        expected_calls = [
            call(ofpp.OFPFlowMod(dp, instructions=[
                 ofpp.OFPInstructionGotoTable(table_id=150)],
                 priority=0, table_id=98)),
        ]
        sendmsg.assert_has_calls(expected_calls)

    def test_install_default_goto_next(self):
        br = self.br
        with mock.patch.object(br, '_send_msg') as sendmsg:
            br.install_default_goto_next(table_id=100)
        (dp, ofp, ofpp) = br._get_dp()
        call = mock.call
        expected_calls = [
            call(ofpp.OFPFlowMod(dp, instructions=[
                 ofpp.OFPInstructionGotoTable(table_id=101)],
                 priority=0, table_id=100)),
        ]
        sendmsg.assert_has_calls(expected_calls)
