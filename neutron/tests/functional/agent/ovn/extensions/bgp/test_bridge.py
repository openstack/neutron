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



from neutron.agent.ovn.extensions.bgp import bridge
from neutron.agent.ovsdb import impl_idl
from neutron.services.bgp import ovn as bgp_ovn
from neutron.tests.common import net_helpers
from neutron.tests.functional.services import bgp as base


class FakeAgentApi:
    def __init__(self, sb_idl):
        self.sb_idl = sb_idl
        self.ovs_idl = impl_idl.api_factory()


class FakeBgpAgentApi:
    def __init__(self, sb_idl):
        self.agent_api = FakeAgentApi(sb_idl)


class BgpTestCaseWithIdls(base.BaseBgpIDLTestCase):
    schemas = ['OVN_Southbound']

    def setUp(self):
        bgp_ovn.OvnSbIdl.tables = ('Port_Binding',)
        try:
            super().setUp()
        finally:
            bgp_ovn.OvnSbIdl.tables = bgp_ovn.OVN_SB_TABLES


class BGPChassisBridgeTestCase(BgpTestCaseWithIdls):
    def setUp(self):
        super().setUp()
        self.ovs_api = impl_idl.api_factory()
        self.test_bridge = self.useFixture(
            net_helpers.OVSBridgeFixture()).bridge
        self.bgp_bridge = bridge.BGPChassisBridge(
            FakeBgpAgentApi(self.sb_api),
            self.test_bridge.br_name)

    def test_patch_port_ofport(self):
        with self.ovs_api.transaction(check_error=True) as txn:
            txn.add(self.ovs_api.add_port(
                self.test_bridge.br_name, 'patch-port', type='patch'))
            txn.add(self.ovs_api.add_port(
                self.test_bridge.br_name, 'internal-port', type='internal'))

        ofport = self.bgp_bridge.patch_port_ofport

        # the patch port is not plugged anywhere, so it returns -1
        self.assertEqual(-1, ofport)
