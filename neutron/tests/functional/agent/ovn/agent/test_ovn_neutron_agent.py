# Copyright 2023 Red Hat, Inc.
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

from oslo_config import fixture as fixture_config
from oslo_utils import uuidutils

from neutron.agent.ovn.agent import ovn_neutron_agent
from neutron.agent.ovn.agent import ovsdb as agent_ovsdb
from neutron.common import utils as n_utils
from neutron.tests.common import net_helpers
from neutron.tests.functional import base


class TestOVNNeutronAgent(base.TestOVNFunctionalBase):

    OVN_BRIDGE = 'br-int'
    FAKE_CHASSIS_HOST = 'ovn-host-fake'

    def setUp(self, **kwargs):
        super().setUp(**kwargs)
        self.mock_chassis_name = mock.patch.object(
            agent_ovsdb, 'get_own_chassis_name').start()
        self.ovn_agent = self._start_ovn_neutron_agent()

    def _start_ovn_neutron_agent(self):
        conf = self.useFixture(fixture_config.Config()).conf
        conf.set_override('extensions', 'testing', group='agent')
        ovn_nb_db = self.ovsdb_server_mgr.get_ovsdb_connection_path('nb')
        conf.set_override('ovn_nb_connection', ovn_nb_db, group='ovn')
        ovn_sb_db = self.ovsdb_server_mgr.get_ovsdb_connection_path('sb')
        conf.set_override('ovn_sb_connection', ovn_sb_db, group='ovn')

        self.chassis_name = uuidutils.generate_uuid()
        self.mock_chassis_name.return_value = self.chassis_name

        agt = ovn_neutron_agent.OVNNeutronAgent(conf)
        agt.test_ovs_idl = []
        agt.test_ovn_sb_idl = []
        agt.test_ovn_nb_idl = []
        agt.start()

        self.add_fake_chassis(self.FAKE_CHASSIS_HOST, name=self.chassis_name)

        self.addCleanup(agt.ext_manager_api.ovs_idl.ovsdb_connection.stop)
        if agt.ext_manager_api.sb_idl:
            self.addCleanup(agt.ext_manager_api.sb_idl.ovsdb_connection.stop)
        if agt.ext_manager_api.nb_idl:
            self.addCleanup(agt.ext_manager_api.nb_idl.ovsdb_connection.stop)
        return agt

    def test_ovs_and_ovs_events(self):
        # Test the OVS IDL is attending the provided events.
        bridge = self.useFixture(net_helpers.OVSBridgeFixture()).bridge
        exc = Exception('Bridge %s not added or not detected by '
                        'OVSInterfaceEvent' % bridge)
        n_utils.wait_until_true(
            lambda: bridge.br_name in self.ovn_agent.test_ovs_idl,
            timeout=10, exception=exc)

        # Test the OVN SB IDL is attending the provided events. The chassis is
        # created before the OVN SB IDL connection is created but the creation
        # event is received during the subscription.
        exc = Exception('Chassis %s not added or not detected by '
                        'OVNSBChassisEvent' % self.chassis_name)
        n_utils.wait_until_true(
            lambda: self.chassis_name in self.ovn_agent.test_ovn_sb_idl,
            timeout=10, exception=exc)

        # Test the OVN SN IDL is attending the provided events.
        lswitch_name = 'ovn-' + uuidutils.generate_uuid()
        self.nb_api.ls_add(lswitch_name).execute(check_error=True)
        exc = Exception('Logical Switch %s not added or not detected by ')
        n_utils.wait_until_true(
            lambda: lswitch_name in self.ovn_agent.test_ovn_nb_idl,
            timeout=10)
