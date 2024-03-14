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
import uuid

from oslo_config import fixture as fixture_config
from oslo_utils import uuidutils

from neutron.agent.ovn.agent import ovn_neutron_agent
from neutron.agent.ovn.agent import ovsdb as agent_ovsdb
from neutron.agent.ovn.metadata import agent as metadata_agent
from neutron.common.ovn import constants as ovn_const
from neutron.common import utils as n_utils
from neutron.tests.common import net_helpers
from neutron.tests.functional import base


TEST_EXTENSION = 'testing'
METADATA_EXTENSION = 'metadata'
EXTENSION_NAMES = {TEST_EXTENSION: 'Fake OVN agent extension',
                   METADATA_EXTENSION: 'Metadata OVN agent extension',
                   }


class TestOVNNeutronAgentBase(base.TestOVNFunctionalBase):

    def setUp(self, extensions, **kwargs):
        super().setUp(**kwargs)
        self.host_name = 'host-' + uuidutils.generate_uuid()[:5]
        self.chassis_name = self.add_fake_chassis(self.host_name)
        self.extensions = extensions
        self.mock_chassis_name = mock.patch.object(
            agent_ovsdb, 'get_own_chassis_name',
            return_value=self.chassis_name).start()
        with mock.patch.object(metadata_agent.MetadataAgent,
                               '_get_own_chassis_name',
                               return_value=self.chassis_name):
            self.ovn_agent = self._start_ovn_neutron_agent()

    def _check_loaded_and_started_extensions(self, ovn_agent):
        for _ext in self.extensions:
            loaded_ext = ovn_agent[_ext]
            self.assertEqual(EXTENSION_NAMES.get(_ext), loaded_ext.name)
            self.assertTrue(loaded_ext.is_started)

    def _start_ovn_neutron_agent(self):
        conf = self.useFixture(fixture_config.Config()).conf
        conf.set_override('extensions', ','.join(self.extensions),
                          group='agent')
        ovn_nb_db = self.ovsdb_server_mgr.get_ovsdb_connection_path('nb')
        conf.set_override('ovn_nb_connection', ovn_nb_db, group='ovn')
        ovn_sb_db = self.ovsdb_server_mgr.get_ovsdb_connection_path('sb')
        conf.set_override('ovn_sb_connection', ovn_sb_db, group='ovn')

        agt = ovn_neutron_agent.OVNNeutronAgent(conf)
        agt.test_ovs_idl = []
        agt.test_ovn_sb_idl = []
        agt.test_ovn_nb_idl = []
        agt.start()
        self._check_loaded_and_started_extensions(agt)

        self.addCleanup(agt.ext_manager_api.ovs_idl.ovsdb_connection.stop)
        if agt.ext_manager_api.sb_idl:
            self.addCleanup(agt.ext_manager_api.sb_idl.ovsdb_connection.stop)
        if agt.ext_manager_api.nb_idl:
            self.addCleanup(agt.ext_manager_api.nb_idl.ovsdb_connection.stop)
        return agt


class TestOVNNeutronAgentFakeAgent(TestOVNNeutronAgentBase):

    def setUp(self, **kwargs):
        super().setUp(extensions=[TEST_EXTENSION], **kwargs)

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
            timeout=10, exception=exc)


class TestOVNNeutronAgentMetadataExtension(TestOVNNeutronAgentBase):

    def setUp(self, **kwargs):
        super().setUp(extensions=[METADATA_EXTENSION], **kwargs)

    def test_check_metadata_started(self):
        # Check the metadata extension is registered.
        chassis_id = uuid.UUID(self.chassis_name)
        agent_id = uuid.uuid5(chassis_id, 'metadata_agent')
        ext_ids = {ovn_const.OVN_AGENT_METADATA_ID_KEY: str(agent_id)}
        ch_private = self.sb_api.lookup('Chassis_Private', self.chassis_name)
        self.assertEqual(ext_ids, ch_private.external_ids)

        # Check Unix proxy is running.
        metadata_extension = self.ovn_agent[METADATA_EXTENSION]
        self.assertIsNotNone(metadata_extension._proxy.server)
