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
from ovsdbapp.backend.ovs_idl import event
from ovsdbapp.backend.ovs_idl import idlutils

from neutron.agent.ovn.agent import ovn_neutron_agent
from neutron.agent.ovn.agent import ovsdb as agent_ovsdb
from neutron.agent.ovn.metadata import agent as metadata_agent
from neutron.agent.ovn.metadata import server_socket
from neutron.agent.ovsdb import impl_idl
from neutron.common.ovn import constants as ovn_const
from neutron.common import utils as n_utils
from neutron.tests.common import net_helpers
from neutron.tests.functional import base


TEST_EXTENSION = 'testing'
METADATA_EXTENSION = 'metadata'
EXTENSION_NAMES = {TEST_EXTENSION: 'Fake OVN agent extension',
                   METADATA_EXTENSION: 'Metadata OVN agent extension',
                   }


class ChassisPrivateUpdateEvent(event.WaitEvent):
    def __init__(self, chassis_private, timeout=5):
        table = 'Chassis_Private'
        events = (self.ROW_UPDATE,)
        conditions = (('name', '=', chassis_private),)
        super().__init__(events, table, conditions, timeout=timeout)


class TestOVNNeutronAgentBase(base.TestOVNFunctionalBase):

    def setUp(self, extensions, **kwargs):
        super().setUp(**kwargs)
        self.host_name = 'host-' + uuidutils.generate_uuid()[:5]
        self.chassis_name = self.add_fake_chassis(self.host_name)
        self.extensions = extensions
        self.mock_chassis_name = mock.patch.object(
            agent_ovsdb, 'get_own_chassis_name',
            return_value=self.chassis_name).start()
        self.ovs_idl_events = []
        with mock.patch.object(metadata_agent.MetadataAgent,
                               '_get_own_chassis_name',
                               return_value=self.chassis_name):
            self.ovn_agent = self._start_ovn_neutron_agent()

    def _check_loaded_and_started_extensions(self, ovn_agent):
        for _ext in self.extensions:
            loaded_ext = ovn_agent[_ext]
            self.assertEqual(EXTENSION_NAMES.get(_ext), loaded_ext.name)
            self.assertTrue(loaded_ext.is_started)

    def _create_ovs_idl(self, ovn_agent):
        for extension in ovn_agent.ext_manager:
            self.ovs_idl_events += extension.obj.ovs_idl_events
        self.ovs_idl_events = [e(ovn_agent) for e in
                                         set(self.ovs_idl_events)]
        ovsdb = impl_idl.api_factory()
        ovsdb.idl.notify_handler.watch_events(self.ovs_idl_events)

        ovn_agent.ext_manager_api.ovs_idl = ovsdb
        return ovsdb

    def _clear_events_ovs_idl(self):
        self.ovn_agent.ovs_idl.idl_monitor.notify_handler.unwatch_events(
            self.ovs_idl_events)

    def _start_ovn_neutron_agent(self):
        conf = self.useFixture(fixture_config.Config()).conf
        conf.set_override('extensions', ','.join(self.extensions),
                          group='agent')
        ovn_nb_db = self.ovsdb_server_mgr.get_ovsdb_connection_path('nb')
        conf.set_override('ovn_nb_connection', [ovn_nb_db], group='ovn')
        ovn_sb_db = self.ovsdb_server_mgr.get_ovsdb_connection_path('sb')
        conf.set_override('ovn_sb_connection', [ovn_sb_db], group='ovn')

        agt = ovn_neutron_agent.OVNNeutronAgent(conf)
        agt.test_ovs_idl = []
        agt.test_ovn_sb_idl = []
        agt.test_ovn_nb_idl = []
        # NOTE(ralonsoh): it is needed to ``UnixDomainMetadataProxy.wait``
        # method in eventlet environments in order not to block the execution.
        # Once eventlet is completely removed, this mock can be deleted.
        with mock.patch.object(ovn_neutron_agent.OVNNeutronAgent, 'wait'), \
                mock.patch.object(server_socket.UnixDomainMetadataProxy,
                                  'wait'), \
                mock.patch.object(ovn_neutron_agent.OVNNeutronAgent,
                                  '_load_ovs_idl') as mock_load_ovs_idl:
            mock_load_ovs_idl.return_value = self._create_ovs_idl(agt)
            agt.start()
            external_ids = agt.sb_idl.db_get(
                'Chassis_Private', agt.chassis, 'external_ids').execute(
                check_error=True)
            self.assertEqual(
                external_ids[ovn_const.OVN_AGENT_NEUTRON_SB_CFG_KEY],
                '0')

        self._check_loaded_and_started_extensions(agt)
        self.addCleanup(self._clear_events_ovs_idl)
        if agt.ext_manager_api.sb_idl:
            self.addCleanup(agt.ext_manager_api.sb_idl.ovsdb_connection.stop)
        if agt.ext_manager_api.nb_idl:
            self.addCleanup(agt.ext_manager_api.nb_idl.ovsdb_connection.stop)
        return agt


class TestOVNNeutronAgent(TestOVNNeutronAgentBase):
    def setUp(self, **kwargs):
        super().setUp(extensions=[METADATA_EXTENSION], **kwargs)

    def test_chassis_private_create_event(self):
        def _check_chassis_private():
            try:
                ext_ids = self.ovn_agent.sb_idl.db_get(
                    'Chassis_Private', self.chassis_name,
                    'external_ids').execute(check_error=True)
                neutron_id = (ext_ids.get(ovn_const.OVN_AGENT_NEUTRON_ID_KEY)
                              is not None)
                agt_cfg = (ext_ids.get(ovn_const.OVN_AGENT_NEUTRON_SB_CFG_KEY)
                           is not None)
                bridge = (ext_ids.get(ovn_const.OVN_AGENT_OVN_BRIDGE)
                          is not None)
                return neutron_id and agt_cfg and bridge
            except idlutils.RowNotFound:
                return False

        # If the "Chassis_Private" register is deleted and created again,
        # the agent should be able to re-register itself.
        self.ovn_agent.sb_idl.chassis_del(self.chassis_name).execute(
            check_error=True)
        self.add_fake_chassis(self.host_name, name=self.chassis_name)

        n_utils.wait_until_true(_check_chassis_private, timeout=10)


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
        def check_extids(expected_ext_ids, chassis_name):
            ch_private = self.sb_api.lookup('Chassis_Private', chassis_name)
            return expected_ext_ids == ch_private.external_ids

        # Check the metadata extension is registered.
        chassis_id = uuid.UUID(self.chassis_name)
        ovn_agent_id = uuid.uuid5(chassis_id, 'ovn_agent')
        ext_ids = {ovn_const.OVN_AGENT_OVN_BRIDGE: 'br-int',
                   ovn_const.OVN_AGENT_NEUTRON_ID_KEY: str(ovn_agent_id),
                   ovn_const.OVN_AGENT_NEUTRON_SB_CFG_KEY: '0',
                   }
        n_utils.wait_until_true(
            lambda: check_extids(ext_ids, self.chassis_name),
            timeout=10)

        # Check Unix proxy is running.
        metadata_extension = self.ovn_agent[METADATA_EXTENSION]
        self.assertIsNotNone(metadata_extension._proxy._server)

    def test__cleanup_previous_tags(self):
        external_ids = {
            ovn_const.OVN_AGENT_METADATA_SB_CFG_KEY: '1',
            ovn_const.OVN_AGENT_METADATA_DESC_KEY: 'description',
            ovn_const.OVN_AGENT_METADATA_ID_KEY: uuidutils.generate_uuid()}
        self.ovn_agent.sb_idl.db_set(
            'Chassis_Private', self.ovn_agent.chassis,
            ('external_ids', external_ids)).execute(check_error=True)

        cp_event = ChassisPrivateUpdateEvent(self.chassis_name)
        self.ovn_agent.sb_idl.idl.notify_handler.watch_event(cp_event)
        self.ovn_agent._cleanup_previous_tags()
        self.assertTrue(cp_event.wait())

        external_ids = self.ovn_agent.sb_idl.db_get(
            'Chassis_Private', self.ovn_agent.chassis,
            'external_ids').execute(check_error=True)
        for _key in (ovn_const.OVN_AGENT_METADATA_SB_CFG_KEY,
                     ovn_const.OVN_AGENT_METADATA_DESC_KEY,
                     ovn_const.OVN_AGENT_METADATA_ID_KEY):
            self.assertNotIn(_key, external_ids)

        # Just in case, check that we are NOT deleting the needed tags.
        # NOTE(ralonsoh): OVN_AGENT_METADATA_ID_KEY is missing here, there is
        # a bug to add it (LP#2118876)
        self.assertIn(ovn_const.OVN_AGENT_NEUTRON_SB_CFG_KEY, external_ids)
