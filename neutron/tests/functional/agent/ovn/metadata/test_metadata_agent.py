# Copyright 2020 Red Hat, Inc.
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

import re
from unittest import mock

from neutron_lib import constants
from oslo_config import fixture as fixture_config
from oslo_utils import uuidutils
from ovsdbapp.backend.ovs_idl import event
from ovsdbapp.backend.ovs_idl import idlutils
from ovsdbapp.tests.functional.schema.ovn_southbound import event as test_event
import testtools

from neutron.agent.linux import iptables_manager
from neutron.agent.ovn.metadata import agent
from neutron.agent.ovn.metadata import ovsdb
from neutron.agent.ovn.metadata import server_socket as metadata_server
from neutron.common.ovn import constants as ovn_const
from neutron.common import utils as n_utils
from neutron.conf.agent.metadata import config as meta_config
from neutron.conf.agent.ovn.metadata import config as meta_config_ovn
from neutron.tests.common import net_helpers
from neutron.tests.functional import base
from neutron.tests.functional.common import ovn as ovn_common
from neutron.tests.functional.resources.ovsdb import events

AGENT_CHASSIS_TABLE = 'Chassis_Private'


class NoDatapathProvision(Exception):
    pass


class MetadataAgentHealthEvent(event.WaitEvent):
    event_name = 'MetadataAgentHealthEvent'

    def __init__(self, chassis, sb_cfg, timeout=5):
        self.chassis = chassis
        self.sb_cfg = sb_cfg
        super().__init__(
            (self.ROW_UPDATE,),
            AGENT_CHASSIS_TABLE,
            (('name', '=', self.chassis),),
            timeout=timeout)

    def matches(self, event, row, old=None):
        if not super().matches(event, row, old):
            return False
        return int(row.external_ids.get(
            ovn_const.OVN_AGENT_METADATA_SB_CFG_KEY, 0)) >= self.sb_cfg


class PortBindingUpdateEvent(event.WaitEvent):
    def __init__(self, lsp, timeout=5):
        table = 'Port_Binding'
        events = (self.ROW_UPDATE,)
        conditions = (('logical_port', '=', lsp),)
        super().__init__(events, table, conditions, timeout=timeout)


class TestMetadataAgent(base.TestOVNFunctionalBase):
    OVN_BRIDGE = 'br-int'
    FAKE_CHASSIS_HOST = 'ovn-host-fake'

    def setUp(self):
        super().setUp()
        self.handler = self.sb_api.idl.notify_handler
        # We only have OVN NB and OVN SB running for functional tests
        self.mock_ovsdb_idl = mock.Mock()
        mock_metadata_instance = mock.Mock()
        mock_metadata_instance.start.return_value = self.mock_ovsdb_idl
        mock_metadata = mock.patch.object(
            ovsdb, 'MetadataAgentOvsIdl').start()
        mock_metadata.return_value = mock_metadata_instance
        self._mock_get_ovn_br = mock.patch.object(
            agent.MetadataAgent,
            '_get_ovn_bridge',
            return_value=self.OVN_BRIDGE).start()
        self.agent = self._start_metadata_agent()

    def _start_metadata_agent(self):
        conf = self.useFixture(fixture_config.Config()).conf
        conf.register_opts(meta_config.SHARED_OPTS)
        conf.register_opts(meta_config.UNIX_DOMAIN_METADATA_PROXY_OPTS)
        conf.register_opts(meta_config.METADATA_PROXY_HANDLER_OPTS)
        conf.register_opts(meta_config_ovn.OVS_OPTS, group='ovs')
        meta_config_ovn.setup_privsep()

        ovn_sb_db = self.ovsdb_server_mgr.get_ovsdb_connection_path('sb')
        conf.set_override('ovn_sb_connection', [ovn_sb_db], group='ovn')
        conf.set_override('metadata_workers', '0')

        self.chassis_name = self.add_fake_chassis(self.FAKE_CHASSIS_HOST)
        mock.patch.object(agent.MetadataAgent,
                          '_get_own_chassis_name',
                          return_value=self.chassis_name).start()
        agt = agent.MetadataAgent(conf)
        with mock.patch.object(metadata_server.UnixDomainMetadataProxy,
                               'wait'):
            agt.start()
            external_ids = agt.sb_idl.db_get(
                'Chassis_Private', agt.chassis, 'external_ids').execute(
                check_error=True)
            self.assertEqual(external_ids[ovn_const.OVN_AGENT_OVN_BRIDGE],
                             self.OVN_BRIDGE)
            self.assertEqual(
                external_ids[ovn_const.OVN_AGENT_METADATA_SB_CFG_KEY],
                '0')

        # Metadata agent will open connections to OVS and SB databases.
        # Close connections to them when the test ends,
        self.addCleanup(agt.ovs_idl.ovsdb_connection.stop)
        self.addCleanup(agt.sb_idl.ovsdb_connection.stop)

        return agt

    def test_metadata_agent_healthcheck(self):
        # Let's list the agents to force the nb_cfg to be bumped on NB
        # db, which will automatically increment the nb_cfg counter on
        # NB_Global and make ovn-controller copy it over to SB_Global. Upon
        # this event, Metadata agent will update the external_ids on its
        # Chassis row to signal that it's healthy.

        row_event = MetadataAgentHealthEvent(self.chassis_name, 1)
        self.handler.watch_event(row_event)
        self.new_list_request('agents').get_response(self.api)

        # If we do not time out waiting for the event, then we are assured
        # that the metadata agent has populated the external_ids from the
        # chassis with the nb_cfg, 1 revisions when listing the agents.
        self.assertTrue(row_event.wait())

    def _create_metadata_port(self, txn, lswitch_name, port_name=None):
        mdt_port_name = port_name or 'ovn-mdt-' + uuidutils.generate_uuid()
        txn.add(
            self.nb_api.lsp_add(
                lswitch_name,
                mdt_port_name,
                type=ovn_const.LSP_TYPE_LOCALPORT,
                addresses='AA:AA:AA:AA:AA:AA 192.168.122.123',
                external_ids={
                    ovn_const.OVN_CIDRS_EXT_ID_KEY: '192.168.122.123/24',
                    ovn_const.OVN_DEVID_EXT_ID_KEY:
                        ovn_const.OVN_METADATA_PREFIX + lswitch_name,
                    ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY:
                        constants.DEVICE_OWNER_DISTRIBUTED
                }))

    def _update_metadata_port_ip(self, metadata_port_name):
        external_ids = {
            ovn_const.OVN_CIDRS_EXT_ID_KEY: "192.168.122.2/24",
            ovn_const.OVN_DEVID_EXT_ID_KEY:
                ovn_const.OVN_METADATA_PREFIX + uuidutils.generate_uuid()
        }
        self.nb_api.set_lswitch_port(lport_name=metadata_port_name,
                                     external_ids=external_ids).execute()

    def _create_logical_switch_port(self, type_=None, addresses=None):
        lswitch_name = 'ovn-' + uuidutils.generate_uuid()
        lswitchport_name = 'ovn-port-' + uuidutils.generate_uuid()
        # It may take some time to ovn-northd to translate from OVN NB DB to
        # the OVN SB DB. Wait for port binding event to happen before binding
        # the port to chassis.
        pb_event = test_event.WaitForPortBindingEvent(lswitchport_name)
        self.handler.watch_event(pb_event)

        lswitch_port_columns = {}
        if addresses:
            lswitch_port_columns['addresses'] = addresses
        if type_:
            lswitch_port_columns['type'] = type_

        with self.nb_api.transaction(check_error=True, log_errors=True) as txn:
            txn.add(
                self.nb_api.ls_add(lswitch_name))
            txn.add(
                self.nb_api.create_lswitch_port(
                    lswitchport_name, lswitch_name, **lswitch_port_columns))
            self._create_metadata_port(txn, lswitch_name)
        self.assertTrue(pb_event.wait())

        return lswitchport_name, lswitch_name

    def test_agent_resync_on_non_existing_bridge(self):
        BR_NEW = 'br-new'
        self._mock_get_ovn_br.return_value = BR_NEW
        self.agent.ovs_idl.list_br.return_value.execute.return_value = [BR_NEW]
        # The agent has initialized with br-int and above list_br doesn't
        # return it, hence the agent should trigger reconfiguration and store
        # new br-new value to its attribute.
        self.assertEqual(self.OVN_BRIDGE, self.agent.ovn_bridge)

        # NOTE: The IP address is specifically picked such that it fits the
        # metadata port external_ids: { neutron:cidrs }. This is because agent
        # will only trigger if the logical port is part of a neutron subnet
        lswitchport_name, _ = self._create_logical_switch_port(
            addresses='AA:AA:AA:AA:AA:AB 192.168.122.125'
        )

        # Trigger PortBindingChassisCreatedEvent
        self.sb_api.lsp_bind(lswitchport_name, self.chassis_name).execute(
            check_error=True, log_errors=True)

        exc = Exception("Agent bridge hasn't changed from %s to %s "
                        "in 10 seconds after Port_Binding event" %
                        (self.agent.ovn_bridge, BR_NEW))
        n_utils.wait_until_true(
            lambda: BR_NEW == self.agent.ovn_bridge,
            timeout=10,
            exception=exc)

    def _test_agent_events_prepare(self, lsp_type=None):
        lswitchport_name, lswitch_name = self._create_logical_switch_port(
            lsp_type)
        with mock.patch.object(
                agent.MetadataAgent, 'provision_datapath') as m_provision:
            self.sb_api.lsp_bind(lswitchport_name, self.chassis_name).execute(
                check_error=True, log_errors=True)

            # Wait until port is bound
            n_utils.wait_until_true(
                lambda: m_provision.called,
                timeout=10,
                exception=Exception(
                    "Datapath provisioning did not happen on port binding"))

        return lswitchport_name, lswitch_name

    def test_agent_unbind_port(self):
        lswitchport_name, lswitch_name = self._test_agent_events_prepare()

        with mock.patch.object(
                agent.MetadataAgent, 'provision_datapath') as m_provision:
            self.sb_api.lsp_unbind(lswitchport_name).execute(
                check_error=True, log_errors=True)

            n_utils.wait_until_true(
                lambda: m_provision.called,
                timeout=10,
                exception=Exception(
                    "Datapath teardown did not happen after the port was "
                    "unbound"))

    def _test_agent_delete_bound_external_port(self, lsp_type=None):
        lswitchport_name, lswitch_name = self._test_agent_events_prepare(
            lsp_type)

        with mock.patch.object(
                agent.MetadataAgent, 'provision_datapath') as m_provision,\
                mock.patch.object(agent.LOG, 'warning') as m_log_warn:
            self.nb_api.delete_lswitch_port(
                lswitchport_name, lswitch_name).execute(
                    check_error=True, log_errors=True)

            n_utils.wait_until_true(
                lambda: m_provision.called,
                timeout=10,
                exception=Exception(
                    "Datapath teardown did not happen after external port was "
                    "deleted"))
            if lsp_type == ovn_const.LSP_TYPE_EXTERNAL:
                m_log_warn.assert_not_called()
            else:
                m_log_warn.assert_called()

    def test_agent_delete_bound_external_port(self):
        self._test_agent_delete_bound_external_port(
            lsp_type=ovn_const.LSP_TYPE_EXTERNAL)

    def test_agent_delete_bound_nonexternal_port(self):
        self._test_agent_delete_bound_external_port()

    def test_agent_registration_at_chassis_create_event(self):
        def check_for_metadata():
            chassis = self.sb_api.lookup(
                AGENT_CHASSIS_TABLE, self.chassis_name)
            return ovn_const.OVN_AGENT_METADATA_ID_KEY in chassis.external_ids

        exc = Exception('Chassis not created, %s is not in chassis '
                        'external_ids' % ovn_const.OVN_AGENT_METADATA_ID_KEY)
        n_utils.wait_until_true(check_for_metadata, timeout=5, exception=exc)

        # Delete Chassis and assert
        chassis = self.sb_api.lookup('Chassis', self.chassis_name)
        self.del_fake_chassis(chassis.name)
        self.assertRaises(idlutils.RowNotFound, self.sb_api.lookup,
                          'Chassis', self.chassis_name)

        # Re-add the Chassis
        self.add_fake_chassis(self.FAKE_CHASSIS_HOST, name=self.chassis_name)
        exc = Exception('Agent metadata failed to re-register itself '
                        'after the Chassis %s was re-created' %
                        self.chassis_name)

        # Check if metadata agent was re-registered
        chassis = self.sb_api.lookup('Chassis', self.chassis_name)
        n_utils.wait_until_true(
            check_for_metadata,
            timeout=10,
            exception=exc)

    def test_agent_metadata_port_ip_update_event(self):
        lswitch_name = 'ovn-' + uuidutils.generate_uuid()
        mdt_port_name = 'ovn-mdt-' + uuidutils.generate_uuid()

        mdt_pb_event = test_event.WaitForPortBindingEvent(mdt_port_name)
        self.handler.watch_event(mdt_pb_event)

        with self.nb_api.transaction(
                check_error=True, log_errors=True) as txn:
            txn.add(
                self.nb_api.ls_add(lswitch_name))
            self._create_metadata_port(txn, lswitch_name, mdt_port_name)

        self.assertTrue(mdt_pb_event.wait())

        with mock.patch.object(
                agent.MetadataAgent, 'provision_datapath') as m_provision:
            self.sb_api.lsp_bind(mdt_port_name, self.chassis_name).execute(
                check_error=True, log_errors=True)

            # Wait until port is bound
            n_utils.wait_until_true(
                lambda: m_provision.called,
                timeout=10,
                exception=Exception(
                    "Datapath provisioning did not happen on port binding"))

            m_provision.reset_mock()

            self._update_metadata_port_ip(mdt_port_name)

            n_utils.wait_until_true(
                lambda: m_provision.called,
                timeout=10,
                exception=Exception(
                    "Datapath provisioning not called after external ids was "
                    "changed"))

    def test_agent_metadata_port_dhcp_reenable_event(self):
        # Test the Port_Binding update event triggered by reenable DHCP after
        # disable DHCP on the subnet where the metadata's port is located.
        lswitch_name = 'ovn-' + uuidutils.generate_uuid()
        mdt_port_name = 'ovn-mdt-' + uuidutils.generate_uuid()

        mdt_pb_event = events.WaitForCreatePortBindingEvent(mdt_port_name)
        self.handler.watch_event(mdt_pb_event)

        with self.nb_api.transaction(
                check_error=True, log_errors=True) as txn:
            txn.add(
                self.nb_api.ls_add(lswitch_name))
            self._create_metadata_port(txn, lswitch_name, mdt_port_name)

            external_ids = {ovn_const.OVN_CIDRS_EXT_ID_KEY: ""}
            txn.add(
                self.nb_api.set_lswitch_port(lport_name=mdt_port_name,
                                             external_ids=external_ids))

        self.assertTrue(mdt_pb_event.wait())

        with mock.patch.object(
                agent.MetadataAgent, 'provision_datapath') as m_provision:
            self.sb_api.lsp_bind(mdt_port_name, self.chassis_name).execute(
                check_error=True, log_errors=True)

            # Wait until port is bound
            n_utils.wait_until_true(
                lambda: m_provision.called,
                timeout=10,
                exception=Exception(
                    "Datapath provisioning did not happen on port binding"))

            m_provision.reset_mock()

            self._update_metadata_port_ip(mdt_port_name)

            n_utils.wait_until_true(
                lambda: m_provision.called,
                timeout=10,
                exception=Exception(
                    "Datapath provisioning not called after external ids was "
                    "changed"))

    def test_metadata_agent_only_monitors_own_chassis(self):
        # We already have the fake chassis which we should be monitoring, so
        # create an event looking for a change to another chassis
        other_name = uuidutils.generate_uuid()
        other_chassis = self.add_fake_chassis(self.FAKE_CHASSIS_HOST,
                                              name=other_name)
        self.assertEqual(other_chassis, other_name)

        event = MetadataAgentHealthEvent(chassis=other_name, sb_cfg=-1,
                                         timeout=0)
        # Use the agent's sb_idl to watch for the event since it has condition
        self.agent.sb_idl.idl.notify_handler.watch_event(event)
        # Use the test sb_api to set other_chassis values since shouldn't exist
        # on agent's sb_idl
        self.sb_api.db_set(
            AGENT_CHASSIS_TABLE, other_chassis,
            ('external_ids', {'test': 'value'})).execute(check_error=True)

        event2 = MetadataAgentHealthEvent(chassis=self.chassis_name, sb_cfg=-1)
        self.agent.sb_idl.idl.notify_handler.watch_event(event2)
        # Use the test's sb_api again to send a command so we can see if it
        # completes and short-circuit the need to wait for a timeout to pass
        # the test. If we get the result to this, we would have gotten the
        # previous result as well.
        self.sb_api.db_set(
            AGENT_CHASSIS_TABLE, self.chassis_name,
            ('external_ids', {'test': 'value'})).execute(check_error=True)
        self.assertTrue(event2.wait())
        self.assertFalse(event.wait())

    def test__ensure_datapath_checksum_if_dpdk(self):
        self.mock_ovsdb_idl.db_get.return_value.execute.return_value = (
            ovn_const.CHASSIS_DATAPATH_NETDEV)
        regex = re.compile(r'-A POSTROUTING -p tcp -m tcp '
                           r'-j CHECKSUM --checksum-fill')
        namespace = self.useFixture(net_helpers.NamespaceFixture()).name
        self.agent._ensure_datapath_checksum(namespace)
        iptables_mgr = iptables_manager.IptablesManager(
            use_ipv6=True, nat=False, namespace=namespace, external_lock=False)
        for rule in iptables_mgr.get_rules_for_table('mangle'):
            if regex.match(rule):
                return
        self.fail('Rule not found in "mangle" table, in namespace %s' %
                  namespace)

    def test_metadata_proxy_handler_idl(self):
        # This test relies on the configuration option metadata_workers=0
        proxy_sb_idl = metadata_server.MetadataProxyHandler._sb_idl
        agent_sb_idl = self.agent.sb_idl
        self.assertEqual(agent_sb_idl, proxy_sb_idl)

    @ovn_common.skip_if_additional_chassis_not_supported('sb_api')
    def test_metadata_provisioned_on_additional_chassis_change(self):
        other_chassis_name = uuidutils.generate_uuid()
        self.add_fake_chassis("other_chassis", name=other_chassis_name)

        agent_chassis = idlutils.row_by_value(
            self.sb_api, 'Chassis', 'name', self.chassis_name)

        lswitchport_name, lswitch_name = self._create_logical_switch_port()

        self.sb_api.lsp_bind(
            lswitchport_name, other_chassis_name).execute(
                check_error=True, log_errors=True)
        pb = idlutils.row_by_value(
            self.sb_api, 'Port_Binding', 'logical_port', lswitchport_name)

        with mock.patch.object(
                agent.MetadataAgent, 'provision_datapath') as m_provision:

            # Update the additional_chassis
            self.sb_api.db_set(
                'Port_Binding', pb.uuid,
                additional_chassis=[agent_chassis.uuid]).execute(
                    check_error=True, log_errors=True)

            n_utils.wait_until_true(
                lambda: m_provision.called,
                timeout=10,
                exception=NoDatapathProvision(
                    "Additional chassis didn't trigger Port Binding event"))

    @ovn_common.skip_if_additional_chassis_not_supported('sb_api')
    def test_metadata_not_provisioned_on_foreign_additional_chassis_change(
            self):
        other_chassis_name = uuidutils.generate_uuid()
        self.add_fake_chassis("other_chassis", name=other_chassis_name)

        agent_chassis = idlutils.row_by_value(
            self.sb_api, 'Chassis', 'name', self.chassis_name)
        other_chassis = idlutils.row_by_value(
            self.sb_api, 'Chassis', 'name', other_chassis_name)

        lswitchport_name, lswitch_name = self._create_logical_switch_port()

        pb_event = PortBindingUpdateEvent(lswitchport_name)
        self.agent.sb_idl.idl.notify_handler.watch_event(pb_event)
        self.sb_api.lsp_bind(
            lswitchport_name, agent_chassis.name).execute(
                check_error=True, log_errors=True)
        self.assertTrue(pb_event.wait())
        pb = idlutils.row_by_value(
            self.sb_api, 'Port_Binding', 'logical_port', lswitchport_name)

        with mock.patch.object(
                agent.MetadataAgent, 'provision_datapath') as m_provision:

            # Update the additional_chassis, the agent should not see the
            # notification because it has only its own chassis row locally and
            # does not see other chassis
            self.sb_api.db_set(
                'Port_Binding', pb.uuid,
                additional_chassis=[other_chassis.uuid]).execute(
                    check_error=True, log_errors=True)

            with testtools.ExpectedException(NoDatapathProvision):
                n_utils.wait_until_true(
                    lambda: m_provision.called,
                    timeout=1,
                    exception=NoDatapathProvision(
                        "Provisioning wasn't triggered"))

    @ovn_common.skip_if_additional_chassis_not_supported
    def test_metadata_teardown_on_additional_chassis_removed(self):
        other_chassis_name = uuidutils.generate_uuid()
        self.add_fake_chassis("other_chassis", name=other_chassis_name)

        agent_chassis = idlutils.row_by_value(
            self.sb_api, 'Chassis', 'name', self.chassis_name)

        lswitchport_name, lswitch_name = self._create_logical_switch_port()

        self.sb_api.lsp_bind(
            lswitchport_name, other_chassis_name).execute(
                check_error=True, log_errors=True)
        pb = idlutils.row_by_value(
            self.sb_api, 'Port_Binding', 'logical_port', lswitchport_name)

        with mock.patch.object(
                agent.MetadataAgent, 'provision_datapath') as m_provision:

            # Update the additional_chassis
            self.sb_api.db_set(
                'Port_Binding', pb.uuid,
                additional_chassis=[agent_chassis.uuid]).execute(
                    check_error=True, log_errors=True)

            n_utils.wait_until_true(
                lambda: m_provision.called,
                timeout=10,
                exception=NoDatapathProvision(
                    "Additional chassis didn't trigger Port Binding event"))

            m_provision.reset_mock()

            # Remove the additional_chassis but keep the chassis. This is
            # simulates the live migration has failed
            self.sb_api.db_set('Port_Binding', pb.uuid,
                               additional_chassis=[]).execute(
                    check_error=True, log_errors=True)

            n_utils.wait_until_true(
                lambda: m_provision.called,
                timeout=10,
                exception=NoDatapathProvision(
                    "Removing additional chassis did not call teardown"))

    @ovn_common.skip_if_additional_chassis_not_supported('sb_api')
    def test_metadata_additional_chassis_removed_chassis_set(self):
        other_chassis_name = uuidutils.generate_uuid()
        self.add_fake_chassis("other_chassis", name=other_chassis_name)

        agent_chassis = idlutils.row_by_value(
            self.sb_api, 'Chassis', 'name', self.chassis_name)

        lswitchport_name, lswitch_name = self._create_logical_switch_port()

        self.sb_api.lsp_bind(
            lswitchport_name, other_chassis_name).execute(
                check_error=True, log_errors=True)
        pb = idlutils.row_by_value(
            self.sb_api, 'Port_Binding', 'logical_port', lswitchport_name)

        with mock.patch.object(
                agent.MetadataAgent, 'provision_datapath') as m_provision:

            # Update the additional_chassis
            self.sb_api.db_set(
                'Port_Binding', pb.uuid,
                additional_chassis=[agent_chassis.uuid]).execute(
                    check_error=True, log_errors=True)

            n_utils.wait_until_true(
                lambda: m_provision.called,
                timeout=10,
                exception=NoDatapathProvision(
                    "Additional chassis didn't trigger Port Binding event"))

            m_provision.reset_mock()

            self.sb_api.db_set(
                'Port_Binding', pb.uuid,
                additional_chassis=[], chassis=agent_chassis.uuid).execute(
                    check_error=True, log_errors=True)

            with testtools.ExpectedException(NoDatapathProvision):
                n_utils.wait_until_true(
                    lambda: m_provision.called,
                    timeout=1,
                    exception=NoDatapathProvision(
                        "Removing additional chassis did not call teardown"))

    def _test_metadata_additional_chassis_removed(self, new_chassis_uuid):
        other_chassis_name = uuidutils.generate_uuid()
        self.add_fake_chassis("other_chassis", name=other_chassis_name)

        agent_chassis = idlutils.row_by_value(
            self.sb_api, 'Chassis', 'name', self.chassis_name)

        lswitchport_name, lswitch_name = self._create_logical_switch_port()

        self.sb_api.lsp_bind(
            lswitchport_name, other_chassis_name).execute(
                check_error=True, log_errors=True)
        pb = idlutils.row_by_value(
            self.sb_api, 'Port_Binding', 'logical_port', lswitchport_name)

        with mock.patch.object(
                agent.MetadataAgent, 'provision_datapath') as m_provision:

            # Update the additional_chassis
            self.sb_api.db_set(
                'Port_Binding', pb.uuid,
                additional_chassis=[agent_chassis.uuid]).execute(
                    check_error=True, log_errors=True)

            n_utils.wait_until_true(
                lambda: m_provision.called,
                timeout=10,
                exception=NoDatapathProvision(
                    "Additional chassis didn't trigger Port Binding event"))

            m_provision.reset_mock()

            self.sb_api.db_set(
                'Port_Binding', pb.uuid,
                additional_chassis=[], chassis=new_chassis_uuid).execute(
                    check_error=True, log_errors=True)

            n_utils.wait_until_true(
                lambda: m_provision.called,
                timeout=10,
                exception=NoDatapathProvision(
                    "Removing additional chassis did not call teardown"))

    @ovn_common.skip_if_additional_chassis_not_supported('sb_api')
    def test_metadata_additional_chassis_removed_different_chassis_set(self):
        other_chassis_name2 = uuidutils.generate_uuid()
        self.add_fake_chassis("other_chassis2", name=other_chassis_name2)
        other_chassis2 = idlutils.row_by_value(
            self.sb_api, 'Chassis', 'name', other_chassis_name2)
        self._test_metadata_additional_chassis_removed(other_chassis2.uuid)

    @ovn_common.skip_if_additional_chassis_not_supported('sb_api')
    def test_metadata_additional_chassis_removed_chassis_unset(self):
        self._test_metadata_additional_chassis_removed(new_chassis_uuid=[])

    @ovn_common.skip_if_additional_chassis_not_supported('sb_api')
    def test_metadata_port_binding_column_updated(self):
        agent_chassis = idlutils.row_by_value(
            self.sb_api, 'Chassis', 'name', self.chassis_name)

        lswitchport_name, lswitch_name = self._create_logical_switch_port()

        pb_event = PortBindingUpdateEvent(lswitchport_name)
        self.agent.sb_idl.idl.notify_handler.watch_event(pb_event)
        self.sb_api.lsp_bind(
            lswitchport_name, agent_chassis.name).execute(
                check_error=True, log_errors=True)
        self.assertTrue(pb_event.wait())
        pb = idlutils.row_by_value(
            self.sb_api, 'Port_Binding', 'logical_port', lswitchport_name)

        with mock.patch.object(
                agent.MetadataAgent, 'provision_datapath') as m_provision:

            self.sb_api.db_add('Port_Binding', pb.uuid,
                               'external_ids', {'foo': 'bar'}).execute(
                    check_error=True, log_errors=True)

            with testtools.ExpectedException(NoDatapathProvision):
                n_utils.wait_until_true(
                    lambda: m_provision.called,
                    timeout=1,
                    exception=NoDatapathProvision(
                        "Provisioning wasn't triggered"))

    def test__cleanup_previous_tags(self):
        def check_tags():
            try:
                external_ids = self.sb_api.db_get(
                    'Chassis_Private', self.chassis_name,
                    'external_ids').execute(check_error=True)
                for _key in (ovn_const.OVN_AGENT_NEUTRON_SB_CFG_KEY,
                             ovn_const.OVN_AGENT_NEUTRON_DESC_KEY,
                             ovn_const.OVN_AGENT_NEUTRON_ID_KEY):
                    self.assertNotIn(_key, external_ids)

                # Just in case, check that we are NOT deleting the needed tags.
                for _key in (ovn_const.OVN_AGENT_METADATA_SB_CFG_KEY,
                             ovn_const.OVN_AGENT_METADATA_ID_KEY):
                    self.assertIn(_key, external_ids)
                return True
            except Exception:
                return False

        external_ids = {
            ovn_const.OVN_AGENT_NEUTRON_SB_CFG_KEY: '1',
            ovn_const.OVN_AGENT_NEUTRON_DESC_KEY: 'description',
            ovn_const.OVN_AGENT_NEUTRON_ID_KEY: uuidutils.generate_uuid()}
        self.sb_api.db_set(
            'Chassis_Private', self.chassis_name,
            ('external_ids', external_ids)).execute(check_error=True)

        self.agent._cleanup_previous_tags()
        n_utils.wait_until_true(check_tags, timeout=10)
