# Copyright (c) 2019 Red Hat Inc.
# All rights reserved.
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

from neutron_lib import constants
from neutron_lib import context
from oslo_utils import uuidutils

from neutron.agent.l3 import agent as l3_agent
from neutron.agent.l3.extensions import conntrack_helper as cth
from neutron.agent.l3 import l3_agent_extension_api as l3_ext_api
from neutron.agent.l3 import router_info as l3router
from neutron.agent.linux import iptables_manager
from neutron.api.rpc.callbacks.consumer import registry
from neutron.api.rpc.callbacks import resources
from neutron.api.rpc.handlers import resources_rpc
from neutron.objects import conntrack_helper as cth_obj
from neutron.tests import base
from neutron.tests.unit.agent.l3 import test_agent


BINARY_NAME = iptables_manager.get_binary_name()
DEFAULT_RULE = ('PREROUTING', '-j %s-' % BINARY_NAME +
                cth.DEFAULT_CONNTRACK_HELPER_CHAIN)
HOSTNAME = 'testhost'


class ConntrackHelperExtensionBaseTestCase(
        test_agent.BasicRouterOperationsFramework):

    def setUp(self):
        super().setUp()

        self.cth_ext = cth.ConntrackHelperAgentExtension()

        self.context = context.get_admin_context()
        self.connection = mock.Mock()

        self.router_id = uuidutils.generate_uuid()
        self.conntrack_helper1 = cth_obj.ConntrackHelper(
            context=None, id=uuidutils.generate_uuid(), protocol='udp',
            port=69, helper='tftp', router_id=self.router_id)

        self.agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        self.router = {'id': self.router_id,
                       'ha': False,
                       'distributed': False}
        self.router_info = l3router.RouterInfo(self.agent, self.router_id,
                                               self.router, **self.ri_kwargs)
        self.agent.router_info[self.router['id']] = self.router_info

        self.get_router_info = mock.patch(
            'neutron.agent.l3.l3_agent_extension_api.'
            'L3AgentExtensionAPI.get_router_info').start()
        self.get_router_info.return_value = self.router_info

        self.agent_api = l3_ext_api.L3AgentExtensionAPI(None, None)
        self.cth_ext.consume_api(self.agent_api)

        self.conntrack_helpers = [self.conntrack_helper1]


class ConntrackHelperExtensionInitializeTestCase(
     ConntrackHelperExtensionBaseTestCase):

    @mock.patch.object(registry, 'register')
    @mock.patch.object(resources_rpc, 'ResourcesPushRpcCallback')
    def test_initialize_subscribed_to_rpc(self, rpc_mock, subscribe_mock):
        call_to_patch = 'neutron_lib.rpc.Connection'
        with mock.patch(call_to_patch,
                        return_value=self.connection) as create_connection:
            self.cth_ext.initialize(
                self.connection, constants.L3_AGENT_MODE)
            create_connection.assert_has_calls([mock.call()])
            self.connection.create_consumer.assert_has_calls(
                [mock.call(
                     resources_rpc.resource_type_versioned_topic(
                         resources.CONNTRACKHELPER),
                     [rpc_mock()],
                     fanout=True)]
            )
            subscribe_mock.assert_called_with(
                mock.ANY, resources.CONNTRACKHELPER)


class ConntrackHelperExtensionTestCase(ConntrackHelperExtensionBaseTestCase):

    def setUp(self):
        super().setUp()
        self.cth_ext.initialize(
            self.connection, constants.L3_AGENT_MODE)
        self._set_bulk_pull_mock()

    def _set_bulk_pull_mock(self):

        def _bulk_pull_mock(context, resource_type, filter_kwargs=None):
            if 'router_id' in filter_kwargs:
                result = []
                for cthobj in self.conntrack_helpers:
                    if cthobj.router_id in filter_kwargs['router_id']:
                        result.append(cthobj)
                return result
            return self.conntrack_helpers
        self.bulk_pull = mock.patch(
            'neutron.api.rpc.handlers.resources_rpc.'
            'ResourcesPullRpcApi.bulk_pull').start()
        self.bulk_pull.side_effect = _bulk_pull_mock

    @mock.patch.object(iptables_manager.IptablesTable, 'add_rule')
    @mock.patch.object(iptables_manager.IptablesTable, 'add_chain')
    def test_create_router(self, mock_add_chain, mock_add_rule):
        self.cth_ext.add_router(self.context, self.router)

        chain_name = (cth.CONNTRACK_HELPER_CHAIN_PREFIX +
                      self.conntrack_helper1.id)[
                     :constants.MAX_IPTABLES_CHAIN_LEN_WRAP]
        chain_rule = ('-p %(protocol)s --dport %(dport)s -j CT --helper '
                      '%(helper)s' %
                      {'protocol': self.conntrack_helper1.protocol,
                       'dport': self.conntrack_helper1.port,
                       'helper': self.conntrack_helper1.helper})
        tag = cth.CONNTRACK_HELPER_PREFIX + self.conntrack_helper1.id

        self.assertEqual(mock_add_chain.call_count, 6)
        self.assertEqual(mock_add_rule.call_count, 6)

        mock_add_chain.assert_has_calls([
            mock.call(cth.DEFAULT_CONNTRACK_HELPER_CHAIN),
            mock.call(cth.DEFAULT_CONNTRACK_HELPER_CHAIN),
            mock.call(cth.DEFAULT_CONNTRACK_HELPER_CHAIN),
            mock.call(chain_name),
            mock.call(chain_name)
        ])

        mock_add_rule.assert_has_calls([
            mock.call(DEFAULT_RULE[0], DEFAULT_RULE[1]),
            mock.call(DEFAULT_RULE[0], DEFAULT_RULE[1]),
            mock.call(cth.DEFAULT_CONNTRACK_HELPER_CHAIN, '-j %s-' %
                      BINARY_NAME + chain_name, tag=tag),
            mock.call(cth.DEFAULT_CONNTRACK_HELPER_CHAIN, '-j %s-' %
                      BINARY_NAME + chain_name, tag=tag),
            mock.call(chain_name, chain_rule, tag=tag),
            mock.call(chain_name, chain_rule, tag=tag)
        ])

    @mock.patch.object(iptables_manager.IptablesTable, 'add_rule')
    @mock.patch.object(iptables_manager.IptablesTable, 'add_chain')
    def test_update_router(self, mock_add_chain, mock_add_rule):
        self.cth_ext.add_router(self.context, self.router)
        mock_add_chain.reset_mock()
        mock_add_rule.reset_mock()
        self.cth_ext.update_router(self.context, self.router)
        mock_add_chain.assert_not_called()
        mock_add_rule.assert_not_called()

    @mock.patch.object(iptables_manager.IptablesTable, 'add_rule')
    @mock.patch.object(iptables_manager.IptablesTable, 'add_chain')
    def test_add_conntrack_helper_update_router(self, mock_add_chain,
                                                mock_add_rule):
        self.cth_ext.add_router(self.context, self.router)
        # Create another conntrack helper with the same router_id
        mock_add_chain.reset_mock()
        mock_add_rule.reset_mock()

        test_conntrackhelper = cth_obj.ConntrackHelper(
            context=None,
            id=uuidutils.generate_uuid(),
            protocol='tcp',
            port=21,
            helper='ftp',
            router_id=self.conntrack_helper1.router_id)
        self.conntrack_helpers.append(test_conntrackhelper)
        self.cth_ext.update_router(self.context, self.router)

        chain_name = (cth.CONNTRACK_HELPER_CHAIN_PREFIX +
                      test_conntrackhelper.id)[
                     :constants.MAX_IPTABLES_CHAIN_LEN_WRAP]
        chain_rule = ('-p %(protocol)s --dport %(dport)s -j CT --helper '
                      '%(helper)s' %
                      {'protocol': test_conntrackhelper.protocol,
                       'dport': test_conntrackhelper.port,
                       'helper': test_conntrackhelper.helper})
        tag = cth.CONNTRACK_HELPER_PREFIX + test_conntrackhelper.id

        self.assertEqual(mock_add_chain.call_count, 6)
        self.assertEqual(mock_add_rule.call_count, 6)

        mock_add_chain.assert_has_calls([
            mock.call(cth.DEFAULT_CONNTRACK_HELPER_CHAIN),
            mock.call(cth.DEFAULT_CONNTRACK_HELPER_CHAIN),
            mock.call(cth.DEFAULT_CONNTRACK_HELPER_CHAIN),
            mock.call(chain_name),
            mock.call(chain_name)
        ])

        mock_add_rule.assert_has_calls([
            mock.call(DEFAULT_RULE[0], DEFAULT_RULE[1]),
            mock.call(DEFAULT_RULE[0], DEFAULT_RULE[1]),
            mock.call(cth.DEFAULT_CONNTRACK_HELPER_CHAIN, '-j %s-' %
                      BINARY_NAME + chain_name, tag=tag),
            mock.call(cth.DEFAULT_CONNTRACK_HELPER_CHAIN, '-j %s-' %
                      BINARY_NAME + chain_name, tag=tag),
            mock.call(chain_name, chain_rule, tag=tag),
            mock.call(chain_name, chain_rule, tag=tag)
        ])

    @mock.patch.object(cth.ConntrackHelperMapping, 'clear_by_router_id')
    def test_delete_router(self, mock_clear_by_router_id):
        router_data = {'id': self.router_id,
                       'ha': False,
                       'distributed': False}
        self.cth_ext.delete_router(self.context, router_data)
        mock_clear_by_router_id.assert_called_with(self.router_id)


class ConntrackHelperMappingTestCase(base.BaseTestCase):
    def setUp(self):
        super().setUp()
        self.mapping = cth.ConntrackHelperMapping()
        self.router1 = uuidutils.generate_uuid()
        self.router2 = uuidutils.generate_uuid()
        self.conntrack_helper1 = cth_obj.ConntrackHelper(
            context=None, id=uuidutils.generate_uuid(), protocol='udp',
            port=69, helper='tftp', router_id=self.router1)
        self.conntrack_helper2 = cth_obj.ConntrackHelper(
            context=None, id=uuidutils.generate_uuid(), protocol='udp',
            port=69, helper='tftp', router_id=self.router2)
        self.conntrack_helper3 = cth_obj.ConntrackHelper(
            context=None, id=uuidutils.generate_uuid(), protocol='udp',
            port=21, helper='ftp', router_id=self.router1)
        self.conntrack_helper4 = cth_obj.ConntrackHelper(
            context=None, id=uuidutils.generate_uuid(), protocol='udp',
            port=21, helper='ftp', router_id=self.router2)
        self.conntrack_helper_dict = {
            self.conntrack_helper1.id: self.conntrack_helper1,
            self.conntrack_helper2.id: self.conntrack_helper2,
            self.conntrack_helper3.id: self.conntrack_helper3,
            self.conntrack_helper4.id: self.conntrack_helper4}

    def _set_cth(self):
        self.mapping.set_conntrack_helpers(
            self.conntrack_helper_dict.values())

    def test_set_conntrack_helpers(self):
        self._set_cth()
        cth_ids = self.conntrack_helper_dict.keys()
        managed_cths = self.mapping.get_managed_conntrack_helpers()

        for cth_id, obj in managed_cths.items():
            self.assertIn(cth_id, cth_ids)
            self.assertEqual(obj, self.conntrack_helper_dict[cth_id])
        self.assertEqual(
            len(cth_ids), len(managed_cths.keys()))

    def test_update_conntrack_helper(self):
        self._set_cth()
        new_conntrack_helper1 = cth_obj.ConntrackHelper(
            context=None, id=self.conntrack_helper1.id, protocol='udp',
            port=6969, helper='tftp', router_id=self.router1)
        self.mapping.update_conntrack_helpers([new_conntrack_helper1])
        managed_cths = self.mapping.get_managed_conntrack_helpers()
        self.assertEqual(
            new_conntrack_helper1,
            managed_cths[self.conntrack_helper1.id])
        for router_id in self.mapping._router_conntrack_helper_mapping.keys():
            self.assertIn(router_id, [self.router1, self.router2])
        self.assertEqual(
            len([self.router1, self.router2]),
            len(self.mapping._router_conntrack_helper_mapping.keys()))

    def test_del_conntrack_helper(self):
        self._set_cth()
        self.mapping.del_conntrack_helpers([self.conntrack_helper3,
                                            self.conntrack_helper2,
                                            self.conntrack_helper4])
        managed_cths = self.mapping.get_managed_conntrack_helpers()
        self.assertEqual([self.conntrack_helper1.id],
                         list(managed_cths.keys()))
        self.assertNotIn(self.conntrack_helper3.id,
                         self.mapping._router_conntrack_helper_mapping[
                             self.conntrack_helper3.router_id])
        self.assertNotIn(self.router2,
                         self.mapping._router_conntrack_helper_mapping.keys())

    def test_clear_by_router_id(self):
        self._set_cth()
        self.mapping.clear_by_router_id(self.router2)
        managed_cths = self.mapping.get_managed_conntrack_helpers()
        self.assertNotIn(self.conntrack_helper2, managed_cths.keys())
        self.assertNotIn(self.conntrack_helper4, managed_cths.keys())

    def test_check_conntrack_helper_changes(self):
        self._set_cth()
        new_cth = cth_obj.ConntrackHelper(
            context=None, id=self.conntrack_helper1.id, protocol='udp',
            port=6969, helper='tftp', router_id=self.router1)
        self.assertTrue(self.mapping.check_conntrack_helper_changes(new_cth))

    def test_check_conntrack_helper_changes_no_change(self):
        self._set_cth()
        new_cth = cth_obj.ConntrackHelper(
            context=None, id=self.conntrack_helper1.id, protocol='udp',
            port=69, helper='tftp', router_id=self.router1)
        self.assertFalse(self.mapping.check_conntrack_helper_changes(new_cth))
