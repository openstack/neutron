# Copyright 2018 OpenStack Foundation
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

import netaddr
from neutron_lib import constants as lib_const
from neutron_lib import context
from oslo_utils import uuidutils

from neutron.agent.l3 import agent as l3_agent
from neutron.agent.l3.extensions import port_forwarding as pf
from neutron.agent.l3 import l3_agent_extension_api as l3_ext_api
from neutron.agent.l3 import router_info as l3router
from neutron.agent.linux import iptables_manager
from neutron.api.rpc.callbacks.consumer import registry
from neutron.api.rpc.callbacks import resources
from neutron.api.rpc.handlers import resources_rpc
from neutron.objects import port_forwarding as pf_obj
from neutron.objects import router
from neutron.tests import base
from neutron.tests.unit.agent.l3 import test_agent

_uuid = uuidutils.generate_uuid

TEST_FIP = '10.100.2.45'
BINARY_NAME = iptables_manager.get_binary_name()
DEFAULT_RULE = ('PREROUTING', '-j %s-fip-pf' % BINARY_NAME)
DEFAULT_CHAIN = 'fip-pf'
HOSTNAME = 'testhost'


class PortForwardingExtensionBaseTestCase(
        test_agent.BasicRouterOperationsFramework):

    def setUp(self):
        super(PortForwardingExtensionBaseTestCase, self).setUp()

        self.fip_pf_ext = pf.PortForwardingAgentExtension()

        self.context = context.get_admin_context()
        self.connection = mock.Mock()
        self.floatingip2 = router.FloatingIP(context=None, id=_uuid(),
                                             floating_ip_address='172.24.6.12',
                                             floating_network_id=_uuid(),
                                             router_id=_uuid(),
                                             status='ACTIVE')
        self.portforwarding1 = pf_obj.PortForwarding(
            context=None, id=_uuid(), floatingip_id=self.floatingip2.id,
            external_port=1111, protocol='tcp', internal_port_id=_uuid(),
            internal_ip_address='1.1.1.1', internal_port=11111,
            floating_ip_address=self.floatingip2.floating_ip_address,
            router_id=self.floatingip2.router_id)

        self.agent = l3_agent.L3NATAgent(HOSTNAME, self.conf)
        self.ex_gw_port = {'id': _uuid()}
        self.fip = {'id': _uuid(),
                    'floating_ip_address': TEST_FIP,
                    'fixed_ip_address': '192.168.0.1',
                    'floating_network_id': _uuid(),
                    'port_id': _uuid(),
                    'host': HOSTNAME}
        self.router = {'id': self.floatingip2.router_id,
                       'gw_port': self.ex_gw_port,
                       'ha': False,
                       'distributed': False,
                       lib_const.FLOATINGIP_KEY: [self.fip]}
        self.router_info = l3router.RouterInfo(
            self.agent, self.floatingip2.router_id, self.router,
            **self.ri_kwargs)
        self.centralized_port_forwarding_fip_set = set(
            [str(self.floatingip2.floating_ip_address) + '/32'])
        self.pf_managed_fips = [self.floatingip2.id]
        self.router_info.ex_gw_port = self.ex_gw_port
        self.router_info.fip_managed_by_port_forwardings = self.pf_managed_fips
        self.agent.router_info[self.router['id']] = self.router_info

        self.get_router_info = mock.patch(
            'neutron.agent.l3.l3_agent_extension_api.'
            'L3AgentExtensionAPI.get_router_info').start()
        self.get_router_info.return_value = self.router_info

        self.agent_api = l3_ext_api.L3AgentExtensionAPI(None, None)
        self.fip_pf_ext.consume_api(self.agent_api)

        self.port_forwardings = [self.portforwarding1]


class FipPortForwardingExtensionInitializeTestCase(
     PortForwardingExtensionBaseTestCase):

    @mock.patch.object(registry, 'register')
    @mock.patch.object(resources_rpc, 'ResourcesPushRpcCallback')
    def test_initialize_subscribed_to_rpc(self, rpc_mock, subscribe_mock):
        call_to_patch = 'neutron_lib.rpc.Connection'
        with mock.patch(call_to_patch,
                        return_value=self.connection) as create_connection:
            self.fip_pf_ext.initialize(
                self.connection, lib_const.L3_AGENT_MODE)
            create_connection.assert_has_calls([mock.call()])
            self.connection.create_consumer.assert_has_calls(
                [mock.call(
                     resources_rpc.resource_type_versioned_topic(
                         resources.PORTFORWARDING),
                     [rpc_mock()],
                     fanout=True)]
            )
            subscribe_mock.assert_called_with(
                mock.ANY, resources.PORTFORWARDING)


class FipPortForwardingExtensionTestCase(PortForwardingExtensionBaseTestCase):

    def setUp(self):
        super(FipPortForwardingExtensionTestCase, self).setUp()
        self.fip_pf_ext.initialize(
            self.connection, lib_const.L3_AGENT_MODE)
        self._set_bulk_pull_mock()

    def _set_bulk_pull_mock(self):

        def _bulk_pull_mock(context, resource_type, filter_kwargs=None):
            if 'floatingip_id' in filter_kwargs:
                result = []
                for pfobj in self.port_forwardings:
                    if pfobj.floatingip_id in filter_kwargs['floatingip_id']:
                        result.append(pfobj)
                return result
            return self.port_forwardings
        self.bulk_pull = mock.patch(
            'neutron.api.rpc.handlers.resources_rpc.'
            'ResourcesPullRpcApi.bulk_pull').start()
        self.bulk_pull.side_effect = _bulk_pull_mock

    def _get_chainrule_tag_from_pf_obj(self, target_obj):
        rule_tag = 'fip_portforwarding-' + target_obj.id
        chain_name = (
            'pf-' + target_obj.id)[:lib_const.MAX_IPTABLES_CHAIN_LEN_WRAP]
        chain_rule = (chain_name,
                      '-d %s/32 -p %s -m %s --dport %s '
                      '-j DNAT --to-destination %s:%s' % (
                          target_obj.floating_ip_address,
                          target_obj.protocol,
                          target_obj.protocol,
                          target_obj.external_port,
                          target_obj.internal_ip_address,
                          target_obj.internal_port))
        return chain_name, chain_rule, rule_tag

    def _assert_called_iptables_process(self, mock_add_chain,
                                        mock_add_rule, mock_add_fip,
                                        mock_send_fip_status, target_obj=None):
        if target_obj:
            obj = target_obj
        else:
            obj = self.portforwarding1
        (chain_name,
         chain_rule, rule_tag) = self._get_chainrule_tag_from_pf_obj(obj)
        mock_add_chain.assert_has_calls([mock.call('fip-pf'),
                                         mock.call(chain_name)])
        mock_add_rule.assert_has_calls(
            [mock.call(DEFAULT_RULE[0], DEFAULT_RULE[1]),
             mock.call(DEFAULT_CHAIN, ('-j %s-' % BINARY_NAME) + chain_name,
                       tag=rule_tag),
             mock.call(chain_name, chain_rule[1], tag=rule_tag)])
        mock_add_fip.assert_called_once_with(
            {'floating_ip_address': str(obj.floating_ip_address)},
            mock.ANY, mock.ANY)
        fip_status = {
            obj.floatingip_id:
                lib_const.FLOATINGIP_STATUS_ACTIVE}
        mock_send_fip_status.assert_called_once_with(mock.ANY, fip_status)

    @mock.patch.object(pf.PortForwardingAgentExtension,
                       '_sending_port_forwarding_fip_status')
    @mock.patch.object(iptables_manager.IptablesTable, 'add_rule')
    @mock.patch.object(iptables_manager.IptablesTable, 'add_chain')
    @mock.patch.object(l3router.RouterInfo, 'add_floating_ip')
    def test_add_update_router(self, mock_add_fip,
                               mock_add_chain, mock_add_rule,
                               mock_send_fip_status):
        # simulate the router add and already there is a port forwarding
        # resource association.
        mock_add_fip.return_value = lib_const.FLOATINGIP_STATUS_ACTIVE
        self.fip_pf_ext.add_router(self.context, self.router)
        self._assert_called_iptables_process(
            mock_add_chain, mock_add_rule, mock_add_fip, mock_send_fip_status,
            target_obj=self.portforwarding1)

        # Then we create another port forwarding with the same fip
        mock_add_fip.reset_mock()
        mock_send_fip_status.reset_mock()
        mock_add_chain.reset_mock()
        mock_add_rule.reset_mock()

        test_portforwarding = pf_obj.PortForwarding(
            context=None, id=_uuid(), floatingip_id=self.floatingip2.id,
            external_port=2222, protocol='tcp', internal_port_id=_uuid(),
            internal_ip_address='2.2.2.2', internal_port=22222,
            floating_ip_address=self.floatingip2.floating_ip_address,
            router_id=self.floatingip2.router_id)
        self.pf_managed_fips.append(self.floatingip2.id)
        self.port_forwardings.append(test_portforwarding)
        self.fip_pf_ext.update_router(self.context, self.router)
        self._assert_called_iptables_process(
            mock_add_chain, mock_add_rule, mock_add_fip, mock_send_fip_status,
            target_obj=test_portforwarding)

    @mock.patch.object(iptables_manager.IptablesTable, 'add_rule')
    @mock.patch.object(iptables_manager.IptablesTable, 'add_chain')
    @mock.patch('neutron.agent.linux.ip_lib.IPDevice')
    @mock.patch.object(iptables_manager.IptablesTable, 'remove_chain')
    def test_add_update_router_port_forwarding_change(
            self, mock_remove_chain, mock_ip_device, mock_add_chain,
            mock_add_rule):
        self.fip_pf_ext.add_router(self.context, self.router)
        update_portforwarding = pf_obj.PortForwarding(
            context=None, id=self.portforwarding1.id,
            floatingip_id=self.portforwarding1.floatingip_id,
            external_port=2222, protocol='tcp', internal_port_id=_uuid(),
            internal_ip_address='2.2.2.2', internal_port=22222,
            floating_ip_address=self.portforwarding1.floating_ip_address,
            router_id=self.portforwarding1.router_id)
        self.port_forwardings = [update_portforwarding]
        mock_delete = mock.Mock()
        mock_ip_device.return_value = mock_delete
        self.fip_pf_ext.update_router(self.context, self.router)
        current_chain = ('pf-' + self.portforwarding1.id)[
                        :lib_const.MAX_IPTABLES_CHAIN_LEN_WRAP]
        mock_remove_chain.assert_called_once_with(current_chain)
        mock_delete.delete_socket_conntrack_state.assert_called_once_with(
            str(self.portforwarding1.floating_ip_address),
            self.portforwarding1.external_port,
            protocol=self.portforwarding1.protocol)
        (chain_name,
         chain_rule, rule_tag) = self._get_chainrule_tag_from_pf_obj(
            update_portforwarding)
        mock_add_chain.assert_has_calls([mock.call('fip-pf'),
                                         mock.call(chain_name)])
        mock_add_rule.assert_has_calls(
            [mock.call(DEFAULT_RULE[0], DEFAULT_RULE[1]),
             mock.call(DEFAULT_CHAIN, ('-j %s-' % BINARY_NAME) + chain_name,
                       tag=rule_tag),
             mock.call(chain_name, chain_rule[1], tag=rule_tag)])

    @mock.patch.object(pf.PortForwardingAgentExtension,
                       '_sending_port_forwarding_fip_status')
    @mock.patch('neutron.agent.linux.ip_lib.IPDevice')
    @mock.patch.object(iptables_manager.IptablesTable, 'remove_chain')
    def test_add_update_router_port_forwarding_remove(
            self, mock_remove_chain, mock_ip_device,
            mock_send_fip_status):
        self.fip_pf_ext.add_router(self.context, self.router)
        mock_send_fip_status.reset_mock()
        self.port_forwardings = []
        mock_device = mock.Mock()
        mock_ip_device.return_value = mock_device
        self.fip_pf_ext.update_router(self.context, self.router)
        current_chain = ('pf-' + self.portforwarding1.id)[
                        :lib_const.MAX_IPTABLES_CHAIN_LEN_WRAP]
        mock_remove_chain.assert_called_once_with(current_chain)
        mock_device.delete_socket_conntrack_state.assert_called_once_with(
            str(self.portforwarding1.floating_ip_address),
            self.portforwarding1.external_port,
            protocol=self.portforwarding1.protocol)
        mock_device.delete_addr_and_conntrack_state.assert_called_once_with(
            str(netaddr.IPNetwork(self.portforwarding1.floating_ip_address)))
        fip_status = {
            self.portforwarding1.floatingip_id:
                lib_const.FLOATINGIP_STATUS_DOWN}
        mock_send_fip_status.assert_called_once_with(mock.ANY, fip_status)

    @mock.patch.object(pf.PortForwardingAgentExtension,
                       '_sending_port_forwarding_fip_status')
    @mock.patch.object(iptables_manager.IptablesTable, 'add_rule')
    @mock.patch.object(iptables_manager.IptablesTable, 'add_chain')
    @mock.patch.object(l3router.RouterInfo, 'add_floating_ip')
    def test_add_delete_router(self, mock_add_fip,
                               mock_add_chain, mock_add_rule,
                               mock_send_fip_status):
        # simulate the router add and already there is a port forwarding
        # resource association.
        mock_add_fip.return_value = lib_const.FLOATINGIP_STATUS_ACTIVE
        self.fip_pf_ext.add_router(self.context, self.router)
        self._assert_called_iptables_process(
            mock_add_chain, mock_add_rule, mock_add_fip, mock_send_fip_status,
            target_obj=self.portforwarding1)

        router_fip_ids = self.fip_pf_ext.mapping.router_fip_mapping.get(
            self.router['id'])
        self.assertIsNotNone(router_fip_ids)
        for fip_id in router_fip_ids:
            pf_ids = self.fip_pf_ext.mapping.fip_port_forwarding.get(fip_id)
            self.assertIsNotNone(pf_ids)
            for pf_id in pf_ids:
                pf = self.fip_pf_ext.mapping.managed_port_forwardings.get(
                    pf_id)
                self.assertIsNotNone(pf)

        self.fip_pf_ext.delete_router(self.context, self.router)

        self.assertIsNone(
            self.fip_pf_ext.mapping.router_fip_mapping.get(self.router['id']))

    def test_check_if_need_process_no_snat_ns(self):
        ex_gw_port = {'id': _uuid()}
        router_id = _uuid()
        router = {'id': router_id,
                  'gw_port': ex_gw_port,
                  'ha': False,
                  'distributed': True}
        router_info = l3router.RouterInfo(
            self.agent, router_id, router,
            **self.ri_kwargs)
        router_info.agent_conf.agent_mode = lib_const.L3_AGENT_MODE_DVR_SNAT
        router_info.fip_managed_by_port_forwardings = True
        router_info.snat_namespace = mock.Mock()
        router_info.snat_namespace.exists.return_value = False
        self.assertFalse(self.fip_pf_ext._check_if_need_process(router_info))


class RouterFipPortForwardingMappingTestCase(base.BaseTestCase):

    def setUp(self):
        super(RouterFipPortForwardingMappingTestCase, self).setUp()
        self.mapping = pf.RouterFipPortForwardingMapping()
        self.router1 = _uuid()
        self.router2 = _uuid()
        self.floatingip1 = _uuid()
        self.floatingip2 = _uuid()
        self.floatingip3 = _uuid()
        self.portforwarding1 = pf_obj.PortForwarding(
            context=None, id=_uuid(), floatingip_id=self.floatingip1,
            external_port=1111, protocol='tcp', internal_port_id=_uuid(),
            internal_ip_address='1.1.1.1', internal_port=11111,
            floating_ip_address='111.111.111.111',
            router_id=self.router1,
            description='Some description')
        self.portforwarding2 = pf_obj.PortForwarding(
            context=None, id=_uuid(), floatingip_id=self.floatingip1,
            external_port=1112, protocol='tcp', internal_port_id=_uuid(),
            internal_ip_address='1.1.1.2', internal_port=11112,
            floating_ip_address='111.111.111.111',
            router_id=self.router1,
            description='Some description')
        self.portforwarding3 = pf_obj.PortForwarding(
            context=None, id=_uuid(), floatingip_id=self.floatingip2,
            external_port=1113, protocol='tcp', internal_port_id=_uuid(),
            internal_ip_address='1.1.1.3', internal_port=11113,
            floating_ip_address='111.222.111.222',
            router_id=self.router1,
            description=None)
        self.portforwarding4 = pf_obj.PortForwarding(
            context=None, id=_uuid(), floatingip_id=self.floatingip3,
            external_port=2222, protocol='tcp', internal_port_id=_uuid(),
            internal_ip_address='2.2.2.2', internal_port=22222,
            floating_ip_address='222.222.222.222',
            router_id=self.router2,
            description='')
        self.portforwardings_dict = {
            self.portforwarding1.id: self.portforwarding1,
            self.portforwarding2.id: self.portforwarding2,
            self.portforwarding3.id: self.portforwarding3,
            self.portforwarding4.id: self.portforwarding4}

    def _set_pf(self):
        self.mapping.set_port_forwardings(self.portforwardings_dict.values())

    def test_set_port_forwardings(self):
        self._set_pf()
        pf_ids = self.portforwardings_dict.keys()
        for pf_id, obj in self.mapping.managed_port_forwardings.items():
            self.assertIn(pf_id, pf_ids)
            self.assertEqual(obj, self.portforwardings_dict[pf_id])
        self.assertEqual(
            len(pf_ids), len(self.mapping.managed_port_forwardings.keys()))

        fip_pf_set = {
            self.floatingip1: set(
                [self.portforwarding1.id, self.portforwarding2.id]),
            self.floatingip2: set([self.portforwarding3.id]),
            self.floatingip3: set([self.portforwarding4.id])
        }
        for fip_id, pf_set in self.mapping.fip_port_forwarding.items():
            self.assertIn(
                fip_id, [self.floatingip1, self.floatingip2, self.floatingip3])
            self.assertEqual(0, len(pf_set - fip_pf_set[fip_id]))
        self.assertEqual(
            len([self.floatingip1, self.floatingip2, self.floatingip3]),
            len(self.mapping.fip_port_forwarding))

        router_fip = {
            self.router1: set([self.floatingip1, self.floatingip2]),
            self.router2: set([self.floatingip3])
        }
        for router_id, fip_set in self.mapping.router_fip_mapping.items():
            self.assertIn(router_id, [self.router1, self.router2])
            self.assertEqual(0, len(fip_set - router_fip[router_id]))
        self.assertEqual(
            len([self.router1, self.router2]),
            len(self.mapping.router_fip_mapping.keys()))

    def test_update_port_forwarding(self):
        self._set_pf()
        description = 'Some description'
        new_pf1 = pf_obj.PortForwarding(
            context=None, id=self.portforwarding2.id,
            floatingip_id=self.floatingip1,
            external_port=11122, protocol='tcp',
            internal_port_id=self.portforwarding2.internal_port_id,
            internal_ip_address='1.1.1.22', internal_port=11122,
            floating_ip_address='111.111.111.111',
            router_id=self.router1,
            description=description)
        self.mapping.update_port_forwardings([new_pf1])
        self.assertEqual(
            new_pf1,
            self.mapping.managed_port_forwardings[self.portforwarding2.id])

    def test_del_port_forwardings(self):
        self._set_pf()
        del_pfs = [self.portforwarding3, self.portforwarding2,
                   self.portforwarding4]
        self.mapping.del_port_forwardings(del_pfs)
        self.assertEqual(
            [self.portforwarding1.id],
            list(self.mapping.managed_port_forwardings.keys()))
        self.assertEqual({self.floatingip1: set([self.portforwarding1.id])},
                         self.mapping.fip_port_forwarding)
        self.assertEqual({self.router1: set([self.floatingip1])},
                         self.mapping.router_fip_mapping)

    def test_clear_by_fip(self):
        self._set_pf()
        self.mapping.clear_by_fip(self.floatingip1, self.router1)
        router_fip = {
            self.router1: set([self.floatingip2]),
            self.router2: set([self.floatingip3])
        }
        for router_id, fip_set in self.mapping.router_fip_mapping.items():
            self.assertIn(router_id, [self.router1, self.router2])
            self.assertEqual(0, len(fip_set - router_fip[router_id]))
        fip_pf_set = {
            self.floatingip2: set([self.portforwarding3.id]),
            self.floatingip3: set([self.portforwarding4.id])
        }
        for fip_id, pf_set in self.mapping.fip_port_forwarding.items():
            self.assertIn(
                fip_id, [self.floatingip2, self.floatingip3])
            self.assertEqual(0, len(pf_set - fip_pf_set[fip_id]))
        self.assertEqual(
            len([self.floatingip2, self.floatingip3]),
            len(self.mapping.fip_port_forwarding))
        pfs_dict = {self.portforwarding3.id: self.portforwarding3,
                    self.portforwarding4.id: self.portforwarding4}
        for pf_id, obj in self.mapping.managed_port_forwardings.items():
            self.assertIn(pf_id,
                          [self.portforwarding3.id, self.portforwarding4.id])
            self.assertEqual(obj, pfs_dict[pf_id])
        self.assertEqual(
            len([self.portforwarding3.id, self.portforwarding4.id]),
            len(self.mapping.managed_port_forwardings.keys()))
