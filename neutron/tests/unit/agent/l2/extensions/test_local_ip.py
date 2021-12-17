# Copyright 2021 Huawei, Inc.
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
from neutron_lib.callbacks import events as lib_events
from neutron_lib.callbacks import registry as lib_registry
from neutron_lib import context
from neutron_lib.plugins.ml2 import ovs_constants
from os_ken.lib.packet import ether_types
from os_ken.lib.packet import in_proto as ip_proto
from oslo_utils import uuidutils

from neutron.agent.l2.extensions import local_ip as local_ip_ext
from neutron.api.rpc.callbacks import events
from neutron.api.rpc.callbacks import resources
from neutron.objects import local_ip as lip_obj
from neutron.plugins.ml2.drivers.openvswitch.agent \
    import ovs_agent_extension_api as ovs_ext_api
from neutron.tests import base


class LocalIPAgentExtensionTestCase(base.BaseTestCase):

    def setUp(self):
        super(LocalIPAgentExtensionTestCase, self).setUp()
        self.context = context.get_admin_context_without_session()
        self.local_ip_ext = local_ip_ext.LocalIPAgentExtension()

        self.plugin_rpc = mock.Mock()
        self.agent_api = ovs_ext_api.OVSAgentExtensionAPI(
            int_br=mock.Mock(),
            tun_br=mock.Mock(),
            phys_brs=None,
            plugin_rpc=self.plugin_rpc)
        self.local_ip_ext.consume_api(self.agent_api)
        with mock.patch.object(
                self.local_ip_ext, '_pull_all_local_ip_associations'):
            self.local_ip_ext.initialize(mock.Mock(), 'ovs')
        self.int_br = self.local_ip_ext.int_br

    def _generate_test_lip_associations(self, count=2):
        return [lip_obj.LocalIPAssociation(
            fixed_port_id=uuidutils.generate_uuid(),
            local_ip_id=uuidutils.generate_uuid(),
            fixed_ip='10.0.0.10',
            local_ip=lip_obj.LocalIP(
                local_ip_address='172.16.0.10')) for _ in range(count)]

    def test_pulling_lip_associations_on_init(self):
        res_rpc = mock.Mock()
        lip_assocs = self._generate_test_lip_associations()
        with mock.patch('neutron.api.rpc.handlers.'
                        'resources_rpc.ResourcesPullRpcApi') as res_rpc_cls:
            res_rpc_cls.return_value = res_rpc
            res_rpc.bulk_pull.return_value = lip_assocs
            self.local_ip_ext.initialize(mock.Mock(), 'ovs')

        res_rpc.bulk_pull.assert_called_once_with(
            mock.ANY, resources.LOCAL_IP_ASSOCIATION)

        for assoc in lip_assocs:
            self.assertEqual(
                assoc, self.local_ip_ext.local_ip_updates[
                    'added'][assoc.fixed_port_id][assoc.local_ip_id])

    def test_notify_port_updated(self):
        with mock.patch.object(lib_registry, "publish") as publish_mock:
            port_id = 'test'
            self.local_ip_ext._notify_port_updated(
                self.context, port_id=port_id)
            publish_mock.assert_called_once_with(
                resources.PORT, lib_events.AFTER_UPDATE,
                self.local_ip_ext, payload=mock.ANY)
            actual_payload = publish_mock.call_args[1]['payload']
            self.assertEqual(port_id, actual_payload.resource_id)
            self.assertEqual({'changed_fields': {'local_ip'}},
                             actual_payload.metadata)

    def test_handle_updated_notification(self):
        lip_assocs = self._generate_test_lip_associations()
        with mock.patch.object(
                self.local_ip_ext,
                "_notify_port_updated") as port_update_notify:
            self.local_ip_ext._handle_notification(
                self.context, resources.LOCAL_IP_ASSOCIATION,
                lip_assocs, events.UPDATED)

        for assoc in lip_assocs:
            self.assertEqual(
                assoc, self.local_ip_ext.local_ip_updates[
                    'added'][assoc.fixed_port_id][assoc.local_ip_id])
            port_update_notify.assert_any_call(
                self.context, assoc.fixed_port_id)

        return lip_assocs

    def test_handle_deleted_notification(self, lip_assocs=None):
        lip_assocs = lip_assocs or self.test_handle_updated_notification()
        with mock.patch.object(
                self.local_ip_ext,
                "_notify_port_updated") as port_update_notify:
            self.local_ip_ext._handle_notification(
                self.context, resources.LOCAL_IP_ASSOCIATION,
                lip_assocs, events.DELETED)
            for assoc in lip_assocs:
                self.assertEqual({}, self.local_ip_ext.local_ip_updates[
                    'added'][assoc.fixed_port_id])
                self.assertEqual(
                    assoc, self.local_ip_ext.local_ip_updates[
                        'deleted'][assoc.fixed_port_id][assoc.local_ip_id])
                port_update_notify.assert_any_call(
                    self.context, assoc.fixed_port_id)

    def test_handle_port(self):
        lip_assocs = self.test_handle_updated_notification()
        for assoc in lip_assocs:
            with mock.patch.object(self.local_ip_ext,
                                   'add_local_ip_flows') as add_lip_flows:
                port = {'port_id': assoc.fixed_port_id, 'local_vlan': 1}
                self.local_ip_ext.handle_port(self.context, port)
                self.assertEqual({}, self.local_ip_ext.local_ip_updates[
                    'added'][assoc.fixed_port_id])
                add_lip_flows.assert_called_once_with(port, assoc)
        self.test_handle_deleted_notification(lip_assocs)
        for assoc in lip_assocs:
            with mock.patch.object(self.local_ip_ext,
                                   'delete_local_ip_flows') as del_lip_flows:
                port = {'port_id': assoc.fixed_port_id, 'local_vlan': 1}
                self.local_ip_ext.handle_port(self.context, port)
                self.assertEqual({}, self.local_ip_ext.local_ip_updates[
                    'deleted'][assoc.fixed_port_id])
                del_lip_flows.assert_called_once_with(port, assoc)

    def test_delete_port(self):
        lip_assocs = self.test_handle_updated_notification()
        for assoc in lip_assocs:
            port = {'port_id': assoc.fixed_port_id}
            self.local_ip_ext.delete_port(self.context, port)

        self.assertEqual({}, self.local_ip_ext.local_ip_updates['added'])
        self.assertEqual({}, self.local_ip_ext.local_ip_updates['added'])

    def test_add_local_ip_flows(self):
        assoc = self._generate_test_lip_associations(1)[0]
        port = {'port_id': assoc.fixed_port_id,
                'mac_address': 'fa:16:3e:11:22:33',
                'local_vlan': 1234}
        with mock.patch.object(self.local_ip_ext,
                               'setup_local_ip_translation') as set_lip_trans:
            self.local_ip_ext.add_local_ip_flows(port, assoc)
            set_lip_trans.assert_called_once_with(
                vlan=port['local_vlan'],
                local_ip=str(assoc.local_ip.local_ip_address),
                dest_ip=str(assoc.fixed_ip),
                mac=port['mac_address']
            )
            self.int_br.install_arp_responder.assert_called_once_with(
                vlan=port['local_vlan'],
                ip=str(assoc.local_ip.local_ip_address),
                mac=port['mac_address'], table_id=31)
            self.int_br.install_garp_blocker.assert_called_once_with(
                vlan=port['local_vlan'],
                ip=str(assoc.local_ip.local_ip_address))
            self.int_br.install_garp_blocker_exception.assert_called_once_with(
                vlan=port['local_vlan'],
                ip=str(assoc.local_ip.local_ip_address),
                except_ip=str(assoc.fixed_ip))

    def test_delete_local_ip_flows(self):
        assoc = self._generate_test_lip_associations(1)[0]
        port = {'port_id': assoc.fixed_port_id,
                'mac_address': 'fa:16:3e:11:22:33',
                'local_vlan': 1234}
        with mock.patch.object(self.local_ip_ext,
                               'delete_local_ip_translation') as del_lip_trans:
            self.local_ip_ext.delete_local_ip_flows(port, assoc)
            del_lip_trans.assert_called_once_with(
                vlan=port['local_vlan'],
                local_ip=str(assoc.local_ip.local_ip_address),
                dest_ip=str(assoc.fixed_ip),
                mac=port['mac_address']
            )
            self.int_br.delete_arp_responder.assert_called_once_with(
                vlan=port['local_vlan'],
                ip=str(assoc.local_ip.local_ip_address),
                table_id=31)
            self.int_br.delete_garp_blocker.assert_called_once_with(
                vlan=port['local_vlan'],
                ip=str(assoc.local_ip.local_ip_address))
            self.int_br.delete_garp_blocker_exception.assert_called_once_with(
                vlan=port['local_vlan'],
                ip=str(assoc.local_ip.local_ip_address),
                except_ip=str(assoc.fixed_ip))

    def test_setup_local_ip_translation(self):
        vlan = 1234
        local_ip = '172.0.0.10'
        dest_ip = '10.0.0.10'
        mac = 'fa:16:3e:11:22:33'
        self.local_ip_ext.setup_local_ip_translation(
            vlan, local_ip, dest_ip, mac)

        expected_calls = [
            mock.call(
                table=31,
                priority=10,
                nw_dst=local_ip,
                reg6=vlan,
                dl_type="0x{:04x}".format(ether_types.ETH_TYPE_IP),
                actions='mod_dl_dst:{:s},'
                        'ct(commit,table={:d},zone={:d},nat(dst={:s}))'.format(
                    mac, 60, vlan, dest_ip)),
            mock.call(
                table=31,
                priority=10,
                dl_src=mac,
                nw_src=dest_ip,
                reg6=vlan,
                ct_state="-trk",
                dl_type="0x{:04x}".format(ether_types.ETH_TYPE_IP),
                actions='ct(table={:d},zone={:d},nat'.format(60, vlan)),
            mock.call(
                    table=31,
                    priority=11,
                    nw_src=dest_ip,
                    nw_dst=local_ip,
                    reg6=vlan,
                    dl_type="0x{:04x}".format(ether_types.ETH_TYPE_IP),
                    actions='resubmit(,{:d})'.format(60))
        ]
        self.assertEqual(expected_calls, self.int_br.add_flow.mock_calls)

    def test_delete_local_ip_translation(self):
        vlan = 1234
        local_ip = '172.0.0.10'
        dest_ip = '10.0.0.10'
        mac = 'fa:16:3e:11:22:33'
        self.local_ip_ext.delete_local_ip_translation(
            vlan, local_ip, dest_ip, mac)

        expected_calls = [
            mock.call(
                table_id=31,
                priority=10,
                ipv4_dst=local_ip,
                reg6=vlan,
                eth_type=ether_types.ETH_TYPE_IP),
            mock.call(
                table_id=31,
                priority=11,
                ipv4_src=dest_ip,
                ipv4_dst=local_ip,
                reg6=vlan,
                eth_type=ether_types.ETH_TYPE_IP),
            mock.call(
                table_id=31,
                priority=10,
                eth_src=mac,
                ipv4_src=dest_ip,
                reg6=vlan,
                eth_type=ether_types.ETH_TYPE_IP)
        ]
        self.assertEqual(
            expected_calls, self.int_br.uninstall_flows.mock_calls)

    def test_setup_static_local_ip_translation(self):
        ofpp_mock = mock.Mock()
        self.int_br._get_dp.return_value = (
            mock.Mock(), mock.Mock(), ofpp_mock)
        vlan = 1234
        local_ip = '172.0.0.10'
        dest_ip = '10.0.0.10'
        mac = 'fa:16:3e:11:22:33'
        self.local_ip_ext.setup_static_local_ip_translation(
            vlan, local_ip, dest_ip, mac)

        expected_calls = [
            mock.call(src=ether_types.ETH_TYPE_IP,
                      dst=('eth_type', 0), n_bits=16),
            mock.call(src=('eth_src', 0), dst=('eth_dst', 0), n_bits=48),
            mock.call(src=('eth_dst', 0), dst=('eth_src', 0), n_bits=48),
            mock.call(src=('ipv4_src', 0), dst=('ipv4_dst', 0), n_bits=32),
            mock.call(src=int(netaddr.IPAddress(dest_ip)),
                      dst=('ipv4_src', 0), n_bits=32),
            mock.call(src=vlan, dst=('reg6', 0), n_bits=4),
            mock.call(src=ip_proto.IPPROTO_ICMP, dst=('ip_proto', 0),
                      n_bits=8),
            mock.call(src=ip_proto.IPPROTO_TCP, dst=('ip_proto', 0),
                      n_bits=8),
            mock.call(src=('tcp_src', 0), dst=('tcp_dst', 0), n_bits=16),
            mock.call(src=('tcp_dst', 0), dst=('tcp_src', 0), n_bits=16),
            mock.call(src=ip_proto.IPPROTO_UDP, dst=('ip_proto', 0),
                      n_bits=8),
            mock.call(src=('udp_src', 0), dst=('udp_dst', 0), n_bits=16),
            mock.call(src=('udp_dst', 0), dst=('udp_src', 0), n_bits=16)
        ]
        self.assertEqual(
            expected_calls, ofpp_mock.NXFlowSpecMatch.mock_calls)

        ofpp_mock.NXFlowSpecLoad.assert_called_once_with(
            src=int(netaddr.IPAddress(local_ip)),
            dst=('ipv4_src', 0), n_bits=32)

        ofpp_mock.NXFlowSpecOutput.assert_called_once_with(
            src=('in_port', 0), dst='', n_bits=32)

        self.assertEqual(3, ofpp_mock.NXActionLearn.call_count)
        ofpp_mock.NXActionLearn.assert_called_with(
            table_id=ovs_constants.LOCAL_IP_TABLE,
            cookie=mock.ANY, priority=20, idle_timeout=30,
            hard_timeout=300, specs=mock.ANY)

        self.assertEqual(6, ofpp_mock.OFPActionSetField.call_count)
        ofpp_mock.OFPActionSetField.assert_any_call(ipv4_dst=dest_ip)
        ofpp_mock.OFPActionSetField.assert_any_call(eth_dst=mac)

        self.assertEqual(3, ofpp_mock.NXActionResubmitTable.call_count)
        ofpp_mock.NXActionResubmitTable.assert_called_with(
            table_id=ovs_constants.TRANSIENT_TABLE)

        self.assertEqual(3, self.int_br.install_apply_actions.call_count)
        self.int_br.install_apply_actions.assert_called_with(
            table_id=ovs_constants.LOCAL_IP_TABLE, match=mock.ANY,
            priority=10, actions=mock.ANY)

        self.int_br.add_flow.assert_called_once_with(
            table=31, priority=11, nw_src=dest_ip, nw_dst=local_ip,
            reg6=vlan, dl_type="0x{:04x}".format(ether_types.ETH_TYPE_IP),
            actions='resubmit(,{:d})'.format(60))
