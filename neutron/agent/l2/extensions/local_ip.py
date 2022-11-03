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

import collections
import sys

import netaddr
from neutron_lib.agent import l2_extension
from neutron_lib.callbacks import events as lib_events
from neutron_lib.callbacks import registry as lib_registry
from neutron_lib import context as lib_ctx
from neutron_lib.plugins.ml2 import ovs_constants
from os_ken.lib.packet import ether_types
from os_ken.lib.packet import in_proto as ip_proto
from oslo_config import cfg
from oslo_log import log as logging

from neutron.api.rpc.callbacks.consumer import registry
from neutron.api.rpc.callbacks import events
from neutron.api.rpc.callbacks import resources
from neutron.api.rpc.handlers import resources_rpc
from neutron.plugins.ml2.drivers.openvswitch.agent import (
    ovs_neutron_agent as ovs_agent)

LOG = logging.getLogger(__name__)


class LocalIPAgentExtension(l2_extension.L2AgentExtension):
    SUPPORTED_RESOURCE_TYPES = [resources.LOCAL_IP_ASSOCIATION]

    def initialize(self, connection, driver_type):
        if driver_type != ovs_constants.EXTENSION_DRIVER_TYPE:
            LOG.error('Local IP extension is only supported for OVS, '
                      'currently uses %(driver_type)s',
                      {'driver_type': driver_type})
            sys.exit(1)
        if self._is_ovs_firewall() and not cfg.CONF.LOCAL_IP.static_nat:
            LOG.error('In order to use Local IP extension together with '
                      'openvswitch firewall please set static_nat config to '
                      'True')
            sys.exit(1)

        self.resource_rpc = resources_rpc.ResourcesPullRpcApi()
        self._register_rpc_consumers(connection)
        self.int_br = self.agent_api.request_int_br()

        self.local_ip_updates = {
            'added': collections.defaultdict(dict),
            'deleted': collections.defaultdict(dict)
        }

        self._pull_all_local_ip_associations()

    def _pull_all_local_ip_associations(self):
        context = lib_ctx.get_admin_context_without_session()

        assoc_list = self.resource_rpc.bulk_pull(
            context, resources.LOCAL_IP_ASSOCIATION)
        for assoc in assoc_list:
            port_id = assoc.fixed_port_id
            lip_id = assoc.local_ip_id
            self.local_ip_updates['added'][port_id][lip_id] = assoc
            # Notify agent about port update to handle Local IP flows
            self._notify_port_updated(context, port_id)

    def consume_api(self, agent_api):
        """Allows an extension to gain access to resources internal to the
           neutron agent and otherwise unavailable to the extension.
        """
        self.agent_api = agent_api

    def _register_rpc_consumers(self, connection):
        """Allows an extension to receive notifications of updates made to
           items of interest.
        """
        endpoints = [resources_rpc.ResourcesPushRpcCallback()]
        for resource_type in self.SUPPORTED_RESOURCE_TYPES:
            # We assume that the neutron server always broadcasts the latest
            # version known to the agent
            registry.register(self._handle_notification, resource_type)
            topic = resources_rpc.resource_type_versioned_topic(resource_type)
            connection.create_consumer(topic, endpoints, fanout=True)

    def _handle_notification(self, context, resource_type,
                             local_ip_associations, event_type):
        if resource_type != resources.LOCAL_IP_ASSOCIATION:
            LOG.warning("Only Local IP Association notifications are "
                        "supported, got: %s", resource_type)
            return

        LOG.info("Local IP Association notification received: %s, %s",
                 local_ip_associations, event_type)
        for assoc in local_ip_associations:
            port_id = assoc.fixed_port_id
            lip_id = assoc.local_ip_id
            if event_type in [events.CREATED, events.UPDATED]:
                self.local_ip_updates['added'][port_id][lip_id] = assoc
            elif event_type == events.DELETED:
                self.local_ip_updates['deleted'][port_id][lip_id] = assoc
                self.local_ip_updates['added'][port_id].pop(lip_id, None)

            # Notify agent about port update to handle Local IP flows
            self._notify_port_updated(context, port_id)

    def _notify_port_updated(self, context, port_id):
        payload = lib_events.DBEventPayload(
            context, metadata={'changed_fields': {'local_ip'}},
            resource_id=port_id, states=(None,))
        lib_registry.publish(resources.PORT, lib_events.AFTER_UPDATE,
                             self, payload=payload)

    def handle_port(self, context, port):
        """Handle Local IP associations for a port.
        """
        port_id = port['port_id']
        local_ip_updates = self._pop_local_ip_updates_for_port(port_id)

        # if port doesn't yet have local vlan - issue port updated
        # notification to handle it on next agent loop, when port
        # should have it
        if ((local_ip_updates['added'] or local_ip_updates['deleted']) and
                not port.get('local_vlan')):
            LOG.debug("Port %s has no local VLAN assigned yet. "
                      "Skipping Local IP handling till next iteration.")
            self._notify_port_updated(context, port['port_id'])
            return

        for assoc in local_ip_updates['added'].values():
            LOG.info("Local IP added for port %s: %s",
                     port_id, assoc.local_ip)
            self.add_local_ip_flows(port, assoc)
        for assoc in local_ip_updates['deleted'].values():
            LOG.info("Local IP deleted from port %s: %s",
                     port_id, assoc.local_ip)
            self.delete_local_ip_flows(port, assoc)

    def _pop_local_ip_updates_for_port(self, port_id):
        return {
            'added': self.local_ip_updates['added'].pop(port_id, {}),
            'deleted': self.local_ip_updates['deleted'].pop(port_id, {})
        }

    def add_local_ip_flows(self, port, assoc):
        local_ip_address = str(assoc.local_ip.local_ip_address)
        dest_mac = str(netaddr.EUI(port['mac_address'],
                                   dialect=ovs_agent._mac_mydialect))
        dest_ip = str(assoc.fixed_ip)
        vlan = port['local_vlan']
        if cfg.CONF.LOCAL_IP.static_nat:
            self.setup_static_local_ip_translation(
                vlan=vlan, local_ip=local_ip_address,
                dest_ip=dest_ip, mac=port['mac_address'])
        else:
            self.setup_local_ip_translation(
                vlan=vlan, local_ip=local_ip_address,
                dest_ip=dest_ip, mac=port['mac_address'])
        self.int_br.install_arp_responder(
            vlan=vlan, ip=local_ip_address, mac=dest_mac,
            table_id=ovs_constants.LOCAL_IP_TABLE)
        self.int_br.install_garp_blocker(
            vlan=vlan, ip=local_ip_address)
        self.int_br.install_garp_blocker_exception(
            vlan=vlan, ip=local_ip_address, except_ip=dest_ip)

    def delete_local_ip_flows(self, port, assoc):
        local_ip_address = str(assoc.local_ip.local_ip_address)
        dest_ip = str(assoc.fixed_ip)
        vlan = port['local_vlan']
        self.delete_local_ip_translation(
            vlan=vlan, local_ip=local_ip_address,
            dest_ip=dest_ip, mac=port['mac_address'])
        self.int_br.delete_arp_responder(
            vlan=vlan, ip=local_ip_address,
            table_id=ovs_constants.LOCAL_IP_TABLE)
        self.int_br.delete_garp_blocker(
            vlan=vlan, ip=local_ip_address)
        self.int_br.delete_garp_blocker_exception(
            vlan=vlan, ip=local_ip_address, except_ip=dest_ip)

    def delete_port(self, context, port):
        self.local_ip_updates['added'].pop(port['port_id'], None)
        self.local_ip_updates['deleted'].pop(port['port_id'], None)

    def setup_local_ip_translation(self, vlan, local_ip, dest_ip, mac):
        self.int_br.add_flow(
            table=ovs_constants.LOCAL_IP_TABLE,
            priority=10,
            nw_dst=local_ip,
            reg6=vlan,
            dl_type="0x{:04x}".format(ether_types.ETH_TYPE_IP),
            actions='mod_dl_dst:{:s},'
                    'ct(commit,table={:d},zone={:d},nat(dst={:s}))'.format(
                        mac, ovs_constants.TRANSIENT_TABLE, vlan, dest_ip)
        )
        self.int_br.add_flow(
            table=ovs_constants.LOCAL_IP_TABLE,
            priority=10,
            dl_src=mac,
            nw_src=dest_ip,
            reg6=vlan,
            ct_state="-trk",
            dl_type="0x{:04x}".format(ether_types.ETH_TYPE_IP),
            actions='ct(table={:d},zone={:d},nat'.format(
                ovs_constants.TRANSIENT_TABLE, vlan)
        )
        self._avoid_nat_to_self(vlan, local_ip, dest_ip)

    def _avoid_nat_to_self(self, vlan, local_ip, dest_ip):
        # avoid NAT to self and let VM with local IP access "true" IP owner
        self.int_br.add_flow(
            table=ovs_constants.LOCAL_IP_TABLE,
            priority=11,
            nw_src=dest_ip,
            nw_dst=local_ip,
            reg6=vlan,
            dl_type="0x{:04x}".format(ether_types.ETH_TYPE_IP),
            actions='resubmit(,{:d})'.format(ovs_constants.TRANSIENT_TABLE)
        )

    def delete_local_ip_translation(self, vlan, local_ip, dest_ip, mac):
        self.int_br.uninstall_flows(
            table_id=ovs_constants.LOCAL_IP_TABLE,
            priority=10,
            ipv4_dst=local_ip,
            reg6=vlan,
            eth_type=ether_types.ETH_TYPE_IP
        )
        self.int_br.uninstall_flows(
            table_id=ovs_constants.LOCAL_IP_TABLE,
            priority=11,
            ipv4_src=dest_ip,
            ipv4_dst=local_ip,
            reg6=vlan,
            eth_type=ether_types.ETH_TYPE_IP
        )
        self.int_br.uninstall_flows(
            table_id=ovs_constants.LOCAL_IP_TABLE,
            priority=10,
            eth_src=mac,
            ipv4_src=dest_ip,
            reg6=vlan,
            eth_type=ether_types.ETH_TYPE_IP
        )

    def setup_static_local_ip_translation(self, vlan, local_ip, dest_ip, mac):
        (dp, ofp, ofpp) = self.int_br._get_dp()
        common_match_kwargs = {
            'reg6': vlan,
            'ipv4_dst': local_ip,
            'eth_type': ether_types.ETH_TYPE_IP}
        common_specs = [
            ofpp.NXFlowSpecMatch(src=ether_types.ETH_TYPE_IP,
                                 dst=('eth_type', 0),
                                 n_bits=16),
            ofpp.NXFlowSpecMatch(src=('eth_src', 0),
                                 dst=('eth_dst', 0),
                                 n_bits=48),
            ofpp.NXFlowSpecMatch(src=('eth_dst', 0),
                                 dst=('eth_src', 0),
                                 n_bits=48),
            ofpp.NXFlowSpecMatch(src=('ipv4_src', 0),
                                 dst=('ipv4_dst', 0),
                                 n_bits=32),
            ofpp.NXFlowSpecMatch(src=int(netaddr.IPAddress(dest_ip)),
                                 dst=('ipv4_src', 0),
                                 n_bits=32),
            ofpp.NXFlowSpecMatch(src=vlan,
                                 dst=('reg6', 0),
                                 n_bits=4),
            ofpp.NXFlowSpecLoad(src=int(netaddr.IPAddress(local_ip)),
                                dst=('ipv4_src', 0),
                                n_bits=32),
            ofpp.NXFlowSpecOutput(src=('in_port', 0),
                                  dst='',
                                  n_bits=32),
        ]
        for specs, match_kwargs in [self._icmp_flow_match_specs(ofpp),
                                    self._tcp_flow_match_specs(ofpp),
                                    self._udp_flow_match_specs(ofpp)]:
            flow_specs = common_specs + specs
            learn_table = ovs_constants.LOCAL_IP_TABLE
            if self._is_ovs_firewall():
                learn_table = ovs_constants.\
                    ACCEPTED_EGRESS_TRAFFIC_NORMAL_TABLE
            actions = [
                ofpp.OFPActionSetField(eth_dst=mac),
                ofpp.NXActionLearn(
                    table_id=learn_table,
                    cookie=self.int_br.default_cookie,
                    priority=20,
                    idle_timeout=30,
                    hard_timeout=300,
                    specs=flow_specs),
                ofpp.OFPActionSetField(ipv4_dst=dest_ip),
                ofpp.NXActionResubmitTable(
                    table_id=ovs_constants.TRANSIENT_TABLE)]

            match = ofpp.OFPMatch(**common_match_kwargs, **match_kwargs)
            self.int_br.install_apply_actions(
                table_id=ovs_constants.LOCAL_IP_TABLE,
                match=match,
                priority=10,
                actions=actions)
        self._avoid_nat_to_self(vlan, local_ip, dest_ip)

    @staticmethod
    def _icmp_flow_match_specs(ofpp):
        specs = [
            ofpp.NXFlowSpecMatch(src=ip_proto.IPPROTO_ICMP,
                                 dst=('ip_proto', 0),
                                 n_bits=8)
        ]
        match_kwargs = {'ip_proto': ip_proto.IPPROTO_ICMP}
        return specs, match_kwargs

    @staticmethod
    def _tcp_flow_match_specs(ofpp):
        specs = [
            ofpp.NXFlowSpecMatch(src=ip_proto.IPPROTO_TCP,
                                 dst=('ip_proto', 0),
                                 n_bits=8),
            ofpp.NXFlowSpecMatch(src=('tcp_src', 0),
                                 dst=('tcp_dst', 0),
                                 n_bits=16),
            ofpp.NXFlowSpecMatch(src=('tcp_dst', 0),
                                 dst=('tcp_src', 0),
                                 n_bits=16)]
        match_kwargs = {'ip_proto': ip_proto.IPPROTO_TCP}
        return specs, match_kwargs

    @staticmethod
    def _udp_flow_match_specs(ofpp):
        specs = [
            ofpp.NXFlowSpecMatch(src=ip_proto.IPPROTO_UDP,
                                 dst=('ip_proto', 0),
                                 n_bits=8),
            ofpp.NXFlowSpecMatch(src=('udp_src', 0),
                                 dst=('udp_dst', 0),
                                 n_bits=16),
            ofpp.NXFlowSpecMatch(src=('udp_dst', 0),
                                 dst=('udp_src', 0),
                                 n_bits=16)]
        match_kwargs = {'ip_proto': ip_proto.IPPROTO_UDP}
        return specs, match_kwargs

    @staticmethod
    def _is_ovs_firewall():
        return (cfg.CONF.SECURITYGROUP.enable_security_group and
                cfg.CONF.SECURITYGROUP.firewall_driver == 'openvswitch')
