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

import netaddr

from neutron_lib.agent import l3_extension
from neutron_lib import constants
from oslo_log import log as logging


from neutron.agent.l3.extensions.qos import base as qos_base
from neutron.agent.linux import ip_lib
from neutron.api.rpc.callbacks import events
from neutron.api.rpc.callbacks import resources
from neutron.api.rpc.handlers import resources_rpc
from neutron.common import coordination

LOG = logging.getLogger(__name__)


class RouterGatewayIPQosAgentExtension(qos_base.L3QosAgentExtensionBase,
                                       l3_extension.L3AgentExtension):

    def initialize(self, connection, driver_type):
        """Initialize agent extension."""
        self.resource_rpc = resources_rpc.ResourcesPullRpcApi()
        self._register_rpc_consumers()
        self.gateway_ip_qos_map = qos_base.RateLimitMaps(
            "gateway-ip-qos-cache")

    def _handle_notification(self, context, resource_type,
                             qos_policies, event_type):
        if event_type == events.UPDATED:
            for qos_policy in qos_policies:
                self._process_update_policy(qos_policy)

    def _process_router_gateway_after_policy_update(
            self, router_id, qos_policy):
        router_info = self._get_router_info(router_id)
        if not router_info:
            return
        ex_gw_port = router_info.get_ex_gw_port()
        if not ex_gw_port:
            return
        interface_name = router_info.get_external_device_name(
                        ex_gw_port['id'])
        device = self._get_gateway_tc_rule_device(
                        router_info, interface_name)
        if not device.exists():
            return
        tc_wrapper = self._get_tc_wrapper(device)
        # Clear all old gateway IP tc rules first.
        self._empty_router_gateway_rate_limits(router_info, tc_wrapper)
        rates = self.get_policy_rates(qos_policy)
        self.gateway_ip_qos_map.set_resource_policy(
            router_info.router_id, qos_policy)
        self._set_gateway_tc_rules(
            router_info, tc_wrapper,
            ex_gw_port, rates)

    def _process_update_policy(self, qos_policy):
        old_qos_policy = self.gateway_ip_qos_map.get_policy(qos_policy.id)
        if old_qos_policy:
            if self._policy_rules_modified(old_qos_policy, qos_policy):
                router_ids = self.gateway_ip_qos_map.get_resources(
                    qos_policy)
                for router_id in list(router_ids):
                    self._process_router_gateway_after_policy_update(
                        router_id, qos_policy)
            self.gateway_ip_qos_map.update_policy(qos_policy)

    def add_router(self, context, data):
        router_info = self._get_router_info(data['id'])
        if router_info:
            self.process_gateway_rate_limit(context, router_info)

    def update_router(self, context, data):
        router_info = self._get_router_info(data['id'])
        if router_info:
            self.process_gateway_rate_limit(context, router_info)

    def delete_router(self, context, data):
        # Remove the router and policy map in case the router deletion with
        # gateway.
        self.gateway_ip_qos_map.clean_by_resource(data['id'])

    def ha_state_change(self, context, data):
        pass

    def update_network(self, context, data):
        pass

    def process_gateway_rate_limit(self, context, router_info):
        is_distributed_router = router_info.router.get('distributed')
        agent_mode = router_info.agent_conf.agent_mode
        LOG.debug("Start processing gateway IP QoS for "
                  "router %(router_id)s, router "
                  "distributed: %(distributed)s, "
                  "agent mode: %(agent_mode)s",
                  {"router_id": router_info.router_id,
                   "distributed": is_distributed_router,
                   "agent_mode": agent_mode})
        if is_distributed_router and agent_mode in (
                constants.L3_AGENT_MODE_DVR,
                constants.L3_AGENT_MODE_DVR_NO_EXTERNAL):
            # Dvr local router and dvr_no_external agent do not process
            # gateway IPs.
            return

        self._handle_router_gateway_rate_limit(context, router_info)

    @coordination.synchronized('qos-gateway-ip-{router_info.router_id}')
    def _empty_router_gateway_rate_limits(self, router_info, tc_wrapper):
        self.gateway_ip_qos_map.clean_by_resource(router_info.router_id)
        for ip in router_info.qos_gateway_ips:
            for direction in constants.VALID_DIRECTIONS:
                tc_wrapper.clear_ip_rate_limit(direction, ip)
        router_info.qos_gateway_ips.clear()

    def _handle_router_gateway_rate_limit(self, context, router_info):
        ex_gw_port = router_info.get_ex_gw_port()
        if not ex_gw_port:
            return

        interface_name = router_info.get_external_device_name(
            ex_gw_port['id'])
        device = self._get_gateway_tc_rule_device(router_info, interface_name)
        if not device.exists():
            return

        tc_wrapper = self._get_tc_wrapper(device)
        # Clear all old gateway IP tc rules first.
        self._empty_router_gateway_rate_limits(router_info, tc_wrapper)

        rates = self._get_rates_by_policy(context, router_info)
        if not rates:
            return

        self._set_gateway_tc_rules(router_info, tc_wrapper, ex_gw_port, rates)

    def _get_gateway_tc_rule_device(self, router_info, interface_name):
        is_distributed_router = router_info.router.get('distributed')
        agent_mode = router_info.agent_conf.agent_mode
        namespace = router_info.ns_name
        if (is_distributed_router and
                agent_mode == constants.L3_AGENT_MODE_DVR_SNAT):
            namespace = router_info.snat_namespace.name
        return ip_lib.IPDevice(interface_name, namespace=namespace)

    def _get_rates_by_policy(self, context, router_info):
        gateway_info = router_info.router.get('external_gateway_info')
        if not gateway_info:
            return

        policy_id = gateway_info.get('qos_policy_id')
        if not policy_id:
            return

        policy = self.resource_rpc.pull(
            context, resources.QOS_POLICY, policy_id)
        self.gateway_ip_qos_map.set_resource_policy(
            router_info.router_id, policy)
        return self.get_policy_rates(policy)

    @coordination.synchronized('qos-gateway-ip-{router_info.router_id}')
    def _set_gateway_tc_rules(self, router_info, tc_wrapper,
                              ex_gw_port, rates):
        for ip_addr in ex_gw_port['fixed_ips']:
            ex_gw_ip = ip_addr['ip_address']
            ip_ver = netaddr.IPAddress(ex_gw_ip).version
            if ip_ver == constants.IP_VERSION_4:
                self._set_gateway_ip_rate_limit(tc_wrapper, ex_gw_ip, rates)
                router_info.qos_gateway_ips.add(ex_gw_ip)

    def _set_gateway_ip_rate_limit(self, tc_wrapper, ex_gw_ip, rates):
        for direction in constants.VALID_DIRECTIONS:
            rate = rates.get(direction)
            if (rate['rate'] == qos_base.IP_DEFAULT_RATE and
                    rate['burst'] == qos_base.IP_DEFAULT_BURST):
                continue
            tc_wrapper.set_ip_rate_limit(direction, ex_gw_ip,
                                         rate['rate'], rate['burst'])
