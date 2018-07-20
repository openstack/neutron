# Copyright 2017 OpenStack Foundation
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

from neutron_lib.agent import l3_extension
from neutron_lib import constants
from neutron_lib.db import constants as db_consts
from neutron_lib.services.qos import constants as qos_consts
from oslo_concurrency import lockutils
from oslo_log import log as logging

from neutron.agent.linux import ip_lib
from neutron.agent.linux import l3_tc_lib as tc_lib
from neutron.api.rpc.callbacks.consumer import registry
from neutron.api.rpc.callbacks import events
from neutron.api.rpc.callbacks import resources
from neutron.api.rpc.handlers import resources_rpc
from neutron.common import constants as n_const
from neutron.common import rpc as n_rpc

LOG = logging.getLogger(__name__)

SUPPORTED_RULES = {
    qos_consts.RULE_TYPE_BANDWIDTH_LIMIT: {
        qos_consts.MAX_KBPS: {
            'type:range': [0, db_consts.DB_INTEGER_MAX_VALUE]},
        qos_consts.MAX_BURST: {
            'type:range': [0, db_consts.DB_INTEGER_MAX_VALUE]},
        qos_consts.DIRECTION: {
            'type:values': constants.VALID_DIRECTIONS}
    }
}

# We use the default values to illustrate:
# 1. QoS policy does not have some direction `bandwidth_limit`, then we use
#    the default value.
# 2. default value 0 will be treated as no limit.
# 3. if one floating IP's rate was changed from x to 0, the extension will do
#    a tc filter clean procedure.
FIP_DEFAULT_RATE = 0
FIP_DEFAULT_BURST = 0


class RouterFipRateLimitMaps(object):
    def __init__(self):
        self.qos_policy_fips = collections.defaultdict(dict)
        self.known_policies = {}
        self.fip_policies = {}

        """
        The router_floating_ips will be:
            router_floating_ips = {
                router_id_1: set(fip1, fip2),
                router_id_2: set(), # default
            }
        """
        self.router_floating_ips = {}

        """
        The rate limits dict will be:
            xxx_ratelimits = {
                fip_1: (rate, burst),
                fip_2: (FIP_DEFAULT_RATE, FIP_DEFAULT_BURST), # default
                fip_3: (1, 2),
                fip_4: (3, 4),
            }
        """
        self.ingress_ratelimits = {}
        self.egress_ratelimits = {}

    def update_policy(self, policy):
        self.known_policies[policy.id] = policy

    def get_policy(self, policy_id):
        return self.known_policies.get(policy_id)

    def get_fips(self, policy):
        return self.qos_policy_fips[policy.id].values()

    def get_fip_policy(self, fip):
        policy_id = self.fip_policies.get(fip)
        return self.get_policy(policy_id)

    def set_fip_policy(self, fip, policy):
        """Attach a fip to policy and return any previous policy on fip."""
        old_policy = self.get_fip_policy(fip)
        self.update_policy(policy)
        self.fip_policies[fip] = policy.id
        self.qos_policy_fips[policy.id][fip] = fip
        if old_policy and old_policy.id != policy.id:
            del self.qos_policy_fips[old_policy.id][fip]

    def clean_by_fip(self, fip):
        """Detach fip from policy and cleanup data we don't need anymore."""
        if fip in self.fip_policies:
            del self.fip_policies[fip]
            for qos_policy_id, fip_dict in self.qos_policy_fips.items():
                if fip in fip_dict:
                    del fip_dict[fip]
                    if not fip_dict:
                        self._clean_policy_info(qos_policy_id)
                    return
        LOG.debug("Floating IP QoS extension did not have "
                  "information on floating IP %s", fip)

    def _clean_policy_info(self, qos_policy_id):
        del self.qos_policy_fips[qos_policy_id]
        del self.known_policies[qos_policy_id]

    def find_fip_router_id(self, fip):
        for router_id, ips in self.router_floating_ips.items():
            if fip in ips:
                return router_id


class FipQosAgentExtension(l3_extension.L3AgentExtension):
    SUPPORTED_RESOURCE_TYPES = [resources.QOS_POLICY]

    def initialize(self, connection, driver_type):
        """Initialize agent extension."""
        self.resource_rpc = resources_rpc.ResourcesPullRpcApi()
        self.fip_qos_map = RouterFipRateLimitMaps()
        self._register_rpc_consumers()

    def consume_api(self, agent_api):
        self.agent_api = agent_api

    @lockutils.synchronized('qos-fip')
    def _handle_notification(self, context, resource_type,
                             qos_policies, event_type):
        if event_type == events.UPDATED:
            for qos_policy in qos_policies:
                self._process_update_policy(qos_policy)

    def _policy_rules_modified(self, old_policy, policy):
        return not (len(old_policy.rules) == len(policy.rules) and
                    all(i in old_policy.rules for i in policy.rules))

    def _process_update_policy(self, qos_policy):
        old_qos_policy = self.fip_qos_map.get_policy(qos_policy.id)
        if old_qos_policy:
            if self._policy_rules_modified(old_qos_policy, qos_policy):
                for fip in self.fip_qos_map.get_fips(qos_policy):
                    router_id = self.fip_qos_map.find_fip_router_id(fip)
                    router_info = self._get_router_info(router_id)
                    if not router_info:
                        continue
                    device = self._get_rate_limit_ip_device(router_info)
                    dvr_fip_device = self._get_dvr_fip_device(router_info)
                    if not device and not dvr_fip_device:
                        LOG.debug("Router %s does not have a floating IP "
                                  "related device, skipping.", router_id)
                        continue
                    rates = self.get_policy_rates(qos_policy)
                    if device:
                        self.process_ip_rates(fip, device, rates)
                    if dvr_fip_device:
                        self.process_ip_rates(
                            fip, dvr_fip_device, rates, with_cache=False)
            self.fip_qos_map.update_policy(qos_policy)

    def _process_reset_fip(self, fip):
        self.fip_qos_map.clean_by_fip(fip)

    def _register_rpc_consumers(self):
        registry.register(self._handle_notification, resources.QOS_POLICY)

        self._connection = n_rpc.create_connection()
        endpoints = [resources_rpc.ResourcesPushRpcCallback()]
        topic = resources_rpc.resource_type_versioned_topic(
            resources.QOS_POLICY)
        self._connection.create_consumer(topic, endpoints, fanout=True)
        self._connection.consume_in_threads()

    def _get_tc_wrapper(self, device):
        return tc_lib.FloatingIPTcCommand(device.name,
                                          namespace=device.namespace)

    def process_ip_rate_limit(self, ip, direction, device, rate, burst):
        rate_limits_direction = direction + "_ratelimits"
        rate_limits = getattr(self.fip_qos_map, rate_limits_direction, {})
        old_rate, old_burst = rate_limits.get(ip, (FIP_DEFAULT_RATE,
                                                   FIP_DEFAULT_BURST))

        if old_rate == rate and old_burst == burst:
            # Two possibilities here:
            # 1. Floating IP rate limit does not change.
            # 2. Floating IP bandwidth does not limit.
            return

        tc_wrapper = self._get_tc_wrapper(device)

        if rate == FIP_DEFAULT_RATE and burst == FIP_DEFAULT_BURST:
            # According to the agreements of default value definition,
            # floating IP bandwidth was changed to default value (no limit).
            # NOTE: l3_tc_lib will ignore exception FilterIDForIPNotFound.
            tc_wrapper.clear_ip_rate_limit(direction, ip)
            rate_limits.pop(ip, None)
            return

        # Finally just set it, l3_tc_lib will clean the old rules if exists.
        tc_wrapper.set_ip_rate_limit(direction, ip, rate, burst)
        rate_limits[ip] = (rate, burst)

    def _get_rate_limit_ip_device(self, router_info):
        ex_gw_port = router_info.get_ex_gw_port()
        if not ex_gw_port:
            return
        agent_mode = router_info.agent_conf.agent_mode
        is_distributed_router = router_info.router.get('distributed')
        if is_distributed_router and agent_mode == (
                constants.L3_AGENT_MODE_DVR_SNAT):
            # DVR edge (or DVR edge ha) router
            if not router_info._is_this_snat_host():
                return
            name = router_info.get_snat_external_device_interface_name(
                ex_gw_port)
        else:
            # DVR local router
            # Legacy/HA router
            name = router_info.get_external_device_interface_name(ex_gw_port)
        if not name:
            # DVR local router in dvr_no_external agent mode may not have
            # such rfp-device.
            return
        namespace = router_info.get_gw_ns_name()
        return ip_lib.IPDevice(name, namespace=namespace)

    def _remove_ip_rate_limit_cache(self, ip, direction):
        rate_limits_direction = direction + "_ratelimits"
        rate_limits = getattr(self.fip_qos_map, rate_limits_direction, {})
        rate_limits.pop(ip, None)

    def _remove_fip_rate_limit(self, device, fip_ip):
        tc_wrapper = self._get_tc_wrapper(device)
        for direction in constants.VALID_DIRECTIONS:
            if device.exists():
                tc_wrapper.clear_ip_rate_limit(direction, fip_ip)
            self._remove_ip_rate_limit_cache(fip_ip, direction)

    def get_fip_qos_rates(self, context, fip, policy_id):
        if policy_id is None:
            self._process_reset_fip(fip)
            # process_ip_rate_limit will treat value 0 as
            # cleaning the tc filters if exits or no action.
            return {constants.INGRESS_DIRECTION: {"rate": FIP_DEFAULT_RATE,
                                                  "burst": FIP_DEFAULT_BURST},
                    constants.EGRESS_DIRECTION: {"rate": FIP_DEFAULT_RATE,
                                                 "burst": FIP_DEFAULT_BURST}}
        policy = self.resource_rpc.pull(
            context, resources.QOS_POLICY, policy_id)
        self.fip_qos_map.set_fip_policy(fip, policy)
        return self.get_policy_rates(policy)

    def get_policy_rates(self, policy):
        rates = {}
        for rule in policy.rules:
            # NOTE(liuyulong): for now, the L3 agent floating IP QoS
            # extension only uses ``bandwidth_limit`` rules..
            if rule.rule_type in SUPPORTED_RULES:
                if rule.direction not in rates:
                    rates[rule.direction] = {"rate": rule.max_kbps,
                                             "burst": rule.max_burst_kbps}

        # The return rates dict must contain all directions. If there is no
        # one specific direction QoS rule, use the default values.
        for direction in constants.VALID_DIRECTIONS:
            if direction not in rates:
                LOG.debug("Policy %(id)s does not have '%(direction)s' "
                          "bandwidth_limit rule, use default value instead.",
                          {"id": policy.id,
                           "direction": direction})
                rates[direction] = {"rate": FIP_DEFAULT_RATE,
                                    "burst": FIP_DEFAULT_BURST}
        return rates

    def process_ip_rates(self, fip, device, rates, with_cache=True):
        for direction in constants.VALID_DIRECTIONS:
            rate = rates.get(direction)
            if with_cache:
                self.process_ip_rate_limit(
                    fip, direction, device,
                    rate['rate'], rate['burst'])
            else:
                tc_wrapper = self._get_tc_wrapper(device)
                if (rate['rate'] == FIP_DEFAULT_RATE and
                        rate['burst'] == FIP_DEFAULT_BURST):
                    # Default value is no limit
                    tc_wrapper.clear_ip_rate_limit(direction, fip)
                else:
                    tc_wrapper.set_ip_rate_limit(direction, fip,
                                                 rate['rate'], rate['burst'])

    def _get_dvr_fip_device(self, router_info):
        is_distributed_router = router_info.router.get('distributed')
        agent_mode = router_info.agent_conf.agent_mode
        if is_distributed_router and agent_mode == (
                constants.L3_AGENT_MODE_DVR_SNAT):
            gw_port = router_info.get_ex_gw_port()
            if gw_port and router_info.fip_ns:
                rfp_dev_name = router_info.get_external_device_interface_name(
                    gw_port)
                if router_info.router_namespace.exists() and rfp_dev_name:
                    return ip_lib.IPDevice(
                        rfp_dev_name, namespace=router_info.ns_name)

    def process_floating_ip_addresses(self, context, router_info):
        # Loop all the router floating ips, the corresponding floating IP tc
        # rules will be configured:
        # 1. for legacy and HA router, it will be all floating IPs to qg-device
        #    of qrouter-namespace in (all ha router hosted) network node.
        # 2. for dvr router, we can do this simple. No matter the agent
        #    type is dvr or dvr_snat, we can just set all the
        #    floating IP tc rules to the corresponding device:
        #    2.1 for dvr local router in compute node:
        #        the namespace is qrouter-x, and the device is rfp-device.
        #    2.2 for dvr edge (ha) router in network node:
        #        the namespace is snat-x, and the device is qg-device.
        # 3. for dvr local router, if agent_mod is dvr_no_external, no
        #    floating IP rules will be configured.
        # 4. for dvr router in snat node, we should process the floating
        #    IP QoS again in qrouter-namespace to cover the mixed deployment
        #    with nova-compute scenario.
        is_distributed_router = router_info.router.get('distributed')
        agent_mode = router_info.agent_conf.agent_mode
        LOG.debug("Start processing floating IP QoS for "
                  "router %(router_id)s, router "
                  "distributed: %(distributed)s, "
                  "agent mode: %(agent_mode)s",
                  {"router_id": router_info.router_id,
                   "distributed": is_distributed_router,
                   "agent_mode": agent_mode})
        if is_distributed_router and agent_mode == (
                n_const.L3_AGENT_MODE_DVR_NO_EXTERNAL):
            # condition 3: dvr local router and dvr_no_external agent
            return

        device = self._get_rate_limit_ip_device(router_info)
        dvr_fip_device = self._get_dvr_fip_device(router_info)
        if not device and not dvr_fip_device:
            LOG.debug("No relevant QoS device found "
                      "for router: %s", router_info.router_id)
            return

        floating_ips = router_info.get_floating_ips()
        current_fips = self.fip_qos_map.router_floating_ips.get(
            router_info.router_id, set())
        new_fips = set()
        for fip in floating_ips:
            fip_addr = fip['floating_ip_address']
            new_fips.add(fip_addr)
            rates = self.get_fip_qos_rates(context,
                                           fip_addr,
                                           fip.get(qos_consts.QOS_POLICY_ID))
            if device:
                self.process_ip_rates(fip_addr, device, rates)

            if dvr_fip_device:
                # NOTE(liuyulong): for scenario 4 (mixed dvr_snat and compute
                # node), because floating IP qos rates may have been
                # processed in dvr snat-namespace, so here the cache was
                # already set. We just install the rules to the device in
                # qrouter-namesapce.
                self.process_ip_rates(
                    fip_addr, dvr_fip_device, rates, with_cache=False)

        self.fip_qos_map.router_floating_ips[router_info.router_id] = new_fips
        fips_removed = current_fips - new_fips
        for fip in fips_removed:
            if device:
                self._remove_fip_rate_limit(device, fip)
            if dvr_fip_device:
                self._remove_fip_rate_limit(dvr_fip_device, fip)
            self._process_reset_fip(fip)

    def _get_router_info(self, router_id):
        router_info = self.agent_api.get_router_info(router_id)
        if router_info:
            return router_info
        LOG.debug("Router %s is not managed by this agent. "
                  "It was possibly deleted concurrently.",
                  router_id)

    @lockutils.synchronized('qos-fip')
    def add_router(self, context, data):
        router_info = self._get_router_info(data['id'])
        if router_info:
            self.process_floating_ip_addresses(context, router_info)

    @lockutils.synchronized('qos-fip')
    def update_router(self, context, data):
        router_info = self._get_router_info(data['id'])
        if router_info:
            self.process_floating_ip_addresses(context, router_info)

    def delete_router(self, context, data):
        # NOTE(liuyulong): to delete the router, you need to disassociate the
        # floating IP first, so the update_router has done the cache clean.
        pass

    def ha_state_change(self, context, data):
        pass
