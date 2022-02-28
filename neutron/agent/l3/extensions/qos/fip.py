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
from neutron_lib.services.qos import constants as qos_consts
from oslo_concurrency import lockutils
from oslo_log import log as logging

from neutron.agent.l3.extensions.qos import base as qos_base
from neutron.agent.linux import ip_lib
from neutron.api.rpc.callbacks import events
from neutron.api.rpc.callbacks import resources
from neutron.api.rpc.handlers import resources_rpc
from neutron.common import coordination

LOG = logging.getLogger(__name__)

FipResource = collections.namedtuple('FipResource', 'id ip_address')


class RouterFipRateLimitMaps(qos_base.RateLimitMaps):
    LOCK_NAME = "fip-qos-cache"

    def __init__(self):
        """Initialize RouterFipRateLimitMaps

        "_router_2_fips" stores the FIP resources (``FipResource`` tuple) per
        router. The "_fips_2_router" dictionary stores the reverse lookup info.
        _router_2_fips = {router_id_1: {fip_res_1, fip_res_2, ...},
                          router_id_2: {fip_res_3, fip_res_4, ...}, ... }
        _fips_2_router = {fip_res_1: router_id_1,
                          fip_res_2: router_id_1,
                          fip_res_3: router_id_2, ... }
        """
        self._router_2_fips = {}
        self._fips_2_router = {}
        """
        The rate limits dict will be:
            xxx_ratelimits = {
                fip_1: (rate, burst),
                fip_2: (IP_DEFAULT_RATE, IP_DEFAULT_BURST), # default
                fip_3: (1, 2),
                fip_4: (3, 4),
            }
        """
        self.ingress_ratelimits = {}
        self.egress_ratelimits = {}
        super(RouterFipRateLimitMaps, self).__init__(self.LOCK_NAME)

    def get_router_id_by_fip(self, fip_res):

        @lockutils.synchronized(self.lock_name)
        def _find_router_id_by_fip_id():
            return self._fips_2_router.get(fip_res)

        return _find_router_id_by_fip_id()

    def get_fips_by_router_id(self, router_id):

        @lockutils.synchronized(self.lock_name)
        def _get_fips_by_router_id():
            return self._router_2_fips.get(router_id, set([]))

        return _get_fips_by_router_id()

    def set_fips(self, router_id, fips):

        @lockutils.synchronized(self.lock_name)
        def _set_fips():
            self._router_2_fips[router_id] = fips
            for fip_res in fips:
                self._fips_2_router[fip_res] = router_id

        if not isinstance(fips, set):
            fips = set(fips)
        return _set_fips()

    def delete_fips(self, fips):

        @lockutils.synchronized(self.lock_name)
        def _delete_fips():
            router_ids = set([])
            for fip_res in fips:
                router_id = self._fips_2_router.pop(fip_res, None)
                if router_id:
                    router_ids.add(router_id)

            for router_id in router_ids:
                stored_fips = self._router_2_fips.pop(router_id)
                current_fips = stored_fips - set(fips)
                if current_fips:
                    self._router_2_fips[router_id] = current_fips

        if not isinstance(fips, set):
            fips = set(fips)
        return _delete_fips()

    def remove_fip_ratelimit_cache(self, direction, fip_id):

        @lockutils.synchronized(self.lock_name)
        def _remove_fip_ratelimit_cache():
            rate_limits = getattr(self, direction + "_ratelimits")
            rate_limits.pop(fip_id, None)

        _remove_fip_ratelimit_cache()

    def set_fip_ratelimit_cache(self, direction, fip_id, rate, burst):

        @lockutils.synchronized(self.lock_name)
        def _set_fip_ratelimit_cache():
            rate_limits = getattr(self, direction + "_ratelimits")
            rate_limits[fip_id] = (rate, burst)

        _set_fip_ratelimit_cache()

    def get_fip_ratelimit_cache(self, direction, fip_id):

        @lockutils.synchronized(self.lock_name)
        def _get_fip_ratelimit_cache():
            rate_limits = getattr(self, direction + "_ratelimits")
            rate, burst = rate_limits.get(fip_id, (qos_base.IP_DEFAULT_RATE,
                                                   qos_base.IP_DEFAULT_BURST))
            return rate, burst

        return _get_fip_ratelimit_cache()

    def clean_router_all_fip_cache(self, router_id):
        for fip_res in self._router_2_fips.pop(router_id, []):
            self._fips_2_router.pop(fip_res, None)
            for direction in constants.VALID_DIRECTIONS:
                self.remove_fip_ratelimit_cache(direction, fip_res.id)
            self.clean_by_resource(fip_res)


class FipQosAgentExtension(qos_base.L3QosAgentExtensionBase,
                           l3_extension.L3AgentExtension):

    def initialize(self, connection, driver_type):
        """Initialize agent extension."""
        self.resource_rpc = resources_rpc.ResourcesPullRpcApi()
        self.fip_qos_map = RouterFipRateLimitMaps()
        self._register_rpc_consumers()

    def _handle_notification(self, context, resource_type,
                             qos_policies, event_type):
        if event_type == events.UPDATED:
            for qos_policy in qos_policies:
                self._process_update_policy(qos_policy)

    def _process_update_policy(self, qos_policy):
        old_qos_policy = self.fip_qos_map.get_policy(qos_policy.id)
        if not old_qos_policy:
            return

        if self._policy_rules_modified(old_qos_policy, qos_policy):
            for fip_res in self.fip_qos_map.get_resources(qos_policy):
                router_id = self.fip_qos_map.get_router_id_by_fip(fip_res)
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
                    self.process_ip_rates(fip_res, device, rates)
                if dvr_fip_device:
                    self.process_ip_rates(
                        fip_res, dvr_fip_device, rates, with_cache=False)
        self.fip_qos_map.update_policy(qos_policy)

    @coordination.synchronized('qos-floating-ip-{ip}')
    def process_ip_rate_limit(self, ip, direction,
                              device, rate, burst):

        tc_wrapper = self._get_tc_wrapper(device)

        if (rate == qos_base.IP_DEFAULT_RATE and
                burst == qos_base.IP_DEFAULT_BURST):
            # According to the agreements of default value definition,
            # floating IP bandwidth was changed to default value (no limit).
            # NOTE: l3_tc_lib will ignore exception FilterIDForIPNotFound.
            tc_wrapper.clear_ip_rate_limit(direction, ip)
            self.fip_qos_map.remove_fip_ratelimit_cache(direction, ip)
            return

        # Finally just set it, l3_tc_lib will clean the old rules if exists.
        tc_wrapper.set_ip_rate_limit(direction, ip, rate, burst)

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

    def _remove_fip_rate_limit(self, device, fip_res):
        tc_wrapper = self._get_tc_wrapper(device)
        for direction in constants.VALID_DIRECTIONS:
            if device.exists():
                tc_wrapper.clear_ip_rate_limit(direction, fip_res.ip_address)
            self.fip_qos_map.remove_fip_ratelimit_cache(direction, fip_res.id)

    def get_fip_qos_rates(self, context, fip_res, policy_id):
        if policy_id is None:
            self.fip_qos_map.clean_by_resource(fip_res)
            # process_ip_rate_limit will treat value 0 as
            # cleaning the tc filters if exits or no action.
            return {constants.INGRESS_DIRECTION: {
                        "rate": qos_base.IP_DEFAULT_RATE,
                        "burst": qos_base.IP_DEFAULT_BURST},
                    constants.EGRESS_DIRECTION: {
                        "rate": qos_base.IP_DEFAULT_RATE,
                        "burst": qos_base.IP_DEFAULT_BURST}}
        policy = self.resource_rpc.pull(
            context, resources.QOS_POLICY, policy_id)
        self.fip_qos_map.set_resource_policy(fip_res, policy)
        return self.get_policy_rates(policy)

    def process_ip_rates(self, fip_res, device, rates, with_cache=True):
        for direction in constants.VALID_DIRECTIONS:
            rate = rates.get(direction)
            if with_cache:

                old_rate, old_burst = self.fip_qos_map.get_fip_ratelimit_cache(
                    direction, fip_res.id)
                if old_rate == rate['rate'] and old_burst == rate['burst']:
                    # Two possibilities here:
                    # 1. Floating IP rate limit does not change.
                    # 2. Floating IP bandwidth does not limit.
                    continue

                self.process_ip_rate_limit(fip_res.ip_address, direction,
                                           device, rate['rate'], rate['burst'])

                self.fip_qos_map.set_fip_ratelimit_cache(
                    direction, fip_res.id, rate['rate'], rate['burst'])
            else:
                tc_wrapper = self._get_tc_wrapper(device)
                if (rate['rate'] == qos_base.IP_DEFAULT_RATE and
                        rate['burst'] == qos_base.IP_DEFAULT_BURST):
                    # Default value is no limit
                    tc_wrapper.clear_ip_rate_limit(direction,
                                                   fip_res.ip_address)
                else:
                    tc_wrapper.set_ip_rate_limit(direction, fip_res.ip_address,
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
                constants.L3_AGENT_MODE_DVR_NO_EXTERNAL):
            # condition 3: dvr local router and dvr_no_external agent
            return

        device = self._get_rate_limit_ip_device(router_info)
        dvr_fip_device = self._get_dvr_fip_device(router_info)
        if not device and not dvr_fip_device:
            LOG.debug("No relevant QoS device found "
                      "for router: %s", router_info.router_id)
            return

        floating_ips = (router_info.get_floating_ips() +
                        router_info.get_port_forwarding_fips())
        current_fips = self.fip_qos_map.get_fips_by_router_id(
            router_info.router_id)
        new_fips = set([])
        for fip in floating_ips:
            fip_res = FipResource(fip['id'], fip['floating_ip_address'])
            new_fips.add(fip_res)
            rates = self.get_fip_qos_rates(context,
                                           fip_res,
                                           fip.get(qos_consts.QOS_POLICY_ID))
            if device:
                self.process_ip_rates(fip_res, device, rates)

            if dvr_fip_device:
                # NOTE(liuyulong): for scenario 4 (mixed dvr_snat and compute
                # node), because floating IP qos rates may have been
                # processed in dvr snat-namespace, so here the cache was
                # already set. We just install the rules to the device in
                # qrouter-namesapce.
                self.process_ip_rates(
                    fip_res, dvr_fip_device, rates, with_cache=False)

        self.fip_qos_map.set_fips(router_info.router_id, new_fips)
        fips_removed = current_fips - new_fips
        for fip_res in fips_removed:
            if device:
                self._remove_fip_rate_limit(device, fip_res)
            if dvr_fip_device:
                self._remove_fip_rate_limit(dvr_fip_device, fip_res)
            self.fip_qos_map.clean_by_resource(fip_res)

    def add_router(self, context, data):
        router_info = self._get_router_info(data['id'])
        if router_info:
            self.process_floating_ip_addresses(context, router_info)

    def update_router(self, context, data):
        router_info = self._get_router_info(data['id'])
        if router_info:
            self.process_floating_ip_addresses(context, router_info)

    def delete_router(self, context, data):
        self.fip_qos_map.clean_router_all_fip_cache(data['id'])

    def ha_state_change(self, context, data):
        pass

    def update_network(self, context, data):
        pass
