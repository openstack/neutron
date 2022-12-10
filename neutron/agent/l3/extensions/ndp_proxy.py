# Copyright 2021 Troila
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

import netaddr
from neutron_lib.agent import l3_extension
from neutron_lib import constants
from neutron_lib import rpc as n_rpc
from oslo_concurrency import lockutils
from oslo_log import log as logging

from neutron.agent.linux import ip_lib
from neutron.api.rpc.callbacks.consumer import registry
from neutron.api.rpc.callbacks import events
from neutron.api.rpc.callbacks import resources
from neutron.api.rpc.handlers import resources_rpc
from neutron.common import coordination
from neutron.common import utils

LOG = logging.getLogger(__name__)
DEFAULT_NDP_PROXY_CHAIN = 'NDP'


class RouterNDPProxyMapping(object):

    def __init__(self):
        self.managed_ndp_proxies = {}
        self.router_ndp_proxy_mapping = collections.defaultdict(set)

    @lockutils.synchronized('ndp-proxy-cache')
    def set_ndp_proxies(self, ndp_proxies):
        for ndp_proxy in ndp_proxies:
            self.router_ndp_proxy_mapping[
                ndp_proxy.router_id].add(ndp_proxy.id)
            self.managed_ndp_proxies[ndp_proxy.id] = ndp_proxy

    @lockutils.synchronized('ndp-proxy-cache')
    def get_ndp_proxy(self, ndp_proxy_id):
        return self.managed_ndp_proxies.get(ndp_proxy_id)

    @lockutils.synchronized('ndp-proxy-cache')
    def del_ndp_proxies(self, ndp_proxies):
        for ndp_proxy in ndp_proxies:
            if not self.managed_ndp_proxies.get(ndp_proxy.id):
                continue
            del self.managed_ndp_proxies[ndp_proxy.id]
            self.router_ndp_proxy_mapping[
                ndp_proxy.router_id].remove(ndp_proxy.id)
            if not self.router_ndp_proxy_mapping[ndp_proxy.router_id]:
                del self.router_ndp_proxy_mapping[ndp_proxy.router_id]

    @lockutils.synchronized('ndp-proxy-cache')
    def get_ndp_proxies_by_router_id(self, router_id):
        ndp_proxies = []
        router_ndp_proxy_ids = self.router_ndp_proxy_mapping.get(router_id, [])
        for ndp_proxy_id in router_ndp_proxy_ids:
            ndp_proxies.append(self.managed_ndp_proxies.get(ndp_proxy_id))
        return ndp_proxies

    @lockutils.synchronized('ndp-proxy-cache')
    def clear_by_router_id(self, router_id):
        router_ndp_proxy_ids = self.router_ndp_proxy_mapping.get(router_id)
        if not router_ndp_proxy_ids:
            return
        for ndp_proxy_id in router_ndp_proxy_ids:
            del self.managed_ndp_proxies[ndp_proxy_id]
        del self.router_ndp_proxy_mapping[router_id]


class NDPProxyAgentExtension(l3_extension.L3AgentExtension):

    def initialize(self, connection, driver_type):
        self.resource_rpc = resources_rpc.ResourcesPullRpcApi()
        self._register_rpc_consumers()
        self.mapping = RouterNDPProxyMapping()

    def consume_api(self, agent_api):
        self.agent_api = agent_api

    def _register_rpc_consumers(self):
        registry.register(self._handle_notification, resources.NDPPROXY)
        self._connection = n_rpc.Connection()
        endpoints = [resources_rpc.ResourcesPushRpcCallback()]
        topic = resources_rpc.resource_type_versioned_topic(
            resources.NDPPROXY)
        self._connection.create_consumer(topic, endpoints, fanout=True)
        self._connection.consume_in_threads()

    def _handle_notification(self, context, resource_type,
                             ndp_proxies, event_type):
        for ndp_proxy in ndp_proxies:
            ri = self.agent_api.get_router_info(
                ndp_proxy.router_id)
            if not (ri and self._check_if_ri_need_process(ri) and
                    self._check_if_ndp_proxy_need_process(
                        context, ri, ndp_proxy)):
                continue
            (interface_name, namespace,
             iptables_manager) = self._get_resource_by_router(ri)
            agent_mode = ri.agent_conf.agent_mode
            is_distributed = ri.router.get('distributed')
            if (is_distributed and
                    agent_mode != constants.L3_AGENT_MODE_DVR_SNAT):
                rtr_2_fip_dev = ri.fip_ns.get_rtr_2_fip_device(ri)
                fip_2_rtr_dev = ri.fip_ns.get_fip_2_rtr_device(ri)
            if event_type == events.CREATED:
                LOG.debug("Create ndp proxy: %s.", ndp_proxy)
                if (is_distributed and
                        agent_mode != constants.L3_AGENT_MODE_DVR_SNAT):
                    self._process_create_dvr([ndp_proxy], rtr_2_fip_dev,
                                             fip_2_rtr_dev, interface_name,
                                             namespace)
                else:
                    self._process_create([ndp_proxy], interface_name,
                                         namespace, iptables_manager)
                self.mapping.set_ndp_proxies([ndp_proxy])
            elif event_type == events.DELETED:
                LOG.debug("Delete ndp proxy: %s.", ndp_proxy)
                if (is_distributed and
                        agent_mode != constants.L3_AGENT_MODE_DVR_SNAT):
                    self._process_delete_dvr([ndp_proxy], rtr_2_fip_dev,
                                             fip_2_rtr_dev, interface_name,
                                             namespace)
                else:
                    self._process_delete([ndp_proxy], interface_name,
                                         namespace, iptables_manager)
                self.mapping.del_ndp_proxies([ndp_proxy])
            if iptables_manager:
                iptables_manager.apply()

    def _check_if_ri_need_process(self, ri):
        if not (ri and ri.get_ex_gw_port()):
            return False
        is_distributed = ri.router.get('distributed')
        agent_mode = ri.agent_conf.agent_mode
        if (is_distributed and
                agent_mode == constants.L3_AGENT_MODE_DVR_NO_EXTERNAL):
            return False
        if is_distributed and agent_mode == constants.L3_AGENT_MODE_DVR_SNAT:
            if ri.router.get('gw_port_host') != ri.agent_conf.host:
                return False
        return True

    def _check_if_ndp_proxy_need_process(self, context, ri, ndp_proxy):
        """Check the ndp proxy whether need processed by local l3 agent"""
        agent_mode = ri.agent_conf.agent_mode
        is_distributed = ri.router.get('distributed')
        if not is_distributed:
            return True
        # dvr_no_external agent don't need process dvr router's ndp proxy
        if agent_mode == constants.L3_AGENT_MODE_DVR_NO_EXTERNAL:
            return False
        port_obj = self.resource_rpc.bulk_pull(
            context, resources.PORT, filter_kwargs={
                'id': ndp_proxy['port_id']})[0]
        if len(port_obj.bindings) != 1:
            return False
        if agent_mode == constants.L3_AGENT_MODE_DVR:
            if port_obj.bindings[0].host == ri.agent_conf.host:
                return True
        # If the l3 agent mode is dvr_no_external of the host which the ndp
        # proxy's port binding to, the rules related the ndp proxy should be
        # applied in snat-namespace
        if agent_mode == constants.L3_AGENT_MODE_DVR_SNAT:
            agent_obj = self.resource_rpc.bulk_pull(
                context, resources.AGENT,
                filter_kwargs={
                    'host': port_obj.bindings[0].host,
                    'agent_type': constants.AGENT_TYPE_L3})[0]
            if agent_obj.configurations['agent_mode'] == \
                    constants.L3_AGENT_MODE_DVR_NO_EXTERNAL:
                return True
        return False

    def _get_resource_by_router(self, ri):
        is_distributed = ri.router.get('distributed')
        ex_gw_port = ri.get_ex_gw_port()
        if not is_distributed:
            interface_name = ri.get_external_device_interface_name(ex_gw_port)
            namespace = ri.ns_name
            iptables_manager = ri.iptables_manager
        elif ri.agent_conf.agent_mode == constants.L3_AGENT_MODE_DVR_SNAT:
            interface_name = ri.get_snat_external_device_interface_name(
                ex_gw_port)
            namespace = ri.snat_namespace.name
            iptables_manager = ri.snat_iptables_manager
        else:
            interface_name = ri.fip_ns.get_ext_device_name(
                ri.fip_ns.agent_gateway_port['id'])
            namespace = ri.fip_ns.name
            iptables_manager = None
        return interface_name, namespace, iptables_manager

    def _get_device_ipv6_lladdr(self, device):
        lladdr_cidr = ip_lib.get_ipv6_lladdr(device.link.address)
        return utils.cidr_to_ip(lladdr_cidr)

    @coordination.synchronized('router-lock-ns-{namespace}')
    def _process_create(self, ndp_proxies, interface_name,
                        namespace, iptables_manager):
        ip_wrapper = ip_lib.IPWrapper(namespace=namespace)
        for proxy in ndp_proxies:
            v6_address = str(proxy.ip_address)
            cmd = ['ip', '-6', 'neigh', 'add',
                   'proxy', v6_address, 'dev', interface_name]
            ip_wrapper.netns.execute(cmd, privsep_exec=True)
            accept_rule = '-i %s --destination %s -j ACCEPT' % (
                interface_name, v6_address)
            iptables_manager.ipv6['filter'].add_rule(
                DEFAULT_NDP_PROXY_CHAIN, accept_rule, top=True)
            cmd = ['ndsend', v6_address, interface_name]
            ip_wrapper.netns.execute(cmd, check_exit_code=False,
                                     log_fail_as_error=True,
                                     privsep_exec=True)

    @coordination.synchronized('router-lock-ns-{namespace}')
    def _process_create_dvr(self, ndp_proxies, rtr_2_fip_dev,
                            fip_2_rtr_dev, interface_name, namespace):
        for proxy in ndp_proxies:
            rtr_2_fip_v6_address = self._get_device_ipv6_lladdr(rtr_2_fip_dev)
            ip_wrapper = ip_lib.IPWrapper(namespace=namespace)
            v6_address = str(proxy.ip_address)
            fip_2_rtr_dev.route.add_route(v6_address, via=rtr_2_fip_v6_address)
            cmd = ['ip', '-6', 'neigh', 'add',
                   'proxy', v6_address, 'dev', interface_name]
            ip_wrapper.netns.execute(cmd, privsep_exec=True)
            cmd = ['ndsend', v6_address, interface_name]
            ip_wrapper.netns.execute(cmd, check_exit_code=False,
                                     log_fail_as_error=True,
                                     privsep_exec=True)

    @coordination.synchronized('router-lock-ns-{namespace}')
    def _process_delete(self, ndp_proxies, interface_name,
                        namespace, iptables_manager):
        ip_wrapper = ip_lib.IPWrapper(namespace=namespace)
        for proxy in ndp_proxies:
            v6_address = str(proxy.ip_address)
            cmd = ['ip', '-6', 'neigh', 'del',
                   'proxy', v6_address, 'dev', interface_name]
            ip_wrapper.netns.execute(cmd, privsep_exec=True)
            accept_rule = '-i %s --destination %s -j ACCEPT' % (
                interface_name, v6_address)
            iptables_manager.ipv6['filter'].remove_rule(
                DEFAULT_NDP_PROXY_CHAIN, accept_rule, top=True)

    @coordination.synchronized('router-lock-ns-{namespace}')
    def _process_delete_dvr(self, ndp_proxies, rtr_2_fip_dev,
                            fip_2_rtr_dev, interface_name, namespace):
        rtr_2_fip_v6_address = self._get_device_ipv6_lladdr(rtr_2_fip_dev)
        ip_wrapper = ip_lib.IPWrapper(namespace=namespace)
        for proxy in ndp_proxies:
            v6_address = str(proxy.ip_address)
            fip_2_rtr_dev.route.delete_route(
                v6_address, via=rtr_2_fip_v6_address)
            cmd = ['ip', '-6', 'neigh', 'del',
                   'proxy', v6_address, 'dev', interface_name]
            ip_wrapper.netns.execute(cmd, privsep_exec=True)

    def _get_router_info(self, router_id):
        ri = self.agent_api.get_router_info(router_id)
        if ri:
            return ri
        LOG.debug("Router %s is not managed by this agent. "
                  "It was possibly deleted concurrently.", router_id)

    def _check_if_address_scopes_match(self, int_port, ex_gw_port):
        """Checks and returns the matching state for v6 scopes."""
        int_port_addr_scopes = int_port.get('address_scopes', {})
        ext_port_addr_scopes = ex_gw_port.get('address_scopes', {})
        key = str(constants.IP_VERSION_6)
        if int_port_addr_scopes.get(key) == ext_port_addr_scopes.get(key):
            return True
        return False

    @coordination.synchronized('router-lock-ns-{namespace}')
    def _init_ndp_proxy_rule(self, ri, interface_name,
                             iptables_manager, is_distributed, ip_wrapper,
                             namespace):
        agent_mode = ri.agent_conf.agent_mode
        sysctl_cmd = ['sysctl', '-w',
                      'net.ipv6.conf.%s.proxy_ndp=1' % interface_name]
        dvr_with_snat = (
            is_distributed and agent_mode == constants.L3_AGENT_MODE_DVR_SNAT)
        if not is_distributed or dvr_with_snat:
            # We need apply some iptable rules in centralized router namespace.
            wrap_name = iptables_manager.wrap_name
            existing_chains = iptables_manager.ipv6['filter'].chains
            if DEFAULT_NDP_PROXY_CHAIN not in existing_chains:
                iptables_manager.ipv6['filter'].add_chain(
                    DEFAULT_NDP_PROXY_CHAIN)
                default_rule = '-i %s -j DROP' % interface_name
                iptables_manager.ipv6['filter'].add_rule(
                    DEFAULT_NDP_PROXY_CHAIN, default_rule)
                iptables_manager.apply()

            new_subnet_cidrs = []
            for internal_port in ri.internal_ports:
                if self._check_if_address_scopes_match(
                        internal_port, ri.ex_gw_port):
                    for subnet in internal_port['subnets']:
                        if netaddr.IPNetwork(subnet['cidr']).version == \
                                constants.IP_VERSION_4:
                            continue
                        new_subnet_cidrs.append(subnet['cidr'])
            existing_subnet_cidrs = []
            for rule in iptables_manager.ipv6['filter'].rules:
                if ("-j %s-%s") % (
                        wrap_name, DEFAULT_NDP_PROXY_CHAIN) not in rule.rule:
                    continue
                rule_lists = rule.rule.split(' ')
                for item in rule_lists:
                    try:
                        netaddr.IPNetwork(item)
                    except netaddr.core.AddrFormatError:
                        continue
                    existing_subnet_cidrs.append(item)

            need_add = set(new_subnet_cidrs) - set(existing_subnet_cidrs)
            need_del = set(existing_subnet_cidrs) - set(new_subnet_cidrs)
            for cidr in need_add:
                subnet_rule = (
                    '-i %s --destination %s -j '
                    '%s-%s') % (interface_name, cidr,
                                wrap_name, DEFAULT_NDP_PROXY_CHAIN)
                iptables_manager.ipv6['filter'].add_rule(
                    'FORWARD', subnet_rule)
            for cidr in need_del:
                subnet_rule = (
                    '-i %s --destination %s -j '
                    '%s-%s') % (interface_name, cidr,
                                wrap_name, DEFAULT_NDP_PROXY_CHAIN)
                iptables_manager.ipv6['filter'].remove_rule(
                    'FORWARD', subnet_rule)
        ip_wrapper.netns.execute(sysctl_cmd, privsep_exec=True)

    def _process_router(self, context, router_id, enable_ndp_proxy):
        ri = self._get_router_info(router_id)
        if not self._check_if_ri_need_process(ri):
            return
        agent_mode = ri.agent_conf.agent_mode
        (interface_name, namespace,
         iptables_manager) = self._get_resource_by_router(ri)
        ip_wrapper = ip_lib.IPWrapper(namespace=namespace)
        is_distributed = ri.router.get('distributed')
        if is_distributed and agent_mode != constants.L3_AGENT_MODE_DVR_SNAT:
            rtr_2_fip_dev = ri.fip_ns.get_rtr_2_fip_device(ri)
            fip_2_rtr_dev = ri.fip_ns.get_fip_2_rtr_device(ri)

        existing_ndp_proxies = self.mapping.get_ndp_proxies_by_router_id(
            ri.router_id)
        if enable_ndp_proxy:
            self._init_ndp_proxy_rule(
                ri, interface_name, iptables_manager,
                is_distributed, ip_wrapper, namespace)

            ndp_proxies = self.resource_rpc.bulk_pull(
                context, resources.NDPPROXY,
                filter_kwargs={'router_id': [router_id]})
            need_create = set(ndp_proxies) - set(existing_ndp_proxies)
            need_delete = set(existing_ndp_proxies) - set(ndp_proxies)

            def filter_ndp_proxies(ri, ndp_proxies):
                result = []
                for ndp_proxy in ndp_proxies:
                    if self._check_if_ndp_proxy_need_process(
                            context, ri, ndp_proxy):
                        result.append(ndp_proxy)
                return result

            need_create = filter_ndp_proxies(ri, need_create)
            if is_distributed and agent_mode == constants.L3_AGENT_MODE_DVR:
                self._process_create_dvr(need_create, rtr_2_fip_dev,
                                         fip_2_rtr_dev, interface_name,
                                         namespace)
                self._process_delete_dvr(need_delete, rtr_2_fip_dev,
                                         fip_2_rtr_dev, interface_name,
                                         namespace)
            else:
                self._process_create(need_create, interface_name,
                                     namespace, iptables_manager)
                self._process_delete(need_delete, interface_name,
                                     namespace, iptables_manager)
            self.mapping.set_ndp_proxies(need_create)
        else:
            if is_distributed and agent_mode == constants.L3_AGENT_MODE_DVR:
                self._process_delete_dvr(
                    existing_ndp_proxies, rtr_2_fip_dev,
                    fip_2_rtr_dev, interface_name, namespace)
            else:
                self._clear_ndp_proxies(
                    ip_wrapper, iptables_manager,
                    interface_name, namespace)
            self.mapping.clear_by_router_id(ri.router_id)

        if iptables_manager:
            iptables_manager.apply()

    @coordination.synchronized('router-lock-ns-{namespace}')
    def _clear_ndp_proxies(self, ip_wrapper, iptables_manager,
                           interface_name, namespace):
        cmd = ['ip', '-6', 'neigh', 'flush', 'proxy']
        ip_wrapper.netns.execute(cmd, check_exit_code=False,
                                 privsep_exec=True)
        iptables_manager.ipv6['filter'].remove_chain(
            DEFAULT_NDP_PROXY_CHAIN)
        sysctl_cmd = ['sysctl', '-w',
                      'net.ipv6.conf.%s.proxy_ndp=0' % interface_name]
        ip_wrapper.netns.execute(sysctl_cmd, privsep_exec=True)

    def add_router(self, context, data):
        self._process_router(context, data['id'],
                             data.get('enable_ndp_proxy', False))

    def update_router(self, context, data):
        self._process_router(context, data['id'],
                             data.get('enable_ndp_proxy', False))

    def delete_router(self, context, data):
        # Just process dvr router, clear the fip-namespace related rules
        if not data['distributed']:
            return
        ndp_proxies = self.mapping.get_ndp_proxies_by_router_id(data['id'])
        if not ndp_proxies:
            return
        ri = self._get_router_info(data['id'])
        (interface_name, namespace,
         iptables_manager) = self._get_resource_by_router(ri)
        rtr_2_fip_dev = ri.fip_ns.get_rtr_2_fip_device(ri)
        fip_2_rtr_dev = ri.fip_ns.get_fip_2_rtr_device(ri)
        self._process_delete_dvr(ndp_proxies, rtr_2_fip_dev,
                                 fip_2_rtr_dev, interface_name, namespace)

    def ha_state_change(self, context, data):
        if data['state'] == 'backup':
            return

        self._process_router(context, data['router_id'],
                             data['enable_ndp_proxy'])

    def update_network(self, context, data):
        pass
