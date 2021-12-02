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

import collections

from neutron_lib.agent import l3_extension
from neutron_lib import constants
from neutron_lib import rpc as n_rpc
from oslo_concurrency import lockutils
from oslo_log import log as logging

from neutron.api.rpc.callbacks.consumer import registry
from neutron.api.rpc.callbacks import events
from neutron.api.rpc.callbacks import resources
from neutron.api.rpc.handlers import resources_rpc


LOG = logging.getLogger(__name__)
DEFAULT_CONNTRACK_HELPER_CHAIN = 'cth'
CONNTRACK_HELPER_PREFIX = 'cthelper-'
CONNTRACK_HELPER_CHAIN_PREFIX = DEFAULT_CONNTRACK_HELPER_CHAIN + '-'


class ConntrackHelperMapping(object):

    def __init__(self):
        self._managed_conntrack_helpers = {}
        """
        router_conntrack_helper_mapping = {
           router_id_1: set(cth_id_1, cth_id_2),
           router_id_2: set(cth_id_3, cth_id_4)
        }
        """
        self._router_conntrack_helper_mapping = collections.defaultdict(set)

    def set_conntrack_helpers(self, conntrack_helpers):
        for cth in conntrack_helpers:
            self._router_conntrack_helper_mapping[cth.router_id].add(cth.id)
            self._managed_conntrack_helpers[cth.id] = cth

    def update_conntrack_helpers(self, conntrack_helpers):
        for cth in conntrack_helpers:
            if (cth.id not in
                    self._router_conntrack_helper_mapping[cth.router_id]):
                self._router_conntrack_helper_mapping[cth.router_id].add(
                    cth.id)
            self._managed_conntrack_helpers[cth.id] = cth

    def get_conntack_helper(self, conntrack_helper_id):
        return self._managed_conntrack_helpers.get(conntrack_helper_id)

    def get_managed_conntrack_helpers(self):
        return self._managed_conntrack_helpers

    def del_conntrack_helpers(self, conntrack_helpers):
        for cth in conntrack_helpers:
            if not self.get_conntack_helper(cth.id):
                continue
            del self._managed_conntrack_helpers[cth.id]
            self._router_conntrack_helper_mapping[cth.router_id].remove(
                cth.id)
            if not self._router_conntrack_helper_mapping[cth.router_id]:
                del self._router_conntrack_helper_mapping[cth.router_id]

    def clear_by_router_id(self, router_id):
        router_cth_ids = self._router_conntrack_helper_mapping.get(router_id)
        if not router_cth_ids:
            return
        for cth_id in router_cth_ids:
            del self._managed_conntrack_helpers[cth_id]
        del self._router_conntrack_helper_mapping[router_id]

    def check_conntrack_helper_changes(self, new_cth):
        old_cth = self.get_conntack_helper(new_cth.id)
        return old_cth != new_cth


class ConntrackHelperAgentExtension(l3_extension.L3AgentExtension):
    SUPPORTED_RESOURCE_TYPES = [resources.CONNTRACKHELPER]

    def initialize(self, connection, driver_type):
        self.resource_rpc = resources_rpc.ResourcesPullRpcApi()
        self._register_rpc_consumers()
        self.mapping = ConntrackHelperMapping()

    def _register_rpc_consumers(self):
        registry.register(self._handle_notification, resources.CONNTRACKHELPER)

        self._connection = n_rpc.Connection()
        endpoints = [resources_rpc.ResourcesPushRpcCallback()]
        topic = resources_rpc.resource_type_versioned_topic(
            resources.CONNTRACKHELPER)
        self._connection.create_consumer(topic, endpoints, fanout=True)
        self._connection.consume_in_threads()

    def consume_api(self, agent_api):
        self.agent_api = agent_api

    @lockutils.synchronized('conntrack-helpers')
    def _handle_notification(self, context, resource_type, conntrack_helpers,
                             event_type):
        for conntrack_helper in conntrack_helpers:
            router_info = self.agent_api.get_router_info(
                conntrack_helper.router_id)
            if not router_info:
                return

            iptables_manager = self._get_iptables_manager(router_info)

            if event_type == events.CREATED:
                self._process_create([conntrack_helper], iptables_manager)
            elif event_type == events.UPDATED:
                self._process_update([conntrack_helper], iptables_manager)
            elif event_type == events.DELETED:
                self._process_delete([conntrack_helper], iptables_manager)

    def _get_chain_name(self, id):
        return (CONNTRACK_HELPER_CHAIN_PREFIX + id)[
               :constants.MAX_IPTABLES_CHAIN_LEN_WRAP]

    def _install_default_rules(self, iptables_manager, version):
        default_rule = '-j %s-%s' % (iptables_manager.wrap_name,
                                     DEFAULT_CONNTRACK_HELPER_CHAIN)
        if version == constants.IPv4:
            iptables_manager.ipv4['raw'].add_chain(
                DEFAULT_CONNTRACK_HELPER_CHAIN)
            iptables_manager.ipv4['raw'].add_rule('PREROUTING', default_rule)
        elif version == constants.IPv6:
            iptables_manager.ipv6['raw'].add_chain(
                DEFAULT_CONNTRACK_HELPER_CHAIN)
            iptables_manager.ipv6['raw'].add_rule('PREROUTING', default_rule)
        iptables_manager.apply()

    def _get_chain_rules_list(self, conntrack_helper, wrap_name):
        chain_name = self._get_chain_name(conntrack_helper.id)
        chain_rule_list = [(DEFAULT_CONNTRACK_HELPER_CHAIN,
                            '-j %s-%s' % (wrap_name, chain_name))]
        chain_rule_list.append((chain_name,
                                '-p %(proto)s --dport %(dport)s -j CT '
                                '--helper %(helper)s' %
                                {'proto': conntrack_helper.protocol,
                                 'dport': conntrack_helper.port,
                                 'helper': conntrack_helper.helper}))

        return chain_rule_list

    def _rule_apply(self, iptables_manager, conntrack_helper):
        tag = CONNTRACK_HELPER_PREFIX + conntrack_helper.id
        iptables_manager.ipv4['raw'].clear_rules_by_tag(tag)
        iptables_manager.ipv6['raw'].clear_rules_by_tag(tag)
        for chain, rule in self._get_chain_rules_list(
                conntrack_helper, iptables_manager.wrap_name):
            if chain not in iptables_manager.ipv4['raw'].chains:
                iptables_manager.ipv4['raw'].add_chain(chain)
            if chain not in iptables_manager.ipv6['raw'].chains:
                iptables_manager.ipv6['raw'].add_chain(chain)

            iptables_manager.ipv4['raw'].add_rule(chain, rule, tag=tag)
            iptables_manager.ipv6['raw'].add_rule(chain, rule, tag=tag)

    def _process_create(self, conntrack_helpers, iptables_manager):
        if not conntrack_helpers:
            return

        if (DEFAULT_CONNTRACK_HELPER_CHAIN not in
                iptables_manager.ipv4['raw'].chains):
            self._install_default_rules(iptables_manager, constants.IPv4)
        if (DEFAULT_CONNTRACK_HELPER_CHAIN not in
                iptables_manager.ipv6['raw'].chains):
            self._install_default_rules(iptables_manager, constants.IPv6)

        for conntrack_helper in conntrack_helpers:
            self._rule_apply(iptables_manager, conntrack_helper)

        iptables_manager.apply()
        self.mapping.set_conntrack_helpers(conntrack_helpers)

    def _process_update(self, conntrack_helpers, iptables_manager):
        if not conntrack_helpers:
            return

        for conntrack_helper in conntrack_helpers:
            if not self.mapping.check_conntrack_helper_changes(
                    conntrack_helper):
                LOG.debug("Skip conntrack helper %s for update, as there is "
                          "no difference between the memory managed by agent",
                          conntrack_helper.id)
                continue

            current_chain = self._get_chain_name(conntrack_helper.id)
            iptables_manager.ipv4['raw'].remove_chain(current_chain)
            iptables_manager.ipv6['raw'].remove_chain(current_chain)

            self._rule_apply(iptables_manager, conntrack_helper)

        iptables_manager.apply()
        self.mapping.update_conntrack_helpers(conntrack_helpers)

    def _process_delete(self, conntrack_helpers, iptables_manager):
        if not conntrack_helpers:
            return

        for conntrack_helper in conntrack_helpers:
            chain_name = self._get_chain_name(conntrack_helper.id)
            iptables_manager.ipv4['raw'].remove_chain(chain_name)
            iptables_manager.ipv6['raw'].remove_chain(chain_name)

        iptables_manager.apply()
        self.mapping.del_conntrack_helpers(conntrack_helpers)

    def _get_iptables_manager(self, router_info):
        if router_info.router.get('distributed'):
            return router_info.snat_iptables_manager

        return router_info.iptables_manager

    def check_local_conntrack_helpers(self, context, router_info):
        local_ct_helpers = set(self.mapping.get_managed_conntrack_helpers()
                               .keys())
        new_ct_helpers = []
        updated_cth_helpers = []
        current_ct_helpers = set()

        ct_helpers = self.resource_rpc.bulk_pull(
            context, resources.CONNTRACKHELPER, filter_kwargs={
                'router_id': router_info.router['id']})

        for cth in ct_helpers:
            # Split request conntrack helpers into update, new and current
            if (cth.id in self.mapping.get_managed_conntrack_helpers() and
                    self.mapping.check_conntrack_helper_changes(cth)):
                updated_cth_helpers.append(cth)
            elif cth.id not in self.mapping.get_managed_conntrack_helpers():
                new_ct_helpers.append(cth)
            current_ct_helpers.add(cth.id)

        remove_ct_helpers = [
            self.mapping.get_managed_conntrack_helpers().get(cth_id) for cth_id
            in local_ct_helpers.difference(current_ct_helpers)]

        iptables_manager = self._get_iptables_manager(router_info)

        self._process_update(updated_cth_helpers, iptables_manager)
        self._process_create(new_ct_helpers, iptables_manager)
        self._process_delete(remove_ct_helpers, iptables_manager)

    def process_conntrack_helper(self, context, data):
        router_info = self.agent_api.get_router_info(data['id'])
        if not router_info:
            LOG.debug("Router %s is not managed by this agent. "
                      "It was possibly deleted concurrently.", data['id'])
            return

        self.check_local_conntrack_helpers(context, router_info)

    @lockutils.synchronized('conntrack-helpers')
    def add_router(self, context, data):
        self.process_conntrack_helper(context, data)

    @lockutils.synchronized('conntrack-helpers')
    def update_router(self, context, data):
        self.process_conntrack_helper(context, data)

    def delete_router(self, context, data):
        self.mapping.clear_by_router_id(data['id'])

    def ha_state_change(self, context, data):
        pass

    def update_network(self, context, data):
        pass
