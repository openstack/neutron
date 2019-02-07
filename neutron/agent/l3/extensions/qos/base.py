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

from neutron_lib import constants
from neutron_lib.db import constants as db_consts
from neutron_lib import rpc as n_rpc
from neutron_lib.services.qos import constants as qos_consts
from oslo_log import log as logging

from neutron.agent.linux import l3_tc_lib as tc_lib
from neutron.api.rpc.callbacks.consumer import registry
from neutron.api.rpc.callbacks import resources
from neutron.api.rpc.handlers import resources_rpc

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
# 3. if one IP's rate was changed from x to 0, the extension will do
#    a tc filter clean procedure.
IP_DEFAULT_RATE = 0
IP_DEFAULT_BURST = 0


class RateLimitMaps(object):

    def __init__(self):
        self.qos_policy_resources = collections.defaultdict(dict)
        self.known_policies = {}
        self.resource_policies = {}

    def update_policy(self, policy):
        self.known_policies[policy.id] = policy

    def get_policy(self, policy_id):
        return self.known_policies.get(policy_id)

    def get_resources(self, policy):
        return self.qos_policy_resources[policy.id].values()

    def get_resource_policy(self, resource):
        policy_id = self.resource_policies.get(resource)
        return self.get_policy(policy_id)

    def set_resource_policy(self, resource, policy):
        """Attach a resource to policy

        and return any previous policy on resource.
        """

        old_policy = self.get_resource_policy(resource)
        self.update_policy(policy)
        self.resource_policies[resource] = policy.id
        self.qos_policy_resources[policy.id][resource] = resource
        if old_policy and old_policy.id != policy.id:
            del self.qos_policy_resources[old_policy.id][resource]

    def clean_by_resource(self, resource):
        """Detach resource from policy

        and cleanup data we don't need anymore.
        """

        if resource in self.resource_policies:
            del self.resource_policies[resource]
            for qos_policy_id, res_dict in self.qos_policy_resources.items():
                if resource in res_dict:
                    del res_dict[resource]
                    if not res_dict:
                        self._clean_policy_info(qos_policy_id)
                    return
        LOG.debug("L3 QoS extension did not have "
                  "information on floating IP %s", resource)

    def _clean_policy_info(self, qos_policy_id):
        del self.qos_policy_resources[qos_policy_id]
        del self.known_policies[qos_policy_id]


class L3QosAgentExtensionBase(object):
    SUPPORTED_RESOURCE_TYPES = [resources.QOS_POLICY]

    def consume_api(self, agent_api):
        self.agent_api = agent_api

    def _handle_notification(self, context, resource_type,
                             qos_policies, event_type):
        pass

    def _process_update_policy(self, qos_policy):
        pass

    def _policy_rules_modified(self, old_policy, policy):
        return not (len(old_policy.rules) == len(policy.rules) and
                    all(i in old_policy.rules for i in policy.rules))

    def _register_rpc_consumers(self):
        registry.register(self._handle_notification, resources.QOS_POLICY)

        self._connection = n_rpc.Connection()
        endpoints = [resources_rpc.ResourcesPushRpcCallback()]
        topic = resources_rpc.resource_type_versioned_topic(
            resources.QOS_POLICY)
        self._connection.create_consumer(topic, endpoints, fanout=True)
        self._connection.consume_in_threads()

    def _get_tc_wrapper(self, device):
        return tc_lib.FloatingIPTcCommand(device.name,
                                          namespace=device.namespace)

    def get_policy_rates(self, policy):
        rates = {}
        for rule in policy.rules:
            # NOTE(liuyulong): for now, the L3 agent QoS extensions only
            # use ``bandwidth_limit`` rules.
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
                rates[direction] = {"rate": IP_DEFAULT_RATE,
                                    "burst": IP_DEFAULT_BURST}
        return rates

    def _get_router_info(self, router_id):
        router_info = self.agent_api.get_router_info(router_id)
        if router_info:
            return router_info
        LOG.debug("Router %s is not managed by this agent. "
                  "It was possibly deleted concurrently.",
                  router_id)
