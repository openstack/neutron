# Copyright (c) 2015 Red Hat Inc.
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

from neutron import manager

from neutron.api.rpc.callbacks import registry as rpc_registry
from neutron.api.rpc.callbacks import resources as rpc_resources
from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.extensions import qos
from neutron.i18n import _LW
from neutron.objects.qos import policy as policy_object
from neutron.objects.qos import rule as rule_object
from neutron.plugins.common import constants

from oslo_log import log as logging


LOG = logging.getLogger(__name__)


#TODO(QoS): remove this stub when db is ready
def _get_qos_policy_cb_stub(resource, policy_id, **kwargs):
    """Hardcoded stub for testing until we get the db working."""
    qos_policy = {
        "tenant_id": "8d4c70a21fed4aeba121a1a429ba0d04",
        "id": "46ebaec0-0570-43ac-82f6-60d2b03168c4",
        "name": "10Mbit",
        "description": "This policy limits the ports to 10Mbit max.",
        "shared": False,
        "rules": [{
            "id": "5f126d84-551a-4dcf-bb01-0e9c0df0c793",
            "max_kbps": "10000",
            "max_burst_kbps": "0",
            "type": "bandwidth_limit"
        }]
    }
    return qos_policy


def _get_qos_policy_cb(resource, policy_id, **kwargs):
    qos_plugin = manager.NeutronManager.get_service_plugins().get(
        constants.QOS)
    context = kwargs.get('context')
    if context is None:
        LOG.warning(_LW(
            'Received %(resource)s %(policy_id)s without context'),
            {'resource': resource, 'policy_id': policy_id}
        )
        return

    qos_policy = qos_plugin.get_qos_policy(context, policy_id)
    return qos_policy


#TODO(QoS): remove this stub when db is ready
def _get_qos_bandwidth_limit_rule_cb_stub(resource, rule_id, **kwargs):
    """Hardcoded for testing until we get the db working."""
    bandwidth_limit = {
        "id": "5f126d84-551a-4dcf-bb01-0e9c0df0c793",
        "qos_policy_id": "46ebaec0-0570-43ac-82f6-60d2b03168c4",
        "max_kbps": "10000",
        "max_burst_kbps": "0",
    }
    return bandwidth_limit


def _get_qos_bandwidth_limit_rule_cb(resource, rule_id, **kwargs):
    qos_plugin = manager.NeutronManager.get_service_plugins().get(
        constants.QOS)
    context = kwargs.get('context')
    if context is None:
        LOG.warning(_LW(
            'Received %(resource)s %(rule_id,)s without context '),
            {'resource': resource, 'rule_id,': rule_id}
        )
        return

    bandwidth_limit = qos_plugin.get_qos_bandwidth_limit_rule(
                                        context,
                                        rule_id)
    return bandwidth_limit


class QoSPlugin(qos.QoSPluginBase):
    """Implementation of the Neutron QoS Service Plugin.

    This class implements a Quality of Service plugin that
    provides quality of service parameters over ports and
    networks.

    """
    supported_extension_aliases = ['qos']

    def __init__(self):
        super(QoSPlugin, self).__init__()
        self.register_resource_providers()
        self.register_port_callbacks()
        self.register_net_callbacks()

    def register_resource_providers(self):
        rpc_registry.register_provider(
            _get_qos_bandwidth_limit_rule_cb_stub,
            rpc_resources.QOS_RULE)

        rpc_registry.register_provider(
            _get_qos_policy_cb_stub,
            rpc_resources.QOS_POLICY)

    def register_port_callbacks(self):
        registry.subscribe(
            self._extend_port_policy_data, resources.PORT, events.AFTER_READ)

    def _extend_port_policy_data(self, resource, event, trigger, **kwargs):
        context = kwargs['context']
        port = kwargs['port']
        policy = policy_object.QosPolicy.get_port_policy(context, port['id'])
        port['qos_policy_id'] = policy.id if policy else None

    def update_port_policy(self, context, port):
        old_policy = policy_object.QosPolicy.get_port_policy(
            context, port['id'])
        if old_policy is not None:
            #TODO(QoS): this means two transactions. One for detaching
            #           one for re-attaching, we may want to update
            #           within a single transaction instead, or put
            #           a whole transaction on top, or handle the switch
            #           at db api level automatically within transaction.
            old_policy.detach_port(port['id'])

        qos_policy_id = port.get('qos_policy_id')
        if qos_policy_id is not None:
            policy = self._get_policy_obj(context, qos_policy_id)
            policy.attach_port(port['id'])

    def register_net_callbacks(self):
        registry.subscribe(self._extend_network_policy_data,
                           resources.NETWORK,
                           events.AFTER_READ)

    def _extend_network_policy_data(self, resource, event, trigger, **kwargs):
        context = kwargs['context']
        network = kwargs['network']
        policy = policy_object.QosPolicy.get_network_policy(
            context, network['id'])
        network['qos_policy_id'] = policy.id if policy else None

    def update_network_policy(self, context, network):
        old_policy = policy_object.QosPolicy.get_network_policy(
            context, network['id'])
        if old_policy:
            old_policy.detach_network(network['id'])

        qos_policy_id = network.get('qos_policy_id')
        if qos_policy_id:
            policy = self._get_policy_obj(context, qos_policy_id)
            policy.attach_network(network['id'])

    def create_policy(self, context, policy):
        policy = policy_object.QosPolicy(context, **policy['policy'])
        policy.create()
        return policy.to_dict()

    def update_policy(self, context, policy_id, qos_policy):
        policy = policy_object.QosPolicy(context, **qos_policy['policy'])
        policy.id = policy_id
        policy.update()
        return policy.to_dict()

    def delete_policy(self, context, policy_id):
        policy = policy_object.QosPolicy(context)
        policy.id = policy_id
        policy.delete()

    def _get_policy_obj(self, context, policy_id):
        return policy_object.QosPolicy.get_by_id(context, policy_id)

    def get_policy(self, context, policy_id, fields=None):
        #TODO(QoS): Support the fields parameter
        return self._get_policy_obj(context, policy_id).to_dict()

    def get_policies(self, context, filters=None, fields=None,
                     sorts=None, limit=None, marker=None,
                     page_reverse=False):
        #TODO(QoS): Support all the optional parameters
        return [policy_obj.to_dict() for policy_obj in
                policy_object.QosPolicy.get_objects(context)]

    #TODO(QoS): Consider adding a proxy catch-all for rules, so
    #           we capture the API function call, and just pass
    #           the rule type as a parameter removing lots of
    #           future code duplication when we have more rules.
    def create_policy_bandwidth_limit_rule(self, context, policy_id,
                                           bandwidth_limit_rule):
        #TODO(QoS): avoid creation of severan bandwidth limit rules
        #           in the future we need an inter-rule validation
        #           mechanism to verify all created rules will
        #           play well together.
        rule = rule_object.QosBandwidthLimitRule(
            context, qos_policy_id=policy_id,
            **bandwidth_limit_rule['bandwidth_limit_rule'])
        rule.create()
        return rule

    def update_policy_bandwidth_limit_rule(self, context, rule_id, policy_id,
                                           bandwidth_limit_rule):
        rule = rule_object.QosBandwidthLimitRule(
            context, **bandwidth_limit_rule['bandwidth_limit_rule'])
        rule.id = rule_id
        rule.update()
        return rule

    def delete_policy_bandwidth_limit_rule(self, context, rule_id, policy_id):
        rule = rule_object.QosBandwidthLimitRule()
        rule.id = rule_id
        rule.delete()

    def get_policy_bandwidth_limit_rule(self, context, rule_id,
                                        policy_id, fields=None):
        #TODO(QoS): Support the fields parameter
        return rule_object.QosBandwidthLimitRule.get_by_id(context,
                                                           rule_id).to_dict()

    def get_policy_bandwidth_limit_rules(self, context, policy_id,
                                         filters=None, fields=None,
                                         sorts=None, limit=None,
                                         marker=None, page_reverse=False):
        #TODO(QoS): Support all the optional parameters
        return [rule_obj.to_dict() for rule_obj in
                rule_object.QosBandwidthLimitRule.get_objects(context)]

    def get_rule_types(self, context, filters=None, fields=None,
                       sorts=None, limit=None,
                       marker=None, page_reverse=False):
        pass
