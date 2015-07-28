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
from neutron.db import db_base_plugin_common
from neutron.extensions import qos
from neutron.i18n import _LW
from neutron.objects.qos import policy as policy_object
from neutron.objects.qos import rule as rule_object
from neutron.objects.qos import rule_type as rule_type_object
from neutron.plugins.common import constants

from oslo_log import log as logging


LOG = logging.getLogger(__name__)


def _get_qos_policy_cb(resource_type, policy_id, **kwargs):
    qos_plugin = manager.NeutronManager.get_service_plugins().get(
        constants.QOS)
    context = kwargs.get('context')
    if context is None:
        LOG.warning(_LW(
            'Received %(resource_type)s %(policy_id)s without context'),
            {'resource_type': resource_type, 'policy_id': policy_id}
        )
        return

    qos_policy = qos_plugin.get_qos_policy(context, policy_id)
    return qos_policy


class QoSPlugin(qos.QoSPluginBase):
    """Implementation of the Neutron QoS Service Plugin.

    This class implements a Quality of Service plugin that
    provides quality of service parameters over ports and
    networks.

    """
    supported_extension_aliases = ['qos']

    def __init__(self):
        super(QoSPlugin, self).__init__()
        rpc_registry.register_provider(
            _get_qos_policy_cb,
            rpc_resources.QOS_POLICY)

    def create_policy(self, context, policy):
        policy = policy_object.QosPolicy(context, **policy['policy'])
        policy.create()
        return policy.to_dict()

    def update_policy(self, context, policy_id, policy):
        policy = policy_object.QosPolicy(context, **policy['policy'])
        policy.id = policy_id
        policy.update()
        return policy.to_dict()

    def delete_policy(self, context, policy_id):
        policy = policy_object.QosPolicy(context)
        policy.id = policy_id
        policy.delete()

    def _get_policy_obj(self, context, policy_id):
        return policy_object.QosPolicy.get_by_id(context, policy_id)

    @db_base_plugin_common.filter_fields
    def get_policy(self, context, policy_id, fields=None):
        return self._get_policy_obj(context, policy_id).to_dict()

    @db_base_plugin_common.filter_fields
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
        return rule.to_dict()

    def update_policy_bandwidth_limit_rule(self, context, rule_id, policy_id,
                                           bandwidth_limit_rule):
        rule = rule_object.QosBandwidthLimitRule(
            context, **bandwidth_limit_rule['bandwidth_limit_rule'])
        rule.id = rule_id
        rule.update()
        return rule.to_dict()

    def delete_policy_bandwidth_limit_rule(self, context, rule_id, policy_id):
        rule = rule_object.QosBandwidthLimitRule(context)
        rule.id = rule_id
        rule.delete()

    @db_base_plugin_common.filter_fields
    def get_policy_bandwidth_limit_rule(self, context, rule_id,
                                        policy_id, fields=None):
        return rule_object.QosBandwidthLimitRule.get_by_id(context,
                                                           rule_id).to_dict()

    @db_base_plugin_common.filter_fields
    def get_policy_bandwidth_limit_rules(self, context, policy_id,
                                         filters=None, fields=None,
                                         sorts=None, limit=None,
                                         marker=None, page_reverse=False):
        #TODO(QoS): Support all the optional parameters
        return [rule_obj.to_dict() for rule_obj in
                rule_object.QosBandwidthLimitRule.get_objects(context)]

    @db_base_plugin_common.filter_fields
    def get_rule_types(self, context, filters=None, fields=None,
                       sorts=None, limit=None,
                       marker=None, page_reverse=False):
        return [rule_type_obj.to_dict() for rule_type_obj in
                rule_type_object.QosRuleType.get_objects()]
