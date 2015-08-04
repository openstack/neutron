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
from oslo_log import log as logging


from neutron.common import exceptions as n_exc
from neutron.db import db_base_plugin_common
from neutron.extensions import qos
from neutron.objects.qos import policy as policy_object
from neutron.objects.qos import rule as rule_object
from neutron.objects.qos import rule_type as rule_type_object
from neutron.services.qos.notification_drivers import manager as driver_mgr


LOG = logging.getLogger(__name__)


class QoSPlugin(qos.QoSPluginBase):
    """Implementation of the Neutron QoS Service Plugin.

    This class implements a Quality of Service plugin that
    provides quality of service parameters over ports and
    networks.

    """
    supported_extension_aliases = ['qos']

    def __init__(self):
        super(QoSPlugin, self).__init__()
        self.notification_driver_manager = (
            driver_mgr.QosServiceNotificationDriverManager())

    @db_base_plugin_common.convert_result_to_dict
    def create_policy(self, context, policy):
        policy = policy_object.QosPolicy(context, **policy['policy'])
        policy.create()
        self.notification_driver_manager.create_policy(policy)
        return policy

    @db_base_plugin_common.convert_result_to_dict
    def update_policy(self, context, policy_id, policy):
        policy = policy_object.QosPolicy(context, **policy['policy'])
        policy.id = policy_id
        policy.update()
        self.notification_driver_manager.update_policy(policy)
        return policy

    def delete_policy(self, context, policy_id):
        policy = policy_object.QosPolicy(context)
        policy.id = policy_id
        self.notification_driver_manager.delete_policy(policy)
        policy.delete()

    def _get_policy_obj(self, context, policy_id):
        obj = policy_object.QosPolicy.get_by_id(context, policy_id)
        if obj is None:
            raise n_exc.QosPolicyNotFound(policy_id=policy_id)
        return obj

    @db_base_plugin_common.filter_fields
    @db_base_plugin_common.convert_result_to_dict
    def get_policy(self, context, policy_id, fields=None):
        return self._get_policy_obj(context, policy_id)

    @db_base_plugin_common.filter_fields
    @db_base_plugin_common.convert_result_to_dict
    def get_policies(self, context, filters=None, fields=None,
                     sorts=None, limit=None, marker=None,
                     page_reverse=False):
        #TODO(QoS): Support all the optional parameters
        return policy_object.QosPolicy.get_objects(context)

    #TODO(QoS): Consider adding a proxy catch-all for rules, so
    #           we capture the API function call, and just pass
    #           the rule type as a parameter removing lots of
    #           future code duplication when we have more rules.
    @db_base_plugin_common.convert_result_to_dict
    def create_policy_bandwidth_limit_rule(self, context, policy_id,
                                           bandwidth_limit_rule):
        # validate that we have access to the policy
        policy = self._get_policy_obj(context, policy_id)
        rule = rule_object.QosBandwidthLimitRule(
            context, qos_policy_id=policy_id,
            **bandwidth_limit_rule['bandwidth_limit_rule'])
        rule.create()
        self.notification_driver_manager.update_policy(policy)
        return rule

    @db_base_plugin_common.convert_result_to_dict
    def update_policy_bandwidth_limit_rule(self, context, rule_id, policy_id,
                                           bandwidth_limit_rule):
        # validate that we have access to the policy
        policy = self._get_policy_obj(context, policy_id)
        rule = rule_object.QosBandwidthLimitRule(
            context, **bandwidth_limit_rule['bandwidth_limit_rule'])
        rule.id = rule_id
        rule.update()
        self.notification_driver_manager.update_policy(policy)
        return rule

    def delete_policy_bandwidth_limit_rule(self, context, rule_id, policy_id):
        # validate that we have access to the policy
        policy = self._get_policy_obj(context, policy_id)
        rule = rule_object.QosBandwidthLimitRule(context)
        rule.id = rule_id
        rule.delete()
        self.notification_driver_manager.update_policy(policy)

    @db_base_plugin_common.filter_fields
    @db_base_plugin_common.convert_result_to_dict
    def get_policy_bandwidth_limit_rule(self, context, rule_id,
                                        policy_id, fields=None):
        # validate that we have access to the policy
        self._get_policy_obj(context, policy_id)
        rule = rule_object.QosBandwidthLimitRule.get_by_id(context, rule_id)
        if not rule:
            raise n_exc.QosRuleNotFound(policy_id=policy_id, rule_id=rule_id)
        return rule

    @db_base_plugin_common.filter_fields
    @db_base_plugin_common.convert_result_to_dict
    def get_policy_bandwidth_limit_rules(self, context, policy_id,
                                         filters=None, fields=None,
                                         sorts=None, limit=None,
                                         marker=None, page_reverse=False):
        #TODO(QoS): Support all the optional parameters
        # validate that we have access to the policy
        self._get_policy_obj(context, policy_id)
        return rule_object.QosBandwidthLimitRule.get_objects(context)

    @db_base_plugin_common.filter_fields
    @db_base_plugin_common.convert_result_to_dict
    def get_rule_types(self, context, filters=None, fields=None,
                       sorts=None, limit=None,
                       marker=None, page_reverse=False):
        return rule_type_object.QosRuleType.get_objects()
