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

from neutron.common import exceptions as n_exc
from neutron.db import api as db_api
from neutron.db import db_base_plugin_common
from neutron.extensions import qos
from neutron.objects.qos import policy as policy_object
from neutron.objects.qos import rule as rule_object
from neutron.objects.qos import rule_type as rule_type_object
from neutron.services.qos.notification_drivers import manager as driver_mgr
from neutron.services.qos import qos_consts


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
        self.notification_driver_manager.create_policy(context, policy)
        return policy

    @db_base_plugin_common.convert_result_to_dict
    def update_policy(self, context, policy_id, policy):
        obj = policy_object.QosPolicy(context, id=policy_id)
        obj.obj_reset_changes()
        for k, v in policy['policy'].items():
            if k != 'id':
                setattr(obj, k, v)
        obj.update()
        self.notification_driver_manager.update_policy(context, obj)
        return obj

    def delete_policy(self, context, policy_id):
        policy = policy_object.QosPolicy(context)
        policy.id = policy_id
        self.notification_driver_manager.delete_policy(context, policy)
        policy.delete()

    def _get_policy_obj(self, context, policy_id):
        obj = policy_object.QosPolicy.get_object(context, id=policy_id)
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
        return policy_object.QosPolicy.get_objects(context, **filters)

    #TODO(QoS): Consider adding a proxy catch-all for rules, so
    #           we capture the API function call, and just pass
    #           the rule type as a parameter removing lots of
    #           future code duplication when we have more rules.
    @db_base_plugin_common.convert_result_to_dict
    def create_policy_bandwidth_limit_rule(self, context, policy_id,
                                           bandwidth_limit_rule):
        # make sure we will have a policy object to push resource update
        with db_api.autonested_transaction(context.session):
            # first, validate that we have access to the policy
            policy = self._get_policy_obj(context, policy_id)
            rule = rule_object.QosBandwidthLimitRule(
                context, qos_policy_id=policy_id,
                **bandwidth_limit_rule['bandwidth_limit_rule'])
            rule.create()
            policy.reload_rules()
        self.notification_driver_manager.update_policy(context, policy)
        return rule

    @db_base_plugin_common.convert_result_to_dict
    def update_policy_bandwidth_limit_rule(self, context, rule_id, policy_id,
                                           bandwidth_limit_rule):
        # make sure we will have a policy object to push resource update
        with db_api.autonested_transaction(context.session):
            # first, validate that we have access to the policy
            policy = self._get_policy_obj(context, policy_id)
            # check if the rule belong to the policy
            policy.get_rule_by_id(rule_id)
            rule = rule_object.QosBandwidthLimitRule(
                context, id=rule_id)
            rule.obj_reset_changes()
            for k, v in bandwidth_limit_rule['bandwidth_limit_rule'].items():
                if k != 'id':
                    setattr(rule, k, v)
            rule.update()
            policy.reload_rules()
        self.notification_driver_manager.update_policy(context, policy)
        return rule

    def delete_policy_bandwidth_limit_rule(self, context, rule_id, policy_id):
        # make sure we will have a policy object to push resource update
        with db_api.autonested_transaction(context.session):
            # first, validate that we have access to the policy
            policy = self._get_policy_obj(context, policy_id)
            rule = policy.get_rule_by_id(rule_id)
            rule.delete()
            policy.reload_rules()
        self.notification_driver_manager.update_policy(context, policy)

    @db_base_plugin_common.filter_fields
    @db_base_plugin_common.convert_result_to_dict
    def get_policy_bandwidth_limit_rule(self, context, rule_id,
                                        policy_id, fields=None):
        # make sure we have access to the policy when fetching the rule
        with db_api.autonested_transaction(context.session):
            # first, validate that we have access to the policy
            self._get_policy_obj(context, policy_id)
            rule = rule_object.QosBandwidthLimitRule.get_object(
                context, id=rule_id)
        if not rule:
            raise n_exc.QosRuleNotFound(policy_id=policy_id, rule_id=rule_id)
        return rule

    @db_base_plugin_common.filter_fields
    @db_base_plugin_common.convert_result_to_dict
    def get_policy_bandwidth_limit_rules(self, context, policy_id,
                                         filters=None, fields=None,
                                         sorts=None, limit=None,
                                         marker=None, page_reverse=False):
        # make sure we have access to the policy when fetching rules
        with db_api.autonested_transaction(context.session):
            # first, validate that we have access to the policy
            self._get_policy_obj(context, policy_id)
            filters = filters or dict()
            filters[qos_consts.QOS_POLICY_ID] = policy_id
            return rule_object.QosBandwidthLimitRule.get_objects(context,
                                                                 **filters)

    # TODO(QoS): enforce rule types when accessing rule objects
    @db_base_plugin_common.filter_fields
    @db_base_plugin_common.convert_result_to_dict
    def get_rule_types(self, context, filters=None, fields=None,
                       sorts=None, limit=None,
                       marker=None, page_reverse=False):
        return rule_type_object.QosRuleType.get_objects(**filters)
