# Copyright (c) 2017-18 NEC Technologies India Pvt Ltd.
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

from neutron_lib.services.qos import constants as qos_consts

from neutron.common import exceptions as n_exc


def check_bandwidth_rule_conflict(policy, rule_data):
    """Implementation of the QoS Rule checker.

    This function checks if the new rule to be associated with the policy
    doesn't conflict with the existing rules.
    Raises an exception if conflict is identified.
    """
    for rule in policy.rules:
        if rule.rule_type == qos_consts.RULE_TYPE_DSCP_MARKING:
            # Skip checks if Rule is DSCP
            continue
        elif rule.rule_type == qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH:
            if "max_kbps" in rule_data and (
                    int(rule.min_kbps) > int(rule_data["max_kbps"])):
                raise n_exc.QoSRuleParameterConflict(
                    rule_value=rule_data["max_kbps"],
                    policy_id=policy["id"],
                    existing_rule=rule.rule_type,
                    existing_value=rule.min_kbps)
        elif rule.rule_type == qos_consts.RULE_TYPE_BANDWIDTH_LIMIT:
            if "min_kbps" in rule_data and (
                    int(rule.max_kbps) < int(rule_data["min_kbps"])):
                raise n_exc.QoSRuleParameterConflict(
                    rule_value=rule_data["min_kbps"],
                    policy_id=policy["id"],
                    existing_rule=rule.rule_type,
                    existing_value=rule.max_kbps)


def check_rules_conflict(policy, rule_obj):
    """Implementation of the QoS Policy rules conflicts.

    This function checks if the new rule to be associated with policy
    doesn't have any duplicate rule already in policy.
    Raises an exception if conflict is identified.
    """

    for rule in policy.rules:
        # NOTE(slaweq): we don't want to raise exception when compared rules
        # have got same id as it means that it is probably exactly the same
        # rule so there is no conflict
        if rule.id == getattr(rule_obj, "id", None):
            continue
        if rule.duplicates(rule_obj):
            raise n_exc.QoSRulesConflict(
                new_rule_type=rule_obj.rule_type,
                rule_id=rule.id,
                policy_id=policy.id)
