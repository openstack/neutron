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

from neutron_lib.api.definitions import qos as qos_apidef
from neutron_lib.callbacks import events as callbacks_events
from neutron_lib.callbacks import registry as callbacks_registry
from neutron_lib.callbacks import resources as callbacks_resources
from neutron_lib import exceptions as lib_exc
from neutron_lib.services.qos import constants as qos_consts

from neutron.common import exceptions as n_exc
from neutron.db import api as db_api
from neutron.db import db_base_plugin_common
from neutron.extensions import qos
from neutron.objects import base as base_obj
from neutron.objects import network as network_object
from neutron.objects import ports as ports_object
from neutron.objects.qos import policy as policy_object
from neutron.objects.qos import qos_policy_validator as checker
from neutron.objects.qos import rule_type as rule_type_object
from neutron.services.qos.drivers import manager


class QoSPlugin(qos.QoSPluginBase):
    """Implementation of the Neutron QoS Service Plugin.

    This class implements a Quality of Service plugin that provides quality of
    service parameters over ports and networks.

    """
    supported_extension_aliases = [qos_apidef.ALIAS,
                                   'qos-bw-limit-direction',
                                   'qos-default',
                                   'qos-rule-type-details']

    __native_pagination_support = True
    __native_sorting_support = True

    def __init__(self):
        super(QoSPlugin, self).__init__()
        self.driver_manager = manager.QosServiceDriverManager()

        callbacks_registry.subscribe(
            self._validate_create_port_callback,
            callbacks_resources.PORT,
            callbacks_events.PRECOMMIT_CREATE)
        callbacks_registry.subscribe(
            self._validate_update_port_callback,
            callbacks_resources.PORT,
            callbacks_events.PRECOMMIT_UPDATE)
        callbacks_registry.subscribe(
            self._validate_update_network_callback,
            callbacks_resources.NETWORK,
            callbacks_events.PRECOMMIT_UPDATE)

    def _get_ports_with_policy(self, context, policy):
        networks_ids = policy.get_bound_networks()
        ports_with_net_policy = ports_object.Port.get_objects(
            context, network_id=networks_ids)

        # Filter only this ports which don't have overwritten policy
        ports_with_net_policy = [
            port for port in ports_with_net_policy if
            port.qos_policy_id is None
        ]

        ports_ids = policy.get_bound_ports()
        ports_with_policy = ports_object.Port.get_objects(
            context, id=ports_ids)
        return list(set(ports_with_policy + ports_with_net_policy))

    def _validate_create_port_callback(self, resource, event, trigger,
                                       **kwargs):
        context = kwargs['context']
        port_id = kwargs['port']['id']
        port = ports_object.Port.get_object(context, id=port_id)
        network = network_object.Network.get_object(context,
                                                    id=port.network_id)

        policy_id = port.qos_policy_id or network.qos_policy_id
        if policy_id is None:
            return

        policy = policy_object.QosPolicy.get_object(
            context.elevated(), id=policy_id)
        self.validate_policy_for_port(policy, port)

    def _validate_update_port_callback(self, resource, event, trigger,
                                       payload=None):
        context = payload.context
        original_policy_id = payload.states[0].get(
            qos_consts.QOS_POLICY_ID)
        policy_id = payload.desired_state.get(qos_consts.QOS_POLICY_ID)

        if policy_id is None or policy_id == original_policy_id:
            return

        updated_port = ports_object.Port.get_object(
            context, id=payload.desired_state['id'])
        policy = policy_object.QosPolicy.get_object(
            context.elevated(), id=policy_id)

        self.validate_policy_for_port(policy, updated_port)

    def _validate_update_network_callback(self, resource, event, trigger,
                                          payload=None):
        context = payload.context
        original_network = payload.states[0]
        updated_network = payload.desired_state

        original_policy_id = original_network.get(qos_consts.QOS_POLICY_ID)
        policy_id = updated_network.get(qos_consts.QOS_POLICY_ID)

        if policy_id is None or policy_id == original_policy_id:
            return

        policy = policy_object.QosPolicy.get_object(
            context.elevated(), id=policy_id)
        ports = ports_object.Port.get_objects(
                context, network_id=updated_network['id'])
        # Filter only this ports which don't have overwritten policy
        ports = [
            port for port in ports if port.qos_policy_id is None
        ]
        self.validate_policy_for_ports(policy, ports)

    def validate_policy(self, context, policy):
        ports = self._get_ports_with_policy(context, policy)
        self.validate_policy_for_ports(policy, ports)

    def validate_policy_for_ports(self, policy, ports):
        for port in ports:
            self.validate_policy_for_port(policy, port)

    def validate_policy_for_port(self, policy, port):
        for rule in policy.rules:
            if not self.driver_manager.validate_rule_for_port(rule, port):
                raise n_exc.QosRuleNotSupported(rule_type=rule.rule_type,
                                                port_id=port['id'])

    @db_base_plugin_common.convert_result_to_dict
    def create_policy(self, context, policy):
        """Create a QoS policy.

        :param context: neutron api request context
        :type context: neutron_lib.context.Context
        :param policy: policy data to be applied
        :type policy: dict

        :returns: a QosPolicy object
        """
        # NOTE(dasm): body 'policy' contains both tenant_id and project_id
        # but only latter needs to be used to create QosPolicy object.
        # We need to remove redundant keyword.
        # This cannot be done in other place of stacktrace, because neutron
        # needs to be backward compatible.
        policy['policy'].pop('tenant_id', None)
        policy_obj = policy_object.QosPolicy(context, **policy['policy'])
        with db_api.context_manager.writer.using(context):
            policy_obj.create()
            self.driver_manager.call(qos_consts.CREATE_POLICY_PRECOMMIT,
                                     context, policy_obj)

        self.driver_manager.call(qos_consts.CREATE_POLICY, context, policy_obj)

        return policy_obj

    @db_base_plugin_common.convert_result_to_dict
    def update_policy(self, context, policy_id, policy):
        """Update a QoS policy.

        :param context: neutron api request context
        :type context: neutron.context.Context
        :param policy_id: the id of the QosPolicy to update
        :param policy_id: str uuid
        :param policy: new policy data to be applied
        :type policy: dict

        :returns: a QosPolicy object
        """
        policy_data = policy['policy']
        with db_api.context_manager.writer.using(context):
            policy_obj = self._get_policy_obj(context, policy_id)
            policy_obj.update_fields(policy_data, reset_changes=True)
            policy_obj.update()
            self.driver_manager.call(qos_consts.UPDATE_POLICY_PRECOMMIT,
                                     context, policy_obj)

        self.driver_manager.call(qos_consts.UPDATE_POLICY,
                                 context, policy_obj)

        return policy_obj

    def delete_policy(self, context, policy_id):
        """Delete a QoS policy.

        :param context: neutron api request context
        :type context: neutron.context.Context
        :param policy_id: the id of the QosPolicy to delete
        :type policy_id: str uuid

        :returns: None
        """
        with db_api.context_manager.writer.using(context):
            policy = policy_object.QosPolicy(context)
            policy.id = policy_id
            policy.delete()
            self.driver_manager.call(qos_consts.DELETE_POLICY_PRECOMMIT,
                                     context, policy)

        self.driver_manager.call(qos_consts.DELETE_POLICY,
                                 context, policy)

    def _get_policy_obj(self, context, policy_id):
        """Fetch a QoS policy.

        :param context: neutron api request context
        :type context: neutron.context.Context
        :param policy_id: the id of the QosPolicy to fetch
        :type policy_id: str uuid

        :returns: a QosPolicy object
        :raises: n_exc.QosPolicyNotFound
        """
        obj = policy_object.QosPolicy.get_object(context, id=policy_id)
        if obj is None:
            raise n_exc.QosPolicyNotFound(policy_id=policy_id)
        return obj

    @db_base_plugin_common.filter_fields
    @db_base_plugin_common.convert_result_to_dict
    def get_policy(self, context, policy_id, fields=None):
        """Get a QoS policy.

        :param context: neutron api request context
        :type context: neutron.context.Context
        :param policy_id: the id of the QosPolicy to update
        :type policy_id: str uuid

        :returns: a QosPolicy object
        """
        return self._get_policy_obj(context, policy_id)

    @db_base_plugin_common.filter_fields
    @db_base_plugin_common.convert_result_to_dict
    def get_policies(self, context, filters=None, fields=None, sorts=None,
                     limit=None, marker=None, page_reverse=False):
        """Get QoS policies.

        :param context: neutron api request context
        :type context: neutron.context.Context
        :param filters: search criteria
        :type filters: dict

        :returns: QosPolicy objects meeting the search criteria
        """
        filters = filters or dict()
        pager = base_obj.Pager(sorts, limit, page_reverse, marker)
        return policy_object.QosPolicy.get_objects(context, _pager=pager,
                                                   **filters)

    @db_base_plugin_common.filter_fields
    @db_base_plugin_common.convert_result_to_dict
    def get_rule_type(self, context, rule_type_name, fields=None):
        if not context.is_admin:
            raise lib_exc.NotAuthorized()
        return rule_type_object.QosRuleType.get_object(rule_type_name)

    @db_base_plugin_common.filter_fields
    @db_base_plugin_common.convert_result_to_dict
    def get_rule_types(self, context, filters=None, fields=None,
                       sorts=None, limit=None,
                       marker=None, page_reverse=False):
        if not filters:
            filters = {}
        return rule_type_object.QosRuleType.get_objects(**filters)

    def supported_rule_type_details(self, rule_type_name):
        return self.driver_manager.supported_rule_type_details(rule_type_name)

    @property
    def supported_rule_types(self):
        return self.driver_manager.supported_rule_types

    @db_base_plugin_common.convert_result_to_dict
    def create_policy_rule(self, context, rule_cls, policy_id, rule_data):
        """Create a QoS policy rule.

        :param context: neutron api request context
        :type context: neutron.context.Context
        :param rule_cls: the rule object class
        :type rule_cls: a class from the rule_object (qos.objects.rule) module
        :param policy_id: the id of the QosPolicy for which to create the rule
        :type policy_id: str uuid
        :param rule_data: the rule data to be applied
        :type rule_data: dict

        :returns: a QoS policy rule object
        """
        rule_type = rule_cls.rule_type
        rule_data = rule_data[rule_type + '_rule']

        with db_api.autonested_transaction(context.session):
            # Ensure that we have access to the policy.
            policy = self._get_policy_obj(context, policy_id)
            checker.check_bandwidth_rule_conflict(policy, rule_data)
            rule = rule_cls(context, qos_policy_id=policy_id, **rule_data)
            checker.check_rules_conflict(policy, rule)
            rule.create()
            policy.obj_load_attr('rules')
            self.validate_policy(context, policy)
            self.driver_manager.call(qos_consts.UPDATE_POLICY_PRECOMMIT,
                                     context, policy)

        self.driver_manager.call(qos_consts.UPDATE_POLICY, context, policy)

        return rule

    @db_base_plugin_common.convert_result_to_dict
    def update_policy_rule(self, context, rule_cls, rule_id, policy_id,
            rule_data):
        """Update a QoS policy rule.

        :param context: neutron api request context
        :type context: neutron.context.Context
        :param rule_cls: the rule object class
        :type rule_cls: a class from the rule_object (qos.objects.rule) module
        :param rule_id: the id of the QoS policy rule to update
        :type rule_id: str uuid
        :param policy_id: the id of the rule's policy
        :type policy_id: str uuid
        :param rule_data: the new rule data to update
        :type rule_data: dict

        :returns: a QoS policy rule object
        """
        rule_type = rule_cls.rule_type
        rule_data = rule_data[rule_type + '_rule']

        with db_api.autonested_transaction(context.session):
            # Ensure we have access to the policy.
            policy = self._get_policy_obj(context, policy_id)
            # Ensure the rule belongs to the policy.
            checker.check_bandwidth_rule_conflict(policy, rule_data)
            rule = policy.get_rule_by_id(rule_id)
            rule.update_fields(rule_data, reset_changes=True)
            checker.check_rules_conflict(policy, rule)
            rule.update()
            policy.obj_load_attr('rules')
            self.validate_policy(context, policy)
            self.driver_manager.call(qos_consts.UPDATE_POLICY_PRECOMMIT,
                                     context, policy)

        self.driver_manager.call(qos_consts.UPDATE_POLICY, context, policy)

        return rule

    def delete_policy_rule(self, context, rule_cls, rule_id, policy_id):
        """Delete a QoS policy rule.

        :param context: neutron api request context
        :type context: neutron.context.Context
        :param rule_cls: the rule object class
        :type rule_cls: a class from the rule_object (qos.objects.rule) module
        :param rule_id: the id of the QosPolicy Rule to delete
        :type rule_id: str uuid
        :param policy_id: the id of the rule's policy
        :type policy_id: str uuid

        :returns: None
        """
        with db_api.autonested_transaction(context.session):
            # Ensure we have access to the policy.
            policy = self._get_policy_obj(context, policy_id)
            rule = policy.get_rule_by_id(rule_id)
            rule.delete()
            policy.obj_load_attr('rules')
            self.driver_manager.call(qos_consts.UPDATE_POLICY_PRECOMMIT,
                                     context, policy)

        self.driver_manager.call(qos_consts.UPDATE_POLICY, context, policy)

    @db_base_plugin_common.filter_fields
    @db_base_plugin_common.convert_result_to_dict
    def get_policy_rule(self, context, rule_cls, rule_id, policy_id,
                        fields=None):
        """Get a QoS policy rule.

        :param context: neutron api request context
        :type context: neutron.context.Context
        :param rule_cls: the rule object class
        :type rule_cls: a class from the rule_object (qos.objects.rule) module
        :param rule_id: the id of the QoS policy rule to get
        :type rule_id: str uuid
        :param policy_id: the id of the rule's policy
        :type policy_id: str uuid

        :returns: a QoS policy rule object
        :raises: n_exc.QosRuleNotFound
        """
        with db_api.autonested_transaction(context.session):
            # Ensure we have access to the policy.
            self._get_policy_obj(context, policy_id)
            rule = rule_cls.get_object(context, id=rule_id)
        if not rule:
            raise n_exc.QosRuleNotFound(policy_id=policy_id, rule_id=rule_id)
        return rule

    # TODO(QoS): enforce rule types when accessing rule objects
    @db_base_plugin_common.filter_fields
    @db_base_plugin_common.convert_result_to_dict
    def get_policy_rules(self, context, rule_cls, policy_id, filters=None,
                         fields=None, sorts=None, limit=None, marker=None,
                         page_reverse=False):
        """Get QoS policy rules.

        :param context: neutron api request context
        :type context: neutron.context.Context
        :param rule_cls: the rule object class
        :type rule_cls: a class from the rule_object (qos.objects.rule) module
        :param policy_id: the id of the QosPolicy for which to get rules
        :type policy_id: str uuid

        :returns: QoS policy rule objects meeting the search criteria
        """
        with db_api.autonested_transaction(context.session):
            # Ensure we have access to the policy.
            self._get_policy_obj(context, policy_id)
            filters = filters or dict()
            filters[qos_consts.QOS_POLICY_ID] = policy_id
            pager = base_obj.Pager(sorts, limit, page_reverse, marker)
            return rule_cls.get_objects(context, _pager=pager, **filters)
