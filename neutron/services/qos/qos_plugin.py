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

from neutron_lib.api.definitions import port as port_def
from neutron_lib.api.definitions import port_resource_request
from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import qos as qos_apidef
from neutron_lib.api.definitions import qos_bw_limit_direction
from neutron_lib.api.definitions import qos_bw_minimum_ingress
from neutron_lib.api.definitions import qos_default
from neutron_lib.api.definitions import qos_rule_type_details
from neutron_lib.api.definitions import qos_rules_alias
from neutron_lib.callbacks import events as callbacks_events
from neutron_lib.callbacks import registry as callbacks_registry
from neutron_lib.callbacks import resources as callbacks_resources
from neutron_lib import constants as nl_constants
from neutron_lib import context
from neutron_lib.db import api as db_api
from neutron_lib.db import resource_extend
from neutron_lib import exceptions as lib_exc
from neutron_lib.exceptions import qos as qos_exc
from neutron_lib.placement import constants as pl_constants
from neutron_lib.placement import utils as pl_utils
from neutron_lib.services.qos import constants as qos_consts

from neutron._i18n import _
from neutron.db import db_base_plugin_common
from neutron.extensions import qos
from neutron.objects import base as base_obj
from neutron.objects import network as network_object
from neutron.objects import ports as ports_object
from neutron.objects.qos import policy as policy_object
from neutron.objects.qos import qos_policy_validator as checker
from neutron.objects.qos import rule as rule_object
from neutron.objects.qos import rule_type as rule_type_object
from neutron.services.qos.drivers import manager


@resource_extend.has_resource_extenders
class QoSPlugin(qos.QoSPluginBase):
    """Implementation of the Neutron QoS Service Plugin.

    This class implements a Quality of Service plugin that provides quality of
    service parameters over ports and networks.

    """
    supported_extension_aliases = [qos_apidef.ALIAS,
                                   qos_bw_limit_direction.ALIAS,
                                   qos_default.ALIAS,
                                   qos_rule_type_details.ALIAS,
                                   port_resource_request.ALIAS,
                                   qos_bw_minimum_ingress.ALIAS,
                                   qos_rules_alias.ALIAS]

    __native_pagination_support = True
    __native_sorting_support = True
    __filter_validation_support = True

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

    @staticmethod
    @resource_extend.extends([port_def.COLLECTION_NAME])
    def _extend_port_resource_request(port_res, port_db):
        """Add resource request to a port."""
        if isinstance(port_db, ports_object.Port):
            qos_id = port_db.qos_policy_id or port_db.qos_network_policy_id
        else:
            qos_id = None
            if port_db.get('qos_policy_binding'):
                qos_id = port_db.qos_policy_binding.policy_id
            elif port_db.get('qos_network_policy_binding'):
                qos_id = port_db.qos_network_policy_binding.policy_id

        port_res['resource_request'] = None
        if not qos_id:
            return port_res

        resources = {}
        # NOTE(ralonsoh): we should move this translation dict to n-lib.
        rule_direction_class = {
            nl_constants.INGRESS_DIRECTION:
                pl_constants.CLASS_NET_BW_INGRESS_KBPS,
            nl_constants.EGRESS_DIRECTION:
                pl_constants.CLASS_NET_BW_EGRESS_KBPS
        }
        min_bw_rules = rule_object.QosMinimumBandwidthRule.get_objects(
            context.get_admin_context(), qos_policy_id=qos_id)
        for rule in min_bw_rules:
            resources[rule_direction_class[rule.direction]] = rule.min_kbps
        if not resources:
            return port_res

        # NOTE(ralonsoh): we should not rely on the current execution order of
        # the port extending functions. Although here we have
        # port_res[VNIC_TYPE], we should retrieve this value from the port DB
        # object instead.
        vnic_trait = pl_utils.vnic_type_trait(
            port_res[portbindings.VNIC_TYPE])

        # TODO(lajoskatona): Change to handle all segments when any traits
        # support will be available. See Placement spec:
        # https://review.opendev.org/565730
        first_segment = network_object.NetworkSegment.get_objects(
            context.get_admin_context(), network_id=port_db.network_id)[0]

        if not first_segment or not first_segment.physical_network:
            return port_res
        physnet_trait = pl_utils.physnet_trait(
            first_segment.physical_network)

        port_res['resource_request'] = {
            'required': [physnet_trait, vnic_trait],
            'resources': resources}
        return port_res

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

        policy_id = port.qos_policy_id or port.qos_network_policy_id
        if policy_id is None:
            return

        policy = policy_object.QosPolicy.get_object(
            context.elevated(), id=policy_id)
        self.validate_policy_for_port(context, policy, port)

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

        self.validate_policy_for_port(context, policy, updated_port)

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
        self.validate_policy_for_ports(context, policy, ports)

    def validate_policy(self, context, policy):
        ports = self._get_ports_with_policy(context, policy)
        self.validate_policy_for_ports(context, policy, ports)

    def validate_policy_for_ports(self, context, policy, ports):
        for port in ports:
            self.validate_policy_for_port(context, policy, port)

    def validate_policy_for_port(self, context, policy, port):
        for rule in policy.rules:
            if not self.driver_manager.validate_rule_for_port(rule, port):
                raise qos_exc.QosRuleNotSupported(rule_type=rule.rule_type,
                                                  port_id=port['id'])
            # minimum-bandwidth rule is only supported (independently of
            # drivers) on networks whose first segment is backed by a physnet
            if rule.rule_type == qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH:
                net = network_object.Network.get_object(
                    context, id=port.network_id)
                physnet = net.segments[0].physical_network
                if physnet is None:
                    raise qos_exc.QosRuleNotSupported(rule_type=rule.rule_type,
                                                      port_id=port['id'])

    def reject_min_bw_rule_updates(self, context, policy):
        ports = self._get_ports_with_policy(context, policy)
        for port in ports:
            # NOTE(bence romsics): In some cases the presence of
            # 'binding:profile.allocation' is a more precise marker than
            # 'device_owner' about when we have to reject min-bw related
            # policy/rule updates. However 'binding:profile.allocation' cannot
            # be used in a generic way here. Consider the case when the first
            # min-bw rule is added to a policy having ports in-use. Those ports
            # will not have 'binding:profile.allocation', but this policy
            # update must be rejected.
            if (port.device_owner is not None and
                    port.device_owner.startswith(
                        nl_constants.DEVICE_OWNER_COMPUTE_PREFIX)):
                raise NotImplementedError(_(
                    'Cannot update QoS policies/rules backed by resources '
                    'tracked in Placement'))

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
        tenant_id = policy['policy'].pop('tenant_id', None)
        if not policy['policy'].get('project_id'):
            policy['policy']['project_id'] = tenant_id
        policy_obj = policy_object.QosPolicy(context, **policy['policy'])
        with db_api.CONTEXT_WRITER.using(context):
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
        with db_api.CONTEXT_WRITER.using(context):
            policy_obj = policy_object.QosPolicy.get_policy_obj(
                context, policy_id)
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
        with db_api.CONTEXT_WRITER.using(context):
            policy = policy_object.QosPolicy(context)
            policy.id = policy_id
            policy.delete()
            self.driver_manager.call(qos_consts.DELETE_POLICY_PRECOMMIT,
                                     context, policy)

        self.driver_manager.call(qos_consts.DELETE_POLICY,
                                 context, policy)

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
        return policy_object.QosPolicy.get_policy_obj(context, policy_id)

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

        with db_api.CONTEXT_WRITER.using(context):
            # Ensure that we have access to the policy.
            policy = policy_object.QosPolicy.get_policy_obj(context, policy_id)
            checker.check_bandwidth_rule_conflict(policy, rule_data)
            rule = rule_cls(context, qos_policy_id=policy_id, **rule_data)
            checker.check_rules_conflict(policy, rule)
            rule.create()
            policy.obj_load_attr('rules')
            self.validate_policy(context, policy)
            if rule.rule_type == qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH:
                self.reject_min_bw_rule_updates(context, policy)
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

        with db_api.CONTEXT_WRITER.using(context):
            # Ensure we have access to the policy.
            policy = policy_object.QosPolicy.get_policy_obj(context, policy_id)
            # Ensure the rule belongs to the policy.
            checker.check_bandwidth_rule_conflict(policy, rule_data)
            rule = policy.get_rule_by_id(rule_id)
            rule.update_fields(rule_data, reset_changes=True)
            checker.check_rules_conflict(policy, rule)
            rule.update()
            policy.obj_load_attr('rules')
            self.validate_policy(context, policy)
            if rule.rule_type == qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH:
                self.reject_min_bw_rule_updates(context, policy)
            self.driver_manager.call(qos_consts.UPDATE_POLICY_PRECOMMIT,
                                     context, policy)

        self.driver_manager.call(qos_consts.UPDATE_POLICY, context, policy)

        return rule

    def _get_policy_id(self, context, rule_cls, rule_id):
        with db_api.autonested_transaction(context.session):
            rule_object = rule_cls.get_object(context, id=rule_id)
            if not rule_object:
                raise qos_exc.QosRuleNotFound(policy_id="", rule_id=rule_id)
        return rule_object.qos_policy_id

    def update_rule(self, context, rule_cls, rule_id, rule_data):
        """Update a QoS policy rule alias. This method processes a QoS policy
        rule update, where the rule is an API first level resource instead of a
        subresource of a policy.

        :param context: neutron api request context
        :type context: neutron.context.Context
        :param rule_cls: the rule object class
        :type rule_cls: a class from the rule_object (qos.objects.rule) module
        :param rule_id: the id of the QoS policy rule to update
        :type rule_id: str uuid
        :param rule_data: the new rule data to update
        :type rule_data: dict

        :returns: a QoS policy rule object
        :raises: qos_exc.QosRuleNotFound
        """
        policy_id = self._get_policy_id(context, rule_cls, rule_id)
        rule_data_name = rule_cls.rule_type + '_rule'
        alias_rule_data_name = 'alias_' + rule_data_name
        rule_data[rule_data_name] = rule_data.pop(alias_rule_data_name)
        return self.update_policy_rule(context, rule_cls, rule_id, policy_id,
                                       rule_data)

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
        with db_api.CONTEXT_WRITER.using(context):
            # Ensure we have access to the policy.
            policy = policy_object.QosPolicy.get_policy_obj(context, policy_id)
            rule = policy.get_rule_by_id(rule_id)
            rule.delete()
            policy.obj_load_attr('rules')
            if rule.rule_type == qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH:
                self.reject_min_bw_rule_updates(context, policy)
            self.driver_manager.call(qos_consts.UPDATE_POLICY_PRECOMMIT,
                                     context, policy)

        self.driver_manager.call(qos_consts.UPDATE_POLICY, context, policy)

    def delete_rule(self, context, rule_cls, rule_id):
        """Delete a QoS policy rule alias. This method processes a QoS policy
        rule delete, where the rule is an API first level resource instead of a
        subresource of a policy.

        :param context: neutron api request context
        :type context: neutron.context.Context
        :param rule_cls: the rule object class
        :type rule_cls: a class from the rule_object (qos.objects.rule) module
        :param rule_id: the id of the QosPolicy Rule to delete
        :type rule_id: str uuid

        :returns: None
        :raises: qos_exc.QosRuleNotFound
        """
        policy_id = self._get_policy_id(context, rule_cls, rule_id)
        return self.delete_policy_rule(context, rule_cls, rule_id, policy_id)

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
        :raises: qos_exc.QosRuleNotFound
        """
        with db_api.CONTEXT_READER.using(context):
            # Ensure we have access to the policy.
            policy_object.QosPolicy.get_policy_obj(context, policy_id)
            rule = rule_cls.get_object(context, id=rule_id)
        if not rule:
            raise qos_exc.QosRuleNotFound(policy_id=policy_id, rule_id=rule_id)
        return rule

    def get_rule(self, context, rule_cls, rule_id, fields=None):
        """Get a QoS policy rule alias. This method processes a QoS policy
        rule get, where the rule is an API first level resource instead of a
        subresource of a policy

        :param context: neutron api request context
        :type context: neutron.context.Context
        :param rule_cls: the rule object class
        :type rule_cls: a class from the rule_object (qos.objects.rule) module
        :param rule_id: the id of the QoS policy rule to get
        :type rule_id: str uuid

        :returns: a QoS policy rule object
        :raises: qos_exc.QosRuleNotFound
        """
        policy_id = self._get_policy_id(context, rule_cls, rule_id)
        return self.get_policy_rule(context, rule_cls, rule_id, policy_id)

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
        with db_api.CONTEXT_READER.using(context):
            # Ensure we have access to the policy.
            policy_object.QosPolicy.get_policy_obj(context, policy_id)
            filters = filters or dict()
            filters[qos_consts.QOS_POLICY_ID] = policy_id
            pager = base_obj.Pager(sorts, limit, page_reverse, marker)
            return rule_cls.get_objects(context, _pager=pager, **filters)
