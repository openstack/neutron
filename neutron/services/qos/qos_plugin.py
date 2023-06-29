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

import copy
import uuid

from keystoneauth1 import exceptions as ks_exc
from neutron_lib.api.definitions import port as port_def
from neutron_lib.api.definitions import port_resource_request
from neutron_lib.api.definitions import port_resource_request_groups
from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import qos as qos_apidef
from neutron_lib.api.definitions import qos_bw_limit_direction
from neutron_lib.api.definitions import qos_bw_minimum_ingress
from neutron_lib.api.definitions import qos_default
from neutron_lib.api.definitions import qos_port_network_policy
from neutron_lib.api.definitions import qos_pps_minimum_rule
from neutron_lib.api.definitions import qos_pps_minimum_rule_alias
from neutron_lib.api.definitions import qos_pps_rule
from neutron_lib.api.definitions import qos_rule_type_details
from neutron_lib.api.definitions import qos_rule_type_filter
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
from neutron_lib.placement import client as pl_client
from neutron_lib.placement import utils as pl_utils
from neutron_lib.services.qos import constants as qos_consts
import os_resource_classes as orc
from oslo_config import cfg
from oslo_log import log as logging

from neutron._i18n import _
from neutron.common import _constants as n_const
from neutron.db import db_base_plugin_common
from neutron.exceptions import qos as neutron_qos_exc
from neutron.extensions import qos
from neutron.objects import base as base_obj
from neutron.objects import network as network_object
from neutron.objects import ports as ports_object
from neutron.objects.qos import policy as policy_object
from neutron.objects.qos import qos_policy_validator as checker
from neutron.objects.qos import rule as rule_object
from neutron.objects.qos import rule_type as rule_type_object
from neutron.services.qos.drivers import manager


LOG = logging.getLogger(__name__)


@resource_extend.has_resource_extenders
class QoSPlugin(qos.QoSPluginBase):
    """Implementation of the Neutron QoS Service Plugin.

    This class implements a Quality of Service plugin that provides quality of
    service parameters over ports and networks.

    """
    supported_extension_aliases = [
        qos_apidef.ALIAS,
        qos_bw_limit_direction.ALIAS,
        qos_default.ALIAS,
        qos_rule_type_details.ALIAS,
        qos_rule_type_filter.ALIAS,
        port_resource_request.ALIAS,
        port_resource_request_groups.ALIAS,
        qos_bw_minimum_ingress.ALIAS,
        qos_rules_alias.ALIAS,
        qos_port_network_policy.ALIAS,
        qos_pps_rule.ALIAS,
        qos_pps_minimum_rule.ALIAS,
        qos_pps_minimum_rule_alias.ALIAS,
    ]

    __native_pagination_support = True
    __native_sorting_support = True
    __filter_validation_support = True

    def __init__(self):
        super(QoSPlugin, self).__init__()
        self.driver_manager = manager.QosServiceDriverManager()
        self._placement_client = pl_client.PlacementAPIClient(cfg.CONF)

        callbacks_registry.subscribe(
            self._validate_create_port_callback,
            callbacks_resources.PORT,
            callbacks_events.PRECOMMIT_CREATE)
        callbacks_registry.subscribe(
            self._check_port_for_placement_allocation_change,
            callbacks_resources.PORT,
            callbacks_events.BEFORE_UPDATE)
        callbacks_registry.subscribe(
            self._validate_update_port_callback,
            callbacks_resources.PORT,
            callbacks_events.PRECOMMIT_UPDATE)
        callbacks_registry.subscribe(
            self._validate_update_network_callback,
            callbacks_resources.NETWORK,
            callbacks_events.PRECOMMIT_UPDATE)
        callbacks_registry.subscribe(
            self._validate_create_network_callback,
            callbacks_resources.NETWORK,
            callbacks_events.PRECOMMIT_CREATE)
        callbacks_registry.subscribe(
            self._check_network_for_placement_allocation_change,
            callbacks_resources.NETWORK,
            callbacks_events.AFTER_UPDATE)

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

        if port_res.get('bulk'):
            port_res['resource_request'] = {
                'qos_id': qos_id,
                'network_id': port_db.network_id,
                'vnic_type': port_res[portbindings.VNIC_TYPE],
                'port_id': port_db.id,
            }
            return port_res

        min_bw_request_group = QoSPlugin._get_min_bw_request_group(
            qos_id, port_db.id, port_res[portbindings.VNIC_TYPE],
            port_db.network_id)
        min_pps_request_group = QoSPlugin._get_min_pps_request_group(
            qos_id, port_db.id, port_res[portbindings.VNIC_TYPE])

        port_res['resource_request'] = (
            QoSPlugin._get_resource_request(min_bw_request_group,
                                            min_pps_request_group))
        return port_res

    @staticmethod
    def _get_resource_request(min_bw_request_group, min_pps_request_group):
        resource_request = None
        request_groups = []

        if min_bw_request_group:
            request_groups += [min_bw_request_group]

        if min_pps_request_group:
            request_groups += [min_pps_request_group]

        if request_groups:
            resource_request = {
                'request_groups': request_groups,
                'same_subtree': [rg['id'] for rg in request_groups],
            }
        return resource_request

    @staticmethod
    def _get_min_bw_resources(min_bw_rules):
        resources = {}
        # NOTE(ralonsoh): we should move this translation dict to n-lib.
        rule_direction_class = {
            nl_constants.INGRESS_DIRECTION:
                orc.NET_BW_IGR_KILOBIT_PER_SEC,
            nl_constants.EGRESS_DIRECTION:
                orc.NET_BW_EGR_KILOBIT_PER_SEC
        }
        for rule in min_bw_rules:
            resources[rule_direction_class[rule.direction]] = rule.min_kbps
        return resources

    @staticmethod
    def _get_min_bw_request_group(qos_policy_id, port_id, vnic_type,
                                  network_id, min_bw_rules=None,
                                  segments=None):
        request_group = {}
        if not min_bw_rules:
            min_bw_rules = rule_object.QosMinimumBandwidthRule.get_objects(
                context.get_admin_context(), qos_policy_id=qos_policy_id)
        min_bw_resources = QoSPlugin._get_min_bw_resources(min_bw_rules)
        if not segments:
            segments = network_object.NetworkSegment.get_objects(
                context.get_admin_context(), network_id=network_id)
        min_bw_traits = QoSPlugin._get_min_bw_traits(vnic_type, segments)
        if min_bw_resources and min_bw_traits:
            request_group.update({
                'id': str(pl_utils.resource_request_group_uuid(
                    uuid.UUID(port_id), min_bw_rules)),
                'required': min_bw_traits,
                'resources': min_bw_resources,
            })
        return request_group

    @staticmethod
    def _get_min_pps_request_group(qos_policy_id, port_id, vnic_type,
                                   min_pps_rules=None):
        request_group = {}
        if not min_pps_rules:
            min_pps_rules = rule_object.QosMinimumPacketRateRule.get_objects(
                context.get_admin_context(),
                qos_policy_id=qos_policy_id)
        min_pps_resources = QoSPlugin._get_min_pps_resources(min_pps_rules)
        min_pps_traits = [pl_utils.vnic_type_trait(vnic_type)]
        if min_pps_resources and min_pps_traits:
            request_group.update({
                'id': str(pl_utils.resource_request_group_uuid(
                    uuid.UUID(port_id), min_pps_rules)),
                'required': min_pps_traits,
                'resources': min_pps_resources,
            })
        return request_group

    @staticmethod
    def _get_min_pps_resources(min_pps_rules):
        resources = {}
        rule_direction_class = {
            nl_constants.INGRESS_DIRECTION:
                orc.NET_PACKET_RATE_IGR_KILOPACKET_PER_SEC,
            nl_constants.EGRESS_DIRECTION:
                orc.NET_PACKET_RATE_EGR_KILOPACKET_PER_SEC,
            nl_constants.ANY_DIRECTION:
                orc.NET_PACKET_RATE_KILOPACKET_PER_SEC,
        }
        for rule in min_pps_rules:
            resources[rule_direction_class[rule.direction]] = rule.min_kpps
        return resources

    @staticmethod
    def _get_min_bw_traits(vnic_type, segments):
        # TODO(lajoskatona): Change to handle all segments when any traits
        # support will be available. See Placement spec:
        # https://review.opendev.org/565730
        first_segment = segments[0]
        if not first_segment:
            return []
        elif not first_segment.physical_network:
            # If there is no physical network this is because this is an
            # overlay network (tunnelled network).
            net_trait = n_const.TRAIT_NETWORK_TUNNEL
        else:
            net_trait = pl_utils.physnet_trait(first_segment.physical_network)

        # NOTE(ralonsoh): we should not rely on the current execution order of
        # the port extending functions. Although here we have
        # port_res[VNIC_TYPE], we should retrieve this value from the port DB
        # object instead.
        vnic_trait = pl_utils.vnic_type_trait(vnic_type)

        return [net_trait, vnic_trait]

    @staticmethod
    @resource_extend.extends([port_def.COLLECTION_NAME_BULK])
    def _extend_port_resource_request_bulk(ports_res, noop):
        """Add resource request to a list of ports."""
        min_bw_rules = dict()
        min_pps_rules = dict()
        net_segments = dict()

        for port_res in ports_res:
            if port_res.get('resource_request') is None:
                continue
            qos_id = port_res['resource_request'].pop('qos_id', None)
            if not qos_id:
                port_res['resource_request'] = None
                continue

            net_id = port_res['resource_request'].pop('network_id')
            vnic_type = port_res['resource_request'].pop('vnic_type')
            port_id = port_res['resource_request'].pop('port_id')

            if qos_id not in min_bw_rules:
                rules = rule_object.QosMinimumBandwidthRule.get_objects(
                    context.get_admin_context(), qos_policy_id=qos_id)
                min_bw_rules[qos_id] = rules

            if net_id not in net_segments:
                segments = network_object.NetworkSegment.get_objects(
                    context.get_admin_context(),
                    network_id=net_id)
                net_segments[net_id] = segments

            min_bw_request_group = QoSPlugin._get_min_bw_request_group(
                qos_id, port_id, vnic_type, net_id,
                min_bw_rules[qos_id], net_segments[net_id])

            if qos_id not in min_pps_rules:
                rules = rule_object.QosMinimumPacketRateRule.get_objects(
                    context.get_admin_context(), qos_policy_id=qos_id)
                min_pps_rules[qos_id] = rules
            min_pps_request_group = QoSPlugin._get_min_pps_request_group(
                qos_id, port_id, vnic_type, min_pps_rules[qos_id])

            port_res['resource_request'] = (
                QoSPlugin._get_resource_request(min_bw_request_group,
                                                min_pps_request_group))

        return ports_res

    def _get_ports_with_policy(self, context, policy):
        networks_ids = policy.get_bound_networks()
        ports_with_net_policy = ports_object.Port.get_objects(
            context, network_id=networks_ids) if networks_ids else []

        # Filter only this ports which don't have overwritten policy
        ports_with_net_policy = [
            port for port in ports_with_net_policy if
            port.qos_policy_id is None
        ]

        ports_ids = policy.get_bound_ports()
        ports_with_policy = ports_object.Port.get_objects(
            context, id=ports_ids) if ports_ids else []
        return list(set(ports_with_policy + ports_with_net_policy))

    def _validate_create_port_callback(self, resource, event, trigger,
                                       payload=None):
        context = payload.context
        port_id = payload.resource_id
        port = ports_object.Port.get_object(context, id=port_id)

        policy_id = port.qos_policy_id or port.qos_network_policy_id
        if policy_id is None:
            return

        policy = policy_object.QosPolicy.get_object(
            context.elevated(), id=policy_id)
        self.validate_policy_for_port(context, policy, port)

    def _check_port_for_placement_allocation_change(self, resource, event,
                                                    trigger, payload):
        context = payload.context
        orig_port = payload.states[0]
        port = payload.latest_state
        original_policy_id = (orig_port.get(qos_consts.QOS_POLICY_ID) or
                              orig_port.get(qos_consts.QOS_NETWORK_POLICY_ID))
        if (qos_consts.QOS_POLICY_ID not in port and
                qos_consts.QOS_NETWORK_POLICY_ID not in port):
            return
        policy_id = (port.get(qos_consts.QOS_POLICY_ID) or
                     port.get(qos_consts.QOS_NETWORK_POLICY_ID))

        if policy_id == original_policy_id:
            return

        # Do this only for compute bound ports
        if (nl_constants.DEVICE_OWNER_COMPUTE_PREFIX in
                orig_port['device_owner']):
            original_policy = policy_object.QosPolicy.get_object(
                context.elevated(), id=original_policy_id)
            policy = policy_object.QosPolicy.get_object(
                context.elevated(), id=policy_id)
            self._change_placement_allocation(original_policy, policy,
                                              orig_port, port)

    def _translate_rule_for_placement(self, rule):
        dir = rule.get('direction')
        if isinstance(rule, rule_object.QosMinimumBandwidthRule):
            value = rule.get('min_kbps')
            # TODO(lajoskatona): move this to neutron-lib, see similar
            # dict @l125.
            if dir == 'egress':
                drctn = orc.NET_BW_EGR_KILOBIT_PER_SEC
            else:
                drctn = orc.NET_BW_IGR_KILOBIT_PER_SEC
            return {drctn: value}
        elif isinstance(rule, rule_object.QosMinimumPacketRateRule):
            value = rule.get('min_kpps')
            # TODO(przszc): move this to neutron-lib, see similar
            # dict @l268.
            rule_direction_class = {
                nl_constants.INGRESS_DIRECTION:
                    orc.NET_PACKET_RATE_IGR_KILOPACKET_PER_SEC,
                nl_constants.EGRESS_DIRECTION:
                    orc.NET_PACKET_RATE_EGR_KILOPACKET_PER_SEC,
                nl_constants.ANY_DIRECTION:
                    orc.NET_PACKET_RATE_KILOPACKET_PER_SEC,
            }
            return {rule_direction_class[dir]: value}
        return {}

    def _prepare_allocation_needs(self, original_port, rule_type_to_rp_map,
                                  original_rules, desired_rules):
        alloc_diff = {}
        for rule in original_rules:
            translated_rule = self._translate_rule_for_placement(rule)
            # NOTE(przszc): Updating Placement resource allocation relies on
            # calculating a difference between current allocation and desired
            # one. If we want to release resources we need to get a negative
            # value of the original allocation.
            translated_rule = {rc: v * -1 for rc, v in translated_rule.items()}
            rp_uuid = rule_type_to_rp_map.get(rule.rule_type)
            if not rp_uuid:
                LOG.warning(
                    "Port %s has no RP responsible for allocating %s resource "
                    "class. Only dataplane enforcement will happen for %s "
                    "rule!", original_port['id'],
                    ''.join(translated_rule.keys()), rule.rule_type)
                continue
            if rp_uuid not in alloc_diff:
                alloc_diff[rp_uuid] = translated_rule
            else:
                alloc_diff[rp_uuid].update(translated_rule)

        for rule in desired_rules:
            translated_rule = self._translate_rule_for_placement(rule)
            rp_uuid = rule_type_to_rp_map.get(rule.rule_type)
            if not rp_uuid:
                LOG.warning(
                    "Port %s has no RP responsible for allocating %s resource "
                    "class. Only dataplane enforcement will happen for %s "
                    "rule!", original_port['id'],
                    ''.join(translated_rule.keys()), rule.rule_type)
                continue
            for rc, value in translated_rule.items():
                if (rc == orc.NET_PACKET_RATE_KILOPACKET_PER_SEC and
                        (orc.NET_PACKET_RATE_IGR_KILOPACKET_PER_SEC in
                         alloc_diff[rp_uuid] or
                         orc.NET_PACKET_RATE_EGR_KILOPACKET_PER_SEC in
                         alloc_diff[rp_uuid]) or
                        (rc in (orc.NET_PACKET_RATE_IGR_KILOPACKET_PER_SEC,
                                orc.NET_PACKET_RATE_EGR_KILOPACKET_PER_SEC) and
                         orc.NET_PACKET_RATE_KILOPACKET_PER_SEC in
                         alloc_diff[rp_uuid])):
                    raise NotImplementedError(_(
                        'Changing from direction-less QoS minimum packet rate '
                        'rule to a direction-oriented minimum packet rate rule'
                        ', or vice versa, is not supported.'))
                new_value = alloc_diff[rp_uuid].get(rc, 0) + value
                if new_value == 0:
                    alloc_diff[rp_uuid].pop(rc, None)
                else:
                    alloc_diff[rp_uuid][rc] = new_value

        alloc_diff = {rp: diff for rp, diff in alloc_diff.items() if diff}
        return alloc_diff

    def _get_updated_port_allocation(self, original_port, original_rules,
                                     desired_rules):
        # NOTE(przszc): Port's binding:profile.allocation attribute can contain
        # multiple RPs and we need to figure out which RP is responsible for
        # providing resources for particular resource class. We could use
        # Placement API to get RP's inventory, but it would require superfluous
        # API calls. Another option is to calculate resource request group
        # UUIDs and check if they match the ones in allocation attribute and
        # create a lookup table. Since we are updating allocation attribute we
        # have to calculate resource request group UUIDs anyways, so creating a
        # lookup table seems like a better solution.
        rule_type_to_rp_map = {}
        updated_allocation = {}

        allocation = original_port['binding:profile']['allocation']

        for group_uuid, rp in allocation.items():
            for rule_type in [qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH,
                              qos_consts.RULE_TYPE_MINIMUM_PACKET_RATE]:
                o_filtered_rules = [r for r in original_rules
                                    if r.rule_type == rule_type]
                d_filtered_rules = [r for r in desired_rules
                                    if r.rule_type == rule_type]
                o_group_uuid = str(
                    pl_utils.resource_request_group_uuid(
                        uuid.UUID(original_port['id']), o_filtered_rules))
                if group_uuid == o_group_uuid:
                    rule_type_to_rp_map[rule_type] = rp
                    # NOTE(przszc): Original QoS policy can have more rule
                    # types than desired QoS policy. We should add RP to
                    # allocation only if there are rules with this type in
                    # desired QoS policy.
                    if d_filtered_rules:
                        d_group_uuid = str(
                            pl_utils.resource_request_group_uuid(
                                uuid.UUID(original_port['id']),
                                d_filtered_rules))
                        updated_allocation[d_group_uuid] = rp
                    break

        return updated_allocation, rule_type_to_rp_map

    def _change_placement_allocation(self, original_policy, desired_policy,
                                     orig_port, port):
        alloc_diff = {}
        original_rules = []
        desired_rules = []
        device_id = orig_port['device_id']
        if original_policy:
            original_rules = original_policy.get('rules')
        if desired_policy:
            desired_rules = desired_policy.get('rules')

        # Filter out rules that can't have resources allocated in Placement
        original_rules = [
            r for r in original_rules
            if (isinstance(r, (rule_object.QosMinimumBandwidthRule,
                               rule_object.QosMinimumPacketRateRule)))]
        desired_rules = [
            r for r in desired_rules
            if (isinstance(r, (rule_object.QosMinimumBandwidthRule,
                               rule_object.QosMinimumPacketRateRule)))]
        if not original_rules and not desired_rules:
            return

        o_rule_types = set(r.rule_type for r in original_rules)
        d_rule_types = set(r.rule_type for r in desired_rules)
        allocation = orig_port['binding:profile'].get('allocation')
        if (not original_rules and desired_rules) or not allocation:
            LOG.warning("There was no QoS policy with minimum_bandwidth or "
                        "minimum_packet_rate rule attached to the port %s, "
                        "there is no allocation record in placement for it, "
                        "only the dataplane enforcement will happen!",
                        orig_port['id'])
            return

        new_rule_types = d_rule_types.difference(o_rule_types)
        if new_rule_types:
            # NOTE(przszc): Port's resource_request and
            # binding:profile.allocation attributes depend on associated
            # QoS policy. resource_request is calculated on the fly, but
            # allocation attribute needs to be updated whenever QoS policy
            # changes. Since desired QoS policy has more rule types than the
            # original QoS policy, Neutron doesn't know which RP is responsible
            # for allocating those resources. That would require scheduling in
            # Nova. However, some users do not use Placement enforcement and
            # are interested only in dataplane enforcement. It means that we
            # cannot raise an exception without breaking legacy behavior.
            # Only rules that have resources allocated in Placement are going
            # to be included in port's binding:profile.allocation.
            LOG.warning(
                "There was no QoS policy with %s rules attached to the port "
                "%s, there is no allocation record in placement for it, only "
                "the dataplane enforcement will happen for those rules!",
                ','.join(new_rule_types), orig_port['id'])
            desired_rules = [
                r for r in desired_rules if r.rule_type not in new_rule_types]

        # NOTE(przszc): Get updated allocation but do not assign it to the
        # port yet. We don't know if Placement API call is going to succeed.
        updated_allocation, rule_type_to_rp_map = (
            self._get_updated_port_allocation(orig_port, original_rules,
                                              desired_rules))
        alloc_diff = self._prepare_allocation_needs(orig_port,
                                                    rule_type_to_rp_map,
                                                    original_rules,
                                                    desired_rules)
        if alloc_diff:
            try:
                self._placement_client.update_qos_allocation(
                    consumer_uuid=device_id, alloc_diff=alloc_diff)
            except ks_exc.Conflict:
                raise neutron_qos_exc.QosPlacementAllocationUpdateConflict(
                    alloc_diff=alloc_diff, consumer=device_id)

        # NOTE(przszc): Upon successful allocation update in Placement we can
        # proceed with updating port's binding:profile.allocation attribute.
        # Keep in mind that updating port state this way is possible only
        # because DBEventPayload's payload attributes are not copied -
        # subscribers obtain a direct reference to event payload objects.
        # If that changes, line below won't have any effect.
        #
        # Subscribers should *NOT* modify event payload objects, but this is
        # the only way we can avoid inconsistency in port's attributes.
        orig_binding_prof = orig_port.get('binding:profile', {})
        binding_prof = copy.deepcopy(orig_binding_prof)
        binding_prof.update({'allocation': updated_allocation})
        port['binding:profile'] = binding_prof

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

    def _validate_create_network_callback(self, resource, event, trigger,
                                          payload=None):
        context = payload.context
        network_id = payload.resource_id
        network = network_object.Network.get_object(context, id=network_id)

        if not network or not getattr(network, 'qos_policy_id', None):
            return
        policy_id = network.qos_policy_id

        policy = policy_object.QosPolicy.get_object(
            context.elevated(), id=policy_id)
        self.validate_policy_for_network(context, policy, network_id)

    def _check_network_for_placement_allocation_change(self, resource, event,
                                                       trigger, payload=None):
        context = payload.context
        original_network, updated_network = payload.states

        original_policy_id = original_network.get(qos_consts.QOS_POLICY_ID)
        policy_id = updated_network.get(qos_consts.QOS_POLICY_ID)

        if policy_id == original_policy_id:
            return

        original_policy = policy_object.QosPolicy.get_object(
            context.elevated(), id=original_policy_id)
        policy = policy_object.QosPolicy.get_object(
            context.elevated(), id=policy_id)
        ports = ports_object.Port.get_objects(
            context, network_id=updated_network['id'])

        # Filter compute bound ports without overwritten QoS policy
        ports = [port for port in ports
                 if (port.qos_policy_id is None and
                     nl_constants.DEVICE_OWNER_COMPUTE_PREFIX in
                     port['device_owner'])]

        for port in ports:
            # Use _make_port_dict() to load extension data
            port_dict = trigger._make_port_dict(port)
            updated_port_attrs = {}
            self._change_placement_allocation(
                original_policy, policy, port_dict, updated_port_attrs)
            for port_binding in port.bindings:
                port_binding.profile = updated_port_attrs.get(
                    'binding:profile', {})
                port_binding.update()

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
        self.validate_policy_for_network(
            context, policy, network_id=updated_network['id'])

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
            if not self.driver_manager.validate_rule_for_port(
                    context, rule, port):
                raise qos_exc.QosRuleNotSupported(rule_type=rule.rule_type,
                                                  port_id=port['id'])

    def validate_policy_for_network(self, context, policy, network_id):
        for rule in policy.rules:
            if not self.driver_manager.validate_rule_for_network(
                    context, rule, network_id):
                raise qos_exc.QosRuleNotSupportedByNetwork(
                    rule_type=rule.rule_type, network_id=network_id)

    def reject_rule_update_for_bound_port(self, context, policy):
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
        # TODO(ralonsoh): "project_id" check and "tenant_id" removal will be
        # unnecessary once we fully migrate to keystone V3.
        if not policy['policy'].get('project_id'):
            raise lib_exc.BadRequest(resource='QoS policy',
                                     msg='Must have "policy_id"')
        policy['policy'].pop('tenant_id', None)
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

    def supported_rule_types(self, all_supported=None, all_rules=None):
        return self.driver_manager.supported_rule_types(
            all_supported=all_supported, all_rules=all_rules)

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
            checker.check_min_pps_rule_conflict(policy, rule)
            checker.check_rules_conflict(policy, rule)
            rule.create()
            policy.obj_load_attr('rules')
            self.validate_policy(context, policy)
            if rule.rule_type in (
                    qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH,
                    qos_consts.RULE_TYPE_MINIMUM_PACKET_RATE):
                self.reject_rule_update_for_bound_port(context, policy)
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
            checker.check_min_pps_rule_conflict(policy, rule)
            checker.check_rules_conflict(policy, rule)
            rule.update()
            policy.obj_load_attr('rules')
            self.validate_policy(context, policy)
            if rule.rule_type in (
                    qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH,
                    qos_consts.RULE_TYPE_MINIMUM_PACKET_RATE):
                self.reject_rule_update_for_bound_port(context, policy)
            self.driver_manager.call(qos_consts.UPDATE_POLICY_PRECOMMIT,
                                     context, policy)

        self.driver_manager.call(qos_consts.UPDATE_POLICY, context, policy)

        return rule

    def _get_policy_id(self, context, rule_cls, rule_id):
        with db_api.CONTEXT_READER.using(context):
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
            if rule.rule_type in (
                    qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH,
                    qos_consts.RULE_TYPE_MINIMUM_PACKET_RATE):
                self.reject_rule_update_for_bound_port(context, policy)
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
