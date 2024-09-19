# Copyright 2015 Huawei Technologies India Pvt Ltd, Inc.
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

import abc
import sys

from neutron_lib import constants
from neutron_lib.objects import common_types
from neutron_lib.services.qos import constants as qos_consts
from neutron_lib.utils import helpers
from oslo_utils import versionutils
from oslo_versionedobjects import exception
from oslo_versionedobjects import fields as obj_fields

from neutron.db.qos import models as qos_db_model
from neutron.objects import base

DSCP_MARK = 'dscp_mark'


def get_rules(obj_cls, context, qos_policy_id):
    all_rules = []
    if not qos_policy_id:
        return all_rules

    with obj_cls.db_context_reader(context):
        for rule_type in qos_consts.VALID_RULE_TYPES:
            rule_cls_name = 'Qos%sRule' % helpers.camelize(rule_type)
            rule_cls = getattr(sys.modules[__name__], rule_cls_name)

            rules = rule_cls.get_objects(context, qos_policy_id=qos_policy_id)
            all_rules.extend(rules)
    return all_rules


class QosRule(base.NeutronDbObject, metaclass=abc.ABCMeta):
    # Version 1.0: Initial version, only BandwidthLimitRule
    #         1.1: Added DscpMarkingRule
    #         1.2: Added QosMinimumBandwidthRule
    #         1.3: Added direction for BandwidthLimitRule
    #         1.4: Added PacketRateLimitRule
    #         1.5: Added QosMinimumPacketRateRule
    #
    # NOTE(mangelajo): versions need to be handled from the top QosRule object
    #                  because it's the only reference QosPolicy can make
    #                  to them via obj_relationships version map
    VERSION = '1.5'

    fields = {
        'id': common_types.UUIDField(),
        'qos_policy_id': common_types.UUIDField()
    }

    fields_no_update = ['id', 'qos_policy_id']

    # must be redefined in subclasses
    rule_type: str
    duplicates_compare_fields: tuple[str, ...] = ()

    def duplicates(self, other_rule):
        """Returns True if rules have got same values in fields defined in
        'duplicates_compare_fields' list.

        In case when subclass don't have defined any field in
        duplicates_compare_fields, only rule types are compared.
        """

        if self.rule_type != other_rule.rule_type:
            return False

        if self.duplicates_compare_fields:
            for field in self.duplicates_compare_fields:
                if getattr(self, field) != getattr(other_rule, field):
                    return False
        return True

    def to_dict(self):
        dict_ = super().to_dict()
        dict_['type'] = self.rule_type
        return dict_

    def should_apply_to_port(self, port):
        """Check whether a rule can be applied to a specific port.

        This function has the logic to decide whether a rule should
        be applied to a port or not, depending on the source of the
        policy (network, or port). Eventually rules could override
        this method, or we could make it abstract to allow different
        rule behaviour.
        """
        is_port_policy = self.qos_policy_id == port[qos_consts.QOS_POLICY_ID]
        is_network_policy_only = port[qos_consts.QOS_POLICY_ID] is None
        is_network_device_port = any(port['device_owner'].startswith(prefix)
                                     for prefix
                                     in constants.DEVICE_OWNER_PREFIXES)
        # NOTE(miouge): Network QoS policies should apply to ext routers ports:
        # - DEVICE_OWNER_AGENT_GW for DVR routers
        # - DEVICE_OWNER_ROUTER_GW for normal neutron routers
        is_router_gw = any(port['device_owner'].startswith(prefix)
                           for prefix in [constants.DEVICE_OWNER_AGENT_GW,
                                          constants.DEVICE_OWNER_ROUTER_GW])
        # NOTE(ralonsoh): return True if:
        #    - Is a port QoS policy (not a network QoS policy)
        #    - Is not an internal network device (e.g. router) and is a network
        #      QoS policy and there is no port QoS policy
        return (is_port_policy or
                ((is_router_gw or not is_network_device_port) and
                 is_network_policy_only))

    def obj_make_compatible(self, primitive, target_version):
        _target_version = versionutils.convert_version_to_tuple(target_version)
        if _target_version < (1, 3):
            raise exception.IncompatibleObjectVersion(
                objver=target_version, objtype=self.__class__.__name__)


@base.NeutronObjectRegistry.register
class QosBandwidthLimitRule(QosRule):

    db_model = qos_db_model.QosBandwidthLimitRule

    fields = {
        'max_kbps': obj_fields.IntegerField(nullable=True),
        'max_burst_kbps': obj_fields.IntegerField(nullable=True),
        'direction': common_types.FlowDirectionEnumField(
            default=constants.EGRESS_DIRECTION)
    }

    duplicates_compare_fields = ('direction',)

    rule_type = qos_consts.RULE_TYPE_BANDWIDTH_LIMIT


@base.NeutronObjectRegistry.register
class QosDscpMarkingRule(QosRule):

    db_model = qos_db_model.QosDscpMarkingRule

    fields = {
        DSCP_MARK: common_types.DscpMarkField(),
    }

    rule_type = qos_consts.RULE_TYPE_DSCP_MARKING


@base.NeutronObjectRegistry.register
class QosMinimumBandwidthRule(QosRule):

    db_model = qos_db_model.QosMinimumBandwidthRule

    fields = {
        'min_kbps': obj_fields.IntegerField(nullable=True),
        'direction': common_types.FlowDirectionEnumField(),
    }

    duplicates_compare_fields = ('direction',)

    rule_type = qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH


@base.NeutronObjectRegistry.register
class QosPacketRateLimitRule(QosRule):

    db_model = qos_db_model.QosPacketRateLimitRule

    fields = {
        'max_kpps': obj_fields.IntegerField(nullable=True),
        'max_burst_kpps': obj_fields.IntegerField(nullable=True),
        'direction': common_types.FlowDirectionEnumField(
            default=constants.EGRESS_DIRECTION)
    }

    duplicates_compare_fields = ('direction',)

    rule_type = qos_consts.RULE_TYPE_PACKET_RATE_LIMIT


@base.NeutronObjectRegistry.register
class QosMinimumPacketRateRule(QosRule):

    db_model = qos_db_model.QosMinimumPacketRateRule

    fields = {
        'min_kpps': obj_fields.IntegerField(nullable=False),
        'direction': common_types.FlowDirectionAndAnyEnumField(),
    }

    duplicates_compare_fields = ('direction',)

    rule_type = qos_consts.RULE_TYPE_MINIMUM_PACKET_RATE
