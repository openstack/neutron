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

from oslo_versionedobjects import base as obj_base
from oslo_versionedobjects import fields as obj_fields
import six

from neutron.common import utils
from neutron.db import api as db_api
from neutron.db.qos import models as qos_db_model
from neutron.objects import base
from neutron.services.qos import qos_consts


def get_rules(context, qos_policy_id):
    all_rules = []
    with db_api.autonested_transaction(context.session):
        for rule_type in qos_consts.VALID_RULE_TYPES:
            rule_cls_name = 'Qos%sRule' % utils.camelize(rule_type)
            rule_cls = getattr(sys.modules[__name__], rule_cls_name)

            rules = rule_cls.get_objects(context, qos_policy_id=qos_policy_id)
            all_rules.extend(rules)
    return all_rules


@six.add_metaclass(abc.ABCMeta)
class QosRule(base.NeutronDbObject):

    fields = {
        'id': obj_fields.UUIDField(),
        'qos_policy_id': obj_fields.UUIDField()
    }

    fields_no_update = ['id', 'qos_policy_id']

    # should be redefined in subclasses
    rule_type = None

    def to_dict(self):
        dict_ = super(QosRule, self).to_dict()
        dict_['type'] = self.rule_type
        return dict_


@obj_base.VersionedObjectRegistry.register
class QosBandwidthLimitRule(QosRule):

    db_model = qos_db_model.QosBandwidthLimitRule

    fields = {
        'max_kbps': obj_fields.IntegerField(nullable=True),
        'max_burst_kbps': obj_fields.IntegerField(nullable=True)
    }

    rule_type = qos_consts.RULE_TYPE_BANDWIDTH_LIMIT
