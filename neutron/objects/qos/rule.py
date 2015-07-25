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

from oslo_versionedobjects import base as obj_base
from oslo_versionedobjects import fields as obj_fields
import six

from neutron.db.qos import models as qos_db_model
from neutron.objects import base


@six.add_metaclass(abc.ABCMeta)
class QosRule(base.NeutronDbObject):

    fields = {
        'id': obj_fields.UUIDField(),
        'qos_policy_id': obj_fields.UUIDField()
    }

    fields_no_update = ['id', 'qos_policy_id']


@obj_base.VersionedObjectRegistry.register
class QosBandwidthLimitRule(QosRule):

    db_model = qos_db_model.QosBandwidthLimitRule

    fields = {
        'max_kbps': obj_fields.IntegerField(nullable=True),
        'max_burst_kbps': obj_fields.IntegerField(nullable=True)
    }
