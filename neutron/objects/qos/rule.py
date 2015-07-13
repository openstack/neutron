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

from neutron.db import api as db_api
from neutron.db.qos import models as qos_db_model
from neutron.objects import base


@six.add_metaclass(abc.ABCMeta)
class QosRule(base.NeutronObject):

    base_db_model = qos_db_model.QosRule

    fields = {
        'id': obj_fields.UUIDField(),
        'type': obj_fields.StringField(),
        'qos_policy_id': obj_fields.UUIDField()
    }

    fields_no_update = ['id', 'tenant_id', 'qos_policy_id']

    _core_fields = list(fields.keys())

    _common_fields = ['id']

    @classmethod
    def _is_common_field(cls, field):
        return field in cls._common_fields

    @classmethod
    def _is_core_field(cls, field):
        return field in cls._core_fields

    @classmethod
    def _is_addn_field(cls, field):
        return not cls._is_core_field(field) or cls._is_common_field(field)

    @staticmethod
    def _filter_fields(fields, func):
        return {
            key: val for key, val in fields.items()
            if func(key)
        }

    # TODO(QoS): reimplement get_by_id to merge both core and addn fields

    def _get_changed_core_fields(self):
        fields = self.obj_get_changes()
        return self._filter_fields(fields, self._is_core_field)

    def _get_changed_addn_fields(self):
        fields = self.obj_get_changes()
        return self._filter_fields(
            fields, lambda key: self._is_addn_field(key))

    def _copy_common_fields(self, from_, to_):
        for field in self._common_fields:
            to_[field] = from_[field]

    # TODO(QoS): create and update are not transactional safe
    def create(self):

        # create base qos_rule
        core_fields = self._get_changed_core_fields()
        base_db_obj = db_api.create_object(
            self._context, self.base_db_model, core_fields)

        # create type specific qos_..._rule
        addn_fields = self._get_changed_addn_fields()
        self._copy_common_fields(core_fields, addn_fields)
        addn_db_obj = db_api.create_object(
            self._context, self.db_model, addn_fields)

        # merge two db objects into single neutron one
        self.from_db_object(base_db_obj, addn_db_obj)

    def update(self):
        updated_db_objs = []

        # update base qos_rule, if needed
        core_fields = self._get_changed_core_fields()
        if core_fields:
            base_db_obj = db_api.update_object(
                self._context, self.base_db_model, self.id, core_fields)
            updated_db_objs.append(base_db_obj)

        addn_fields = self._get_changed_addn_fields()
        if addn_fields:
            addn_db_obj = db_api.update_object(
                self._context, self.db_model, self.id, addn_fields)
            updated_db_objs.append(addn_db_obj)

        # update neutron object with values from both database objects
        self.from_db_object(*updated_db_objs)

    # delete is the same, additional rule object cleanup is done thru cascading


@obj_base.VersionedObjectRegistry.register
class QosBandwidthLimitRule(QosRule):

    db_model = qos_db_model.QosBandwidthLimitRule

    fields = {
        'max_kbps': obj_fields.IntegerField(),
        'max_burst_kbps': obj_fields.IntegerField()
    }
