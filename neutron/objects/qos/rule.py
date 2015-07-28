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
from neutron.services.qos import qos_consts


@six.add_metaclass(abc.ABCMeta)
class QosRule(base.NeutronDbObject):

    base_db_model = qos_db_model.QosRule

    fields = {
        'id': obj_fields.UUIDField(),
        #TODO(QoS): We ought to kill the `type' attribute
        'type': obj_fields.StringField(),
        'qos_policy_id': obj_fields.UUIDField()
    }

    fields_no_update = ['id', 'tenant_id', 'qos_policy_id']

    # each rule subclass should redefine it
    rule_type = None

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

    def _get_changed_core_fields(self):
        fields = self.obj_get_changes()
        return self._filter_fields(fields, self._is_core_field)

    def _get_changed_addn_fields(self):
        fields = self.obj_get_changes()
        return self._filter_fields(fields, self._is_addn_field)

    def _copy_common_fields(self, from_, to_):
        for field in self._common_fields:
            to_[field] = from_[field]

    @classmethod
    def get_objects(cls, context, **kwargs):
        # TODO(QoS): support searching for subtype fields
        db_objs = db_api.get_objects(context, cls.base_db_model, **kwargs)
        return [cls.get_by_id(context, db_obj['id']) for db_obj in db_objs]

    @classmethod
    def get_by_id(cls, context, id):
        obj = super(QosRule, cls).get_by_id(context, id)

        if obj:
            # the object above does not contain fields from base QosRule yet,
            # so fetch it and mix its fields into the object
            base_db_obj = db_api.get_object(context, cls.base_db_model, id=id)
            for field in cls._core_fields:
                setattr(obj, field, base_db_obj[field])

            obj.obj_reset_changes()
            return obj

    # TODO(QoS): Test that create is in single transaction
    def create(self):

        # TODO(QoS): enforce that type field value is bound to specific class
        self.type = self.rule_type

        # create base qos_rule
        core_fields = self._get_changed_core_fields()

        with db_api.autonested_transaction(self._context.session):
            base_db_obj = db_api.create_object(
                self._context, self.base_db_model, core_fields)

            # create type specific qos_..._rule
            addn_fields = self._get_changed_addn_fields()
            self._copy_common_fields(core_fields, addn_fields)
            addn_db_obj = db_api.create_object(
                self._context, self.db_model, addn_fields)

        # merge two db objects into single neutron one
        self.from_db_object(base_db_obj, addn_db_obj)

    # TODO(QoS): Test that update is in single transaction
    def update(self):
        updated_db_objs = []

        # TODO(QoS): enforce that type field cannot be changed

        # update base qos_rule, if needed
        core_fields = self._get_changed_core_fields()

        with db_api.autonested_transaction(self._context.session):
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

    @classmethod
    def get_rules_by_policy(cls, context, policy_id):
        return cls.get_objects(context, qos_policy_id=policy_id)


@obj_base.VersionedObjectRegistry.register
class QosBandwidthLimitRule(QosRule):

    db_model = qos_db_model.QosBandwidthLimitRule

    rule_type = qos_consts.RULE_TYPE_BANDWIDTH_LIMIT

    fields = {
        'max_kbps': obj_fields.IntegerField(nullable=True),
        'max_burst_kbps': obj_fields.IntegerField(nullable=True)
    }
