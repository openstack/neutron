# Copyright 2015 Red Hat, Inc.
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

from neutron.common import exceptions
from neutron.common import utils
from neutron.db import api as db_api
from neutron.db.qos import api as qos_db_api
from neutron.db.qos import models as qos_db_model
from neutron.objects import base
from neutron.objects.qos import rule as rule_obj_impl
from neutron.services.qos import qos_consts


class QosRulesExtenderMeta(abc.ABCMeta):

    def __new__(mcs, name, bases, dct):
        cls = super(QosRulesExtenderMeta, mcs).__new__(mcs, name, bases, dct)

        cls.rule_fields = {}
        for rule in qos_consts.VALID_RULE_TYPES:
            rule_cls_name = 'Qos%sRule' % utils.camelize(rule)
            field = '%s_rules' % rule
            cls.fields[field] = obj_fields.ListOfObjectsField(rule_cls_name)
            cls.rule_fields[field] = rule_cls_name

        cls.synthetic_fields = list(cls.rule_fields.keys())

        return cls


@obj_base.VersionedObjectRegistry.register
@six.add_metaclass(QosRulesExtenderMeta)
class QosPolicy(base.NeutronDbObject):

    db_model = qos_db_model.QosPolicy

    port_binding_model = qos_db_model.QosPortPolicyBinding
    network_binding_model = qos_db_model.QosNetworkPolicyBinding

    fields = {
        'id': obj_fields.UUIDField(),
        'tenant_id': obj_fields.UUIDField(),
        'name': obj_fields.StringField(),
        'description': obj_fields.StringField(),
        'shared': obj_fields.BooleanField(default=False)
    }

    fields_no_update = ['id', 'tenant_id']

    def to_dict(self):
        dict_ = super(QosPolicy, self).to_dict()
        for field in self.rule_fields:
            if field in dict_:
                dict_[field] = [rule.to_dict() for rule in dict_[field]]
        return dict_

    def obj_load_attr(self, attrname):
        if attrname not in self.rule_fields:
            raise exceptions.ObjectActionError(
                action='obj_load_attr', reason='unable to load %s' % attrname)

        rule_cls = getattr(rule_obj_impl, self.rule_fields[attrname])
        rules = rule_cls.get_rules_by_policy(self._context, self.id)
        setattr(self, attrname, rules)
        self.obj_reset_changes([attrname])

    def _load_rules(self):
        for attr in self.rule_fields:
            self.obj_load_attr(attr)

    @classmethod
    def get_by_id(cls, context, id):
        with db_api.autonested_transaction(context.session):
            policy_obj = super(QosPolicy, cls).get_by_id(context, id)
            if policy_obj:
                policy_obj._load_rules()
        return policy_obj

    # TODO(QoS): Test that all objects are fetched within one transaction
    @classmethod
    def get_objects(cls, context, **kwargs):
        with db_api.autonested_transaction(context.session):
            db_objs = db_api.get_objects(context, cls.db_model, **kwargs)
            objs = list()
            for db_obj in db_objs:
                obj = cls(context, **db_obj)
                obj._load_rules()
                objs.append(obj)
        return objs

    @classmethod
    def _get_object_policy(cls, context, model, **kwargs):
        with db_api.autonested_transaction(context.session):
            binding_db_obj = db_api.get_object(context, model, **kwargs)
            if binding_db_obj:
                return cls.get_by_id(context, binding_db_obj['policy_id'])

    @classmethod
    def get_network_policy(cls, context, network_id):
        return cls._get_object_policy(context, cls.network_binding_model,
                                      network_id=network_id)

    @classmethod
    def get_port_policy(cls, context, port_id):
        return cls._get_object_policy(context, cls.port_binding_model,
                                      port_id=port_id)

    def create(self):
        with db_api.autonested_transaction(self._context.session):
            super(QosPolicy, self).create()
            self._load_rules()

    def attach_network(self, network_id):
        qos_db_api.create_policy_network_binding(self._context,
                                                 policy_id=self.id,
                                                 network_id=network_id)

    def attach_port(self, port_id):
        qos_db_api.create_policy_port_binding(self._context,
                                              policy_id=self.id,
                                              port_id=port_id)

    def detach_network(self, network_id):
        qos_db_api.delete_policy_network_binding(self._context,
                                                 policy_id=self.id,
                                                 network_id=network_id)

    def detach_port(self, port_id):
        qos_db_api.delete_policy_port_binding(self._context,
                                              policy_id=self.id,
                                              port_id=port_id)
