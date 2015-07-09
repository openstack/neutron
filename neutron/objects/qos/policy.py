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

from oslo_versionedobjects import base as obj_base
from oslo_versionedobjects import fields as obj_fields

from neutron.db import api as db_api
from neutron.db.qos import api as qos_db_api
from neutron.db.qos import models as qos_db_model
from neutron.objects import base


# TODO(QoS): add rule lists to object fields
# TODO(QoS): implement something for binding networks and ports with policies


@obj_base.VersionedObjectRegistry.register
class QosPolicy(base.NeutronObject):

    db_model = qos_db_model.QosPolicy

    port_binding_model = qos_db_model.QosPortPolicyBinding
    network_binding_model = qos_db_model.QosNetworkPolicyBinding

    fields = {
        'id': obj_fields.UUIDField(),
        'tenant_id': obj_fields.UUIDField(),
        'name': obj_fields.StringField(),
        'description': obj_fields.StringField(),
        'shared': obj_fields.BooleanField()
    }

    @classmethod
    def _get_object_policy(cls, context, model, **kwargs):
        # TODO(QoS): we should make sure we use public functions
        binding_db_obj = db_api._find_object(context, model, **kwargs)
        # TODO(QoS): rethink handling missing binding case
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

    def attach_network(self, network_id):
        qos_db_api.create_policy_network_binding(self._context,
                                                 policy_id=self.id,
                                                 network_id=network_id)

    def attach_port(self, port_id):
        qos_db_api.create_policy_port_binding(self._context,
                                              policy_id=self.id,
                                              port_id=port_id)

    def detach_network(self, network_id):
        # TODO(QoS): implement it, in the next life maybe
        pass

    def detach_port(self, port_id):
        # TODO(QoS): implement it, in the next life maybe
        pass
