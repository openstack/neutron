# Copyright 2018 Red Hat, Inc.
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

from oslo_versionedobjects import fields as obj_fields
from six import add_metaclass
from sqlalchemy import and_

from neutron.db import rbac_db_models as models
from neutron.objects import base
from neutron.objects import common_types


@add_metaclass(abc.ABCMeta)
class RBACBaseObject(base.NeutronDbObject):
    # Version 1.0: Initial version

    VERSION = '1.0'

    fields = {
        'id': common_types.UUIDField(),
        'project_id': obj_fields.StringField(),
        'object_id': common_types.UUIDField(),
        'target_tenant': obj_fields.StringField(),
        'action': obj_fields.StringField(),
    }

    fields_no_update = ['id', 'project_id', 'object_id']

    @classmethod
    def get_projects(cls, context, object_id=None, action=None,
                     target_tenant=None):
        clauses = []
        if object_id:
            clauses.append(models.NetworkRBAC.object_id == object_id)
        if action:
            clauses.append(models.NetworkRBAC.action == action)
        if target_tenant:
            clauses.append(models.NetworkRBAC.target_tenant ==
                           target_tenant)
        query = context.session.query(models.NetworkRBAC.target_tenant)
        if clauses:
            query = query.filter(and_(*clauses))
        return [data[0] for data in query]

    @classmethod
    def get_type_class_map(cls):
        return {klass.db_model.object_type: klass
                for klass in cls.__subclasses__()}
