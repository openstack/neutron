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

from neutron_lib.db import api as db_api
from neutron_lib.objects import common_types
from oslo_utils import versionutils
from oslo_versionedobjects import fields as obj_fields
from sqlalchemy import and_

from neutron.objects import base


class RBACBaseObject(base.NeutronDbObject, metaclass=abc.ABCMeta):
    # Version 1.0: Initial version
    # Version 1.1: Changed 'target_tenant' to 'target_project'
    VERSION = '1.1'

    fields = {
        'id': common_types.UUIDField(),
        'project_id': obj_fields.StringField(),
        'object_id': common_types.UUIDField(),
        'target_project': obj_fields.StringField(),
        'action': obj_fields.StringField(),
    }

    fields_no_update = ['id', 'project_id', 'object_id']

    @classmethod
    @db_api.CONTEXT_READER
    def get_projects(cls, context, object_id=None, action=None,
                     target_project=None):
        clauses = []
        if object_id:
            clauses.append(cls.db_model.object_id == object_id)
        if action:
            clauses.append(cls.db_model.action == action)
        if target_project:
            clauses.append(cls.db_model.target_project == target_project)
        query = context.session.query(cls.db_model.target_project)
        if clauses:
            query = query.filter(and_(*clauses))
        return [data[0] for data in query]

    @classmethod
    def get_type_class_map(cls):
        return {klass.db_model.object_type: klass
                for klass in cls.__subclasses__()}

    def obj_make_compatible(self, primitive, target_version):
        _target_version = versionutils.convert_version_to_tuple(target_version)
        if _target_version < (1, 1):  # NOTE(ralonsoh): remove in Yoga + 4.
            primitive['target_tenant'] = primitive.pop('target_project')
