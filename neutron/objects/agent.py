# Copyright (c) 2016 Intel Corporation.
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

from oslo_serialization import jsonutils
from oslo_versionedobjects import base as obj_base
from oslo_versionedobjects import fields as obj_fields

from neutron.agent.common import utils
from neutron.db.models import agent as agent_model
from neutron.objects import base


@obj_base.VersionedObjectRegistry.register
class Agent(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = agent_model.Agent

    fields = {
        'id': obj_fields.UUIDField(),
        'agent_type': obj_fields.StringField(),
        'binary': obj_fields.StringField(),
        'topic': obj_fields.StringField(),
        'host': obj_fields.StringField(),
        'availability_zone': obj_fields.StringField(nullable=True),
        'admin_state_up': obj_fields.BooleanField(default=True),
        'started_at': obj_fields.DateTimeField(tzinfo_aware=False),
        'created_at': obj_fields.DateTimeField(tzinfo_aware=False),
        'heartbeat_timestamp': obj_fields.DateTimeField(tzinfo_aware=False),
        'description': obj_fields.StringField(nullable=True),
        'configurations': obj_fields.DictOfStringsField(),
        'resource_versions': obj_fields.DictOfStringsField(nullable=True),
        'load': obj_fields.IntegerField(default=0),
    }

    @classmethod
    def modify_fields_to_db(cls, fields):
        result = super(Agent, cls).modify_fields_to_db(fields)
        if 'configurations' in result:
            result['configurations'] = (
                cls.filter_to_json_str(result['configurations']))
        if 'resource_versions' in result:
            if result['resource_versions']:
                result['resource_versions'] = (
                    cls.filter_to_json_str(result['resource_versions']))
            if not fields['resource_versions']:
                result['resource_versions'] = None
        return result

    @classmethod
    def modify_fields_from_db(cls, db_obj):
        fields = super(Agent, cls).modify_fields_from_db(db_obj)
        if 'configurations' in fields:
            if fields['configurations']:
                fields['configurations'] = jsonutils.loads(
                    fields['configurations'])
            if not fields['configurations']:
                fields['configurations'] = {}
        if 'resource_versions' in fields:
            if fields['resource_versions']:
                fields['resource_versions'] = jsonutils.loads(
                    fields['resource_versions'])
            if not fields['resource_versions']:
                fields['resource_versions'] = None
        return fields

    @property
    def is_active(self):
        return not utils.is_agent_down(self.heartbeat_timestamp)
