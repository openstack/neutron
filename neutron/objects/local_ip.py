# Copyright 2021 Huawei, Inc.
# All rights reserved.
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

import netaddr

from neutron_lib.objects import common_types
from oslo_versionedobjects import fields as obj_fields

from neutron.db.models import local_ip as lip_db
from neutron.objects import base


@base.NeutronObjectRegistry.register
class LocalIP(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = lip_db.LocalIP

    fields = {
        'id': common_types.UUIDField(),
        'name': obj_fields.StringField(nullable=True),
        'description': obj_fields.StringField(nullable=True),
        'project_id': obj_fields.StringField(nullable=True),
        'local_port_id': common_types.UUIDField(),
        'network_id': common_types.UUIDField(),
        'local_ip_address': obj_fields.IPAddressField(),
        'ip_mode': obj_fields.StringField(),
    }
    foreign_keys = {'Port': {'local_port_id': 'id'},
                    'LocalIPAssociation': {'id': 'local_ip_id'}}

    fields_no_update = ['project_id', 'local_ip_address',
                        'network_id', 'local_port_id']
    synthetic_fields = []

    @classmethod
    def modify_fields_to_db(cls, fields):
        result = super(LocalIP, cls).modify_fields_to_db(fields)
        if 'local_ip_address' in result:
            result['local_ip_address'] = cls.filter_to_str(
                result['local_ip_address'])
        return result

    @classmethod
    def modify_fields_from_db(cls, db_obj):
        fields = super(LocalIP, cls).modify_fields_from_db(db_obj)
        if 'local_ip_address' in fields:
            fields['local_ip_address'] = netaddr.IPAddress(
                fields['local_ip_address'])
        return fields


@base.NeutronObjectRegistry.register
class LocalIPAssociation(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = lip_db.LocalIPAssociation

    fields = {
        'id': obj_fields.StringField(),
        'local_ip_id': common_types.UUIDField(nullable=False),
        'fixed_port_id': common_types.UUIDField(nullable=False),
        'fixed_ip': obj_fields.IPAddressField(nullable=False),
        'local_ip': obj_fields.ObjectField('LocalIP'),
    }

    primary_keys = ['local_ip_id', 'fixed_port_id']
    foreign_keys = {'LocalIP': {'local_ip_id': 'id'},
                    'Port': {'fixed_port_id': 'id'}}
    fields_no_update = ['local_ip_id', 'fixed_port_id', 'fixed_ip']
    synthetic_fields = ['id', 'local_ip']

    @classmethod
    def modify_fields_to_db(cls, fields):
        result = super(LocalIPAssociation, cls).modify_fields_to_db(fields)
        if 'fixed_ip' in result:
            result['fixed_ip'] = cls.filter_to_str(result['fixed_ip'])
        return result

    @classmethod
    def modify_fields_from_db(cls, db_obj):
        fields = super(LocalIPAssociation, cls).modify_fields_from_db(db_obj)
        if 'fixed_ip' in fields:
            fields['fixed_ip'] = netaddr.IPAddress(fields['fixed_ip'])
        return fields

    def obj_load_attr(self, attrname):
        if attrname in ['id']:
            self._set_id()
        super(LocalIPAssociation, self).obj_load_attr(attrname)

    def from_db_object(self, db_obj):
        super(LocalIPAssociation, self).from_db_object(db_obj)
        self._set_id()

    def _set_id(self):
        self.id = self.local_ip_id + '_' + self.fixed_port_id
        self.obj_reset_changes(['id'])
