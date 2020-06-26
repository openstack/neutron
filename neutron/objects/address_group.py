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

from neutron.db.models import address_group as models
from neutron.objects import base


@base.NeutronObjectRegistry.register
class AddressGroup(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = models.AddressGroup

    fields = {
        'id': common_types.UUIDField(),
        'name': obj_fields.StringField(nullable=True),
        'description': obj_fields.StringField(nullable=True),
        'project_id': obj_fields.StringField(),
        'addresses': obj_fields.ListOfObjectsField('AddressAssociation',
                                                   nullable=True)
    }
    synthetic_fields = ['addresses']


@base.NeutronObjectRegistry.register
class AddressAssociation(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = models.AddressAssociation

    fields = {
        'address': common_types.IPNetworkField(nullable=False),
        'address_group_id': common_types.UUIDField(nullable=False)
    }
    primary_keys = ['address', 'address_group_id']
    foreign_keys = {'AddressGroup': {'address_group_id': 'id'}}

    @classmethod
    def modify_fields_to_db(cls, fields):
        result = super(AddressAssociation, cls).modify_fields_to_db(fields)
        if 'address' in result:
            result['address'] = cls.filter_to_str(result['address'])
        return result

    @classmethod
    def modify_fields_from_db(cls, db_obj):
        fields = super(AddressAssociation, cls).modify_fields_from_db(db_obj)
        if 'address' in fields:
            fields['address'] = netaddr.IPNetwork(fields['address'])
        return fields
