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
from oslo_utils import versionutils
from oslo_versionedobjects import fields as obj_fields

from neutron.db.models import address_group as models
from neutron.db import rbac_db_models
from neutron.objects import base
from neutron.objects import rbac
from neutron.objects import rbac_db
from neutron.objects import securitygroup


@base.NeutronObjectRegistry.register
class AddressGroupRBAC(rbac.RBACBaseObject):
    # Version 1.0: Initial version
    # Version 1.1: Changed 'target_tenant' to 'target_project'
    VERSION = '1.1'

    db_model = rbac_db_models.AddressGroupRBAC


@base.NeutronObjectRegistry.register
class AddressGroup(rbac_db.NeutronRbacObject):
    # Version 1.0: Initial version
    # Version 1.1: Added standard attributes
    # Version 1.2: Added RBAC support
    VERSION = '1.2'

    # required by RbacNeutronMetaclass
    rbac_db_cls = AddressGroupRBAC

    db_model = models.AddressGroup

    fields = {
        'id': common_types.UUIDField(),
        'name': obj_fields.StringField(nullable=True),
        'project_id': obj_fields.StringField(),
        'shared': obj_fields.BooleanField(default=False),
        'addresses': obj_fields.ListOfObjectsField('AddressAssociation',
                                                   nullable=True)
    }
    synthetic_fields = ['addresses']

    def obj_make_compatible(self, primitive, target_version):
        _target_version = versionutils.convert_version_to_tuple(target_version)
        if _target_version < (1, 1):
            standard_fields = ['revision_number', 'created_at', 'updated_at']
            for f in standard_fields:
                primitive.pop(f, None)
        if _target_version < (1, 2):
            primitive.pop('shared', None)

    @classmethod
    def get_bound_project_ids(cls, context, obj_id):
        ag_objs = securitygroup.SecurityGroupRule.get_objects(
            context, remote_address_group_id=[obj_id])
        return {ag.project_id for ag in ag_objs}


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
