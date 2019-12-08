# Copyright (c) 2015 OpenStack Foundation.
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

import netaddr
from oslo_versionedobjects import fields as obj_fields

from neutron.db import models_v2 as models
from neutron.db import rbac_db_models
from neutron.objects import base
from neutron.objects import common_types
from neutron.objects import rbac
from neutron.objects import rbac_db


@base.NeutronObjectRegistry.register
class SubnetPoolRBAC(rbac.RBACBaseObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = rbac_db_models.SubnetPoolRBAC

    @classmethod
    def get_projects(cls, context, object_id=None, action=None,
                     target_tenant=None):
        clauses = []
        if object_id:
            clauses.append(rbac_db_models.SubnetPoolRBAC.object_id == object_id)
        if action:
            clauses.append(rbac_db_models.SubnetPoolRBAC.action == action)
        if target_tenant:
            clauses.append(rbac_db_models.SubnetPoolRBAC.target_tenant ==
                           target_tenant)
        query = context.session.query(
            rbac_db_models.SubnetPoolRBAC.target_tenant)
        if clauses:
            query = query.filter(sa.and_(*clauses))
        return [data[0] for data in query]


@base.NeutronObjectRegistry.register
class SubnetPool(base.NeutronDbObject):
    # Version 1.0: Initial version
    # Version 1.1: Add RBAC support
    VERSION = '1.1'

    # required by RbacNeutronMetaclass
    rbac_db_cls = SubnetPoolRBAC
    db_model = models.SubnetPool

    fields = {
        'id': common_types.UUIDField(),
        'project_id': obj_fields.StringField(nullable=True),
        'name': obj_fields.StringField(nullable=True),
        'ip_version': common_types.IPVersionEnumField(),
        'default_prefixlen': common_types.IPNetworkPrefixLenField(),
        'min_prefixlen': common_types.IPNetworkPrefixLenField(),
        'max_prefixlen': common_types.IPNetworkPrefixLenField(),
        'shared': obj_fields.BooleanField(),
        'is_default': obj_fields.BooleanField(),
        'default_quota': obj_fields.IntegerField(nullable=True),
        'hash': obj_fields.StringField(nullable=True),
        'address_scope_id': common_types.UUIDField(nullable=True),
        'prefixes': common_types.ListOfIPNetworksField(nullable=True)
    }

    fields_no_update = ['id', 'project_id']

    synthetic_fields = ['prefixes']

    def from_db_object(self, db_obj):
        super(SubnetPool, self).from_db_object(db_obj)
        self.prefixes = []
        self.prefixes = [
            prefix.cidr
            for prefix in db_obj.get('prefixes', [])
        ]
        self.obj_reset_changes(['prefixes'])

    def _attach_prefixes(self, prefixes):
        SubnetPoolPrefix.delete_objects(self.obj_context,
                                        subnetpool_id=self.id)
        for prefix in prefixes:
            SubnetPoolPrefix(self.obj_context, subnetpool_id=self.id,
                             cidr=prefix).create()
        self.prefixes = prefixes
        self.obj_reset_changes(['prefixes'])

    # TODO(ihrachys): Consider extending base to trigger registered methods
    def create(self):
        fields = self.obj_get_changes()
        with self.db_context_writer(self.obj_context):
            prefixes = self.prefixes
            super(SubnetPool, self).create()
            if 'prefixes' in fields:
                self._attach_prefixes(prefixes)

    # TODO(ihrachys): Consider extending base to trigger registered methods
    def update(self):
        fields = self.obj_get_changes()
        with self.db_context_writer(self.obj_context):
            super(SubnetPool, self).update()
            if 'prefixes' in fields:
                self._attach_prefixes(fields['prefixes'])

    def obj_make_compatible(self, primitive, target_version):
        _target_version = versionutils.convert_version_to_tuple(target_version)
        if _target_version < (1, 1):
            primitive.pop('shared')

    @classmethod
    def get_bound_tenant_ids(cls, context, obj_id):
        port_objs = ports.Port.get_objects(context,
                                           security_group_ids=[obj_id])
        return {port.tenant_id for port in port_objs}


@base.NeutronObjectRegistry.register
class SubnetPoolPrefix(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = models.SubnetPoolPrefix

    fields = {
        'subnetpool_id': common_types.UUIDField(),
        'cidr': common_types.IPNetworkField(),
    }

    primary_keys = ['subnetpool_id', 'cidr']

    # TODO(ihrachys): get rid of it once we switch the db model to using CIDR
    # custom type
    @classmethod
    def modify_fields_to_db(cls, fields):
        result = super(SubnetPoolPrefix, cls).modify_fields_to_db(fields)
        if 'cidr' in result:
            result['cidr'] = cls.filter_to_str(result['cidr'])
        return result

    # TODO(ihrachys): get rid of it once we switch the db model to using CIDR
    # custom type
    @classmethod
    def modify_fields_from_db(cls, db_obj):
        fields = super(SubnetPoolPrefix, cls).modify_fields_from_db(db_obj)
        if 'cidr' in fields:
            fields['cidr'] = netaddr.IPNetwork(fields['cidr'])
        return fields
