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

from neutron_lib.db import api as db_api
from neutron_lib.objects import common_types
from oslo_utils import versionutils
from oslo_versionedobjects import fields as obj_fields

from neutron.db.models import address_scope as models
from neutron.db import models_v2
from neutron.db import rbac_db_models
from neutron.objects import base
from neutron.objects import rbac
from neutron.objects import rbac_db
from neutron.objects import subnetpool


@base.NeutronObjectRegistry.register
class AddressScopeRBAC(rbac.RBACBaseObject):
    # Version 1.0: Initial version
    # Version 1.1: Changed 'target_tenant' to 'target_project'
    VERSION = '1.1'

    db_model = rbac_db_models.AddressScopeRBAC


@base.NeutronObjectRegistry.register
class AddressScope(rbac_db.NeutronRbacObject):
    # Version 1.0: Initial version
    # Version 1.1: Add RBAC support
    # Version 1.2: Remove "shared" field
    VERSION = '1.2'

    # required by RbacNeutronMetaclass
    rbac_db_cls = AddressScopeRBAC
    _rbac_shared_field = False

    db_model = models.AddressScope

    fields = {
        'id': common_types.UUIDField(),
        'project_id': obj_fields.StringField(nullable=True),
        'name': obj_fields.StringField(),
        'ip_version': common_types.IPVersionEnumField(),
    }

    @classmethod
    @db_api.CONTEXT_READER
    def get_network_address_scope(cls, context, network_id, ip_version):
        query = context.session.query(cls.db_model)
        query = query.join(
            models_v2.SubnetPool,
            models_v2.SubnetPool.address_scope_id == cls.db_model.id)
        query = query.filter(
            cls.db_model.ip_version == ip_version,
            models_v2.Subnet.subnetpool_id == models_v2.SubnetPool.id,
            models_v2.Subnet.network_id == network_id)
        scope_model_obj = query.one_or_none()

        if scope_model_obj:
            return cls._load_object(context, scope_model_obj)

        return None

    @classmethod
    def get_bound_project_ids(cls, context, obj_id):
        snp_objs = subnetpool.SubnetPool.get_objects(
            context, address_scope_id=obj_id, fields=['project_id'])
        return {snp['project_id'] for snp in snp_objs}

    def obj_make_compatible(self, primitive, target_version):
        _target_version = versionutils.convert_version_to_tuple(target_version)
        if _target_version >= (1, 2):
            primitive.pop('shared', None)
        elif 'shared' not in primitive:
            if self.obj_context and self.id:
                primitive['shared'] = self.get_shared_with_project(
                    self.obj_context.elevated(), self.rbac_db_cls,
                    self.id, self.project_id)
            else:
                primitive['shared'] = False
        return super().obj_make_compatible(primitive, target_version)
