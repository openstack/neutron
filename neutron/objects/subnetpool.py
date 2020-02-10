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
from neutron_lib.db import model_query
from neutron_lib.objects import common_types
from oslo_versionedobjects import fields as obj_fields
import sqlalchemy as sa

from neutron._i18n import _
from neutron.db import models_v2 as models
from neutron.db import rbac_db_models
from neutron.extensions import rbac as ext_rbac
from neutron.objects import base
from neutron.objects.db import api as obj_db_api
from neutron.objects import rbac
from neutron.objects import rbac_db
from neutron.objects import subnet


@base.NeutronObjectRegistry.register
class SubnetPoolRBAC(rbac.RBACBaseObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = rbac_db_models.SubnetPoolRBAC


@base.NeutronObjectRegistry.register
class SubnetPool(rbac_db.NeutronRbacObject):
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

    @classmethod
    def get_bound_tenant_ids(cls, context, obj_id):
        sn_objs = subnet.Subnet.get_objects(context, subnetpool_id=obj_id)
        return {snp.project_id for snp in sn_objs}

    @classmethod
    def validate_rbac_policy_create(cls, resource, event, trigger,
                                    payload=None):
        context = payload.context
        policy = payload.request_body

        db_obj = obj_db_api.get_object(
            cls, context.elevated(), id=policy['object_id'])

        if not db_obj["address_scope_id"]:
            # Nothing to validate
            return

        rbac_as_model = rbac_db_models.AddressScopeRBAC

        # Ensure that target project has access to AS
        shared_to_target_project_or_to_all = (
            sa.and_(
                rbac_as_model.target_tenant.in_(
                    ["*", policy['target_tenant']]
                ),
                rbac_as_model.object_id == db_obj["address_scope_id"]
            )
        )

        matching_policies = model_query.query_with_hooks(
            context, rbac_db_models.AddressScopeRBAC
        ).filter(shared_to_target_project_or_to_all).count()

        if matching_policies == 0:
            raise ext_rbac.RbacPolicyInitError(
                object_id=policy['object_id'],
                reason=_("target project doesn't have access to "
                         "associated address scope."))


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
