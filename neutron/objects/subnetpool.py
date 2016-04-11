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
from oslo_log import log
from oslo_versionedobjects import base as obj_base
from oslo_versionedobjects import fields as obj_fields

from neutron.db import api as db_api
from neutron.db import models_v2 as models
from neutron.objects import base
from neutron.objects import common_types

LOG = log.getLogger(__name__)


@obj_base.VersionedObjectRegistry.register
class SubnetPool(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = models.SubnetPool

    fields = {
        'id': obj_fields.UUIDField(),
        'tenant_id': obj_fields.UUIDField(nullable=True),
        'name': obj_fields.StringField(nullable=True),
        'ip_version': common_types.IPVersionEnumField(),
        'default_prefixlen': common_types.IPNetworkPrefixLenField(),
        'min_prefixlen': common_types.IPNetworkPrefixLenField(),
        'max_prefixlen': common_types.IPNetworkPrefixLenField(),
        'shared': obj_fields.BooleanField(),
        'is_default': obj_fields.BooleanField(),
        'default_quota': obj_fields.IntegerField(nullable=True),
        'hash': obj_fields.StringField(nullable=True),
        'address_scope_id': obj_fields.UUIDField(nullable=True),
        'prefixes': common_types.ListOfIPNetworksField(nullable=True)
    }

    fields_no_update = ['id', 'tenant_id']

    synthetic_fields = ['prefixes']

    @classmethod
    def modify_fields_from_db(cls, db_obj):
        fields = super(SubnetPool, cls).modify_fields_from_db(db_obj)
        if 'prefixes' in fields:
            fields['prefixes'] = [
                netaddr.IPNetwork(prefix.cidr)
                for prefix in fields['prefixes']
            ]
        return fields

    def modify_fields_to_db(self, fields):
        result = super(SubnetPool, self).modify_fields_to_db(fields)
        if 'prefixes' in result:
            result['prefixes'] = [
                models.SubnetPoolPrefix(cidr=str(prefix),
                                        subnetpool_id=self.id)
                for prefix in result['prefixes']
            ]
        return result

    def reload_prefixes(self):
        prefixes = [
            obj.cidr
            for obj in SubnetPoolPrefix.get_objects(
                self._context,
                subnetpool_id=self.id)
        ]
        setattr(self, 'prefixes', prefixes)
        self.obj_reset_changes(['prefixes'])

    @classmethod
    def get_object(cls, context, **kwargs):
        with db_api.autonested_transaction(context.session):
            pool_obj = super(SubnetPool, cls).get_object(context, **kwargs)
            if pool_obj is not None:
                pool_obj.reload_prefixes()
            return pool_obj

    @classmethod
    def get_objects(cls, context, **kwargs):
        with db_api.autonested_transaction(context.session):
            objs = super(SubnetPool, cls).get_objects(context, **kwargs)
            for obj in objs:
                obj.reload_prefixes()
            return objs

    def _get_changed_synthetic_fields(self):
        fields = self.obj_get_changes()
        for field in self._get_changed_persistent_fields():
            if field in fields:
                del fields[field]
        return fields

    # TODO(ihrachys): Consider extending base to trigger registered methods
    def create(self):
        synthetic_changes = self._get_changed_synthetic_fields()
        with db_api.autonested_transaction(self._context.session):
            super(SubnetPool, self).create()
            if 'prefixes' in synthetic_changes:
                for prefix in self.prefixes:
                    prefix = SubnetPoolPrefix(
                        self._context, subnetpool_id=self.id, cidr=prefix)
                    prefix.create()
            self.reload_prefixes()

    # TODO(ihrachys): Consider extending base to trigger registered methods
    def update(self):
        with db_api.autonested_transaction(self._context.session):
            synthetic_changes = self._get_changed_synthetic_fields()
            super(SubnetPool, self).update()
            if synthetic_changes:
                if 'prefixes' in synthetic_changes:
                    old = SubnetPoolPrefix.get_objects(
                        self._context, subnetpool_id=self.id)
                    for prefix in old:
                        prefix.delete()
                    for prefix in self.prefixes:
                        prefix_obj = SubnetPoolPrefix(self._context,
                                                      subnetpool_id=self.id,
                                                      cidr=prefix)
                        prefix_obj.create()


@obj_base.VersionedObjectRegistry.register
class SubnetPoolPrefix(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = models.SubnetPoolPrefix

    fields = {
        'subnetpool_id': obj_fields.UUIDField(),
        'cidr': obj_fields.IPNetworkField(),
    }

    primary_keys = ['subnetpool_id', 'cidr']

    # TODO(ihrachys): get rid of it once we switch the db model to using CIDR
    # custom type
    def modify_fields_to_db(self, fields):
        result = super(SubnetPoolPrefix, self).modify_fields_to_db(fields)
        if 'cidr' in result:
            result['cidr'] = str(result['cidr'])
        return result

    # TODO(ihrachys): get rid of it once we switch the db model to using CIDR
    # custom type
    @classmethod
    def modify_fields_from_db(cls, db_obj):
        fields = super(SubnetPoolPrefix, cls).modify_fields_from_db(db_obj)
        if 'cidr' in fields:
            fields['cidr'] = netaddr.IPNetwork(fields['cidr'])
        return fields
