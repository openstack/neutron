# Copyright (c) 2016 Intel Corporation.
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

from oslo_versionedobjects import fields as obj_fields

from neutron.db.models import flavor as models
from neutron.objects import base
from neutron.objects import common_types


@base.NeutronObjectRegistry.register
class FlavorServiceProfileBinding(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = models.FlavorServiceProfileBinding

    primary_keys = ['flavor_id', 'service_profile_id']

    fields = {
        'flavor_id': common_types.UUIDField(),
        'service_profile_id': common_types.UUIDField(),
    }


@base.NeutronObjectRegistry.register
class ServiceProfile(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = models.ServiceProfile

    synthetic_fields = ['flavor_ids']

    fields = {
        'id': common_types.UUIDField(),
        'description': obj_fields.StringField(nullable=True),
        'driver': obj_fields.StringField(),
        'enabled': obj_fields.BooleanField(default=True),
        'metainfo': obj_fields.StringField(nullable=True),
        'flavor_ids': common_types.SetOfUUIDsField(nullable=True, default=None)
    }

    def from_db_object(self, db_obj):
        super(ServiceProfile, self).from_db_object(db_obj)
        if db_obj.get('flavors', []):
            self.flavor_ids = {
                fl.flavor_id
                for fl in db_obj.flavors
            }
        else:
            self.flavor_ids = set()
        self.obj_reset_changes(['flavor_ids'])


@base.NeutronObjectRegistry.register
class Flavor(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = models.Flavor

    synthetic_fields = ['service_profile_ids']

    fields = {
        'id': common_types.UUIDField(),
        'name': obj_fields.StringField(nullable=True),
        'description': obj_fields.StringField(nullable=True),
        'enabled': obj_fields.BooleanField(default=True),
        'service_type': obj_fields.StringField(nullable=True),
        'service_profile_ids': common_types.SetOfUUIDsField(nullable=True,
                                                            default=None)
    }

    def from_db_object(self, db_obj):
        super(Flavor, self).from_db_object(db_obj)
        if db_obj.get('service_profiles', []):
            self.service_profile_ids = {
                sp.service_profile_id
                for sp in db_obj.service_profiles
            }
        else:
            self.service_profile_ids = set()
        self.obj_reset_changes(['service_profile_ids'])
