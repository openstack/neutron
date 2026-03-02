# Copyright (c) 2026 OpenStack Foundation
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

from neutron_lib.objects import common_types
from neutron_lib.services.pvlan import constants as pvlan_const
from oslo_versionedobjects import fields as obj_fields

from neutron.db.models import pvlan as pvlan_models
from neutron.objects import base


@base.NeutronObjectRegistry.register
class NetworkPVLAN(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = pvlan_models.NetworkPVLAN

    primary_keys = ['network_id']

    fields = {
        'network_id': common_types.UUIDField(),
        'pvlan': obj_fields.BooleanField(default=False),
    }


@base.NeutronObjectRegistry.register
class PortPVLAN(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = pvlan_models.PortPVLAN

    primary_keys = ['port_id']

    fields = {
        'port_id': common_types.UUIDField(),
        'pvlan_type': obj_fields.EnumField(
            valid_values=pvlan_const.PVLAN_TYPES),
        'pvlan_community': obj_fields.StringField(nullable=True),
    }
