# Copyright (c) 2023 Red Hat, Inc.
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

from neutron_lib import constants as lib_constants
from neutron_lib.objects import common_types
from oslo_versionedobjects import fields as obj_fields

from neutron.db.models import port_hardware_offload_type
from neutron.objects import base


# TODO(ralonsoh): move to neutron_lib.objects.common_types
class PortHardwareOffloadTypeEnumField(obj_fields.AutoTypedField):
    AUTO_TYPE = obj_fields.Enum(valid_values=lib_constants.VALID_HWOL_TYPES)


@base.NeutronObjectRegistry.register
class PortHardwareOffloadType(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = port_hardware_offload_type.PortHardwareOffloadType

    primary_keys = ['port_id']

    fields = {
        'port_id': common_types.UUIDField(),
        'hardware_offload_type': PortHardwareOffloadTypeEnumField(),
    }

    foreign_keys = {'Port': {'port_id': 'id'}}
