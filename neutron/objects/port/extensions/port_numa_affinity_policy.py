# Copyright (c) 2020 Red Hat, Inc.
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

from neutron.db.models import port_numa_affinity_policy
from neutron.objects import base


# TODO(ralonsoh): move to neutron_lib.objects.common_types
class NumaAffinityPoliciesEnumField(obj_fields.AutoTypedField):
    AUTO_TYPE = obj_fields.Enum(valid_values=lib_constants.PORT_NUMA_POLICIES)


@base.NeutronObjectRegistry.register
class PortNumaAffinityPolicy(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = port_numa_affinity_policy.PortNumaAffinityPolicy

    primary_keys = ['port_id']

    new_facade = True

    fields = {
        'port_id': common_types.UUIDField(),
        'numa_affinity_policy': NumaAffinityPoliciesEnumField(),
    }

    foreign_keys = {'Port': {'port_id': 'id'}}
