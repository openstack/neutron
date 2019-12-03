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
from oslo_versionedobjects import fields as obj_fields

from neutron.db.models import uplink_status_propagation as db_models
from neutron.objects import base


@base.NeutronObjectRegistry.register
class PortUplinkStatusPropagation(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = "1.0"

    db_model = db_models.PortUplinkStatusPropagation

    primary_keys = ['port_id']

    fields = {
        'port_id': common_types.UUIDField(),
        'propagate_uplink_status': obj_fields.BooleanField(default=False),
    }

    foreign_keys = {'Port': {'port_id': 'id'}}
