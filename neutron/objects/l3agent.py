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

from oslo_versionedobjects import base as obj_base
from oslo_versionedobjects import fields as obj_fields

from neutron.db.models import l3agent
from neutron.objects import base
from neutron.objects import common_types


@obj_base.VersionedObjectRegistry.register
class RouterL3AgentBinding(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = l3agent.RouterL3AgentBinding

    primary_keys = ['router_id', 'l3_agent_id']

    fields = {
        'router_id': common_types.UUIDField(),
        'l3_agent_id': common_types.UUIDField(),
        'binding_index': obj_fields.IntegerField(
                             default=l3agent.LOWEST_BINDING_INDEX),
    }
