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

from neutron_lib.api.definitions import port_security
from neutron_lib.objects import common_types
from oslo_versionedobjects import fields as obj_fields

from neutron.objects import base


class _PortSecurity(base.NeutronDbObject):
    fields = {
        'id': common_types.UUIDField(),
        'port_security_enabled': obj_fields.BooleanField(
            default=port_security.DEFAULT_PORT_SECURITY),
    }

    foreign_keys = {
        'Port': {'id': 'id'},
        'Network': {'id': 'id'},
    }
