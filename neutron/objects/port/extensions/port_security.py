# Copyright 2013 VMware, Inc.  All rights reserved.
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

from oslo_versionedobjects import base as obj_base
from oslo_versionedobjects import fields as obj_fields

from neutron.db import portsecurity_db_common as models
from neutron.objects import base


@obj_base.VersionedObjectRegistry.register
class PortSecurity(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = "1.0"

    db_model = models.PortSecurityBinding

    primary_keys = ['port_id']

    fields = {
        'port_id': obj_fields.UUIDField(),
        'port_security_enabled': obj_fields.BooleanField(default=True),
    }
