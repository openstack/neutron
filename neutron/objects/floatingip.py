# Copyright (c) 2016 Intel Corporation.
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

from neutron.db.models import dns as models
from neutron.objects import base


@base.NeutronObjectRegistry.register
class FloatingIPDNS(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = models.FloatingIPDNS

    primary_keys = ['floatingip_id']
    foreign_keys = {'FloatingIP': {'floatingip_id': 'id'}}

    fields = {
        'floatingip_id': common_types.UUIDField(),
        'dns_name': common_types.DomainNameField(),
        'dns_domain': common_types.DomainNameField(),
        'published_dns_name': common_types.DomainNameField(),
        'published_dns_domain': common_types.DomainNameField(),
    }
