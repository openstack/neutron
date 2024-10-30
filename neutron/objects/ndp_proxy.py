# Copyright (c) 2022 Troila
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

from neutron_lib.objects import common_types
from oslo_log import log as logging
from oslo_versionedobjects import fields as obj_fields

from neutron.db.models import ndp_proxy as models
from neutron.objects import base

LOG = logging.getLogger(__name__)


@base.NeutronObjectRegistry.register
class NDPProxy(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = models.NDPProxy

    primary_keys = ['id']
    foreign_keys = {'Router': {'router_id': id}, 'Port': {'port_id': id}}

    fields = {
        'id': common_types.UUIDField(),
        'name': obj_fields.StringField(nullable=True),
        'project_id': obj_fields.StringField(nullable=True),
        'router_id': common_types.UUIDField(nullable=False),
        'port_id': common_types.UUIDField(nullable=False),
        'ip_address': obj_fields.IPV6AddressField(),
        'description': obj_fields.StringField(nullable=True)
    }

    fields_no_update = ['id', 'project_id']

    @classmethod
    def modify_fields_from_db(cls, db_obj):
        result = super().modify_fields_from_db(db_obj)
        if 'ip_address' in result:
            result['ip_address'] = netaddr.IPAddress(
                result['ip_address'])
        return result

    @classmethod
    def modify_fields_to_db(cls, fields):
        result = super().modify_fields_to_db(fields)
        if 'ip_address' in result:
            if result['ip_address'] is not None:
                result['ip_address'] = cls.filter_to_str(
                    result['ip_address'])
        return result


@base.NeutronObjectRegistry.register
class RouterNDPProxyState(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'
    db_model = models.RouterNDPProxyState

    foreign_keys = {'Router': {'router_id': id}}
    primary_keys = ['router_id']

    fields = {
        'router_id': common_types.UUIDField(nullable=False),
        'enable_ndp_proxy': obj_fields.BooleanField(nullable=False),
    }
