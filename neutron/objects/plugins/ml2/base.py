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

import netaddr

from neutron.objects import base


class EndpointBase(base.NeutronDbObject):

    primary_keys = ['ip_address']

    @classmethod
    def modify_fields_from_db(cls, db_obj):
        result = super(EndpointBase, cls).modify_fields_from_db(db_obj)
        if 'ip_address' in result:
            result['ip_address'] = netaddr.IPAddress(result['ip_address'])
        return result

    @classmethod
    def modify_fields_to_db(cls, fields):
        result = super(EndpointBase, cls).modify_fields_to_db(fields)
        if 'ip_address' in fields:
            result['ip_address'] = cls.filter_to_str(result['ip_address'])
        return result
