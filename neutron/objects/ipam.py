# Copyright (c) 2016 Intel Corporation.
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
from oslo_versionedobjects import fields as obj_fields

from neutron.ipam.drivers.neutrondb_ipam import db_models
from neutron.objects import base


@base.NeutronObjectRegistry.register
class IpamAllocationPool(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = db_models.IpamAllocationPool

    foreign_keys = {'IpamSubnet': {'ipam_subnet_id': 'id'}}

    fields = {
        'id': common_types.UUIDField(),
        'ipam_subnet_id': common_types.UUIDField(),
        'first_ip': obj_fields.IPAddressField(),
        'last_ip': obj_fields.IPAddressField(),
    }

    fields_no_update = ['ipam_subnet_id']

    @classmethod
    def modify_fields_from_db(cls, db_obj):
        result = super().modify_fields_from_db(db_obj)
        if 'first_ip' in result:
            result['first_ip'] = netaddr.IPAddress(result['first_ip'])
        if 'last_ip' in result:
            result['last_ip'] = netaddr.IPAddress(result['last_ip'])
        return result

    @classmethod
    def modify_fields_to_db(cls, fields):
        result = super().modify_fields_to_db(fields)
        if 'first_ip' in result:
            result['first_ip'] = cls.filter_to_str(result['first_ip'])
        if 'last_ip' in result:
            result['last_ip'] = cls.filter_to_str(result['last_ip'])
        return result


@base.NeutronObjectRegistry.register
class IpamAllocation(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = db_models.IpamAllocation

    primary_keys = ['ip_address', 'ipam_subnet_id']

    fields = {
        'ip_address': obj_fields.IPAddressField(),
        'status': common_types.IpamAllocationStatusEnumField(nullable=True),
        'ipam_subnet_id': common_types.UUIDField()
    }

    @classmethod
    def modify_fields_from_db(cls, db_obj):
        result = super().modify_fields_from_db(db_obj)
        if 'ip_address' in result:
            result['ip_address'] = netaddr.IPAddress(result['ip_address'])
        return result

    @classmethod
    def modify_fields_to_db(cls, fields):
        result = super().modify_fields_to_db(fields)
        if 'ip_address' in result:
            result['ip_address'] = cls.filter_to_str(result['ip_address'])
        return result


@base.NeutronObjectRegistry.register
class IpamSubnet(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = db_models.IpamSubnet

    fields = {
        'id': common_types.UUIDField(),
        'neutron_subnet_id': common_types.UUIDField(nullable=True),
        'allocation_pools': obj_fields.ListOfObjectsField(
            'IpamAllocationPool')
    }

    synthetic_fields = ['allocation_pools']
