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

from oslo_versionedobjects import base as obj_base
from oslo_versionedobjects import fields as obj_fields

from neutron.db import models_v2
from neutron.objects import base
from neutron.objects import common_types


@obj_base.VersionedObjectRegistry.register
class DNSNameServer(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = models_v2.DNSNameServer

    primary_keys = ['address', 'subnet_id']

    foreign_keys = {'subnet_id': 'id'}

    fields = {
        'address': obj_fields.StringField(),
        'subnet_id': obj_fields.UUIDField(),
        'order': obj_fields.IntegerField()
    }

    @classmethod
    def get_objects(cls, context, _pager=None, **kwargs):
        """Fetch DNSNameServer objects with default sort by 'order' field.
        """
        if not _pager:
            _pager = base.Pager()
        if not _pager.sorts:
            # (NOTE) True means ASC, False is DESC
            _pager.sorts = [('order', True)]
        return super(DNSNameServer, cls).get_objects(context, _pager,
                                                     **kwargs)


@obj_base.VersionedObjectRegistry.register
class Route(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = models_v2.SubnetRoute

    primary_keys = ['destination', 'nexthop', 'subnet_id']

    foreign_keys = {'subnet_id': 'id'}

    fields = {
        'subnet_id': obj_fields.UUIDField(),
        'destination': obj_fields.IPNetworkField(),
        'nexthop': obj_fields.IPAddressField()
    }

    @classmethod
    def modify_fields_from_db(cls, db_obj):
        # TODO(korzen) remove this method when IP and CIDR decorator ready
        result = super(Route, cls).modify_fields_from_db(db_obj)
        if 'destination' in result:
            result['destination'] = netaddr.IPNetwork(result['destination'])
        if 'nexthop' in result:
            result['nexthop'] = netaddr.IPAddress(result['nexthop'])
        return result

    @classmethod
    def modify_fields_to_db(cls, fields):
        # TODO(korzen) remove this method when IP and CIDR decorator ready
        result = super(Route, cls).modify_fields_to_db(fields)
        if 'destination' in result:
            result['destination'] = str(result['destination'])
        if 'nexthop' in fields:
            result['nexthop'] = str(result['nexthop'])
        return result


@obj_base.VersionedObjectRegistry.register
class IPAllocationPool(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = models_v2.IPAllocationPool

    foreign_keys = {'subnet_id': 'id'}

    fields_need_translation = {
        'start': 'first_ip',
        'end': 'last_ip'
    }

    fields = {
        'id': obj_fields.UUIDField(),
        'subnet_id': obj_fields.UUIDField(),
        'start': obj_fields.IPAddressField(),
        'end': obj_fields.IPAddressField()
    }

    @classmethod
    def modify_fields_from_db(cls, db_obj):
        # TODO(korzen) remove this method when IP and CIDR decorator ready
        result = super(IPAllocationPool, cls).modify_fields_from_db(db_obj)
        if 'start' in result:
            result['start'] = netaddr.IPAddress(result['start'])
        if 'end' in result:
            result['end'] = netaddr.IPAddress(result['end'])
        return result

    @classmethod
    def modify_fields_to_db(cls, fields):
        # TODO(korzen) remove this method when IP and CIDR decorator ready
        result = super(IPAllocationPool, cls).modify_fields_to_db(fields)
        if 'first_ip' in result:
            result['first_ip'] = str(result['first_ip'])
        if 'last_ip' in result:
            result['last_ip'] = str(result['last_ip'])
        return result


@obj_base.VersionedObjectRegistry.register
class Subnet(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = models_v2.Subnet

    fields = {
        'id': obj_fields.UUIDField(),
        'project_id': obj_fields.UUIDField(),
        'name': obj_fields.StringField(),
        'network_id': obj_fields.UUIDField(),
        'subnetpool_id': obj_fields.UUIDField(nullable=True),
        'ip_version': common_types.IPVersionEnumField(),
        'cidr': obj_fields.IPNetworkField(),
        'gateway_ip': obj_fields.IPAddressField(nullable=True),
        'allocation_pools': obj_fields.ListOfObjectsField('IPAllocationPool',
                                                          nullable=True),
        'enable_dhcp': obj_fields.BooleanField(),
        'dns_nameservers': obj_fields.ListOfObjectsField('DNSNameServer',
                                                         nullable=True),
        'host_routes': obj_fields.ListOfObjectsField('Route', nullable=True),
        'ipv6_ra_mode': common_types.IPV6ModeEnumField(nullable=True),
        'ipv6_address_mode': common_types.IPV6ModeEnumField(nullable=True)
    }

    synthetic_fields = ['allocation_pools', 'dns_nameservers', 'host_routes']

    foreign_keys = {'network_id': 'id'}

    fields_need_translation = {
        'project_id': 'tenant_id'
    }

    @classmethod
    def modify_fields_from_db(cls, db_obj):
        # TODO(korzen) remove this method when IP and CIDR decorator ready
        result = super(Subnet, cls).modify_fields_from_db(db_obj)
        if 'cidr' in result:
            result['cidr'] = netaddr.IPNetwork(result['cidr'])
        if 'gateway_ip' in result and result['gateway_ip'] is not None:
            result['gateway_ip'] = netaddr.IPAddress(result['gateway_ip'])
        return result

    @classmethod
    def modify_fields_to_db(cls, fields):
        # TODO(korzen) remove this method when IP and CIDR decorator ready
        result = super(Subnet, cls).modify_fields_to_db(fields)
        if 'cidr' in result:
            result['cidr'] = str(result['cidr'])
        if 'gateway_ip' in result and result['gateway_ip'] is not None:
            result['gateway_ip'] = str(result['gateway_ip'])
        return result
