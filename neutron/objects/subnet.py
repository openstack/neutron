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

from oslo_versionedobjects import fields as obj_fields

from neutron.common import utils
from neutron.db.models import subnet_service_type
from neutron.db import models_v2
from neutron.objects import base
from neutron.objects import common_types
from neutron.objects import network
from neutron.objects import rbac_db


@base.NeutronObjectRegistry.register
class DNSNameServer(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = models_v2.DNSNameServer

    primary_keys = ['address', 'subnet_id']

    foreign_keys = {'Subnet': {'subnet_id': 'id'}}

    fields = {
        'address': obj_fields.StringField(),
        'subnet_id': common_types.UUIDField(),
        'order': obj_fields.IntegerField()
    }

    @classmethod
    def get_objects(cls, context, _pager=None, validate_filters=True,
                    **kwargs):
        """Fetch DNSNameServer objects with default sort by 'order' field.
        """
        if not _pager:
            _pager = base.Pager()
        if not _pager.sorts:
            # (NOTE) True means ASC, False is DESC
            _pager.sorts = [('order', True)]
        return super(DNSNameServer, cls).get_objects(context, _pager,
                                                     validate_filters,
                                                     **kwargs)


@base.NeutronObjectRegistry.register
class Route(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = models_v2.SubnetRoute

    primary_keys = ['destination', 'nexthop', 'subnet_id']

    foreign_keys = {'Subnet': {'subnet_id': 'id'}}

    fields = {
        'subnet_id': common_types.UUIDField(),
        'destination': common_types.IPNetworkField(),
        'nexthop': obj_fields.IPAddressField()
    }

    @classmethod
    def modify_fields_from_db(cls, db_obj):
        # TODO(korzen) remove this method when IP and CIDR decorator ready
        result = super(Route, cls).modify_fields_from_db(db_obj)
        if 'destination' in result:
            result['destination'] = utils.AuthenticIPNetwork(
                result['destination'])
        if 'nexthop' in result:
            result['nexthop'] = netaddr.IPAddress(result['nexthop'])
        return result

    @classmethod
    def modify_fields_to_db(cls, fields):
        # TODO(korzen) remove this method when IP and CIDR decorator ready
        result = super(Route, cls).modify_fields_to_db(fields)
        if 'destination' in result:
            result['destination'] = cls.filter_to_str(result['destination'])
        if 'nexthop' in fields:
            result['nexthop'] = cls.filter_to_str(result['nexthop'])
        return result


@base.NeutronObjectRegistry.register
class IPAllocationPool(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = models_v2.IPAllocationPool

    foreign_keys = {'Subnet': {'subnet_id': 'id'}}

    fields_need_translation = {
        'start': 'first_ip',
        'end': 'last_ip'
    }

    fields = {
        'id': common_types.UUIDField(),
        'subnet_id': common_types.UUIDField(),
        'start': obj_fields.IPAddressField(),
        'end': obj_fields.IPAddressField()
    }

    fields_no_update = ['subnet_id']

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
            result['first_ip'] = cls.filter_to_str(result['first_ip'])
        if 'last_ip' in result:
            result['last_ip'] = cls.filter_to_str(result['last_ip'])
        return result


@base.NeutronObjectRegistry.register
class SubnetServiceType(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = subnet_service_type.SubnetServiceType

    foreign_keys = {'Subnet': {'subnet_id': 'id'}}

    primary_keys = ['subnet_id', 'service_type']

    fields = {
        'subnet_id': common_types.UUIDField(),
        'service_type': obj_fields.StringField()
    }


# RBAC metaclass is not applied here because 'shared' attribute of Subnet
# is dependent on Network 'shared' state, and in Subnet object
# it can be read-only. The necessary changes are applied manually:
#   - defined 'shared' attribute in 'fields'
#   - added 'shared' to synthetic_fields
#   - registered extra_filter_name for 'shared' attribute
#   - added loading shared attribute based on network 'rbac_entries'
@base.NeutronObjectRegistry.register
class Subnet(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = models_v2.Subnet

    fields = {
        'id': common_types.UUIDField(),
        'project_id': obj_fields.StringField(nullable=True),
        'name': obj_fields.StringField(nullable=True),
        'network_id': common_types.UUIDField(),
        'segment_id': common_types.UUIDField(nullable=True),
        # NOTE: subnetpool_id can be 'prefix_delegation' string
        # when the IPv6 Prefix Delegation is enabled
        'subnetpool_id': obj_fields.StringField(nullable=True),
        'ip_version': common_types.IPVersionEnumField(),
        'cidr': common_types.IPNetworkField(),
        'gateway_ip': obj_fields.IPAddressField(nullable=True),
        'allocation_pools': obj_fields.ListOfObjectsField('IPAllocationPool',
                                                          nullable=True),
        'enable_dhcp': obj_fields.BooleanField(nullable=True),
        'shared': obj_fields.BooleanField(nullable=True),
        'dns_nameservers': obj_fields.ListOfObjectsField('DNSNameServer',
                                                         nullable=True),
        'host_routes': obj_fields.ListOfObjectsField('Route', nullable=True),
        'ipv6_ra_mode': common_types.IPV6ModeEnumField(nullable=True),
        'ipv6_address_mode': common_types.IPV6ModeEnumField(nullable=True),
        'service_types': obj_fields.ListOfStringsField(nullable=True)
    }

    synthetic_fields = ['allocation_pools', 'dns_nameservers', 'host_routes',
                        'service_types', 'shared']

    foreign_keys = {'Network': {'network_id': 'id'}}

    fields_no_update = ['project_id', 'network_id', 'segment_id']

    fields_need_translation = {
        'host_routes': 'routes'
    }

    def __init__(self, context=None, **kwargs):
        super(Subnet, self).__init__(context, **kwargs)
        self.add_extra_filter_name('shared')

    def obj_load_attr(self, attrname):
        if attrname == 'shared':
            return self._load_shared()
        if attrname == 'service_types':
            return self._load_service_types()
        super(Subnet, self).obj_load_attr(attrname)

    def _load_shared(self, db_obj=None):
        if db_obj:
            # NOTE(korzen) db_obj is passed when Subnet object is loaded
            # from DB
            rbac_entries = db_obj.get('rbac_entries') or {}
            shared = (rbac_db.RbacNeutronDbObjectMixin.
                      is_network_shared(self.obj_context, rbac_entries))
        else:
            # NOTE(korzen) this case is used when Subnet object was
            # instantiated and without DB interaction (get_object(s), update,
            # create), it should be rare case to load 'shared' by that method
            shared = (rbac_db.RbacNeutronDbObjectMixin.
                      get_shared_with_tenant(self.obj_context.elevated(),
                                             network.NetworkRBAC,
                                             self.network_id,
                                             self.project_id))
        setattr(self, 'shared', shared)
        self.obj_reset_changes(['shared'])

    def _load_service_types(self, db_obj=None):
        if db_obj:
            service_types = db_obj.get('service_types', [])
        else:
            service_types = SubnetServiceType.get_objects(self.obj_context,
                                                          subnet_id=self.id)

        self.service_types = [service_type['service_type'] for
                              service_type in service_types]
        self.obj_reset_changes(['service_types'])

    def from_db_object(self, db_obj):
        super(Subnet, self).from_db_object(db_obj)
        self._load_shared(db_obj)
        self._load_service_types(db_obj)

    @classmethod
    def modify_fields_from_db(cls, db_obj):
        # TODO(korzen) remove this method when IP and CIDR decorator ready
        result = super(Subnet, cls).modify_fields_from_db(db_obj)
        if 'cidr' in result:
            result['cidr'] = utils.AuthenticIPNetwork(result['cidr'])
        if 'gateway_ip' in result and result['gateway_ip'] is not None:
            result['gateway_ip'] = netaddr.IPAddress(result['gateway_ip'])
        return result

    @classmethod
    def modify_fields_to_db(cls, fields):
        # TODO(korzen) remove this method when IP and CIDR decorator ready
        result = super(Subnet, cls).modify_fields_to_db(fields)
        if 'cidr' in result:
            result['cidr'] = cls.filter_to_str(result['cidr'])
        if 'gateway_ip' in result and result['gateway_ip'] is not None:
            result['gateway_ip'] = cls.filter_to_str(result['gateway_ip'])
        return result
