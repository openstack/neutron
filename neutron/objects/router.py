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

import itertools

import netaddr

from neutron_lib.api.definitions import availability_zone as az_def
from neutron_lib.api.validators import availability_zone as az_validator
from oslo_versionedobjects import fields as obj_fields
import six
from sqlalchemy import func

from neutron.common import constants as n_const
from neutron.common import utils
from neutron.db.models import dvr as dvr_models
from neutron.db.models import l3
from neutron.db.models import l3_attrs
from neutron.db.models import l3agent as rb_model
from neutron.db import models_v2
from neutron.objects import base
from neutron.objects import common_types


@base.NeutronObjectRegistry.register
class RouterRoute(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = l3.RouterRoute

    fields = {
        'router_id': common_types.UUIDField(),
        'destination': common_types.IPNetworkField(),
        'nexthop': obj_fields.IPAddressField()
    }

    primary_keys = ['router_id', 'destination', 'nexthop']
    foreign_keys = {'Router': {'router_id': 'id'}}

    @classmethod
    def modify_fields_from_db(cls, db_obj):
        result = super(RouterRoute, cls).modify_fields_from_db(db_obj)
        if 'destination' in result:
            result['destination'] = utils.AuthenticIPNetwork(
                result['destination'])
        if 'nexthop' in result:
            result['nexthop'] = netaddr.IPAddress(result['nexthop'])
        return result

    @classmethod
    def modify_fields_to_db(cls, fields):
        result = super(RouterRoute, cls).modify_fields_to_db(fields)
        if 'destination' in result:
            result['destination'] = cls.filter_to_str(result['destination'])
        if 'nexthop' in result:
            result['nexthop'] = cls.filter_to_str(result['nexthop'])
        return result


@base.NeutronObjectRegistry.register
class RouterExtraAttributes(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = l3_attrs.RouterExtraAttributes

    fields = {
        'router_id': common_types.UUIDField(),
        'distributed': obj_fields.BooleanField(default=False),
        'service_router': obj_fields.BooleanField(default=False),
        'ha': obj_fields.BooleanField(default=False),
        'ha_vr_id': obj_fields.IntegerField(nullable=True),
        'availability_zone_hints': obj_fields.ListOfStringsField(nullable=True)
    }

    primary_keys = ['router_id']

    foreign_keys = {'Router': {'router_id': 'id'}}

    @classmethod
    def modify_fields_from_db(cls, db_obj):
        result = super(RouterExtraAttributes, cls).modify_fields_from_db(
            db_obj)
        if az_def.AZ_HINTS in result:
            result[az_def.AZ_HINTS] = (
                az_validator.convert_az_string_to_list(
                    result[az_def.AZ_HINTS]))
        return result

    @classmethod
    def modify_fields_to_db(cls, fields):
        result = super(RouterExtraAttributes, cls).modify_fields_to_db(fields)
        if az_def.AZ_HINTS in result:
            result[az_def.AZ_HINTS] = (
                az_validator.convert_az_list_to_string(
                    result[az_def.AZ_HINTS]))
        return result

    @classmethod
    def get_router_agents_count(cls, context):
        # TODO(sshank): This is pulled out from l3_agentschedulers_db.py
        # until a way to handle joins is figured out.
        binding_model = rb_model.RouterL3AgentBinding
        sub_query = (context.session.query(
            binding_model.router_id,
            func.count(binding_model.router_id).label('count')).
                     join(l3_attrs.RouterExtraAttributes,
                          binding_model.router_id ==
                          l3_attrs.RouterExtraAttributes.router_id).
                     join(l3.Router).
                     group_by(binding_model.router_id).subquery())

        query = (context.session.query(l3.Router, sub_query.c.count).
                 outerjoin(sub_query))

        return [(router, agent_count) for router, agent_count in query]


@base.NeutronObjectRegistry.register
class RouterPort(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = l3.RouterPort

    primary_keys = ['router_id', 'port_id']

    foreign_keys = {'Router': {'router_id': 'id'}}

    fields = {
        'router_id': common_types.UUIDField(),
        'port_id': common_types.UUIDField(),
        'port_type': obj_fields.StringField(nullable=True),
    }

    @classmethod
    def get_router_ids_by_subnetpool(cls, context, subnetpool_id):
        query = context.session.query(l3.RouterPort.router_id)
        query = query.join(models_v2.Port)
        query = query.join(
            models_v2.Subnet,
            models_v2.Subnet.network_id == models_v2.Port.network_id)
        query = query.filter(
            models_v2.Subnet.subnetpool_id == subnetpool_id,
            l3.RouterPort.port_type.in_(n_const.ROUTER_PORT_OWNERS))
        query = query.distinct()
        return [r[0] for r in query]


@base.NeutronObjectRegistry.register
class DVRMacAddress(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = dvr_models.DistributedVirtualRouterMacAddress

    primary_keys = ['host']

    fields = {
        'host': obj_fields.StringField(),
        'mac_address': common_types.MACAddressField()
    }

    @classmethod
    def modify_fields_from_db(cls, db_obj):
        fields = super(DVRMacAddress, cls).modify_fields_from_db(db_obj)
        if 'mac_address' in fields:
            # NOTE(tonytan4ever): Here uses AuthenticEUI to retain the format
            # passed from API.
            fields['mac_address'] = utils.AuthenticEUI(fields['mac_address'])
        return fields

    @classmethod
    def modify_fields_to_db(cls, fields):
        result = super(DVRMacAddress, cls).modify_fields_to_db(fields)
        if 'mac_address' in fields:
            result['mac_address'] = cls.filter_to_str(result['mac_address'])
        return result


@base.NeutronObjectRegistry.register
class Router(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = l3.Router

    fields = {
        'id': common_types.UUIDField(),
        'project_id': obj_fields.StringField(nullable=True),
        'name': obj_fields.StringField(nullable=True),
        'status': common_types.RouterStatusEnumField(nullable=True),
        'admin_state_up': obj_fields.BooleanField(nullable=True),
        'gw_port_id': common_types.UUIDField(nullable=True),
        'enable_snat': obj_fields.BooleanField(default=True),
        'flavor_id': common_types.UUIDField(nullable=True),
        'extra_attributes': obj_fields.ObjectField(
            'RouterExtraAttributes', nullable=True),
    }

    synthetic_fields = ['extra_attributes']


@base.NeutronObjectRegistry.register
class FloatingIP(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = l3.FloatingIP

    fields = {
        'id': common_types.UUIDField(),
        'project_id': obj_fields.StringField(nullable=True),
        'floating_ip_address': obj_fields.IPAddressField(),
        'floating_network_id': common_types.UUIDField(),
        'floating_port_id': common_types.UUIDField(),
        'fixed_port_id': common_types.UUIDField(nullable=True),
        'fixed_ip_address': obj_fields.IPAddressField(nullable=True),
        'router_id': common_types.UUIDField(nullable=True),
        'last_known_router_id': common_types.UUIDField(nullable=True),
        'status': common_types.FloatingIPStatusEnumField(nullable=True),
        'dns': obj_fields.ObjectField('FloatingIPDNS', nullable=True),
    }
    fields_no_update = ['project_id', 'floating_ip_address',
                        'floating_network_id', 'floating_port_id']
    synthetic_fields = ['dns']

    @classmethod
    def modify_fields_from_db(cls, db_obj):
        result = super(FloatingIP, cls).modify_fields_from_db(db_obj)
        if 'fixed_ip_address' in result:
            result['fixed_ip_address'] = netaddr.IPAddress(
                result['fixed_ip_address'])
        if 'floating_ip_address' in result:
            result['floating_ip_address'] = netaddr.IPAddress(
                result['floating_ip_address'])
        return result

    @classmethod
    def modify_fields_to_db(cls, fields):
        result = super(FloatingIP, cls).modify_fields_to_db(fields)
        if 'fixed_ip_address' in result:
            if result['fixed_ip_address'] is not None:
                result['fixed_ip_address'] = cls.filter_to_str(
                    result['fixed_ip_address'])
        if 'floating_ip_address' in result:
            result['floating_ip_address'] = cls.filter_to_str(
                result['floating_ip_address'])
        return result

    @classmethod
    def get_scoped_floating_ips(cls, context, router_ids):
        query = context.session.query(l3.FloatingIP,
                                      models_v2.SubnetPool.address_scope_id)
        query = query.join(models_v2.Port,
            l3.FloatingIP.fixed_port_id == models_v2.Port.id)
        # Outer join of Subnet can cause each ip to have more than one row.
        query = query.outerjoin(models_v2.Subnet,
            models_v2.Subnet.network_id == models_v2.Port.network_id)
        query = query.filter(models_v2.Subnet.ip_version == 4)
        query = query.outerjoin(models_v2.SubnetPool,
            models_v2.Subnet.subnetpool_id == models_v2.SubnetPool.id)

        # Filter out on router_ids
        query = query.filter(l3.FloatingIP.router_id.in_(router_ids))
        return cls._unique_floatingip_iterator(context, query)

    @classmethod
    def _unique_floatingip_iterator(cls, context, query):
        """Iterates over only one row per floating ip. Ignores others."""
        # Group rows by fip id. They must be sorted by same.
        q = query.order_by(l3.FloatingIP.id)
        keyfunc = lambda row: row[0]['id']
        group_iterator = itertools.groupby(q, keyfunc)

        # Just hit the first row of each group
        for key, value in group_iterator:
            row = [r for r in six.next(value)]
            yield (cls._load_object(context, row[0]), row[1])
