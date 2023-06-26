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

from neutron_lib.api.definitions import availability_zone as az_def
from neutron_lib.api.validators import availability_zone as az_validator
from neutron_lib import constants as n_const
from neutron_lib.db import api as db_api
from neutron_lib.objects import common_types
from neutron_lib.utils import net as net_utils
from oslo_utils import versionutils
from oslo_versionedobjects import fields as obj_fields
from sqlalchemy import func
from sqlalchemy import or_
from sqlalchemy import sql

from neutron.db.models import dvr as dvr_models
from neutron.db.models import l3
from neutron.db.models import l3_attrs
from neutron.db.models import l3agent as rb_model
from neutron.db import models_v2
from neutron.objects import base
from neutron.objects.qos import binding as qos_binding
from neutron.plugins.ml2 import models as ml2_models


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
            result['destination'] = net_utils.AuthenticIPNetwork(
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
    # Version 1.1: Added ECMP and BFD attributes
    VERSION = '1.1'

    db_model = l3_attrs.RouterExtraAttributes

    fields = {
        'router_id': common_types.UUIDField(),
        'distributed': obj_fields.BooleanField(default=False),
        'service_router': obj_fields.BooleanField(default=False),
        'ha': obj_fields.BooleanField(default=False),
        'ha_vr_id': obj_fields.IntegerField(nullable=True),
        'availability_zone_hints': obj_fields.ListOfStringsField(
            nullable=True),
        'enable_default_route_bfd': obj_fields.BooleanField(default=False),
        'enable_default_route_ecmp': obj_fields.BooleanField(default=False),
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
    @db_api.CONTEXT_READER
    def get_router_agents_count(cls, context, ha=False, less_than=0):
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
        count = func.coalesce(sub_query.c.count, 0)
        query = (context.session.query(l3.Router, count).
                 outerjoin(sub_query).join(l3_attrs.RouterExtraAttributes).
                 filter(l3_attrs.RouterExtraAttributes.ha == ha))
        if less_than > 0:
            query = query.filter(count < less_than)

        return list(query)

    @classmethod
    @db_api.CONTEXT_WRITER
    def update_distributed_flag(cls, context, distributed):
        query = context.session.query(cls.db_model)
        query.update({'distributed': distributed})

    def obj_make_compatible(self, primitive, target_version):
        _target_version = versionutils.convert_version_to_tuple(target_version)
        if _target_version < (1, 1):
            primitive.pop('enable_default_route_bfd', None)
            primitive.pop('enable_default_route_ecmp', None)


@base.NeutronObjectRegistry.register
class RouterPort(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = l3.RouterPort

    primary_keys = ['router_id', 'port_id']

    foreign_keys = {'Router': {'router_id': 'id'},
                    'Port': {'port_id': 'id'}}

    fields = {
        'router_id': common_types.UUIDField(),
        'port_id': common_types.UUIDField(),
        'port_type': obj_fields.StringField(nullable=True),
    }

    @classmethod
    @db_api.CONTEXT_READER
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

    @classmethod
    @db_api.CONTEXT_READER
    def get_gw_port_ids_by_router_id(cls, context, router_id):
        query = context.session.query(l3.RouterPort)
        query = query.filter(
            l3.RouterPort.router_id == router_id,
            l3.RouterPort.port_type == n_const.DEVICE_OWNER_ROUTER_GW)
        return [rp.port_id for rp in query]


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
            fields['mac_address'] = net_utils.AuthenticEUI(
                fields['mac_address'])
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
    # Version 1.1: Added "qos_policy_id" field
    VERSION = '1.1'

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
        'qos_policy_id': common_types.UUIDField(nullable=True, default=None),
    }

    synthetic_fields = ['extra_attributes',
                        'qos_policy_id',
                        ]

    fields_no_update = ['project_id']

    @classmethod
    @db_api.CONTEXT_READER
    def check_routers_not_owned_by_projects(cls, context, gw_ports, projects):
        """This method is to check whether routers that aren't owned by
        existing projects or not
        """

        # TODO(hungpv) We may want to implement NOT semantic in get_object(s)
        query = context.session.query(l3.Router).filter(
            l3.Router.gw_port_id.in_(gw_ports))

        query = query.filter(
            ~l3.Router.project_id.in_(projects))

        return bool(query.count())

    def _attach_qos_policy(self, qos_policy_id):
        qos_binding.QosPolicyRouterGatewayIPBinding.delete_objects(
            self.obj_context, router_id=self.id)
        if qos_policy_id:
            qos_binding.QosPolicyRouterGatewayIPBinding(
                self.obj_context, policy_id=qos_policy_id,
                router_id=self.id).create()

        self.qos_policy_id = qos_policy_id
        self.obj_reset_changes(['qos_policy_id'])

    def create(self):
        fields = self.obj_get_changes()
        with self.db_context_writer(self.obj_context):
            qos_policy_id = self.qos_policy_id
            super().create()
            if 'qos_policy_id' in fields:
                self._attach_qos_policy(qos_policy_id)

    def update(self):
        fields = self.obj_get_changes()
        with self.db_context_writer(self.obj_context):
            super().update()
            if 'qos_policy_id' in fields:
                self._attach_qos_policy(fields['qos_policy_id'])

    def from_db_object(self, db_obj):
        super().from_db_object(db_obj)
        fields_to_change = []
        if db_obj.get('qos_policy_binding'):
            self.qos_policy_id = db_obj.qos_policy_binding.policy_id
            fields_to_change.append('qos_policy_id')

        self.obj_reset_changes(fields_to_change)

    def obj_make_compatible(self, primitive, target_version):
        _target_version = versionutils.convert_version_to_tuple(target_version)
        if _target_version < (1, 1):
            primitive.pop('qos_policy_id', None)

    @staticmethod
    @db_api.CONTEXT_READER
    def get_router_ids_without_router_std_attrs(context):
        r_attrs = l3_attrs.RouterExtraAttributes
        query = context.session.query(l3.Router)
        query = query.join(r_attrs, r_attrs.router_id == l3.Router.id,
                           isouter=True)
        query = query.filter(r_attrs.router_id == sql.null())
        return [r.id for r in query.all()]


@base.NeutronObjectRegistry.register
class FloatingIP(base.NeutronDbObject):
    # Version 1.0: Initial version
    # Version 1.1: Added qos_policy_id field
    # Version 1.2: Added qos_network_policy_id field
    VERSION = '1.2'

    db_model = l3.FloatingIP

    fields = {
        'id': common_types.UUIDField(),
        'project_id': obj_fields.StringField(nullable=True),
        'floating_ip_address': obj_fields.IPAddressField(),
        'floating_network_id': common_types.UUIDField(),
        'floating_port_id': common_types.UUIDField(),
        'fixed_port_id': common_types.UUIDField(nullable=True),
        'fixed_ip_address': obj_fields.IPAddressField(nullable=True),
        'qos_policy_id': common_types.UUIDField(nullable=True, default=None),
        'qos_network_policy_id': common_types.UUIDField(nullable=True,
                                                        default=None),
        'router_id': common_types.UUIDField(nullable=True),
        'last_known_router_id': common_types.UUIDField(nullable=True),
        'status': common_types.FloatingIPStatusEnumField(nullable=True),
        'dns': obj_fields.ObjectField('FloatingIPDNS', nullable=True),
    }
    fields_no_update = ['project_id', 'floating_ip_address',
                        'floating_network_id', 'floating_port_id']
    synthetic_fields = ['dns',
                        'qos_policy_id',
                        'qos_network_policy_id',
                        ]

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

    def _attach_qos_policy(self, qos_policy_id):
        qos_binding.QosPolicyFloatingIPBinding.delete_objects(
            self.obj_context, fip_id=self.id)
        if qos_policy_id:
            fip_binding_obj = qos_binding.QosPolicyFloatingIPBinding(
                self.obj_context, policy_id=qos_policy_id, fip_id=self.id)
            fip_binding_obj.create()

        self.qos_policy_id = qos_policy_id
        self.obj_reset_changes(['qos_policy_id'])

    def create(self):
        fields = self.obj_get_changes()
        with self.db_context_writer(self.obj_context):
            qos_policy_id = self.qos_policy_id
            super(FloatingIP, self).create()
            if 'qos_policy_id' in fields:
                self._attach_qos_policy(qos_policy_id)

    def update(self):
        fields = self.obj_get_changes()
        with self.db_context_writer(self.obj_context):
            super(FloatingIP, self).update()
            if 'qos_policy_id' in fields:
                self._attach_qos_policy(fields['qos_policy_id'])

    def from_db_object(self, db_obj):
        super(FloatingIP, self).from_db_object(db_obj)
        fields_to_change = []
        if db_obj.get('qos_policy_binding'):
            self.qos_policy_id = db_obj.qos_policy_binding.policy_id
            fields_to_change.append('qos_policy_id')
        if db_obj.get('qos_network_policy_binding'):
            self.qos_network_policy_id = (
                db_obj.qos_network_policy_binding.policy_id)
            fields_to_change.append('qos_network_policy_binding')
        self.obj_reset_changes(fields_to_change)

    def obj_make_compatible(self, primitive, target_version):
        _target_version = versionutils.convert_version_to_tuple(target_version)
        if _target_version < (1, 1):
            primitive.pop('qos_policy_id', None)
        if _target_version < (1, 2):
            primitive.pop('qos_network_policy_id', None)

    @classmethod
    @db_api.CONTEXT_READER
    def get_scoped_floating_ips(cls, context, router_ids, host=None):
        query = context.session.query(l3.FloatingIP,
                                      models_v2.SubnetPool.address_scope_id)
        query = query.join(
            models_v2.Port,
            l3.FloatingIP.fixed_port_id == models_v2.Port.id)
        # Outer join of Subnet can cause each ip to have more than one row.
        query = query.outerjoin(
            models_v2.Subnet,
            models_v2.Subnet.network_id == models_v2.Port.network_id)
        query = query.filter(models_v2.Subnet.ip_version == 4)
        query = query.outerjoin(
            models_v2.SubnetPool,
            models_v2.Subnet.subnetpool_id == models_v2.SubnetPool.id)

        # Filter out on router_ids
        query = query.filter(l3.FloatingIP.router_id.in_(router_ids))

        # If a host value is provided, filter output to a specific host
        if host is not None:
            query = query.outerjoin(
                ml2_models.PortBinding,
                models_v2.Port.id == ml2_models.PortBinding.port_id)
            # Also filter for ports with migrating_to as they may be relevant
            # to this host but might not yet have the 'host' column updated
            # if the migration is in a pre-live migration state
            query = query.filter(or_(
                ml2_models.PortBinding.host == host,
                ml2_models.PortBinding.profile.like('%migrating_to%'),
            ))

        # Remove duplicate rows based on FIP IDs and the subnet pool address
        # scope. Only one subnet pool (per IP version, 4 in this case) can
        # be assigned to a subnet. The subnet pool address scope for a FIP is
        # unique.
        query = query.group_by(l3.FloatingIP.id,
                               models_v2.SubnetPool.address_scope_id)

        for row in query:
            yield (cls._load_object(context, row[0]), row[1])

    @classmethod
    @db_api.CONTEXT_READER
    def get_disassociated_ids_for_net(cls, context, network_id):
        query = context.session.query(cls.db_model.id)
        query = query.filter_by(
            floating_network_id=network_id,
            router_id=None,
            fixed_port_id=None)
        return [f.id for f in query]


@base.NeutronObjectRegistry.register
class DvrFipGatewayPortAgentBinding(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = dvr_models.DvrFipGatewayPortAgentBinding

    primary_keys = ['network_id', 'agent_id']

    fields = {
        'network_id': common_types.UUIDField(),
        'agent_id': common_types.UUIDField(),
    }
