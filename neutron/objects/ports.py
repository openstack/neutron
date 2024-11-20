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
from neutron_lib import constants
from neutron_lib.db import api as db_api
from neutron_lib.objects import common_types
from neutron_lib.utils import net as net_utils
from oslo_log import log as logging
from oslo_utils import versionutils
from oslo_versionedobjects import fields as obj_fields
import sqlalchemy
from sqlalchemy import and_

from neutron.common import _constants
from neutron.db.models import dns as dns_models
from neutron.db.models import l3
from neutron.db.models import securitygroup as sg_models
from neutron.db import models_v2
from neutron.objects import base
from neutron.objects.db import api as obj_db_api
from neutron.objects.qos import binding
from neutron.plugins.ml2 import models as ml2_models

LOG = logging.getLogger(__name__)


class PortBindingBase(base.NeutronDbObject):

    foreign_keys = {
        'Port': {'port_id': 'id'},
    }

    @classmethod
    def modify_fields_to_db(cls, fields):
        result = super().modify_fields_to_db(fields)
        for field in ['profile', 'vif_details']:
            if field in result:
                # dump field into string, set '' if empty '{}' or None
                result[field] = (
                    cls.filter_to_json_str(result[field], default=''))
        return result

    @classmethod
    def modify_fields_from_db(cls, db_obj):
        fields = super().modify_fields_from_db(db_obj)
        if 'vif_details' in fields:
            # load string from DB into dict, set None if vif_details is ''
            fields['vif_details'] = (
                cls.load_json_from_str(fields['vif_details']))
        if 'profile' in fields:
            # load string from DB into dict, set {} if profile is ''
            fields['profile'] = (
                cls.load_json_from_str(fields['profile'], default={}))
        return fields


@base.NeutronObjectRegistry.register
class PortBinding(PortBindingBase):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = ml2_models.PortBinding

    fields = {
        'port_id': common_types.UUIDField(),
        'host': obj_fields.StringField(),
        'profile': common_types.DictOfMiscValuesField(),
        'vif_type': obj_fields.StringField(),
        'vif_details': common_types.DictOfMiscValuesField(nullable=True),
        'vnic_type': obj_fields.StringField(),
        'status': common_types.PortBindingStatusEnumField(
            default=constants.ACTIVE),
    }

    primary_keys = ['port_id', 'host']

    @classmethod
    def get_port_id_and_host(cls, context, vif_type, vnic_type, status):
        """Returns only the port_id and the host of matching registers

        This method returns only the primary keys of a "PortBinding" register,
        reducing the query complexity and increasing the retrieval speed.
        This query does not check the "PortBinding" owner or RBACs.
        """
        with cls.db_context_reader(context):
            query = context.session.query(cls.db_model.port_id,
                                          cls.db_model.host)
            query = query.filter(and_(
                cls.db_model.vif_type == vif_type,
                cls.db_model.vnic_type == vnic_type,
                cls.db_model.status == status))
            return query.all()

    @classmethod
    @db_api.CONTEXT_READER
    def get_duplicated_port_bindings(cls, context):
        # This query will return the port_id of all "ml2_port_bindings"
        # registers that appears more than once (duplicated
        # "ml2_port_bindings" registers).
        # At the same time, this query returns only the "ml2_port_bindings"
        # that have status=INACTIVE.
        select = (
            sqlalchemy.select(cls.db_model.port_id).
            select_from(cls.db_model).
            group_by(cls.db_model.port_id).
            having(sqlalchemy.func.count(cls.db_model.port_id) > 1))
        _filter = and_(cls.db_model.port_id.in_(select),
                       cls.db_model.status == constants.INACTIVE)
        return context.session.query(cls.db_model).filter(_filter).all()

    @classmethod
    @db_api.CONTEXT_READER
    def get_port_binding_by_vnic_type(cls, context, vnic_type):
        """Returns the port binding filtering by VNIC type."""
        query = context.session.query(cls.db_model)
        query = query.filter(cls.db_model.vnic_type == vnic_type)
        return query.all()


@base.NeutronObjectRegistry.register
class DistributedPortBinding(PortBindingBase):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = ml2_models.DistributedPortBinding

    fields = {
        'port_id': common_types.UUIDField(),
        'host': obj_fields.StringField(),
        'profile': common_types.DictOfMiscValuesField(),
        'vif_type': obj_fields.StringField(),
        'vif_details': common_types.DictOfMiscValuesField(nullable=True),
        'vnic_type': obj_fields.StringField(),
        # NOTE(ihrachys): Fields below are specific to this type of binding. In
        # the future, we could think of converging different types of bindings
        # into a single field
        'status': obj_fields.StringField(),
        'router_id': obj_fields.StringField(nullable=True),
    }

    primary_keys = ['host', 'port_id']


@base.NeutronObjectRegistry.register
class PortBindingLevel(base.NeutronDbObject):
    # Version 1.0: Initial version
    # Version 1.1: Added segment_id
    VERSION = '1.1'

    db_model = ml2_models.PortBindingLevel

    primary_keys = ['port_id', 'host', 'level']

    fields = {
        'port_id': common_types.UUIDField(),
        'host': obj_fields.StringField(),
        'level': obj_fields.IntegerField(),
        'driver': obj_fields.StringField(nullable=True),
        'segment': obj_fields.ObjectField(
            'NetworkSegment', nullable=True
        ),
        # arguably redundant but allows us to define foreign key for 'segment'
        # synthetic field inside NetworkSegment definition
        'segment_id': common_types.UUIDField(nullable=True),
    }

    synthetic_fields = ['segment']

    foreign_keys = {
        'Port': {'port_id': 'id'},
    }

    @classmethod
    def get_objects(cls, context, _pager=None, validate_filters=True,
                    **kwargs):
        if not _pager:
            _pager = base.Pager()
        if not _pager.sorts:
            # (NOTE) True means ASC, False is DESC
            _pager.sorts = [('port_id', True), ('level', True)]
        return super().get_objects(
            context, _pager, validate_filters, **kwargs)

    def obj_make_compatible(self, primitive, target_version):
        _target_version = versionutils.convert_version_to_tuple(target_version)
        if _target_version < (1, 1):
            primitive.pop('segment_id', None)


@base.NeutronObjectRegistry.register
class IPAllocation(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = models_v2.IPAllocation

    fields = {
        'port_id': common_types.UUIDField(nullable=True),
        'subnet_id': common_types.UUIDField(),
        'network_id': common_types.UUIDField(),
        'ip_address': obj_fields.IPAddressField(),
    }

    fields_no_update = list(fields.keys())

    primary_keys = ['subnet_id', 'network_id', 'ip_address']

    foreign_keys = {
        'Port': {'port_id': 'id'},
    }

    # TODO(rossella_s): get rid of it once we switch the db model to using
    # custom types.
    @classmethod
    def modify_fields_to_db(cls, fields):
        result = super().modify_fields_to_db(fields)
        if 'ip_address' in result:
            result['ip_address'] = cls.filter_to_str(result['ip_address'])
        return result

    # TODO(rossella_s): get rid of it once we switch the db model to using
    # custom types.
    @classmethod
    def modify_fields_from_db(cls, db_obj):
        fields = super().modify_fields_from_db(db_obj)
        if 'ip_address' in fields:
            fields['ip_address'] = netaddr.IPAddress(fields['ip_address'])
        return fields

    @classmethod
    def get_alloc_by_subnet_id(cls, context, subnet_id, device_owner,
                               exclude=True):
        # need to join with ports table as IPAllocation's port
        # is not joined eagerly and thus producing query which yields
        # incorrect results
        if exclude:
            alloc_db = (context.session.query(models_v2.IPAllocation).
                        filter_by(subnet_id=subnet_id).join(models_v2.Port).
                        filter(~models_v2.Port.device_owner.
                               in_(device_owner)).first())
        else:
            alloc_db = (context.session.query(models_v2.IPAllocation).
                        filter_by(subnet_id=subnet_id).join(models_v2.Port).
                        filter(models_v2.Port.device_owner.
                               in_(device_owner)).first())
        if exclude and alloc_db:
            return super()._load_object(context, alloc_db)
        if alloc_db:
            return True

    @classmethod
    def delete_alloc_by_subnet_id(cls, context, subnet_id):
        allocs = context.session.query(models_v2.IPAllocation).filter_by(
            subnet_id=subnet_id).all()
        for alloc in allocs:
            alloc_obj = super()._load_object(context, alloc)
            alloc_obj.delete()

    @classmethod
    @db_api.CONTEXT_READER
    def get_alloc_routerports(cls, context, subnet_id, gateway_ip=None,
                              first=False):
        alloc_qry = context.session.query(cls.db_model.port_id)
        alloc_qry = alloc_qry.join(
            l3.RouterPort, l3.RouterPort.port_id == cls.db_model.port_id)
        alloc_qry = alloc_qry.filter(cls.db_model.subnet_id == subnet_id)
        if gateway_ip:
            alloc_qry = alloc_qry.filter(cls.db_model.ip_address == gateway_ip)

        if first:
            return alloc_qry.first()
        return alloc_qry.all()


@base.NeutronObjectRegistry.register
class PortDNS(base.NeutronDbObject):
    # Version 1.0: Initial version
    # Version 1.1: Add dns_domain attribute
    VERSION = '1.1'

    db_model = dns_models.PortDNS

    primary_keys = ['port_id']

    foreign_keys = {
        'Port': {'port_id': 'id'},
    }

    fields = {
        'port_id': common_types.UUIDField(),
        'current_dns_name': common_types.DomainNameField(),
        'current_dns_domain': common_types.DomainNameField(),
        'previous_dns_name': common_types.DomainNameField(),
        'previous_dns_domain': common_types.DomainNameField(),
        'dns_name': common_types.DomainNameField(),
        'dns_domain': common_types.DomainNameField(),
    }


@base.NeutronObjectRegistry.register
class SecurityGroupPortBinding(base.NeutronDbObject):

    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = sg_models.SecurityGroupPortBinding

    fields = {
        'port_id': common_types.UUIDField(),
        'security_group_id': common_types.UUIDField(),
    }

    primary_keys = ['port_id', 'security_group_id']


@base.NeutronObjectRegistry.register
class Port(base.NeutronDbObject):
    # Version 1.0: Initial version
    # Version 1.1: Add data_plane_status field
    # Version 1.2: Added segment_id to binding_levels
    # Version 1.3: distributed_binding -> distributed_bindings
    # Version 1.4: Attribute binding becomes ListOfObjectsField
    # Version 1.5: Added qos_network_policy_id field
    # Version 1.6: Added numa_affinity_policy field
    # Version 1.7: Added port_device field
    # Version 1.8: Added hints field
    # Version 1.9: Added hardware_offload_type field
    # Version 1.10: Added trusted field
    VERSION = '1.10'

    db_model = models_v2.Port

    fields = {
        'id': common_types.UUIDField(),
        'project_id': obj_fields.StringField(nullable=True),
        'name': obj_fields.StringField(nullable=True),
        'network_id': common_types.UUIDField(),
        'mac_address': common_types.MACAddressField(),
        'admin_state_up': obj_fields.BooleanField(),
        'device_id': obj_fields.StringField(),
        'device_owner': obj_fields.StringField(),
        'status': obj_fields.StringField(),

        'allowed_address_pairs': obj_fields.ListOfObjectsField(
            'AllowedAddressPair', nullable=True
        ),
        'bindings': obj_fields.ListOfObjectsField(
            'PortBinding', nullable=True
        ),
        'data_plane_status': obj_fields.ObjectField(
            'PortDataPlaneStatus', nullable=True
        ),
        'dhcp_options': obj_fields.ListOfObjectsField(
            'ExtraDhcpOpt', nullable=True
        ),
        'distributed_bindings': obj_fields.ListOfObjectsField(
            'DistributedPortBinding', nullable=True
        ),
        'dns': obj_fields.ObjectField('PortDNS', nullable=True),
        'fixed_ips': obj_fields.ListOfObjectsField(
            'IPAllocation', nullable=True
        ),
        'hints': obj_fields.ObjectField(
            'PortHints', nullable=True
        ),
        # TODO(ihrachys): consider converting to boolean
        'security': obj_fields.ObjectField(
            'PortSecurity', nullable=True
        ),
        'security_group_ids': common_types.SetOfUUIDsField(
            nullable=True,
            # TODO(ihrachys): how do we safely pass a mutable default?
            default=None,
        ),
        'qos_policy_id': common_types.UUIDField(nullable=True, default=None),
        'qos_network_policy_id': common_types.UUIDField(nullable=True,
                                                        default=None),

        'binding_levels': obj_fields.ListOfObjectsField(
            'PortBindingLevel', nullable=True
        ),
        'numa_affinity_policy': obj_fields.StringField(nullable=True),
        'device_profile': obj_fields.StringField(nullable=True),
        'hardware_offload_type': obj_fields.StringField(nullable=True),
        'trusted': obj_fields.BooleanField(nullable=True),

        # TODO(ihrachys): consider adding a 'dns_assignment' fully synthetic
        # field in later object iterations
    }

    extra_filter_names = {'security_group_ids'}

    fields_no_update = ['project_id', 'network_id']

    synthetic_fields = [
        'allowed_address_pairs',
        'bindings',
        'binding_levels',
        'data_plane_status',
        'device_profile',
        'dhcp_options',
        'distributed_bindings',
        'dns',
        'fixed_ips',
        'hardware_offload_type',
        'hints',
        'numa_affinity_policy',
        'qos_policy_id',
        'qos_network_policy_id',
        'security',
        'security_group_ids',
        'trusted',
    ]

    fields_need_translation = {
        'bindings': 'port_bindings',
        'dhcp_options': 'dhcp_opts',
        'distributed_bindings': 'distributed_port_binding',
        'security': 'port_security',
    }

    def create(self):
        fields = self.obj_get_changes()
        with self.db_context_writer(self.obj_context):
            sg_ids = self.security_group_ids
            if sg_ids is None:
                sg_ids = set()
            qos_policy_id = self.qos_policy_id
            super().create()
            if 'security_group_ids' in fields:
                self._attach_security_groups(sg_ids)
            if 'qos_policy_id' in fields:
                self._attach_qos_policy(qos_policy_id)

    def update(self):
        fields = self.obj_get_changes()
        with self.db_context_writer(self.obj_context):
            super().update()
            if 'security_group_ids' in fields:
                self._attach_security_groups(fields['security_group_ids'])
            if 'qos_policy_id' in fields:
                self._attach_qos_policy(fields['qos_policy_id'])

    def _attach_qos_policy(self, qos_policy_id):
        binding.QosPolicyPortBinding.delete_objects(
            self.obj_context, port_id=self.id)
        if qos_policy_id:
            port_binding_obj = binding.QosPolicyPortBinding(
                self.obj_context, policy_id=qos_policy_id, port_id=self.id)
            port_binding_obj.create()

        self.qos_policy_id = qos_policy_id
        self.obj_reset_changes(['qos_policy_id'])

    def _attach_security_groups(self, sg_ids):
        # TODO(ihrachys): consider introducing an (internal) object for the
        # binding to decouple database operations a bit more
        obj_db_api.delete_objects(
            SecurityGroupPortBinding, self.obj_context, port_id=self.id)
        if sg_ids:
            for sg_id in sg_ids:
                self._attach_security_group(sg_id)
        self.security_group_ids = sg_ids
        self.obj_reset_changes(['security_group_ids'])

    def _attach_security_group(self, sg_id):
        obj_db_api.create_object(
            SecurityGroupPortBinding, self.obj_context,
            {'port_id': self.id, 'security_group_id': sg_id}
        )

    @classmethod
    def get_objects(cls, context, _pager=None, validate_filters=True,
                    security_group_ids=None, **kwargs):
        if security_group_ids:
            ports_with_sg = cls.get_ports_ids_by_security_groups(
                context, security_group_ids)
            port_ids = kwargs.get("id", [])
            if port_ids:
                kwargs['id'] = list(set(port_ids) & set(ports_with_sg))
            else:
                kwargs['id'] = ports_with_sg
        port_array = super().get_objects(context, _pager,
                                         validate_filters,
                                         **kwargs)
        sg_count = len(security_group_ids) if security_group_ids else 0
        LOG.debug("Time-cost: Fetching %(port_count)s ports in %(sg_count)s "
                  "security groups",
                  {'port_count': len(port_array),
                   'sg_count': sg_count})
        return port_array

    @classmethod
    @db_api.CONTEXT_READER
    def get_auto_deletable_port_ids_and_proper_port_count_by_segment(
            cls, context, segment_id):

        query = context.session.query(models_v2.Port.id)
        query = query.join(
            ml2_models.PortBindingLevel,
            ml2_models.PortBindingLevel.port_id == models_v2.Port.id)
        query = query.filter(
            ml2_models.PortBindingLevel.segment_id == segment_id)

        q_delete = query.filter(
            models_v2.Port.device_owner.in_(
                _constants.AUTO_DELETE_PORT_OWNERS))

        q_proper = query.filter(
            ~models_v2.Port.device_owner.in_(
                _constants.AUTO_DELETE_PORT_OWNERS))

        return ([r.id for r in q_delete.all()], q_proper.count())

    @classmethod
    def modify_fields_to_db(cls, fields):
        result = super().modify_fields_to_db(fields)

        # TODO(rossella_s): get rid of it once we switch the db model to using
        # custom types.
        if 'mac_address' in result:
            result['mac_address'] = cls.filter_to_str(result['mac_address'])

        # convert None to []
        if 'distributed_port_binding' in result:
            result['distributed_port_binding'] = (
                result['distributed_port_binding'] or []
            )
        return result

    @classmethod
    def modify_fields_from_db(cls, db_obj):
        fields = super().modify_fields_from_db(db_obj)

        # TODO(rossella_s): get rid of it once we switch the db model to using
        # custom types.
        if 'mac_address' in fields:
            fields['mac_address'] = net_utils.AuthenticEUI(
                fields['mac_address'])

        distributed_port_binding = fields.get('distributed_bindings')
        if distributed_port_binding:
            # TODO(ihrachys) support multiple bindings
            fields['distributed_bindings'] = fields['distributed_bindings'][0]
        else:
            fields['distributed_bindings'] = []
        return fields

    def from_db_object(self, db_obj):
        super().from_db_object(db_obj)
        # extract security group bindings
        if db_obj.get('security_groups', []):
            self.security_group_ids = {
                sg.security_group_id
                for sg in db_obj.security_groups
            }
        else:
            self.security_group_ids = set()
        fields_to_change = ['security_group_ids']

        # extract qos policy binding
        if db_obj.get('qos_policy_binding'):
            self.qos_policy_id = db_obj.qos_policy_binding.policy_id
            fields_to_change.append('qos_policy_id')
        if db_obj.get('qos_network_policy_binding'):
            self.qos_network_policy_id = (
                db_obj.qos_network_policy_binding.policy_id)
            fields_to_change.append('qos_network_policy_binding')

        if db_obj.get('numa_affinity_policy'):
            self.numa_affinity_policy = (
                db_obj.numa_affinity_policy.numa_affinity_policy)
            fields_to_change.append('numa_affinity_policy')

        if db_obj.get('device_profile'):
            self.device_profile = db_obj.device_profile.device_profile
            fields_to_change.append('device_profile')

        if db_obj.get('hardware_offload_type'):
            self.hardware_offload_type = (
                db_obj.hardware_offload_type.hardware_offload_type)
            fields_to_change.append('hardware_offload_type')

        if db_obj.get('trusted') is not None:
            self.trusted = db_obj.trusted.trusted
            fields_to_change.append('trusted')

        self.obj_reset_changes(fields_to_change)

    def obj_make_compatible(self, primitive, target_version):
        _target_version = versionutils.convert_version_to_tuple(target_version)
        if _target_version < (1, 2):
            binding_levels = primitive.get('binding_levels', [])
            for lvl in binding_levels:
                lvl['versioned_object.version'] = '1.0'
                lvl['versioned_object.data'].pop('segment_id', None)
        if _target_version < (1, 3):
            bindings = primitive.pop('distributed_bindings', [])
            primitive['distributed_binding'] = (bindings[0]
                                                if bindings else None)
        if _target_version < (1, 4):
            # In version 1.4 we add support for multiple port bindings.
            # Previous versions only support one port binding. The following
            # lines look for the active port binding, which is the only one
            # needed in previous versions
            if 'bindings' in primitive:
                original_bindings = primitive.pop('bindings')
                primitive['binding'] = None
                for a_binding in original_bindings:
                    if (a_binding['versioned_object.data']['status'] ==
                            constants.ACTIVE):
                        primitive['binding'] = a_binding
                        break
        if _target_version < (1, 5):
            primitive.pop('qos_network_policy_id', None)
        if _target_version < (1, 6):
            primitive.pop('numa_affinity_policy', None)
        if _target_version < (1, 7):
            primitive.pop('device_profile', None)
        if _target_version < (1, 8):
            primitive.pop('hints', None)
        if _target_version < (1, 9):
            primitive.pop('hardware_offload_type', None)
        if _target_version < (1, 10):
            primitive.pop('trusted', None)

    @classmethod
    @db_api.CONTEXT_READER
    def get_ports_by_router_and_network(cls, context, router_id, owner,
                                        network_id):
        """Returns port objects filtering by router ID, owner and network ID"""
        rports_filter = (models_v2.Port.network_id == network_id, )
        router_filter = (models_v2.Port.network_id == network_id, )
        return cls._get_ports_by_router(context, router_id, owner,
                                        rports_filter, router_filter)

    @classmethod
    @db_api.CONTEXT_READER
    def get_ports_by_router_and_port(cls, context, router_id, owner, port_id):
        """Returns port objects filtering by router ID, owner and port ID"""
        rports_filter = (l3.RouterPort.port_id == port_id, )
        router_filter = (models_v2.Port.id == port_id, )
        return cls._get_ports_by_router(context, router_id, owner,
                                        rports_filter, router_filter)

    @classmethod
    def _get_ports_by_router(cls, context, router_id, owner, rports_filter,
                             router_filter):
        """Returns port objects filtering by router id and owner

        The method will receive extra filters depending of the caller (filter
        by network or filter by port).

        The ports are retrieved using:
        - The RouterPort registers. Each time a port is assigned to a router,
          a new RouterPort register is added to the DB.
        - The port owner and device_id information.

        Both searches should return the same result. If not, a warning message
        is logged and the port list to be returned is completed with the
        missing ones.
        """
        rports_filter += (l3.RouterPort.router_id == router_id,
                          l3.RouterPort.port_type == owner)
        router_filter += (models_v2.Port.device_id == router_id,
                          models_v2.Port.device_owner == owner)

        ports = context.session.query(models_v2.Port).join(
            l3.RouterPort).filter(*rports_filter)
        ports_rports = [cls._load_object(context, db_obj)
                        for db_obj in ports.all()]

        ports = context.session.query(models_v2.Port).filter(*router_filter)
        ports_router = [cls._load_object(context, db_obj)
                        for db_obj in ports.all()]

        ports_rports_ids = {p.id for p in ports_rports}
        ports_router_ids = {p.id for p in ports_router}
        missing_port_ids = ports_router_ids - ports_rports_ids
        if missing_port_ids:
            LOG.warning('The following ports, assigned to router '
                        '%(router_id)s, do not have a "routerport" register: '
                        '%(port_ids)s', {'router_id': router_id,
                                         'port_ids': missing_port_ids})
            port_objs = [p for p in ports_router if p.id in missing_port_ids]
            ports_rports += port_objs

        return ports_rports

    @classmethod
    @db_api.CONTEXT_READER
    def get_ports_ids_by_security_groups(cls, context, security_group_ids,
                                         excluded_device_owners=None):
        query = context.session.query(sg_models.SecurityGroupPortBinding)
        query = query.filter(
            sg_models.SecurityGroupPortBinding.security_group_id.in_(
                security_group_ids))
        if excluded_device_owners:
            query = query.join(models_v2.Port)
            query = query.filter(
                ~models_v2.Port.device_owner.in_(excluded_device_owners))
        return [port_binding['port_id'] for port_binding in query.all()]

    @classmethod
    @db_api.CONTEXT_READER
    def get_ports_by_host(cls, context, host):
        query = context.session.query(models_v2.Port.id).join(
            ml2_models.PortBinding)
        query = query.filter(
            ml2_models.PortBinding.host == host)
        return [port_id[0] for port_id in query.all()]

    @classmethod
    @db_api.CONTEXT_READER
    def get_ports_by_binding_type_and_host(cls, context,
                                           binding_type, host):
        query = context.session.query(models_v2.Port).join(
            ml2_models.PortBinding)
        query = query.filter(
            ml2_models.PortBinding.vif_type == binding_type,
            ml2_models.PortBinding.host == host)
        return [cls._load_object(context, db_obj) for db_obj in query.all()]

    @classmethod
    @db_api.CONTEXT_READER
    def get_ports_by_vnic_type_and_host(cls, context, vnic_type, host=None):
        query = context.session.query(models_v2.Port).join(
            ml2_models.PortBinding)
        query = query.filter(ml2_models.PortBinding.vnic_type == vnic_type)
        if host:
            query = query.filter(ml2_models.PortBinding.host == host)
        return [cls._load_object(context, db_obj) for db_obj in query.all()]

    @classmethod
    @db_api.CONTEXT_READER
    def check_network_ports_by_binding_types(
            cls, context, network_id, binding_types, negative_search=False):
        """This method is to check whether networks have ports with given
        binding_types.

        :param context:
        :param network_id: ID of network to check
        :param binding_types: list of binding types to look for
        :param negative_search: if set to true, ports with with binding_type
                                other than "binding_types" will be counted
        :return: True if any port is found, False otherwise
        """
        query = context.session.query(models_v2.Port).join(
            ml2_models.PortBinding)
        query = query.filter(models_v2.Port.network_id == network_id)
        if negative_search:
            query = query.filter(
                ml2_models.PortBinding.vif_type.notin_(binding_types))
        else:
            query = query.filter(
                ml2_models.PortBinding.vif_type.in_(binding_types))
        return bool(query.count())

    @classmethod
    @db_api.CONTEXT_READER
    def get_ports_allocated_by_subnet_id(cls, context, subnet_id):
        """Return ports with fixed IPs in a subnet"""
        return context.session.query(models_v2.Port).filter(
            models_v2.IPAllocation.port_id == models_v2.Port.id).filter(
                models_v2.IPAllocation.subnet_id == subnet_id).all()

    @classmethod
    def get_port_from_mac_and_pci_slot(cls, context, device_mac,
                                       pci_slot=None):
        with db_api.CONTEXT_READER.using(context):
            ports = cls.get_objects(context, mac_address=device_mac)

        if not ports:
            return
        if not pci_slot:
            return ports.pop()
        for port in ports:
            for _binding in port.bindings:
                if _binding.get('profile', {}).get('pci_slot') == pci_slot:
                    return port

    @classmethod
    @db_api.CONTEXT_READER
    def get_gateway_port_ids_by_network(cls, context, network_id):
        gw_ports = context.session.query(models_v2.Port.id).filter_by(
            device_owner=constants.DEVICE_OWNER_ROUTER_GW,
            network_id=network_id)
        return [gw_port[0] for gw_port in gw_ports]
