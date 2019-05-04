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
from oslo_utils import versionutils
from oslo_versionedobjects import fields as obj_fields

from neutron.common import utils
from neutron.db.models import dns as dns_models
from neutron.db.models import l3
from neutron.db.models import securitygroup as sg_models
from neutron.db import models_v2
from neutron.objects import base
from neutron.objects import common_types
from neutron.objects.db import api as obj_db_api
from neutron.objects.qos import binding
from neutron.plugins.ml2 import models as ml2_models


class PortBindingBase(base.NeutronDbObject):

    foreign_keys = {
        'Port': {'port_id': 'id'},
    }

    @classmethod
    def modify_fields_to_db(cls, fields):
        result = super(PortBindingBase, cls).modify_fields_to_db(fields)
        for field in ['profile', 'vif_details']:
            if field in result:
                # dump field into string, set '' if empty '{}' or None
                result[field] = (
                    cls.filter_to_json_str(result[field], default=''))
        return result

    @classmethod
    def modify_fields_from_db(cls, db_obj):
        fields = super(PortBindingBase, cls).modify_fields_from_db(db_obj)
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
    VERSION = '1.0'

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
        return super(PortBindingLevel, cls).get_objects(
            context, _pager, validate_filters, **kwargs)


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

    fields_no_update = fields.keys()

    primary_keys = ['subnet_id', 'network_id', 'ip_address']

    foreign_keys = {
        'Port': {'port_id': 'id'},
    }

    # TODO(rossella_s): get rid of it once we switch the db model to using
    # custom types.
    @classmethod
    def modify_fields_to_db(cls, fields):
        result = super(IPAllocation, cls).modify_fields_to_db(fields)
        if 'ip_address' in result:
            result['ip_address'] = cls.filter_to_str(result['ip_address'])
        return result

    # TODO(rossella_s): get rid of it once we switch the db model to using
    # custom types.
    @classmethod
    def modify_fields_from_db(cls, db_obj):
        fields = super(IPAllocation, cls).modify_fields_from_db(db_obj)
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
            return super(IPAllocation, cls)._load_object(context, alloc_db)
        if alloc_db:
            return True


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

    def obj_make_compatible(self, primitive, target_version):
        _target_version = versionutils.convert_version_to_tuple(target_version)
        if _target_version < (1, 1):
            primitive.pop('dns_domain', None)


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
    VERSION = '1.1'

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
        'binding': obj_fields.ObjectField(
            'PortBinding', nullable=True
        ),
        'data_plane_status': obj_fields.ObjectField(
            'PortDataPlaneStatus', nullable=True
        ),
        'dhcp_options': obj_fields.ListOfObjectsField(
            'ExtraDhcpOpt', nullable=True
        ),
        'distributed_binding': obj_fields.ObjectField(
            'DistributedPortBinding', nullable=True
        ),
        'dns': obj_fields.ObjectField('PortDNS', nullable=True),
        'fixed_ips': obj_fields.ListOfObjectsField(
            'IPAllocation', nullable=True
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

        'binding_levels': obj_fields.ListOfObjectsField(
            'PortBindingLevel', nullable=True
        ),

        # TODO(ihrachys): consider adding a 'dns_assignment' fully synthetic
        # field in later object iterations
    }

    extra_filter_names = {'security_group_ids'}

    fields_no_update = ['project_id', 'network_id']

    synthetic_fields = [
        'allowed_address_pairs',
        'binding',
        'binding_levels',
        'data_plane_status',
        'dhcp_options',
        'distributed_binding',
        'dns',
        'fixed_ips',
        'qos_policy_id',
        'security',
        'security_group_ids',
    ]

    fields_need_translation = {
        'binding': 'port_binding',
        'dhcp_options': 'dhcp_opts',
        'distributed_binding': 'distributed_port_binding',
        'security': 'port_security',
    }

    def create(self):
        fields = self.obj_get_changes()
        with self.db_context_writer(self.obj_context):
            sg_ids = self.security_group_ids
            if sg_ids is None:
                sg_ids = set()
            qos_policy_id = self.qos_policy_id
            super(Port, self).create()
            if 'security_group_ids' in fields:
                self._attach_security_groups(sg_ids)
            if 'qos_policy_id' in fields:
                self._attach_qos_policy(qos_policy_id)

    def update(self):
        fields = self.obj_get_changes()
        with self.db_context_writer(self.obj_context):
            super(Port, self).update()
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
        return super(Port, cls).get_objects(context, _pager, validate_filters,
                                            **kwargs)

    @classmethod
    def modify_fields_to_db(cls, fields):
        result = super(Port, cls).modify_fields_to_db(fields)

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
        fields = super(Port, cls).modify_fields_from_db(db_obj)

        # TODO(rossella_s): get rid of it once we switch the db model to using
        # custom types.
        if 'mac_address' in fields:
            fields['mac_address'] = utils.AuthenticEUI(fields['mac_address'])

        distributed_port_binding = fields.get('distributed_binding')
        if distributed_port_binding:
            fields['distributed_binding'] = fields['distributed_binding'][0]
        else:
            fields['distributed_binding'] = None
        return fields

    def from_db_object(self, db_obj):
        super(Port, self).from_db_object(db_obj)
        # extract security group bindings
        if db_obj.get('security_groups', []):
            self.security_group_ids = {
                sg.security_group_id
                for sg in db_obj.security_groups
            }
        else:
            self.security_group_ids = set()
        self.obj_reset_changes(['security_group_ids'])

        # extract qos policy binding
        if db_obj.get('qos_policy_binding'):
            self.qos_policy_id = (
                db_obj.qos_policy_binding.policy_id
            )
        else:
            self.qos_policy_id = None
        self.obj_reset_changes(['qos_policy_id'])

    def obj_make_compatible(self, primitive, target_version):
        _target_version = versionutils.convert_version_to_tuple(target_version)

        if _target_version < (1, 1):
            primitive.pop('data_plane_status', None)

    @classmethod
    def get_ports_by_router(cls, context, router_id, owner, subnet):
        rport_qry = context.session.query(models_v2.Port).join(
            l3.RouterPort)
        ports = rport_qry.filter(
            l3.RouterPort.router_id == router_id,
            l3.RouterPort.port_type == owner,
            models_v2.Port.network_id == subnet['network_id']
        )
        return [cls._load_object(context, db_obj) for db_obj in ports.all()]

    @classmethod
    def get_ports_ids_by_security_groups(cls, context, security_group_ids):
        query = context.session.query(sg_models.SecurityGroupPortBinding)
        query = query.filter(
            sg_models.SecurityGroupPortBinding.security_group_id.in_(
                security_group_ids))
        return [port_binding['port_id'] for port_binding in query.all()]

    @classmethod
    def get_ports_by_binding_type_and_host(cls, context,
                                           binding_type, host):
        query = context.session.query(models_v2.Port).join(
            ml2_models.PortBinding)
        query = query.filter(
            ml2_models.PortBinding.vif_type == binding_type,
            ml2_models.PortBinding.host == host)
        return [cls._load_object(context, db_obj) for db_obj in query.all()]
