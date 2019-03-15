# Copyright (c) 2016 OpenStack Foundation.  All rights reserved.
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

from neutron_lib.api.definitions import availability_zone as az_def
from neutron_lib.api.validators import availability_zone as az_validator
from oslo_utils import versionutils
from oslo_versionedobjects import fields as obj_fields
import sqlalchemy as sa

from neutron.db.models import dns as dns_models
from neutron.db.models import external_net as ext_net_model
from neutron.db.models import segment as segment_model
from neutron.db import models_v2
from neutron.db.network_dhcp_agent_binding import models as ndab_models
from neutron.db.port_security import models as ps_models
from neutron.db import rbac_db_models
from neutron.objects import agent as agent_obj
from neutron.objects import base
from neutron.objects import common_types
from neutron.objects.extensions import port_security as base_ps
from neutron.objects.qos import binding
from neutron.objects import rbac
from neutron.objects import rbac_db


@base.NeutronObjectRegistry.register
class NetworkRBAC(rbac.RBACBaseObject):
    # Version 1.0: Initial version
    # Version 1.1: Added 'id' and 'project_id'
    # Version 1.2: Inherit from rbac.RBACBaseObject; changed 'object_id' from
    #              StringField to UUIDField

    VERSION = '1.2'

    db_model = rbac_db_models.NetworkRBAC

    def obj_make_compatible(self, primitive, target_version):
        _target_version = versionutils.convert_version_to_tuple(target_version)
        if _target_version < (1, 1):
            standard_fields = ['id', 'project_id']
            for f in standard_fields:
                primitive.pop(f, None)

    @classmethod
    def get_projects(cls, context, object_id=None, action=None,
                     target_tenant=None):
        clauses = []
        if object_id:
            clauses.append(rbac_db_models.NetworkRBAC.object_id == object_id)
        if action:
            clauses.append(rbac_db_models.NetworkRBAC.action == action)
        if target_tenant:
            clauses.append(rbac_db_models.NetworkRBAC.target_tenant ==
                           target_tenant)
        query = context.session.query(rbac_db_models.NetworkRBAC.target_tenant)
        if clauses:
            query = query.filter(sa.and_(*clauses))
        return [data[0] for data in query]


@base.NeutronObjectRegistry.register
class NetworkDhcpAgentBinding(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = ndab_models.NetworkDhcpAgentBinding

    primary_keys = ['network_id', 'dhcp_agent_id']

    fields = {
        'network_id': common_types.UUIDField(),
        'dhcp_agent_id': common_types.UUIDField(),
    }

    # NOTE(ndahiwade): The join was implemented this way as get_objects
    # currently doesn't support operators like '<' or '>'
    @classmethod
    def get_down_bindings(cls, context, cutoff):
        agent_objs = agent_obj.Agent.get_objects(context)
        dhcp_agent_ids = [obj.id for obj in agent_objs
                          if obj.heartbeat_timestamp < cutoff]
        return cls.get_objects(context, dhcp_agent_id=dhcp_agent_ids)


@base.NeutronObjectRegistry.register
class NetworkSegment(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = segment_model.NetworkSegment

    fields = {
        'id': common_types.UUIDField(),
        'network_id': common_types.UUIDField(),
        'name': obj_fields.StringField(nullable=True),
        'network_type': obj_fields.StringField(),
        'physical_network': obj_fields.StringField(nullable=True),
        'segmentation_id': obj_fields.IntegerField(nullable=True),
        'is_dynamic': obj_fields.BooleanField(default=False),
        'segment_index': obj_fields.IntegerField(default=0),
        'hosts': obj_fields.ListOfStringsField(nullable=True)
    }

    synthetic_fields = ['hosts']

    fields_no_update = ['network_id']

    foreign_keys = {
        'Network': {'network_id': 'id'},
        'PortBindingLevel': {'id': 'segment_id'},
    }

    def create(self):
        fields = self.obj_get_changes()
        with self.db_context_writer(self.obj_context):
            hosts = self.hosts
            if hosts is None:
                hosts = []
            super(NetworkSegment, self).create()
            if 'hosts' in fields:
                self._attach_hosts(hosts)

    def update(self):
        fields = self.obj_get_changes()
        with self.db_context_writer(self.obj_context):
            super(NetworkSegment, self).update()
            if 'hosts' in fields:
                self._attach_hosts(fields['hosts'])

    def _attach_hosts(self, hosts):
        SegmentHostMapping.delete_objects(
            self.obj_context, segment_id=self.id,
        )
        if hosts:
            for host in hosts:
                SegmentHostMapping(
                    self.obj_context, segment_id=self.id, host=host).create()
        self.hosts = hosts
        self.obj_reset_changes(['hosts'])

    def obj_load_attr(self, attrname):
        if attrname == 'hosts':
            return self._load_hosts()
        super(NetworkSegment, self).obj_load_attr(attrname)

    def _load_hosts(self, db_obj=None):
        if db_obj:
            hosts = db_obj.get('segment_host_mapping', [])
        else:
            hosts = SegmentHostMapping.get_objects(self.obj_context,
                                                   segment_id=self.id)

        self.hosts = [host['host'] for host in hosts]
        self.obj_reset_changes(['hosts'])

    def from_db_object(self, db_obj):
        super(NetworkSegment, self).from_db_object(db_obj)
        self._load_hosts(db_obj)

    @classmethod
    def get_objects(cls, context, _pager=None, **kwargs):
        if not _pager:
            _pager = base.Pager()
        if not _pager.sorts:
            # (NOTE) True means ASC, False is DESC
            _pager.sorts = [
                (field, True) for field in ('network_id', 'segment_index')
            ]
        return super(NetworkSegment, cls).get_objects(context, _pager,
                                                      **kwargs)


@base.NeutronObjectRegistry.register
class NetworkPortSecurity(base_ps._PortSecurity):
    # Version 1.0: Initial version
    VERSION = "1.0"

    db_model = ps_models.NetworkSecurityBinding

    fields_need_translation = {'id': 'network_id'}


@base.NeutronObjectRegistry.register
class ExternalNetwork(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = ext_net_model.ExternalNetwork

    foreign_keys = {'Network': {'network_id': 'id'}}

    primary_keys = ['network_id']

    fields = {
        'network_id': common_types.UUIDField(),
        'is_default': obj_fields.BooleanField(default=False),
    }


@base.NeutronObjectRegistry.register
class Network(rbac_db.NeutronRbacObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    rbac_db_cls = NetworkRBAC
    db_model = models_v2.Network

    fields = {
        'id': common_types.UUIDField(),
        'project_id': obj_fields.StringField(nullable=True),
        'name': obj_fields.StringField(nullable=True),
        'status': obj_fields.StringField(nullable=True),
        'admin_state_up': obj_fields.BooleanField(nullable=True),
        'vlan_transparent': obj_fields.BooleanField(nullable=True),
        # TODO(ihrachys): consider converting to a field of stricter type
        'availability_zone_hints': obj_fields.ListOfStringsField(
            nullable=True),
        'shared': obj_fields.BooleanField(default=False),

        'mtu': obj_fields.IntegerField(nullable=True),

        # TODO(ihrachys): consider exposing availability zones

        # TODO(ihrachys): consider converting to boolean
        'security': obj_fields.ObjectField(
            'NetworkPortSecurity', nullable=True),
        'segments': obj_fields.ListOfObjectsField(
            'NetworkSegment', nullable=True),
        'dns_domain': common_types.DomainNameField(nullable=True),
        'qos_policy_id': common_types.UUIDField(nullable=True, default=None),

        # TODO(ihrachys): add support for tags, probably through a base class
        # since it's a feature that will probably later be added for other
        # resources too

        # TODO(ihrachys): expose external network attributes
    }

    synthetic_fields = [
        'dns_domain',
        'qos_policy_id',
        'security',
        'segments',
    ]

    fields_need_translation = {
        'security': 'port_security',
    }

    def create(self):
        fields = self.obj_get_changes()
        with self.db_context_writer(self.obj_context):
            dns_domain = self.dns_domain
            qos_policy_id = self.qos_policy_id
            super(Network, self).create()
            if 'dns_domain' in fields:
                self._set_dns_domain(dns_domain)
            if 'qos_policy_id' in fields:
                self._attach_qos_policy(qos_policy_id)

    def update(self):
        fields = self.obj_get_changes()
        with self.db_context_writer(self.obj_context):
            super(Network, self).update()
            if 'dns_domain' in fields:
                self._set_dns_domain(fields['dns_domain'])
            if 'qos_policy_id' in fields:
                self._attach_qos_policy(fields['qos_policy_id'])

    def _attach_qos_policy(self, qos_policy_id):
        binding.QosPolicyNetworkBinding.delete_objects(
            self.obj_context, network_id=self.id)
        if qos_policy_id:
            net_binding_obj = binding.QosPolicyNetworkBinding(
                self.obj_context, policy_id=qos_policy_id, network_id=self.id)
            net_binding_obj.create()

        self.qos_policy_id = qos_policy_id
        self.obj_reset_changes(['qos_policy_id'])

    def _set_dns_domain(self, dns_domain):
        NetworkDNSDomain.delete_objects(self.obj_context, network_id=self.id)
        if dns_domain:
            NetworkDNSDomain(self.obj_context, network_id=self.id,
                             dns_domain=dns_domain).create()
        self.dns_domain = dns_domain
        self.obj_reset_changes(['dns_domain'])

    @classmethod
    def modify_fields_from_db(cls, db_obj):
        result = super(Network, cls).modify_fields_from_db(db_obj)
        if az_def.AZ_HINTS in result:
            result[az_def.AZ_HINTS] = (
                az_validator.convert_az_string_to_list(
                    result[az_def.AZ_HINTS]))
        return result

    @classmethod
    def modify_fields_to_db(cls, fields):
        result = super(Network, cls).modify_fields_to_db(fields)
        if az_def.AZ_HINTS in result:
            result[az_def.AZ_HINTS] = (
                az_validator.convert_az_list_to_string(
                    result[az_def.AZ_HINTS]))
        return result

    def from_db_object(self, *objs):
        super(Network, self).from_db_object(*objs)
        for db_obj in objs:
            # extract domain name
            if db_obj.get('dns_domain'):
                self.dns_domain = (
                    db_obj.dns_domain.dns_domain
                )
            else:
                self.dns_domain = None
            self.obj_reset_changes(['dns_domain'])

            # extract qos policy binding
            if db_obj.get('qos_policy_binding'):
                self.qos_policy_id = (
                    db_obj.qos_policy_binding.policy_id
                )
            else:
                self.qos_policy_id = None
            self.obj_reset_changes(['qos_policy_id'])

    @classmethod
    def get_bound_tenant_ids(cls, context, policy_id):
        # TODO(ihrachys): provide actual implementation
        return set()


@base.NeutronObjectRegistry.register
class SegmentHostMapping(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = segment_model.SegmentHostMapping

    fields = {
        'segment_id': common_types.UUIDField(),
        'host': obj_fields.StringField(),
    }

    primary_keys = ['segment_id', 'host']


@base.NeutronObjectRegistry.register
class NetworkDNSDomain(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = dns_models.NetworkDNSDomain

    primary_keys = ['network_id']

    fields = {
        'network_id': common_types.UUIDField(),
        'dns_domain': common_types.DomainNameField(),
    }

    @classmethod
    def get_net_dns_from_port(cls, context, port_id):
        net_dns = context.session.query(cls.db_model).join(
            models_v2.Port, cls.db_model.network_id ==
            models_v2.Port.network_id).filter_by(
                id=port_id).one_or_none()
        if net_dns is None:
            return None
        return super(NetworkDNSDomain, cls)._load_object(context, net_dns)
