# Copyright 2015 Red Hat, Inc.
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

import itertools

from neutron_lib import constants as n_const
from oslo_db import exception as db_exc
from oslo_utils import versionutils
from oslo_versionedobjects import exception
from oslo_versionedobjects import fields as obj_fields

from neutron.common import exceptions
from neutron.db.models import l3
from neutron.db import models_v2
from neutron.db.qos import models as qos_db_model
from neutron.db import rbac_db_models
from neutron.objects import base as base_db
from neutron.objects import common_types
from neutron.objects.db import api as obj_db_api
from neutron.objects.qos import binding
from neutron.objects.qos import rule as rule_obj_impl
from neutron.objects import rbac_db


@base_db.NeutronObjectRegistry.register
class QosPolicyRBAC(base_db.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = rbac_db_models.QosPolicyRBAC

    fields = {
        'object_id': obj_fields.StringField(),
        'target_tenant': obj_fields.StringField(),
        'action': obj_fields.StringField(),
    }


@base_db.NeutronObjectRegistry.register
class QosPolicy(rbac_db.NeutronRbacObject):
    # Version 1.0: Initial version
    # Version 1.1: QosDscpMarkingRule introduced
    # Version 1.2: Added QosMinimumBandwidthRule
    # Version 1.3: Added standard attributes (created_at, revision, etc)
    # Version 1.4: Changed tenant_id to project_id
    # Version 1.5: Direction for bandwidth limit rule added
    # Version 1.6: Added "is_default" field
    # Version 1.7: Added floating IP bindings
    VERSION = '1.7'

    # required by RbacNeutronMetaclass
    rbac_db_cls = QosPolicyRBAC
    db_model = qos_db_model.QosPolicy

    fields = {
        'id': common_types.UUIDField(),
        'project_id': obj_fields.StringField(),
        'name': obj_fields.StringField(),
        'shared': obj_fields.BooleanField(default=False),
        'rules': obj_fields.ListOfObjectsField('QosRule', subclasses=True),
        'is_default': obj_fields.BooleanField(default=False),
    }

    fields_no_update = ['id', 'project_id']

    synthetic_fields = ['rules', 'is_default']

    extra_filter_names = {'is_default'}

    binding_models = {'port': binding.QosPolicyPortBinding,
                      'network': binding.QosPolicyNetworkBinding,
                      'fip': binding.QosPolicyFloatingIPBinding}

    def obj_load_attr(self, attrname):
        if attrname == 'rules':
            return self._reload_rules()
        elif attrname == 'is_default':
            return self._reload_is_default()
        return super(QosPolicy, self).obj_load_attr(attrname)

    def _reload_rules(self):
        rules = rule_obj_impl.get_rules(self, self.obj_context, self.id)
        setattr(self, 'rules', rules)
        self.obj_reset_changes(['rules'])

    def _reload_is_default(self):
        if self.get_default() == self.id:
            setattr(self, 'is_default', True)
        else:
            setattr(self, 'is_default', False)
        self.obj_reset_changes(['is_default'])

    def get_rule_by_id(self, rule_id):
        """Return rule specified by rule_id.

        @raise QosRuleNotFound: if there is no such rule in the policy.
        """

        for rule in self.rules:
            if rule_id == rule.id:
                return rule
        raise exceptions.QosRuleNotFound(policy_id=self.id,
                                         rule_id=rule_id)

    # TODO(hichihara): For tag mechanism. This will be removed in bug/1704137
    def to_dict(self):
        _dict = super(QosPolicy, self).to_dict()
        try:
            _dict['tags'] = [t.tag for t in self.db_obj.standard_attr.tags]
        except AttributeError:
            # AttrtibuteError can be raised when accessing self.db_obj
            # or self.db_obj.standard_attr
            pass
        return _dict

    @classmethod
    def get_object(cls, context, **kwargs):
        # We want to get the policy regardless of its tenant id. We'll make
        # sure the tenant has permission to access the policy later on.
        admin_context = context.elevated()
        with cls.db_context_reader(admin_context):
            policy_obj = super(QosPolicy, cls).get_object(admin_context,
                                                          **kwargs)
            if (not policy_obj or
                not cls.is_accessible(context, policy_obj)):
                return

            policy_obj.obj_load_attr('rules')
            policy_obj.obj_load_attr('is_default')
            return policy_obj

    @classmethod
    def get_objects(cls, context, _pager=None, validate_filters=True,
                    **kwargs):
        # We want to get the policy regardless of its tenant id. We'll make
        # sure the tenant has permission to access the policy later on.
        admin_context = context.elevated()
        with cls.db_context_reader(admin_context):
            objs = super(QosPolicy, cls).get_objects(admin_context, _pager,
                                                     validate_filters,
                                                     **kwargs)
            result = []
            for obj in objs:
                if not cls.is_accessible(context, obj):
                    continue
                obj.obj_load_attr('rules')
                obj.obj_load_attr('is_default')
                result.append(obj)
            return result

    @classmethod
    def _get_object_policy(cls, context, binding_cls, **kwargs):
        with cls.db_context_reader(context):
            binding_db_obj = obj_db_api.get_object(binding_cls, context,
                                                   **kwargs)
            if binding_db_obj:
                return cls.get_object(context, id=binding_db_obj['policy_id'])

    @classmethod
    def get_network_policy(cls, context, network_id):
        return cls._get_object_policy(context, binding.QosPolicyNetworkBinding,
                                      network_id=network_id)

    @classmethod
    def get_port_policy(cls, context, port_id):
        return cls._get_object_policy(context, binding.QosPolicyPortBinding,
                                      port_id=port_id)

    @classmethod
    def get_fip_policy(cls, context, fip_id):
        return cls._get_object_policy(
            context, binding.QosPolicyFloatingIPBinding, fip_id=fip_id)

    # TODO(QoS): Consider extending base to trigger registered methods for us
    def create(self):
        with self.db_context_writer(self.obj_context):
            super(QosPolicy, self).create()
            if self.is_default:
                self.set_default()
            self.obj_load_attr('rules')

    def update(self):
        with self.db_context_writer(self.obj_context):
            if 'is_default' in self.obj_what_changed():
                if self.is_default:
                    self.set_default()
                else:
                    self.unset_default()
            super(QosPolicy, self).update()

    def delete(self):
        with self.db_context_writer(self.obj_context):
            for object_type, obj_class in self.binding_models.items():
                pager = base_db.Pager(limit=1)
                binding_obj = obj_class.get_objects(self.obj_context,
                                                    policy_id=self.id,
                                                    _pager=pager)
                if binding_obj:
                    raise exceptions.QosPolicyInUse(
                        policy_id=self.id,
                        object_type=object_type,
                        object_id=binding_obj[0]['%s_id' % object_type])

            super(QosPolicy, self).delete()

    def attach_network(self, network_id):
        network_binding = {'policy_id': self.id,
                           'network_id': network_id}
        network_binding_obj = binding.QosPolicyNetworkBinding(
            self.obj_context, **network_binding)
        try:
            network_binding_obj.create()
        except db_exc.DBReferenceError as e:
            raise exceptions.NetworkQosBindingError(policy_id=self.id,
                                                    net_id=network_id,
                                                    db_error=e)

    def attach_port(self, port_id):
        port_binding_obj = binding.QosPolicyPortBinding(
            self.obj_context, policy_id=self.id, port_id=port_id)
        try:
            port_binding_obj.create()
        except db_exc.DBReferenceError as e:
            raise exceptions.PortQosBindingError(policy_id=self.id,
                                                 port_id=port_id,
                                                 db_error=e)

    def attach_floatingip(self, fip_id):
        fip_binding_obj = binding.QosPolicyFloatingIPBinding(
            self.obj_context, policy_id=self.id, fip_id=fip_id)
        try:
            fip_binding_obj.create()
        except db_exc.DBReferenceError as e:
            raise exceptions.FloatingIPQosBindingError(policy_id=self.id,
                                                       fip_id=fip_id,
                                                       db_error=e)

    def detach_network(self, network_id):
        deleted = binding.QosPolicyNetworkBinding.delete_objects(
            self.obj_context, network_id=network_id)
        if not deleted:
            raise exceptions.NetworkQosBindingNotFound(net_id=network_id,
                                                       policy_id=self.id)

    def detach_port(self, port_id):
        deleted = binding.QosPolicyPortBinding.delete_objects(self.obj_context,
                                                              port_id=port_id)
        if not deleted:
            raise exceptions.PortQosBindingNotFound(port_id=port_id,
                                                    policy_id=self.id)

    def detach_floatingip(self, fip_id):
        deleted = binding.QosPolicyFloatingIPBinding.delete_objects(
            self.obj_context, fip_id=fip_id)
        if not deleted:
            raise exceptions.FloatingIPQosBindingNotFound(fip_id=fip_id,
                                                          policy_id=self.id)

    def set_default(self):
        if not self.get_default():
            qos_default_policy = QosPolicyDefault(self.obj_context,
                                                  qos_policy_id=self.id,
                                                  project_id=self.project_id)
            qos_default_policy.create()
        elif self.get_default() != self.id:
            raise exceptions.QoSPolicyDefaultAlreadyExists(
                project_id=self.project_id)

    def unset_default(self):
        if self.get_default() == self.id:
            qos_default_policy = QosPolicyDefault.get_object(
                self.obj_context, project_id=self.project_id)
            qos_default_policy.delete()

    def get_default(self):
        qos_default_policy = QosPolicyDefault.get_object(
            self.obj_context, project_id=self.project_id)
        if qos_default_policy:
            return qos_default_policy.qos_policy_id

    def get_bound_networks(self):
        return [
            nb.network_id
            for nb in binding.QosPolicyNetworkBinding.get_objects(
                self.obj_context, policy_id=self.id)
        ]

    def get_bound_ports(self):
        return [
            pb.port_id
            for pb in binding.QosPolicyPortBinding.get_objects(
                self.obj_context, policy_id=self.id)
        ]

    def get_bound_floatingips(self):
        return [
            fb.fip_id
            for fb in binding.QosPolicyFloatingIPBinding.get_objects(
                self.obj_context, policy_id=self.id)
        ]

    @classmethod
    def _get_bound_tenant_ids(cls, session, binding_db, bound_db,
                              binding_db_id_column, policy_id):
        return list(itertools.chain.from_iterable(
            session.query(bound_db.tenant_id).join(
                binding_db, bound_db.id == binding_db_id_column).filter(
                binding_db.policy_id == policy_id).all()))

    @classmethod
    def get_bound_tenant_ids(cls, context, policy_id):
        """Implements RbacNeutronObject.get_bound_tenant_ids.

        :returns: set -- a set of tenants' ids dependent on QosPolicy.
        """
        net = models_v2.Network
        qosnet = qos_db_model.QosNetworkPolicyBinding
        port = models_v2.Port
        qosport = qos_db_model.QosPortPolicyBinding
        fip = l3.FloatingIP
        qosfip = qos_db_model.QosFIPPolicyBinding
        bound_tenants = []
        with cls.db_context_reader(context):
            bound_tenants.extend(cls._get_bound_tenant_ids(
                context.session, qosnet, net, qosnet.network_id, policy_id))
            bound_tenants.extend(
                cls._get_bound_tenant_ids(context.session, qosport, port,
                                          qosport.port_id, policy_id))
            bound_tenants.extend(
                cls._get_bound_tenant_ids(context.session, qosfip, fip,
                                          qosfip.fip_id, policy_id))
        return set(bound_tenants)

    def obj_make_compatible(self, primitive, target_version):
        def filter_rules(obj_names, rules):
            return [rule for rule in rules if
                    rule['versioned_object.name'] in obj_names]

        def filter_ingress_bandwidth_limit_rules(rules):
            bwlimit_obj_name = rule_obj_impl.QosBandwidthLimitRule.obj_name()
            filtered_rules = []
            for rule in rules:
                if rule['versioned_object.name'] == bwlimit_obj_name:
                    direction = rule['versioned_object.data'].get("direction")
                    if direction == n_const.EGRESS_DIRECTION:
                        rule['versioned_object.data'].pop('direction')
                        filtered_rules.append(rule)
                else:
                    filtered_rules.append(rule)
            return filtered_rules

        _target_version = versionutils.convert_version_to_tuple(target_version)
        names = []
        if _target_version >= (1, 0):
            names.append(rule_obj_impl.QosBandwidthLimitRule.obj_name())
        if _target_version >= (1, 1):
            names.append(rule_obj_impl.QosDscpMarkingRule.obj_name())
        if _target_version >= (1, 2):
            names.append(rule_obj_impl.QosMinimumBandwidthRule.obj_name())
        if 'rules' in primitive and names:
            primitive['rules'] = filter_rules(names, primitive['rules'])

        if _target_version < (1, 3):
            standard_fields = ['revision_number', 'created_at', 'updated_at']
            for f in standard_fields:
                primitive.pop(f)
            if primitive['description'] is None:
                # description was not nullable before
                raise exception.IncompatibleObjectVersion(
                    objver=target_version, objname='QoSPolicy')

        if _target_version < (1, 4):
            primitive['tenant_id'] = primitive.pop('project_id')

        if _target_version < (1, 5):
            if 'rules' in primitive:
                primitive['rules'] = filter_ingress_bandwidth_limit_rules(
                    primitive['rules'])

        if _target_version < (1, 6):
            primitive.pop('is_default', None)


@base_db.NeutronObjectRegistry.register
class QosPolicyDefault(base_db.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = qos_db_model.QosPolicyDefault

    fields = {
        'qos_policy_id': common_types.UUIDField(),
        'project_id': obj_fields.StringField(),
    }

    primary_keys = ['project_id']
