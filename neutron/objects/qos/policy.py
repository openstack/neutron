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

from oslo_utils import versionutils
from oslo_versionedobjects import base as obj_base
from oslo_versionedobjects import fields as obj_fields
from six import add_metaclass

from neutron._i18n import _
from neutron.common import exceptions
from neutron.db import api as db_api
from neutron.db import models_v2
from neutron.db.qos import api as qos_db_api
from neutron.db.qos import models as qos_db_model
from neutron.db.rbac_db_models import QosPolicyRBAC
from neutron.objects import base
from neutron.objects.db import api as obj_db_api
from neutron.objects.qos import rule as rule_obj_impl
from neutron.objects import rbac_db


@obj_base.VersionedObjectRegistry.register
@add_metaclass(rbac_db.RbacNeutronMetaclass)
class QosPolicy(base.NeutronDbObject):
    # Version 1.0: Initial version
    # Version 1.1: QosDscpMarkingRule introduced
    VERSION = '1.1'

    # required by RbacNeutronMetaclass
    rbac_db_model = QosPolicyRBAC
    db_model = qos_db_model.QosPolicy

    port_binding_model = qos_db_model.QosPortPolicyBinding
    network_binding_model = qos_db_model.QosNetworkPolicyBinding

    fields = {
        'id': obj_fields.UUIDField(),
        'tenant_id': obj_fields.UUIDField(),
        'name': obj_fields.StringField(),
        'description': obj_fields.StringField(),
        'shared': obj_fields.BooleanField(default=False),
        'rules': obj_fields.ListOfObjectsField('QosRule', subclasses=True),
    }

    fields_no_update = ['id', 'tenant_id']

    synthetic_fields = ['rules']

    binding_models = {'network': network_binding_model,
                      'port': port_binding_model}

    def obj_load_attr(self, attrname):
        if attrname != 'rules':
            raise exceptions.ObjectActionError(
                action='obj_load_attr',
                reason=_('unable to load %s') % attrname)

        if not hasattr(self, attrname):
            self.reload_rules()

    def reload_rules(self):
        rules = rule_obj_impl.get_rules(self._context, self.id)
        setattr(self, 'rules', rules)
        self.obj_reset_changes(['rules'])

    def get_rule_by_id(self, rule_id):
        """Return rule specified by rule_id.

        @raise QosRuleNotFound: if there is no such rule in the policy.
        """

        for rule in self.rules:
            if rule_id == rule.id:
                return rule
        raise exceptions.QosRuleNotFound(policy_id=self.id,
                                         rule_id=rule_id)

    @classmethod
    def get_object(cls, context, **kwargs):
        # We want to get the policy regardless of its tenant id. We'll make
        # sure the tenant has permission to access the policy later on.
        admin_context = context.elevated()
        with db_api.autonested_transaction(admin_context.session):
            policy_obj = super(QosPolicy, cls).get_object(admin_context,
                                                          **kwargs)
            if (not policy_obj or
                not cls.is_accessible(context, policy_obj)):
                return

            policy_obj.reload_rules()
            return policy_obj

    @classmethod
    def get_objects(cls, context, **kwargs):
        # We want to get the policy regardless of its tenant id. We'll make
        # sure the tenant has permission to access the policy later on.
        admin_context = context.elevated()
        with db_api.autonested_transaction(admin_context.session):
            objs = super(QosPolicy, cls).get_objects(admin_context,
                                                     **kwargs)
            result = []
            for obj in objs:
                if not cls.is_accessible(context, obj):
                    continue
                obj.reload_rules()
                result.append(obj)
            return result

    @classmethod
    def _get_object_policy(cls, context, model, **kwargs):
        with db_api.autonested_transaction(context.session):
            binding_db_obj = obj_db_api.get_object(context, model, **kwargs)
            if binding_db_obj:
                return cls.get_object(context, id=binding_db_obj['policy_id'])

    @classmethod
    def get_network_policy(cls, context, network_id):
        return cls._get_object_policy(context, cls.network_binding_model,
                                      network_id=network_id)

    @classmethod
    def get_port_policy(cls, context, port_id):
        return cls._get_object_policy(context, cls.port_binding_model,
                                      port_id=port_id)

    # TODO(QoS): Consider extending base to trigger registered methods for us
    def create(self):
        with db_api.autonested_transaction(self._context.session):
            super(QosPolicy, self).create()
            self.reload_rules()

    def delete(self):
        with db_api.autonested_transaction(self._context.session):
            for object_type, model in self.binding_models.items():
                binding_db_obj = obj_db_api.get_object(self._context, model,
                                                       policy_id=self.id)
                if binding_db_obj:
                    raise exceptions.QosPolicyInUse(
                        policy_id=self.id,
                        object_type=object_type,
                        object_id=binding_db_obj['%s_id' % object_type])

            super(QosPolicy, self).delete()

    def attach_network(self, network_id):
        qos_db_api.create_policy_network_binding(self._context,
                                                 policy_id=self.id,
                                                 network_id=network_id)

    def attach_port(self, port_id):
        qos_db_api.create_policy_port_binding(self._context,
                                              policy_id=self.id,
                                              port_id=port_id)

    def detach_network(self, network_id):
        qos_db_api.delete_policy_network_binding(self._context,
                                                 policy_id=self.id,
                                                 network_id=network_id)

    def detach_port(self, port_id):
        qos_db_api.delete_policy_port_binding(self._context,
                                              policy_id=self.id,
                                              port_id=port_id)

    def get_bound_networks(self):
        return qos_db_api.get_network_ids_by_network_policy_binding(
            self._context, self.id)

    def get_bound_ports(self):
        return qos_db_api.get_port_ids_by_port_policy_binding(
            self._context, self.id)

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

        :returns: set -- a set of tenants' ids dependant on QosPolicy.
        """
        net = models_v2.Network
        qosnet = qos_db_model.QosNetworkPolicyBinding
        port = models_v2.Port
        qosport = qos_db_model.QosPortPolicyBinding
        bound_tenants = []
        with db_api.autonested_transaction(context.session):
            bound_tenants.extend(cls._get_bound_tenant_ids(
                context.session, qosnet, net, qosnet.network_id, policy_id))
            bound_tenants.extend(
                cls._get_bound_tenant_ids(context.session, qosport, port,
                                          qosport.port_id, policy_id))
        return set(bound_tenants)

    def obj_make_compatible(self, primitive, target_version):
        _target_version = versionutils.convert_version_to_tuple(target_version)
        if _target_version < (1, 1):
            if 'rules' in primitive:
                bw_obj_name = rule_obj_impl.QosBandwidthLimitRule.obj_name()
                primitive['rules'] = filter(
                    lambda rule: (rule['versioned_object.name'] ==
                                  bw_obj_name),
                    primitive['rules'])
