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

from neutron_lib import context as context_lib
from neutron_lib.objects import common_types
from neutron_lib.utils import net as net_utils
from oslo_utils import versionutils
from oslo_versionedobjects import fields as obj_fields
from sqlalchemy import or_

from neutron.db.models import securitygroup as sg_models
from neutron.db import rbac_db_models
from neutron.objects import base
from neutron.objects import ports
from neutron.objects import rbac
from neutron.objects import rbac_db


@base.NeutronObjectRegistry.register
class SecurityGroupRBAC(rbac.RBACBaseObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = rbac_db_models.SecurityGroupRBAC


@base.NeutronObjectRegistry.register
class SecurityGroup(rbac_db.NeutronRbacObject):
    # Version 1.0: Initial version
    # Version 1.1: Add RBAC support
    # Version 1.2: Added stateful support
    # Version 1.3: Added support for remote_address_group_id in rules
    # Version 1.4: Added support for normalized_cidr in rules
    VERSION = '1.4'

    # required by RbacNeutronMetaclass
    rbac_db_cls = SecurityGroupRBAC
    db_model = sg_models.SecurityGroup

    fields = {
        'id': common_types.UUIDField(),
        'name': obj_fields.StringField(nullable=True),
        'project_id': obj_fields.StringField(nullable=True),
        'shared': obj_fields.BooleanField(default=False),
        'stateful': obj_fields.BooleanField(default=True),
        'is_default': obj_fields.BooleanField(default=False),
        'rules': obj_fields.ListOfObjectsField(
            'SecurityGroupRule', nullable=True
        ),
        # NOTE(ihrachys): we don't include source_rules that is present in the
        # model until we realize it's actually needed
    }

    fields_no_update = ['project_id', 'is_default']

    synthetic_fields = ['is_default', 'rules']

    extra_filter_names = {'is_default'}

    lazy_fields = set(['rules'])

    def create(self):
        # save is_default before super() resets it to False
        is_default = self.is_default
        with self.db_context_writer(self.obj_context):
            super(SecurityGroup, self).create()
            if is_default:
                default_group = DefaultSecurityGroup(
                    self.obj_context,
                    project_id=self.project_id,
                    security_group_id=self.id)
                default_group.create()
                self.is_default = True
                self.obj_reset_changes(['is_default'])

    def from_db_object(self, db_obj):
        super(SecurityGroup, self).from_db_object(db_obj)
        if self._load_synthetic_fields:
            setattr(self, 'is_default',
                    bool(db_obj.get('default_security_group')))
            self.obj_reset_changes(['is_default'])

    @classmethod
    def get_sg_by_id(cls, context, sg_id):
        return super(SecurityGroup, cls).get_object(context, id=sg_id)

    def obj_make_compatible(self, primitive, target_version):
        _target_version = versionutils.convert_version_to_tuple(target_version)

        def filter_remote_address_group_id_from_rules(rules):
            sg_rule = SecurityGroupRule()
            for rule in rules:
                sg_rule.obj_make_compatible(
                    rule['versioned_object.data'], '1.0')
                rule['versioned_object.version'] = '1.0'

        def filter_normalized_cidr_from_rules(rules):
            sg_rule = SecurityGroupRule()
            for rule in rules:
                rule_version = versionutils.convert_version_to_tuple(
                    rule['versioned_object.version'])
                if rule_version > (1, 1):
                    sg_rule.obj_make_compatible(
                        rule['versioned_object.data'], '1.1')
                    rule['versioned_object.version'] = '1.1'

        if _target_version < (1, 1):
            primitive.pop('shared')
        if _target_version < (1, 2):
            primitive.pop('stateful')
        if _target_version < (1, 3):
            if 'rules' in primitive:
                filter_remote_address_group_id_from_rules(primitive['rules'])
        if _target_version < (1, 4):
            if 'rules' in primitive:
                filter_normalized_cidr_from_rules(primitive['rules'])

    @classmethod
    def get_bound_tenant_ids(cls, context, obj_id):
        port_objs = ports.Port.get_objects(context,
                                           security_group_ids=[obj_id])
        return {port.tenant_id for port in port_objs}


@base.NeutronObjectRegistry.register
class DefaultSecurityGroup(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = sg_models.DefaultSecurityGroup

    fields = {
        'project_id': obj_fields.StringField(),
        'security_group_id': common_types.UUIDField(),
    }

    fields_no_update = ['security_group_id']

    primary_keys = ['project_id']


@base.NeutronObjectRegistry.register
class SecurityGroupRule(base.NeutronDbObject):
    # Version 1.0: Initial version
    # Version 1.1: Add remote address group support
    # Version 1.2: Added normalized cidr column
    VERSION = '1.2'

    db_model = sg_models.SecurityGroupRule

    fields = {
        'id': common_types.UUIDField(),
        'project_id': obj_fields.StringField(nullable=True),
        'security_group_id': common_types.UUIDField(),
        'remote_group_id': common_types.UUIDField(nullable=True),
        'direction': common_types.FlowDirectionEnumField(nullable=True),
        'ethertype': common_types.EtherTypeEnumField(nullable=True),
        'protocol': common_types.IpProtocolEnumField(nullable=True),
        'port_range_min': common_types.PortRangeWith0Field(nullable=True),
        'port_range_max': common_types.PortRangeWith0Field(nullable=True),
        'remote_ip_prefix': common_types.IPNetworkField(nullable=True),
        'remote_address_group_id': common_types.UUIDField(nullable=True),
        'normalized_cidr': common_types.IPNetworkField(nullable=True),
    }

    synthetic_fields = ['normalized_cidr']

    foreign_keys = {'SecurityGroup': {'security_group_id': 'id'}}

    fields_no_update = ['project_id', 'security_group_id', 'remote_group_id',
                        'remote_address_group_id']

    def obj_make_compatible(self, primitive, target_version):
        _target_version = versionutils.convert_version_to_tuple(target_version)
        if _target_version < (1, 1):
            primitive.pop('remote_address_group_id', None)
        if _target_version < (1, 2):
            primitive.pop('normalized_cidr', None)

    # TODO(sayalilunkad): get rid of it once we switch the db model to using
    # custom types.
    @classmethod
    def modify_fields_to_db(cls, fields):
        result = super(SecurityGroupRule, cls).modify_fields_to_db(fields)
        remote_ip_prefix = result.get('remote_ip_prefix')
        if remote_ip_prefix:
            result['remote_ip_prefix'] = cls.filter_to_str(remote_ip_prefix)
        return result

    def _load_normalized_cidr(self, db_obj=None):
        db_obj = db_obj or SecurityGroupRule.get_object(self.obj_context,
                                                        id=self.id)
        if not db_obj:
            return

        cidr = None
        if db_obj.remote_ip_prefix:
            cidr = net_utils.AuthenticIPNetwork(db_obj.remote_ip_prefix).cidr

        setattr(self, 'normalized_cidr', cidr)
        self.obj_reset_changes(['normalized_cidr'])

    def from_db_object(self, db_obj):
        super(SecurityGroupRule, self).from_db_object(db_obj)
        self._load_normalized_cidr(db_obj)

    def obj_load_attr(self, attrname):
        if attrname == 'normalized_cidr':
            return self._load_normalized_cidr()
        super(SecurityGroupRule, self).obj_load_attr(attrname)

    # TODO(sayalilunkad): get rid of it once we switch the db model to using
    # custom types.
    @classmethod
    def modify_fields_from_db(cls, db_obj):
        fields = super(SecurityGroupRule, cls).modify_fields_from_db(db_obj)
        if 'remote_ip_prefix' in fields:
            fields['remote_ip_prefix'] = (
                net_utils.AuthenticIPNetwork(fields['remote_ip_prefix']))
        return fields

    @classmethod
    def get_security_group_rule_ids(cls, project_id):
        """Retrieve all SG rules related to this project_id

        This method returns the SG rule IDs that meet these conditions:
        - The rule belongs to this project_id
        - The rule belongs to a security group that belongs to the project_id
        """
        context = context_lib.get_admin_context()
        query = context.session.query(cls.db_model.id)
        query = query.join(
            SecurityGroup.db_model,
            cls.db_model.security_group_id == SecurityGroup.db_model.id)
        clauses = or_(SecurityGroup.db_model.project_id == project_id,
                      cls.db_model.project_id == project_id)
        rule_ids = query.filter(clauses).all()
        return [rule_id[0] for rule_id in rule_ids]
