# Copyright 2012 VMware, Inc.  All rights reserved.
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
import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc
from sqlalchemy.orm import scoped_session

from neutron.api.v2 import attributes as attr
from neutron.common import constants
from neutron.db import db_base_plugin_v2
from neutron.db import model_base
from neutron.db import models_v2
from neutron.extensions import securitygroup as ext_sg
from neutron.openstack.common import uuidutils


IP_PROTOCOL_MAP = {constants.PROTO_NAME_TCP: constants.PROTO_NUM_TCP,
                   constants.PROTO_NAME_UDP: constants.PROTO_NUM_UDP,
                   constants.PROTO_NAME_ICMP: constants.PROTO_NUM_ICMP,
                   constants.PROTO_NAME_ICMP_V6: constants.PROTO_NUM_ICMP_V6}


class SecurityGroup(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a v2 neutron security group."""

    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))


class SecurityGroupPortBinding(model_base.BASEV2):
    """Represents binding between neutron ports and security profiles."""

    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey("ports.id",
                                      ondelete='CASCADE'),
                        primary_key=True)
    security_group_id = sa.Column(sa.String(36),
                                  sa.ForeignKey("securitygroups.id"),
                                  primary_key=True)

    # Add a relationship to the Port model in order to instruct SQLAlchemy to
    # eagerly load security group bindings
    ports = orm.relationship(
        models_v2.Port,
        backref=orm.backref("security_groups",
                            lazy='joined', cascade='delete'))


class SecurityGroupRule(model_base.BASEV2, models_v2.HasId,
                        models_v2.HasTenant):
    """Represents a v2 neutron security group rule."""

    security_group_id = sa.Column(sa.String(36),
                                  sa.ForeignKey("securitygroups.id",
                                                ondelete="CASCADE"),
                                  nullable=False)

    remote_group_id = sa.Column(sa.String(36),
                                sa.ForeignKey("securitygroups.id",
                                              ondelete="CASCADE"),
                                nullable=True)

    direction = sa.Column(sa.Enum('ingress', 'egress',
                                  name='securitygrouprules_direction'))
    ethertype = sa.Column(sa.String(40))
    protocol = sa.Column(sa.String(40))
    port_range_min = sa.Column(sa.Integer)
    port_range_max = sa.Column(sa.Integer)
    remote_ip_prefix = sa.Column(sa.String(255))
    security_group = orm.relationship(
        SecurityGroup,
        backref=orm.backref('rules', cascade='all,delete'),
        primaryjoin="SecurityGroup.id==SecurityGroupRule.security_group_id")
    source_group = orm.relationship(
        SecurityGroup,
        backref=orm.backref('source_rules', cascade='all,delete'),
        primaryjoin="SecurityGroup.id==SecurityGroupRule.remote_group_id")


class SecurityGroupDbMixin(ext_sg.SecurityGroupPluginBase):
    """Mixin class to add security group to db_plugin_base_v2."""

    __native_bulk_support = True

    def create_security_group_bulk(self, context, security_group_rule):
        return self._create_bulk('security_group', context,
                                 security_group_rule)

    def create_security_group(self, context, security_group, default_sg=False):
        """Create security group.

        If default_sg is true that means we are a default security group for
        a given tenant if it does not exist.
        """
        s = security_group['security_group']
        tenant_id = self._get_tenant_id_for_create(context, s)

        if not default_sg:
            self._ensure_default_security_group(context, tenant_id)

        with context.session.begin(subtransactions=True):
            security_group_db = SecurityGroup(id=s.get('id') or (
                                              uuidutils.generate_uuid()),
                                              description=s['description'],
                                              tenant_id=tenant_id,
                                              name=s['name'])
            context.session.add(security_group_db)
            for ethertype in ext_sg.sg_supported_ethertypes:
                if s.get('name') == 'default':
                    # Allow intercommunication
                    ingress_rule = SecurityGroupRule(
                        id=uuidutils.generate_uuid(), tenant_id=tenant_id,
                        security_group=security_group_db,
                        direction='ingress',
                        ethertype=ethertype,
                        source_group=security_group_db)
                    context.session.add(ingress_rule)

                egress_rule = SecurityGroupRule(
                    id=uuidutils.generate_uuid(), tenant_id=tenant_id,
                    security_group=security_group_db,
                    direction='egress',
                    ethertype=ethertype)
                context.session.add(egress_rule)

        return self._make_security_group_dict(security_group_db)

    def get_security_groups(self, context, filters=None, fields=None,
                            sorts=None, limit=None,
                            marker=None, page_reverse=False, default_sg=False):

        # If default_sg is True do not call _ensure_default_security_group()
        # so this can be done recursively. Context.tenant_id is checked
        # because all the unit tests do not explicitly set the context on
        # GETS. TODO(arosen)  context handling can probably be improved here.
        if not default_sg and context.tenant_id:
            self._ensure_default_security_group(context, context.tenant_id)
        marker_obj = self._get_marker_obj(context, 'security_group', limit,
                                          marker)
        return self._get_collection(context,
                                    SecurityGroup,
                                    self._make_security_group_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts,
                                    limit=limit, marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    def get_security_groups_count(self, context, filters=None):
        return self._get_collection_count(context, SecurityGroup,
                                          filters=filters)

    def get_security_group(self, context, id, fields=None, tenant_id=None):
        """Tenant id is given to handle the case when creating a security
        group rule on behalf of another use.
        """

        if tenant_id:
            tmp_context_tenant_id = context.tenant_id
            context.tenant_id = tenant_id

        try:
            with context.session.begin(subtransactions=True):
                ret = self._make_security_group_dict(self._get_security_group(
                                                     context, id), fields)
                ret['security_group_rules'] = self.get_security_group_rules(
                    context, {'security_group_id': [id]})
        finally:
            if tenant_id:
                context.tenant_id = tmp_context_tenant_id
        return ret

    def _get_security_group(self, context, id):
        try:
            query = self._model_query(context, SecurityGroup)
            sg = query.filter(SecurityGroup.id == id).one()

        except exc.NoResultFound:
            raise ext_sg.SecurityGroupNotFound(id=id)
        return sg

    def delete_security_group(self, context, id):
        filters = {'security_group_id': [id]}
        ports = self._get_port_security_group_bindings(context, filters)
        if ports:
            raise ext_sg.SecurityGroupInUse(id=id)
        # confirm security group exists
        sg = self._get_security_group(context, id)

        if sg['name'] == 'default' and not context.is_admin:
            raise ext_sg.SecurityGroupCannotRemoveDefault()
        with context.session.begin(subtransactions=True):
            context.session.delete(sg)

    def update_security_group(self, context, id, security_group):
        s = security_group['security_group']
        with context.session.begin(subtransactions=True):
            sg = self._get_security_group(context, id)
            if sg['name'] == 'default' and 'name' in s:
                raise ext_sg.SecurityGroupCannotUpdateDefault()
            sg.update(s)
        return self._make_security_group_dict(sg)

    def _make_security_group_dict(self, security_group, fields=None):
        res = {'id': security_group['id'],
               'name': security_group['name'],
               'tenant_id': security_group['tenant_id'],
               'description': security_group['description']}
        res['security_group_rules'] = [self._make_security_group_rule_dict(r)
                                       for r in security_group.rules]
        return self._fields(res, fields)

    def _make_security_group_binding_dict(self, security_group, fields=None):
        res = {'port_id': security_group['port_id'],
               'security_group_id': security_group['security_group_id']}
        return self._fields(res, fields)

    def _create_port_security_group_binding(self, context, port_id,
                                            security_group_id):
        with context.session.begin(subtransactions=True):
            db = SecurityGroupPortBinding(port_id=port_id,
                                          security_group_id=security_group_id)
            context.session.add(db)

    def _get_port_security_group_bindings(self, context,
                                          filters=None, fields=None):
        return self._get_collection(context,
                                    SecurityGroupPortBinding,
                                    self._make_security_group_binding_dict,
                                    filters=filters, fields=fields)

    def _delete_port_security_group_bindings(self, context, port_id):
        query = self._model_query(context, SecurityGroupPortBinding)
        bindings = query.filter(
            SecurityGroupPortBinding.port_id == port_id)
        with context.session.begin(subtransactions=True):
            for binding in bindings:
                context.session.delete(binding)

    def create_security_group_rule_bulk(self, context, security_group_rule):
        return self._create_bulk('security_group_rule', context,
                                 security_group_rule)

    def create_security_group_rule_bulk_native(self, context,
                                               security_group_rule):
        r = security_group_rule['security_group_rules']

        scoped_session(context.session)
        security_group_id = self._validate_security_group_rules(
            context, security_group_rule)
        with context.session.begin(subtransactions=True):
            if not self.get_security_group(context, security_group_id):
                raise ext_sg.SecurityGroupNotFound(id=security_group_id)

            self._check_for_duplicate_rules(context, r)
            ret = []
            for rule_dict in r:
                rule = rule_dict['security_group_rule']
                tenant_id = self._get_tenant_id_for_create(context, rule)
                db = SecurityGroupRule(
                    id=uuidutils.generate_uuid(), tenant_id=tenant_id,
                    security_group_id=rule['security_group_id'],
                    direction=rule['direction'],
                    remote_group_id=rule.get('remote_group_id'),
                    ethertype=rule['ethertype'],
                    protocol=rule['protocol'],
                    port_range_min=rule['port_range_min'],
                    port_range_max=rule['port_range_max'],
                    remote_ip_prefix=rule.get('remote_ip_prefix'))
                context.session.add(db)
            ret.append(self._make_security_group_rule_dict(db))
        return ret

    def create_security_group_rule(self, context, security_group_rule):
        bulk_rule = {'security_group_rules': [security_group_rule]}
        return self.create_security_group_rule_bulk_native(context,
                                                           bulk_rule)[0]

    def _get_ip_proto_number(self, protocol):
        if protocol is None:
            return
        return IP_PROTOCOL_MAP.get(protocol, protocol)

    def _validate_port_range(self, rule):
        """Check that port_range is valid."""
        if (rule['port_range_min'] is None and
            rule['port_range_max'] is None):
            return
        if not rule['protocol']:
            raise ext_sg.SecurityGroupProtocolRequiredWithPorts()
        ip_proto = self._get_ip_proto_number(rule['protocol'])
        if ip_proto in [constants.PROTO_NUM_TCP, constants.PROTO_NUM_UDP]:
            if (rule['port_range_min'] is not None and
                rule['port_range_min'] <= rule['port_range_max']):
                pass
            else:
                raise ext_sg.SecurityGroupInvalidPortRange()
        elif ip_proto == constants.PROTO_NUM_ICMP:
            for attr, field in [('port_range_min', 'type'),
                                ('port_range_max', 'code')]:
                if rule[attr] > 255:
                    raise ext_sg.SecurityGroupInvalidIcmpValue(
                        field=field, attr=attr, value=rule[attr])

    def _validate_security_group_rules(self, context, security_group_rule):
        """Check that rules being installed.

        Check that all rules belong to the same security
        group, remote_group_id/security_group_id belong to the same tenant,
        and rules are valid.
        """
        new_rules = set()
        tenant_ids = set()
        for rules in security_group_rule['security_group_rules']:
            rule = rules.get('security_group_rule')
            new_rules.add(rule['security_group_id'])

            self._validate_port_range(rule)
            self._validate_ip_prefix(rule)

            if rule['remote_ip_prefix'] and rule['remote_group_id']:
                raise ext_sg.SecurityGroupRemoteGroupAndRemoteIpPrefix()

            if rule['tenant_id'] not in tenant_ids:
                tenant_ids.add(rule['tenant_id'])
            remote_group_id = rule.get('remote_group_id')
            # Check that remote_group_id exists for tenant
            if remote_group_id:
                self.get_security_group(context, remote_group_id,
                                        tenant_id=rule['tenant_id'])
        if len(new_rules) > 1:
            raise ext_sg.SecurityGroupNotSingleGroupRules()
        security_group_id = new_rules.pop()

        # Confirm single tenant and that the tenant has permission
        # to add rules to this security group.
        if len(tenant_ids) > 1:
            raise ext_sg.SecurityGroupRulesNotSingleTenant()
        for tenant_id in tenant_ids:
            self.get_security_group(context, security_group_id,
                                    tenant_id=tenant_id)
        return security_group_id

    def _make_security_group_rule_dict(self, security_group_rule, fields=None):
        res = {'id': security_group_rule['id'],
               'tenant_id': security_group_rule['tenant_id'],
               'security_group_id': security_group_rule['security_group_id'],
               'ethertype': security_group_rule['ethertype'],
               'direction': security_group_rule['direction'],
               'protocol': security_group_rule['protocol'],
               'port_range_min': security_group_rule['port_range_min'],
               'port_range_max': security_group_rule['port_range_max'],
               'remote_ip_prefix': security_group_rule['remote_ip_prefix'],
               'remote_group_id': security_group_rule['remote_group_id']}

        return self._fields(res, fields)

    def _make_security_group_rule_filter_dict(self, security_group_rule):
        sgr = security_group_rule['security_group_rule']
        res = {'tenant_id': [sgr['tenant_id']],
               'security_group_id': [sgr['security_group_id']],
               'direction': [sgr['direction']]}

        include_if_present = ['protocol', 'port_range_max', 'port_range_min',
                              'ethertype', 'remote_ip_prefix',
                              'remote_group_id']
        for key in include_if_present:
            value = sgr.get(key)
            if value:
                res[key] = [value]
        return res

    def _check_for_duplicate_rules(self, context, security_group_rules):
        for i in security_group_rules:
            found_self = False
            for j in security_group_rules:
                if i['security_group_rule'] == j['security_group_rule']:
                    if found_self:
                        raise ext_sg.DuplicateSecurityGroupRuleInPost(rule=i)
                    found_self = True

            # Check in database if rule exists
            filters = self._make_security_group_rule_filter_dict(i)
            db_rules = self.get_security_group_rules(context, filters)
            # Note(arosen): the call to get_security_group_rules wildcards
            # values in the filter that have a value of [None]. For
            # example, filters = {'remote_group_id': [None]} will return
            # all security group rules regardless of their value of
            # remote_group_id. Therefore it is not possible to do this
            # query unless the behavior of _get_collection()
            # is changed which cannot be because other methods are already
            # relying on this behavor. Therefore, we do the filtering
            # below to check for these corner cases.
            for db_rule in db_rules:
                # need to remove id from db_rule for matching
                id = db_rule.pop('id')
                if (i['security_group_rule'] == db_rule):
                    raise ext_sg.SecurityGroupRuleExists(id=id)

    def _validate_ip_prefix(self, rule):
        """Check that a valid cidr was specified as remote_ip_prefix

        No need to check that it is in fact an IP address as this is already
        validated by attribute validators.
        Check that rule ethertype is consistent with remote_ip_prefix ip type.
        Add mask to ip_prefix if absent (192.168.1.10 -> 192.168.1.10/32).
        """
        input_prefix = rule['remote_ip_prefix']
        if input_prefix:
            addr = netaddr.IPNetwork(input_prefix)
            # set input_prefix to always include the netmask:
            rule['remote_ip_prefix'] = str(addr)
            # check consistency of ethertype with addr version
            if rule['ethertype'] != "IPv%d" % (addr.version):
                raise ext_sg.SecurityGroupRuleParameterConflict(
                    ethertype=rule['ethertype'], cidr=input_prefix)

    def get_security_group_rules(self, context, filters=None, fields=None,
                                 sorts=None, limit=None, marker=None,
                                 page_reverse=False):
        marker_obj = self._get_marker_obj(context, 'security_group_rule',
                                          limit, marker)
        return self._get_collection(context,
                                    SecurityGroupRule,
                                    self._make_security_group_rule_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts,
                                    limit=limit, marker_obj=marker_obj,
                                    page_reverse=page_reverse)

    def get_security_group_rules_count(self, context, filters=None):
        return self._get_collection_count(context, SecurityGroupRule,
                                          filters=filters)

    def get_security_group_rule(self, context, id, fields=None):
        security_group_rule = self._get_security_group_rule(context, id)
        return self._make_security_group_rule_dict(security_group_rule, fields)

    def _get_security_group_rule(self, context, id):
        try:
            query = self._model_query(context, SecurityGroupRule)
            sgr = query.filter(SecurityGroupRule.id == id).one()
        except exc.NoResultFound:
            raise ext_sg.SecurityGroupRuleNotFound(id=id)
        return sgr

    def delete_security_group_rule(self, context, id):
        with context.session.begin(subtransactions=True):
            rule = self._get_security_group_rule(context, id)
            context.session.delete(rule)

    def _extend_port_dict_security_group(self, port_res, port_db):
        # Security group bindings will be retrieved from the sqlalchemy
        # model. As they're loaded eagerly with ports because of the
        # joined load they will not cause an extra query.
        security_group_ids = [sec_group_mapping['security_group_id'] for
                              sec_group_mapping in port_db.security_groups]
        port_res[ext_sg.SECURITYGROUPS] = security_group_ids
        return port_res

    # Register dict extend functions for ports
    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        attr.PORTS, ['_extend_port_dict_security_group'])

    def _process_port_create_security_group(self, context, port,
                                            security_group_ids):
        if attr.is_attr_set(security_group_ids):
            for security_group_id in security_group_ids:
                self._create_port_security_group_binding(context, port['id'],
                                                         security_group_id)
        # Convert to list as a set might be passed here and
        # this has to be serialized
        port[ext_sg.SECURITYGROUPS] = (security_group_ids and
                                       list(security_group_ids) or [])

    def _ensure_default_security_group(self, context, tenant_id):
        """Create a default security group if one doesn't exist.

        :returns: the default security group id.
        """
        filters = {'name': ['default'], 'tenant_id': [tenant_id]}
        default_group = self.get_security_groups(context, filters,
                                                 default_sg=True)
        if not default_group:
            security_group = {'security_group': {'name': 'default',
                                                 'tenant_id': tenant_id,
                                                 'description': 'default'}}
            ret = self.create_security_group(context, security_group, True)
            return ret['id']
        else:
            return default_group[0]['id']

    def _get_security_groups_on_port(self, context, port):
        """Check that all security groups on port belong to tenant.

        :returns: all security groups IDs on port belonging to tenant.
        """
        p = port['port']
        if not attr.is_attr_set(p.get(ext_sg.SECURITYGROUPS)):
            return
        if p.get('device_owner') and p['device_owner'].startswith('network:'):
            return

        port_sg = p.get(ext_sg.SECURITYGROUPS, [])
        valid_groups = set(g['id'] for g in
                           self.get_security_groups(context, fields=['id'],
                                                    filters={'id': port_sg}))

        requested_groups = set(port_sg)
        port_sg_missing = requested_groups - valid_groups
        if port_sg_missing:
            raise ext_sg.SecurityGroupNotFound(id=str(port_sg_missing[0]))

        return requested_groups

    def _ensure_default_security_group_on_port(self, context, port):
        # we don't apply security groups for dhcp, router
        if (port['port'].get('device_owner') and
                port['port']['device_owner'].startswith('network:')):
            return
        tenant_id = self._get_tenant_id_for_create(context,
                                                   port['port'])
        default_sg = self._ensure_default_security_group(context, tenant_id)
        if attr.is_attr_set(port['port'].get(ext_sg.SECURITYGROUPS)):
            sgids = port['port'].get(ext_sg.SECURITYGROUPS)
        else:
            sgids = [default_sg]
        port['port'][ext_sg.SECURITYGROUPS] = sgids

    def _check_update_deletes_security_groups(self, port):
        """Return True if port has as a security group and it's value
        is either [] or not is_attr_set, otherwise return False
        """
        if (ext_sg.SECURITYGROUPS in port['port'] and
            not (attr.is_attr_set(port['port'][ext_sg.SECURITYGROUPS])
                 and port['port'][ext_sg.SECURITYGROUPS] != [])):
            return True
        return False

    def _check_update_has_security_groups(self, port):
        """Return True if port has as a security group and False if the
        security_group field is is_attr_set or [].
        """
        if (ext_sg.SECURITYGROUPS in port['port'] and
            (attr.is_attr_set(port['port'][ext_sg.SECURITYGROUPS]) and
             port['port'][ext_sg.SECURITYGROUPS] != [])):
            return True
        return False
