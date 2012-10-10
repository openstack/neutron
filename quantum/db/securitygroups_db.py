# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 Nicira Networks, Inc.  All rights reserved.
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
#
# @author: Aaron Rosen, Nicira, Inc
#

import re

import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc
from sqlalchemy.orm import scoped_session

from quantum.api.v2 import attributes
from quantum.openstack.common import cfg
from quantum.common import utils
from quantum.db import model_base
from quantum.db import models_v2
from quantum.extensions import securitygroup as ext_sg


class SecurityGroup(model_base.BASEV2, models_v2.HasId, models_v2.HasTenant):
    """Represents a v2 quantum security group."""
    name = sa.Column(sa.String(255))
    description = sa.Column(sa.String(255))
    external_id = sa.Column(sa.Integer, unique=True)


class SecurityGroupPortBinding(model_base.BASEV2):
    """Represents binding between quantum ports and security profiles"""
    port_id = sa.Column(sa.String(36), sa.ForeignKey("ports.id"),
                        primary_key=True)
    security_group_id = sa.Column(sa.String(36),
                                  sa.ForeignKey("securitygroups.id"),
                                  primary_key=True)


class SecurityGroupRule(model_base.BASEV2, models_v2.HasId,
                        models_v2.HasTenant):
    """Represents a v2 quantum security group rule."""
    external_id = sa.Column(sa.Integer)
    security_group_id = sa.Column(sa.String(36),
                                  sa.ForeignKey("securitygroups.id",
                                                ondelete="CASCADE"),
                                  nullable=False)

    source_group_id = sa.Column(sa.String(36),
                                sa.ForeignKey("securitygroups.id",
                                              ondelete="CASCADE"),
                                nullable=True)

    direction = sa.Column(sa.Enum('ingress', 'egress'))
    ethertype = sa.Column(sa.String(40))
    protocol = sa.Column(sa.String(40))
    port_range_min = sa.Column(sa.Integer)
    port_range_max = sa.Column(sa.Integer)
    source_ip_prefix = sa.Column(sa.String(255))
    security_group = orm.relationship(
        SecurityGroup,
        backref=orm.backref('rules', cascade='all,delete'),
        primaryjoin="SecurityGroup.id==SecurityGroupRule.security_group_id")
    source_group = orm.relationship(
        SecurityGroup,
        backref=orm.backref('source_rules', cascade='all,delete'),
        primaryjoin="SecurityGroup.id==SecurityGroupRule.source_group_id")


class SecurityGroupDbMixin(ext_sg.SecurityGroupPluginBase):
    """Mixin class to add security group to db_plugin_base_v2."""

    __native_bulk_support = True
    sg_supported_protocols = ['tcp', 'udp', 'icmp']
    sg_supported_ethertypes = ['IPv4', 'IPv6']

    def create_security_group_bulk(self, context, security_group_rule):
        return self._create_bulk('security_group', context,
                                 security_group_rule)

    def create_security_group(self, context, security_group, default_sg=False):
        """Create security group.
        If default_sg is true that means we are a default security group for
        a given tenant if it does not exist.
        """
        s = security_group['security_group']
        if (cfg.CONF.SECURITYGROUP.proxy_mode and not context.is_admin):
            raise ext_sg.SecurityGroupProxyModeNotAdmin()
        if (cfg.CONF.SECURITYGROUP.proxy_mode and not s.get('external_id')):
            raise ext_sg.SecurityGroupProxyMode()
        if not cfg.CONF.SECURITYGROUP.proxy_mode and s.get('external_id'):
            raise ext_sg.SecurityGroupNotProxyMode()

        tenant_id = self._get_tenant_id_for_create(context, s)

        # if in proxy mode a default security group will be created by source
        if not default_sg and not cfg.CONF.SECURITYGROUP.proxy_mode:
            self._ensure_default_security_group(context, tenant_id,
                                                security_group)
        if s.get('external_id'):
            try:
                # Check if security group already exists
                sg = self.get_security_group(context, s.get('external_id'))
                if sg:
                    raise ext_sg.SecurityGroupAlreadyExists(
                        name=sg.get('name', ''),
                        external_id=s.get('external_id'))
            except ext_sg.SecurityGroupNotFound:
                pass

        with context.session.begin(subtransactions=True):
            security_group_db = SecurityGroup(id=s.get('id') or (
                                              utils.str_uuid()),
                                              description=s['description'],
                                              tenant_id=tenant_id,
                                              name=s['name'],
                                              external_id=s.get('external_id'))
            context.session.add(security_group_db)
            if s.get('name') == 'default':
                for ethertype in self.sg_supported_ethertypes:
                    # Allow all egress traffic
                    db = SecurityGroupRule(
                        id=utils.str_uuid(), tenant_id=tenant_id,
                        security_group=security_group_db,
                        direction='egress',
                        ethertype=ethertype)
                    context.session.add(db)
                    # Allow intercommunication
                    db = SecurityGroupRule(
                        id=utils.str_uuid(), tenant_id=tenant_id,
                        security_group=security_group_db,
                        direction='ingress',
                        source_group=security_group_db,
                        ethertype=ethertype)
                    context.session.add(db)

        return self._make_security_group_dict(security_group_db)

    def get_security_groups(self, context, filters=None, fields=None):
        return self._get_collection(context, SecurityGroup,
                                    self._make_security_group_dict,
                                    filters=filters, fields=fields)

    def get_security_group(self, context, id, fields=None, tenant_id=None):
        """Tenant id is given to handle the case when we
        are creating a security group or security group rule on behalf of
        another use.
        """

        if tenant_id:
            tmp_context_tenant_id = context.tenant_id
            context.tenant_id = tenant_id

        try:
            ret = self._make_security_group_dict(self._get_security_group(
                                                 context, id), fields)
        finally:
            if tenant_id:
                context.tenant_id = tmp_context_tenant_id
        return ret

    def _get_security_group(self, context, id):
        try:
            query = self._model_query(context, SecurityGroup)
            if not re.match(attributes.UUID_PATTERN, str(id)):
                sg = query.filter(SecurityGroup.external_id == id).one()
            else:
                sg = query.filter(SecurityGroup.id == id).one()

        except exc.NoResultFound:
            raise ext_sg.SecurityGroupNotFound(id=id)
        return sg

    def delete_security_group(self, context, id):
        if (cfg.CONF.SECURITYGROUP.proxy_mode and not context.is_admin):
            raise ext_sg.SecurityGroupProxyModeNotAdmin()

        filters = {'security_group_id': [id]}
        ports = self._get_port_security_group_bindings(context, filters)
        if ports:
            raise ext_sg.SecurityGroupInUse(id=id)
        # confirm security group exists
        sg = self._get_security_group(context, id)

        if sg['name'] == 'default':
            raise ext_sg.SecurityGroupCannotRemoveDefault()
        with context.session.begin(subtransactions=True):
            context.session.delete(sg)

    def _make_security_group_dict(self, security_group, fields=None):
        res = {'id': security_group['id'],
               'name': security_group['name'],
               'tenant_id': security_group['tenant_id'],
               'description': security_group['description']}
        if security_group.get('external_id'):
            res['external_id'] = security_group['external_id']
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
        return self._get_collection(context, SecurityGroupPortBinding,
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
                    id=utils.str_uuid(), tenant_id=tenant_id,
                    security_group_id=rule['security_group_id'],
                    direction=rule['direction'],
                    external_id=rule.get('external_id'),
                    source_group_id=rule.get('source_group_id'),
                    ethertype=rule['ethertype'],
                    protocol=rule['protocol'],
                    port_range_min=rule['port_range_min'],
                    port_range_max=rule['port_range_max'],
                    source_ip_prefix=rule.get('source_ip_prefix'))
                context.session.add(db)
            ret.append(self._make_security_group_rule_dict(db))
        return ret

    def create_security_group_rule(self, context, security_group_rule):
        bulk_rule = {'security_group_rules': [security_group_rule]}
        return self.create_security_group_rule_bulk_native(context,
                                                           bulk_rule)[0]

    def _validate_security_group_rules(self, context, security_group_rule):
        """Check that rules being installed all belong to the same security
        group, source_group_id/security_group_id belong to the same tenant,
        and rules are valid.
        """

        if (cfg.CONF.SECURITYGROUP.proxy_mode and not context.is_admin):
            raise ext_sg.SecurityGroupProxyModeNotAdmin()

        new_rules = set()
        tenant_ids = set()
        for rules in security_group_rule['security_group_rules']:
            rule = rules.get('security_group_rule')
            new_rules.add(rule['security_group_id'])

            if (cfg.CONF.SECURITYGROUP.proxy_mode and
                not rule.get('external_id')):
                raise ext_sg.SecurityGroupProxyMode()
            if (not cfg.CONF.SECURITYGROUP.proxy_mode and
                rule.get('external_id')):
                raise ext_sg.SecurityGroupNotProxyMode()

            # Check that protocol/ethertype are valid
            protocol = rule.get('protocol')
            if protocol and protocol not in self.sg_supported_protocols:
                raise ext_sg.SecurityGroupInvalidProtocolType(value=protocol)
            ethertype = rule.get('ethertype')
            if ethertype and ethertype not in self.sg_supported_ethertypes:
                raise ext_sg.SecurityGroupInvalidEtherType(value=ethertype)

            # Check that port_range's are valid
            if (rule['port_range_min'] is None and
                rule['port_range_max'] is None):
                pass
            elif (rule['port_range_min'] is not None and
                  rule['port_range_min'] <= rule['port_range_max']):
                if not rule['protocol']:
                    raise ext_sg.SecurityGroupProtocolRequiredWithPorts()
            else:
                raise ext_sg.SecurityGroupInvalidPortRange()

            if rule['source_ip_prefix'] and rule['source_group_id']:
                raise ext_sg.SecurityGroupSourceGroupAndIpPrefix()

            if rule['tenant_id'] not in tenant_ids:
                tenant_ids.add(rule['tenant_id'])
            source_group_id = rule.get('source_group_id')
            # Check that source_group_id exists for tenant
            if source_group_id:
                self.get_security_group(context, source_group_id,
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
               'source_ip_prefix': security_group_rule['source_ip_prefix'],
               'source_group_id': security_group_rule['source_group_id'],
               'external_id': security_group_rule['external_id']}

        return self._fields(res, fields)

    def _make_security_group_rule_filter_dict(self, security_group_rule):
        sgr = security_group_rule['security_group_rule']
        res = {'tenant_id': [sgr['tenant_id']],
               'security_group_id': [sgr['security_group_id']],
               'direction': [sgr['direction']]}

        include_if_present = ['protocol', 'port_range_max', 'port_range_min',
                              'ethertype', 'source_ip_prefix',
                              'source_group_id', 'external_id']
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
            if self.get_security_group_rules(context, filters):
                raise ext_sg.SecurityGroupRuleExists(rule=i)

    def get_security_group_rules(self, context, filters=None, fields=None):
        return self._get_collection(context, SecurityGroupRule,
                                    self._make_security_group_rule_dict,
                                    filters=filters, fields=fields)

    def get_security_group_rule(self, context, id, fields=None):
        security_group_rule = self._get_security_group_rule(context, id)
        return self._make_security_group_rule_dict(security_group_rule, fields)

    def _get_security_group_rule(self, context, id):
        try:
            if not re.match(attributes.UUID_PATTERN, id):
                query = self._model_query(context, SecurityGroupRule)
                sgr = query.filter(SecurityGroupRule.external_id == id).one()
            else:
                query = self._model_query(context, SecurityGroupRule)
                sgr = query.filter(SecurityGroupRule.id == id).one()
        except exc.NoResultFound:
            raise ext_sg.SecurityGroupRuleNotFound(id=id)
        return sgr

    def delete_security_group_rule(self, context, sgrid):
        if (cfg.CONF.SECURITYGROUP.proxy_mode and not context.is_admin):
            raise ext_sg.SecurityGroupProxyModeNotAdmin()
        with context.session.begin(subtransactions=True):
            rule = self._get_security_group_rule(context, sgrid)
            context.session.delete(rule)

    def _extend_port_dict_security_group(self, context, port):
        filters = {'port_id': [port['id']]}
        fields = {'security_group_id': None}
        port[ext_sg.SECURITYGROUP] = []
        security_group_id = self._get_port_security_group_bindings(
            context, filters, fields)
        for security_group_id in security_group_id:
            port[ext_sg.SECURITYGROUP].append(
                security_group_id['security_group_id'])
        return port

    def _process_port_create_security_group(self, context, port_id,
                                            security_group_id):
        if not security_group_id:
            return
        for security_group_id in security_group_id:
            self._create_port_security_group_binding(context, port_id,
                                                     security_group_id)

    def _ensure_default_security_group(self, context, tenant_id,
                                       security_group=None):
        """Create a default security group if one doesn't exist.

        :returns: the default security group id.
        """
        # if in proxy mode a default security group will be created by source
        if not security_group and cfg.CONF.SECURITYGROUP.proxy_mode:
            return

        filters = {'name': ['default'], 'tenant_id': [tenant_id]}
        default_group = self.get_security_groups(context, filters)
        if not default_group:
            security_group = {'security_group': {'name': 'default',
                                                 'tenant_id': tenant_id,
                                                 'description': 'default'}}
            if security_group:
                security_group['security_group']['external_id'] = (
                    security_group['security_group'].get('external_id'))
            ret = self.create_security_group(context, security_group, True)
            return ret['id']
        else:
            return default_group[0]['id']

    def _validate_security_groups_on_port(self, context, port):
        p = port['port']
        if not p.get(ext_sg.SECURITYGROUP):
            return

        valid_groups = self.get_security_groups(context, fields={'id': None})
        valid_groups_set = set([x['id'] for x in valid_groups])
        req_sg_set = set(p[ext_sg.SECURITYGROUP])
        invalid_sg_set = req_sg_set - valid_groups_set
        if invalid_sg_set:
            msg = ' '.join(str(x) for x in invalid_sg_set)
            raise ext_sg.SecurityGroupNotFound(id=msg)
