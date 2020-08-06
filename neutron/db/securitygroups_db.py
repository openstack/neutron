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
from neutron_lib.api.definitions import port as port_def
from neutron_lib.api import validators
from neutron_lib.callbacks import events
from neutron_lib.callbacks import exceptions
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib import context as context_lib
from neutron_lib.db import api as db_api
from neutron_lib.db import model_query
from neutron_lib.db import resource_extend
from neutron_lib.db import utils as db_utils
from neutron_lib import exceptions as n_exc
from neutron_lib.objects import exceptions as obj_exc
from neutron_lib.utils import helpers
from neutron_lib.utils import net
from oslo_log import log as logging
from oslo_utils import uuidutils
import six
from sqlalchemy.orm import scoped_session

from neutron._i18n import _
from neutron.common import _constants as const
from neutron.db.models import securitygroup as sg_models
from neutron.db import rbac_db_mixin as rbac_mixin
from neutron.extensions import securitygroup as ext_sg
from neutron.objects import base as base_obj
from neutron.objects import ports as port_obj
from neutron.objects import securitygroup as sg_obj
from neutron import quota


LOG = logging.getLogger(__name__)

DEFAULT_SG_DESCRIPTION = _('Default security group')


@resource_extend.has_resource_extenders
@registry.has_registry_receivers
class SecurityGroupDbMixin(ext_sg.SecurityGroupPluginBase,
                           rbac_mixin.RbacPluginMixin):
    """Mixin class to add security group to db_base_plugin_v2."""

    __native_bulk_support = True

    def create_security_group_bulk(self, context, security_groups):
        return self._create_bulk('security_group', context,
                                 security_groups)

    def _registry_notify(self, res, event, id=None, exc_cls=None, **kwargs):
        # NOTE(armax): a callback exception here will prevent the request
        # from being processed. This is a hook point for backend's validation;
        # we raise to propagate the reason for the failure.
        try:
            if 'payload' in kwargs:
                # TODO(boden): remove shim once all callbacks use payloads
                registry.publish(res, event, self, payload=kwargs['payload'])
            else:
                registry.notify(res, event, self, **kwargs)
        except exceptions.CallbackFailure as e:
            if exc_cls:
                reason = (_('cannot perform %(event)s due to %(reason)s') %
                          {'event': event, 'reason': e})
                raise exc_cls(reason=reason, id=id)

    @db_api.retry_if_session_inactive()
    def create_security_group(self, context, security_group, default_sg=False):
        """Create security group.

        If default_sg is true that means we are a default security group for
        a given tenant if it does not exist.
        """
        s = security_group['security_group']
        kwargs = {
            'context': context,
            'security_group': s,
            'is_default': default_sg,
        }
        self._registry_notify(resources.SECURITY_GROUP, events.BEFORE_CREATE,
                              exc_cls=ext_sg.SecurityGroupConflict,
                              payload=events.DBEventPayload(
                                  context, metadata={'is_default': default_sg},
                                  request_body=security_group,
                                  desired_state=s))

        tenant_id = s['tenant_id']

        if not default_sg:
            self._ensure_default_security_group(context, tenant_id)
        else:
            existing_def_sg_id = self._get_default_sg_id(context, tenant_id)
            if existing_def_sg_id is not None:
                # default already exists, return it
                return self.get_security_group(context, existing_def_sg_id)

        with db_api.CONTEXT_WRITER.using(context):
            sg = sg_obj.SecurityGroup(
                context, id=s.get('id') or uuidutils.generate_uuid(),
                description=s['description'], project_id=tenant_id,
                name=s['name'], is_default=default_sg)
            sg.create()

            delta = len(ext_sg.sg_supported_ethertypes)
            delta = delta * 2 if default_sg else delta
            reservation = quota.QUOTAS.make_reservation(
                context, tenant_id, {'security_group_rule': delta},
                self)

            for ethertype in ext_sg.sg_supported_ethertypes:
                if default_sg:
                    # Allow intercommunication
                    ingress_rule = sg_obj.SecurityGroupRule(
                        context, id=uuidutils.generate_uuid(),
                        project_id=tenant_id, security_group_id=sg.id,
                        direction='ingress', ethertype=ethertype,
                        remote_group_id=sg.id)
                    ingress_rule.create()
                    sg.rules.append(ingress_rule)

                egress_rule = sg_obj.SecurityGroupRule(
                    context, id=uuidutils.generate_uuid(),
                    project_id=tenant_id, security_group_id=sg.id,
                    direction='egress', ethertype=ethertype)
                egress_rule.create()
                sg.rules.append(egress_rule)
            sg.obj_reset_changes(['rules'])

            quota.QUOTAS.commit_reservation(context,
                                            reservation.reservation_id)

            # fetch sg from db to load the sg rules with sg model.
            sg = sg_obj.SecurityGroup.get_object(context, id=sg.id)
            secgroup_dict = self._make_security_group_dict(sg)
            kwargs['security_group'] = secgroup_dict
            self._registry_notify(resources.SECURITY_GROUP,
                                  events.PRECOMMIT_CREATE,
                                  exc_cls=ext_sg.SecurityGroupConflict,
                                  **kwargs)

        registry.notify(resources.SECURITY_GROUP, events.AFTER_CREATE, self,
                        **kwargs)
        return secgroup_dict

    @db_api.retry_if_session_inactive()
    def get_security_groups(self, context, filters=None, fields=None,
                            sorts=None, limit=None,
                            marker=None, page_reverse=False, default_sg=False):

        # If default_sg is True do not call _ensure_default_security_group()
        # so this can be done recursively. Context.tenant_id is checked
        # because all the unit tests do not explicitly set the context on
        # GETS. TODO(arosen)  context handling can probably be improved here.
        filters = filters or {}
        if not default_sg and context.tenant_id:
            tenant_id = filters.get('tenant_id')
            if tenant_id:
                tenant_id = tenant_id[0]
            else:
                tenant_id = context.tenant_id
            self._ensure_default_security_group(context, tenant_id)

        pager = base_obj.Pager(
            sorts=sorts, limit=limit, marker=marker, page_reverse=page_reverse)

        sg_objs = sg_obj.SecurityGroup.get_objects(
            context, _pager=pager, validate_filters=False,
            fields=fields, **filters)

        return [self._make_security_group_dict(obj, fields) for obj in sg_objs]

    @db_api.retry_if_session_inactive()
    def get_security_groups_count(self, context, filters=None):
        filters = filters or {}
        return sg_obj.SecurityGroup.count(
            context, validate_filters=False, **filters)

    @db_api.retry_if_session_inactive()
    def get_security_group(self, context, id, fields=None, tenant_id=None):
        """Tenant id is given to handle the case when creating a security
        group rule on behalf of another use.
        """
        if tenant_id:
            tmp_context_tenant_id = context.tenant_id
            context.tenant_id = tenant_id

        try:
            with db_api.CONTEXT_READER.using(context):
                ret = self._make_security_group_dict(self._get_security_group(
                                                     context, id,
                                                     fields=fields),
                                                     fields)
                if (fields is None or len(fields) == 0 or
                   'security_group_rules' in fields):
                    rules = self.get_security_group_rules(
                        context_lib.get_admin_context(),
                        {'security_group_id': [id]})
                    ret['security_group_rules'] = rules

        finally:
            if tenant_id:
                context.tenant_id = tmp_context_tenant_id
        return ret

    def _get_security_group(self, context, id, fields=None):
        sg = sg_obj.SecurityGroup.get_object(context, fields=fields, id=id)
        if sg is None:
            raise ext_sg.SecurityGroupNotFound(id=id)
        return sg

    def _check_security_group(self, context, id, tenant_id=None):
        if tenant_id:
            tmp_context_tenant_id = context.tenant_id
            context.tenant_id = tenant_id

        try:
            if not sg_obj.SecurityGroup.objects_exist(context, id=id):
                raise ext_sg.SecurityGroupNotFound(id=id)
        finally:
            if tenant_id:
                context.tenant_id = tmp_context_tenant_id

    @db_api.retry_if_session_inactive()
    def delete_security_group(self, context, id):
        filters = {'security_group_id': [id]}
        with db_api.CONTEXT_READER.using(context):
            ports = self._get_port_security_group_bindings(context, filters)
            if ports:
                raise ext_sg.SecurityGroupInUse(id=id)
            # confirm security group exists
            sg = self._get_security_group(context, id, fields=['id', 'name'])

            if sg['name'] == 'default' and not context.is_admin:
                raise ext_sg.SecurityGroupCannotRemoveDefault()
        kwargs = {
            'context': context,
            'security_group_id': id,
            'security_group': sg,
        }
        self._registry_notify(resources.SECURITY_GROUP,
                              events.BEFORE_DELETE,
                              exc_cls=ext_sg.SecurityGroupInUse, id=id,
                              payload=events.DBEventPayload(
                                  context, states=(sg,), resource_id=id))

        with db_api.CONTEXT_WRITER.using(context):
            # pass security_group_rule_ids to ensure
            # consistency with deleted rules
            # get security_group_bindings and security_group one more time
            # so that they will be attached for session where sg will be
            # deleted
            ports = self._get_port_security_group_bindings(context, filters)
            sg = self._get_security_group(context, id)
            kwargs['security_group_rule_ids'] = [r['id'] for r in sg.rules]
            kwargs['security_group'] = self._make_security_group_dict(sg)
            self._registry_notify(resources.SECURITY_GROUP,
                                  events.PRECOMMIT_DELETE,
                                  exc_cls=ext_sg.SecurityGroupInUse, id=id,
                                  **kwargs)
            sg.delete()

        kwargs.pop('security_group')
        kwargs['name'] = sg['name']
        registry.notify(resources.SECURITY_GROUP, events.AFTER_DELETE,
                        self, **kwargs)

    @db_api.retry_if_session_inactive()
    def update_security_group(self, context, id, security_group):
        s = security_group['security_group']

        kwargs = {
            'context': context,
            'security_group_id': id,
            'security_group': s,
        }
        self._registry_notify(resources.SECURITY_GROUP, events.BEFORE_UPDATE,
                              exc_cls=ext_sg.SecurityGroupConflict, **kwargs)

        with db_api.CONTEXT_WRITER.using(context):
            sg = self._get_security_group(context, id)
            if sg.name == 'default' and 'name' in s:
                raise ext_sg.SecurityGroupCannotUpdateDefault()
            sg_dict = self._make_security_group_dict(sg)
            kwargs['original_security_group'] = sg_dict
            sg.update_fields(s)
            sg.update()
            sg_dict = self._make_security_group_dict(sg)
            kwargs['security_group'] = sg_dict
            self._registry_notify(
                    resources.SECURITY_GROUP,
                    events.PRECOMMIT_UPDATE,
                    exc_cls=ext_sg.SecurityGroupConflict,
                    payload=events.DBEventPayload(
                        context, request_body=s,
                        states=(kwargs['original_security_group'],),
                        resource_id=id, desired_state=sg_dict))
        registry.notify(resources.SECURITY_GROUP, events.AFTER_UPDATE, self,
                        **kwargs)
        return sg_dict

    def _make_security_group_dict(self, security_group, fields=None):
        res = {'id': security_group['id'],
               'name': security_group['name'],
               'tenant_id': security_group['tenant_id'],
               'description': security_group['description']}
        if security_group.rules:
            res['security_group_rules'] = [
                self._make_security_group_rule_dict(r.db_obj)
                for r in security_group.rules
            ]
        else:
            res['security_group_rules'] = []
        resource_extend.apply_funcs(ext_sg.SECURITYGROUPS, res,
                                    security_group.db_obj)
        return db_utils.resource_fields(res, fields)

    @staticmethod
    def _make_security_group_binding_dict(security_group, fields=None):
        res = {'port_id': security_group['port_id'],
               'security_group_id': security_group['security_group_id']}
        return db_utils.resource_fields(res, fields)

    @db_api.retry_if_session_inactive()
    def _create_port_security_group_binding(self, context, port_id,
                                            security_group_id):
        with db_api.CONTEXT_WRITER.using(context):
            db = sg_models.SecurityGroupPortBinding(
                port_id=port_id, security_group_id=security_group_id)
            context.session.add(db)

    def _get_port_security_group_bindings(self, context,
                                          filters=None, fields=None):
        return model_query.get_collection(
            context, sg_models.SecurityGroupPortBinding,
            self._make_security_group_binding_dict,
            filters=filters, fields=fields)

    @db_api.retry_if_session_inactive()
    def _delete_port_security_group_bindings(self, context, port_id):
        with db_api.CONTEXT_WRITER.using(context):
            query = model_query.query_with_hooks(
                context, sg_models.SecurityGroupPortBinding)
            bindings = query.filter(
                sg_models.SecurityGroupPortBinding.port_id == port_id)
            for binding in bindings:
                context.session.delete(binding)

    @db_api.retry_if_session_inactive()
    def create_security_group_rule_bulk(self, context, security_group_rules):
        return self._create_bulk('security_group_rule', context,
                                 security_group_rules)

    @db_api.retry_if_session_inactive()
    def create_security_group_rule_bulk_native(self, context,
                                               security_group_rules):
        rules = security_group_rules['security_group_rules']
        scoped_session(context.session)
        security_group_id = self._validate_security_group_rules(
            context, security_group_rules)
        with db_api.CONTEXT_WRITER.using(context):
            self._check_for_duplicate_rules(context, security_group_id, rules)
            ret = []
            for rule_dict in rules:
                res_rule_dict = self._create_security_group_rule(
                    context, rule_dict, validate=False)
                ret.append(res_rule_dict)
        for rdict in ret:
            registry.notify(
                resources.SECURITY_GROUP_RULE, events.AFTER_CREATE, self,
                context=context, security_group_rule=rdict)
        return ret

    @db_api.retry_if_session_inactive()
    def create_security_group_rule(self, context, security_group_rule):
        res = self._create_security_group_rule(context, security_group_rule)
        registry.notify(
            resources.SECURITY_GROUP_RULE, events.AFTER_CREATE, self,
            context=context, security_group_rule=res)
        return res

    def _create_security_group_rule(self, context, security_group_rule,
                                    validate=True):
        if validate:
            sg_id = self._validate_security_group_rule(context,
                                                       security_group_rule)
        rule_dict = security_group_rule['security_group_rule']
        remote_ip_prefix = rule_dict.get('remote_ip_prefix')
        if remote_ip_prefix:
            remote_ip_prefix = net.AuthenticIPNetwork(remote_ip_prefix)

        protocol = rule_dict.get('protocol')
        if protocol:
            # object expects strings only
            protocol = six.text_type(protocol)

        args = {
            'id': (rule_dict.get('id') or uuidutils.generate_uuid()),
            'project_id': rule_dict['tenant_id'],
            'security_group_id': rule_dict['security_group_id'],
            'direction': rule_dict['direction'],
            'remote_group_id': rule_dict.get('remote_group_id'),
            'ethertype': rule_dict['ethertype'],
            'protocol': protocol,
            'remote_ip_prefix': remote_ip_prefix,
            'description': rule_dict.get('description'),
        }

        port_range_min = self._safe_int(rule_dict['port_range_min'])
        if port_range_min is not None:
            args['port_range_min'] = port_range_min

        port_range_max = self._safe_int(rule_dict['port_range_max'])
        if port_range_max is not None:
            args['port_range_max'] = port_range_max

        kwargs = {
            'context': context,
            'security_group_rule': args
        }
        self._registry_notify(resources.SECURITY_GROUP_RULE,
                              events.BEFORE_CREATE,
                              exc_cls=ext_sg.SecurityGroupConflict, **kwargs)
        with db_api.CONTEXT_WRITER.using(context):
            if validate:
                self._check_for_duplicate_rules(context, sg_id,
                                                [security_group_rule])
            sg_rule = sg_obj.SecurityGroupRule(context, **args)
            sg_rule.create()

            # fetch sg_rule from db to load the sg rules with sg model
            # otherwise a DetachedInstanceError can occur for model extensions
            sg_rule = sg_obj.SecurityGroupRule.get_object(context,
                                                          id=sg_rule.id)
            res_rule_dict = self._make_security_group_rule_dict(sg_rule.db_obj)
            kwargs['security_group_rule'] = res_rule_dict
            self._registry_notify(
                resources.SECURITY_GROUP_RULE,
                events.PRECOMMIT_CREATE,
                exc_cls=ext_sg.SecurityGroupConflict, **kwargs)
        return res_rule_dict

    def _get_ip_proto_number(self, protocol):
        if protocol is None:
            return
        # According to bug 1381379, protocol is always set to string to avoid
        # problems with comparing int and string in PostgreSQL. Here this
        # string is converted to int to give an opportunity to use it as
        # before.
        if protocol in constants.IP_PROTOCOL_NAME_ALIASES:
            protocol = constants.IP_PROTOCOL_NAME_ALIASES[protocol]
        return int(constants.IP_PROTOCOL_MAP.get(protocol, protocol))

    def _get_ip_proto_name_and_num(self, protocol, ethertype=None):
        if protocol is None:
            return
        protocol = str(protocol)
        # Force all legacy IPv6 ICMP protocol names to be 'ipv6-icmp', and
        # protocol number 1 to be 58
        if ethertype == constants.IPv6:
            if protocol in const.IPV6_ICMP_LEGACY_PROTO_LIST:
                protocol = constants.PROTO_NAME_IPV6_ICMP
            elif protocol == str(constants.PROTO_NUM_ICMP):
                protocol = str(constants.PROTO_NUM_IPV6_ICMP)
        if protocol in constants.IP_PROTOCOL_MAP:
            return [protocol, str(constants.IP_PROTOCOL_MAP.get(protocol))]
        elif protocol in constants.IP_PROTOCOL_NUM_TO_NAME_MAP:
            return [constants.IP_PROTOCOL_NUM_TO_NAME_MAP.get(protocol),
                    protocol]
        return [protocol, protocol]

    def _safe_int(self, port_range):
        if port_range is None:
            return
        try:
            return int(port_range)
        except (ValueError, TypeError):
            msg = "port range must be an integer"
            raise n_exc.InvalidInput(error_message=msg)

    def _validate_port_range(self, rule):
        """Check that port_range is valid."""
        if rule['port_range_min'] is None and rule['port_range_max'] is None:
            return
        if not rule['protocol']:
            raise ext_sg.SecurityGroupProtocolRequiredWithPorts()
        ip_proto = self._get_ip_proto_number(rule['protocol'])
        # Not all firewall_driver support all these protocols,
        # but being strict here doesn't hurt.
        if (ip_proto in const.SG_PORT_PROTO_NUMS or
                ip_proto in const.SG_PORT_PROTO_NAMES):
            if rule['port_range_min'] == 0 or rule['port_range_max'] == 0:
                raise ext_sg.SecurityGroupInvalidPortValue(port=0)
            elif (rule['port_range_min'] is not None and
                  rule['port_range_max'] is not None and
                  rule['port_range_min'] <= rule['port_range_max']):
                # When min/max are the same it is just a single port
                pass
            else:
                raise ext_sg.SecurityGroupInvalidPortRange()
        elif ip_proto in [constants.PROTO_NUM_ICMP,
                          constants.PROTO_NUM_IPV6_ICMP]:
            for attr, field in [('port_range_min', 'type'),
                                ('port_range_max', 'code')]:
                if rule[attr] is not None and not (0 <= rule[attr] <= 255):
                    raise ext_sg.SecurityGroupInvalidIcmpValue(
                        field=field, attr=attr, value=rule[attr])
            if (rule['port_range_min'] is None and
                    rule['port_range_max'] is not None):
                raise ext_sg.SecurityGroupMissingIcmpType(
                    value=rule['port_range_max'])
        else:
            # Only the protocols above support ports, raise otherwise.
            if (rule['port_range_min'] is not None or
                    rule['port_range_max'] is not None):
                port_protocols = (
                    ', '.join(s.upper() for s in const.SG_PORT_PROTO_NAMES))
                raise ext_sg.SecurityGroupInvalidProtocolForPort(
                    protocol=ip_proto, valid_port_protocols=port_protocols)

    def _validate_ethertype_and_protocol(self, rule):
        """Check if given ethertype and  protocol are valid or not"""
        if rule['protocol'] in [constants.PROTO_NAME_IPV6_ENCAP,
                                constants.PROTO_NAME_IPV6_FRAG,
                                constants.PROTO_NAME_IPV6_ICMP,
                                constants.PROTO_NAME_IPV6_ICMP_LEGACY,
                                constants.PROTO_NAME_IPV6_NONXT,
                                constants.PROTO_NAME_IPV6_OPTS,
                                constants.PROTO_NAME_IPV6_ROUTE,
                                str(constants.PROTO_NUM_IPV6_ENCAP),
                                str(constants.PROTO_NUM_IPV6_FRAG),
                                str(constants.PROTO_NUM_IPV6_ICMP),
                                str(constants.PROTO_NUM_IPV6_NONXT),
                                str(constants.PROTO_NUM_IPV6_OPTS),
                                str(constants.PROTO_NUM_IPV6_ROUTE)]:
            if rule['ethertype'] == constants.IPv4:
                raise ext_sg.SecurityGroupEthertypeConflictWithProtocol(
                        ethertype=rule['ethertype'], protocol=rule['protocol'])

    def _validate_single_tenant_and_group(self, security_group_rules):
        """Check that all rules belong to the same security group and tenant
        """
        sg_groups = set()
        tenants = set()
        for rule_dict in security_group_rules['security_group_rules']:
            rule = rule_dict['security_group_rule']
            sg_groups.add(rule['security_group_id'])
            if len(sg_groups) > 1:
                raise ext_sg.SecurityGroupNotSingleGroupRules()

            tenants.add(rule['tenant_id'])
            if len(tenants) > 1:
                raise ext_sg.SecurityGroupRulesNotSingleTenant()
        return sg_groups.pop()

    def _make_canonical_ipv6_icmp_protocol(self, rule):
        if rule.get('ethertype') == constants.IPv6:
            if rule.get('protocol') in const.IPV6_ICMP_LEGACY_PROTO_LIST:
                LOG.info('Project %(project)s added a security group rule '
                         'with legacy IPv6 ICMP protocol name %(protocol)s, '
                         '%(new_protocol)s should be used instead. It was '
                         'automatically converted.',
                         {'project': rule['tenant_id'],
                          'protocol': rule['protocol'],
                          'new_protocol': constants.PROTO_NAME_IPV6_ICMP})
                rule['protocol'] = constants.PROTO_NAME_IPV6_ICMP
            elif rule.get('protocol') == str(constants.PROTO_NUM_ICMP):
                LOG.info('Project %(project)s added a security group rule '
                         'with legacy IPv6 ICMP protocol number %(protocol)s, '
                         '%(new_protocol)s should be used instead. It was '
                         'automatically converted.',
                         {'project': rule['tenant_id'],
                          'protocol': rule['protocol'],
                          'new_protocol': str(constants.PROTO_NUM_IPV6_ICMP)})
                rule['protocol'] = str(constants.PROTO_NUM_IPV6_ICMP)

    def _validate_security_group_rule(self, context, security_group_rule):
        rule = security_group_rule['security_group_rule']
        self._make_canonical_ipv6_icmp_protocol(rule)
        self._validate_port_range(rule)
        self._validate_ip_prefix(rule)
        self._validate_ethertype_and_protocol(rule)

        if rule['remote_ip_prefix'] and rule['remote_group_id']:
            raise ext_sg.SecurityGroupRemoteGroupAndRemoteIpPrefix()

        remote_group_id = rule['remote_group_id']
        # Check that remote_group_id exists for tenant
        if remote_group_id:
            self._check_security_group(context, remote_group_id,
                                       tenant_id=rule['tenant_id'])

        security_group_id = rule['security_group_id']

        # Confirm that the tenant has permission
        # to add rules to this security group.
        self._check_security_group(context, security_group_id,
                                   tenant_id=rule['tenant_id'])
        return security_group_id

    def _validate_security_group_rules(self, context, security_group_rules):
        sg_id = self._validate_single_tenant_and_group(security_group_rules)
        for rule in security_group_rules['security_group_rules']:
            self._validate_security_group_rule(context, rule)
        return sg_id

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

        resource_extend.apply_funcs(ext_sg.SECURITYGROUPRULES, res,
                                    security_group_rule)
        return db_utils.resource_fields(res, fields)

    def _rule_to_key(self, rule):
        def _normalize_rule_value(key, value):
            # This string is used as a placeholder for str(None), but shorter.
            none_char = '+'

            if key == 'remote_ip_prefix':
                all_address = ['0.0.0.0/0', '::/0', None]
                if value in all_address:
                    return none_char
            elif value is None:
                return none_char
            elif key == 'protocol':
                return str(self._get_ip_proto_name_and_num(
                               value, ethertype=rule.get('ethertype')))
            return str(value)

        comparison_keys = [
            'direction',
            'ethertype',
            'port_range_max',
            'port_range_min',
            'protocol',
            'remote_group_id',
            'remote_ip_prefix',
            'security_group_id'
        ]
        return '_'.join([_normalize_rule_value(x, rule.get(x))
                         for x in comparison_keys])

    def _check_for_duplicate_rules(self, context, security_group_id,
                                   new_security_group_rules):
        # First up, check for any duplicates in the new rules.
        new_rules_set = set()
        for i in new_security_group_rules:
            rule_key = self._rule_to_key(i['security_group_rule'])
            if rule_key in new_rules_set:
                raise ext_sg.DuplicateSecurityGroupRuleInPost(rule=i)
            new_rules_set.add(rule_key)

        # Now, let's make sure none of the new rules conflict with
        # existing rules; note that we do *not* store the db rules
        # in the set, as we assume they were already checked,
        # when added.
        sg = self.get_security_group(context, security_group_id)
        if sg:
            for i in sg['security_group_rules']:
                rule_key = self._rule_to_key(i)
                if rule_key in new_rules_set:
                    raise ext_sg.SecurityGroupRuleExists(rule_id=i.get('id'))

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

    @db_api.retry_if_session_inactive()
    def get_security_group_rules(self, context, filters=None, fields=None,
                                 sorts=None, limit=None, marker=None,
                                 page_reverse=False):
        filters = filters or {}
        pager = base_obj.Pager(
            sorts=sorts, marker=marker, limit=limit, page_reverse=page_reverse)

        project_id = filters.get('project_id') or filters.get('tenant_id')
        if project_id:
            project_id = project_id[0]
        else:
            project_id = context.project_id
        if project_id:
            self._ensure_default_security_group(context, project_id)

        if not filters and context.project_id and not context.is_admin:
            rule_ids = sg_obj.SecurityGroupRule.get_security_group_rule_ids(
                context.project_id)
            filters = {'id': rule_ids}

        # NOTE(slaweq): use admin context here to be able to get all rules
        # which fits filters' criteria. Later in policy engine rules will be
        # filtered and only those which are allowed according to policy will
        # be returned
        rule_objs = sg_obj.SecurityGroupRule.get_objects(
            context_lib.get_admin_context(), _pager=pager,
            validate_filters=False, **filters
        )
        return [
            self._make_security_group_rule_dict(obj.db_obj, fields)
            for obj in rule_objs
        ]

    @db_api.retry_if_session_inactive()
    def get_security_group_rules_count(self, context, filters=None):
        filters = filters or {}
        return sg_obj.SecurityGroupRule.count(
            context, validate_filters=False, **filters)

    @db_api.retry_if_session_inactive()
    def get_security_group_rule(self, context, id, fields=None):
        # NOTE(slaweq): use admin context here to be able to get all rules
        # which fits filters' criteria. Later in policy engine rules will be
        # filtered and only those which are allowed according to policy will
        # be returned
        security_group_rule = self._get_security_group_rule(
            context_lib.get_admin_context(), id)
        return self._make_security_group_rule_dict(
            security_group_rule.db_obj, fields)

    def _get_security_group_rule(self, context, id):
        sgr = sg_obj.SecurityGroupRule.get_object(context, id=id)
        if sgr is None:
            raise ext_sg.SecurityGroupRuleNotFound(id=id)
        return sgr

    @db_api.retry_if_session_inactive()
    def delete_security_group_rule(self, context, id):
        kwargs = {
            'context': context,
            'security_group_rule_id': id
        }
        self._registry_notify(resources.SECURITY_GROUP_RULE,
                              events.BEFORE_DELETE, id=id,
                              exc_cls=ext_sg.SecurityGroupRuleInUse, **kwargs)

        with db_api.CONTEXT_WRITER.using(context):
            sgr = self._get_security_group_rule(context, id)
            kwargs['security_group_id'] = sgr['security_group_id']
            self._registry_notify(resources.SECURITY_GROUP_RULE,
                                  events.PRECOMMIT_DELETE,
                                  exc_cls=ext_sg.SecurityGroupRuleInUse, id=id,
                                  **kwargs)
            sgr.delete()

        registry.notify(
            resources.SECURITY_GROUP_RULE, events.AFTER_DELETE, self,
            **kwargs)

    @staticmethod
    @resource_extend.extends([port_def.COLLECTION_NAME])
    def _extend_port_dict_security_group(port_res, port_db):
        # Security group bindings will be retrieved from the SQLAlchemy
        # model. As they're loaded eagerly with ports because of the
        # joined load they will not cause an extra query.
        if isinstance(port_db, port_obj.Port):
            port_res[ext_sg.SECURITYGROUPS] = port_db.security_group_ids
        else:
            security_group_ids = [sec_group_mapping['security_group_id'] for
                                  sec_group_mapping in port_db.security_groups]
            port_res[ext_sg.SECURITYGROUPS] = security_group_ids
        return port_res

    def _process_port_create_security_group(self, context, port,
                                            security_group_ids):
        if validators.is_attr_set(security_group_ids):
            for security_group_id in security_group_ids:
                self._create_port_security_group_binding(context, port['id'],
                                                         security_group_id)
        # Convert to list as a set might be passed here and
        # this has to be serialized
        port[ext_sg.SECURITYGROUPS] = (security_group_ids and
                                       list(security_group_ids) or [])

    def _get_default_sg_id(self, context, tenant_id):
        default_group = sg_obj.DefaultSecurityGroup.get_object(
            context,
            project_id=tenant_id,
        )
        if default_group:
            return default_group.security_group_id

    @registry.receives(resources.PORT, [events.BEFORE_CREATE,
                                        events.BEFORE_UPDATE])
    @registry.receives(resources.NETWORK, [events.BEFORE_CREATE])
    def _ensure_default_security_group_handler(self, resource, event, trigger,
                                               context, **kwargs):
        if event == events.BEFORE_UPDATE:
            tenant_id = kwargs['original_' + resource]['tenant_id']
        else:
            tenant_id = kwargs[resource]['tenant_id']
        if tenant_id:
            self._ensure_default_security_group(context, tenant_id)

    def _ensure_default_security_group(self, context, tenant_id):
        """Create a default security group if one doesn't exist.

        :returns: the default security group id for given tenant.
        """
        default_group_id = self._get_default_sg_id(context, tenant_id)
        if default_group_id:
            return default_group_id

        security_group = {
            'security_group':
                {'name': 'default',
                 'tenant_id': tenant_id,
                 'description': DEFAULT_SG_DESCRIPTION}
        }
        try:
            return self.create_security_group(context, security_group,
                                              default_sg=True)['id']
        except obj_exc.NeutronDbObjectDuplicateEntry:
            return self._get_default_sg_id(context, tenant_id)

    def _get_security_groups_on_port(self, context, port):
        """Check that all security groups on port belong to tenant.

        :returns: all security groups IDs on port belonging to tenant.
        """
        port = port['port']
        if not validators.is_attr_set(port.get(ext_sg.SECURITYGROUPS)):
            return
        if port.get('device_owner') and net.is_port_trusted(port):
            return

        port_sg = port.get(ext_sg.SECURITYGROUPS, [])
        tenant_id = port.get('tenant_id')

        sg_objs = sg_obj.SecurityGroup.get_objects(context, id=port_sg)

        valid_groups = set(
            g.id for g in sg_objs
            if (context.is_admin or not tenant_id or
                g.tenant_id == tenant_id or
                sg_obj.SecurityGroup.is_shared_with_tenant(
                    context, g.id, tenant_id))
        )

        requested_groups = set(port_sg)
        port_sg_missing = requested_groups - valid_groups
        if port_sg_missing:
            raise ext_sg.SecurityGroupNotFound(id=', '.join(port_sg_missing))

        return list(requested_groups)

    def _ensure_default_security_group_on_port(self, context, port):
        # we don't apply security groups for dhcp, router
        port = port['port']
        if port.get('device_owner') and net.is_port_trusted(port):
            return
        port_sg = port.get(ext_sg.SECURITYGROUPS)
        if port_sg is None or not validators.is_attr_set(port_sg):
            port_project = port.get('tenant_id')
            default_sg = self._ensure_default_security_group(context,
                                                             port_project)
            port[ext_sg.SECURITYGROUPS] = [default_sg]

    def _check_update_deletes_security_groups(self, port):
        """Return True if port has as a security group and it's value
        is either [] or not is_attr_set, otherwise return False
        """
        if (ext_sg.SECURITYGROUPS in port['port'] and
            not (validators.is_attr_set(
                     port['port'][ext_sg.SECURITYGROUPS]) and
                 port['port'][ext_sg.SECURITYGROUPS] != [])):
            return True
        return False

    def _check_update_has_security_groups(self, port):
        """Return True if port has security_groups attribute set and
        its not empty, or False otherwise.
        This method is called both for port create and port update.
        """
        if (ext_sg.SECURITYGROUPS in port['port'] and
            (validators.is_attr_set(port['port'][ext_sg.SECURITYGROUPS]) and
             port['port'][ext_sg.SECURITYGROUPS] != [])):
            return True
        return False

    def update_security_group_on_port(self, context, id, port,
                                      original_port, updated_port):
        """Update security groups on port.

        This method returns a flag which indicates request notification
        is required and does not perform notification itself.
        It is because another changes for the port may require notification.
        """
        need_notify = False
        port_updates = port['port']
        if (ext_sg.SECURITYGROUPS in port_updates and
            not helpers.compare_elements(
                original_port.get(ext_sg.SECURITYGROUPS),
                port_updates[ext_sg.SECURITYGROUPS])):
            # delete the port binding and read it with the new rules
            port_updates[ext_sg.SECURITYGROUPS] = (
                self._get_security_groups_on_port(context, port))
            self._delete_port_security_group_bindings(context, id)
            self._process_port_create_security_group(
                context,
                updated_port,
                port_updates[ext_sg.SECURITYGROUPS])
            need_notify = True
        else:
            updated_port[ext_sg.SECURITYGROUPS] = (
                original_port[ext_sg.SECURITYGROUPS])
        return need_notify
