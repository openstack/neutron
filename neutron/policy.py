# Copyright (c) 2012 OpenStack Foundation.
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

"""
Policy engine for neutron.  Largely copied from nova.
"""

import collections
import logging as std_logging
import re

from oslo_config import cfg
from oslo_log import log as logging
from oslo_policy import policy
from oslo_utils import excutils
from oslo_utils import importutils
import six

from neutron.api.v2 import attributes
from neutron.common import constants as const
from neutron.common import exceptions
from neutron.i18n import _LE, _LW


LOG = logging.getLogger(__name__)

_ENFORCER = None
ADMIN_CTX_POLICY = 'context_is_admin'
ADVSVC_CTX_POLICY = 'context_is_advsvc'


def reset():
    global _ENFORCER
    if _ENFORCER:
        _ENFORCER.clear()
        _ENFORCER = None


def init(conf=cfg.CONF, policy_file=None):
    """Init an instance of the Enforcer class."""

    global _ENFORCER
    if not _ENFORCER:
        _ENFORCER = policy.Enforcer(conf, policy_file=policy_file)
        _ENFORCER.load_rules(True)


def refresh(policy_file=None):
    """Reset policy and init a new instance of Enforcer."""
    reset()
    init(policy_file=policy_file)


def get_resource_and_action(action, pluralized=None):
    """Extract resource and action (write, read) from api operation."""
    data = action.split(':', 1)[0].split('_', 1)
    resource = pluralized or ("%ss" % data[-1])
    return (resource, data[0] != 'get')


def set_rules(policies, overwrite=True):
    """Set rules based on the provided dict of rules.

    :param policies: New policies to use. It should be an instance of dict.
    :param overwrite: Whether to overwrite current rules or update them
                          with the new rules.
    """

    LOG.debug("Loading policies from file: %s", _ENFORCER.policy_path)
    init()
    _ENFORCER.set_rules(policies, overwrite)


def _is_attribute_explicitly_set(attribute_name, resource, target, action):
    """Verify that an attribute is present and is explicitly set."""
    if 'update' in action:
        # In the case of update, the function should not pay attention to a
        # default value of an attribute, but check whether it was explicitly
        # marked as being updated instead.
        return (attribute_name in target[const.ATTRIBUTES_TO_UPDATE] and
                target[attribute_name] is not attributes.ATTR_NOT_SPECIFIED)
    return ('default' in resource[attribute_name] and
            attribute_name in target and
            target[attribute_name] is not attributes.ATTR_NOT_SPECIFIED and
            target[attribute_name] != resource[attribute_name]['default'])


def _should_validate_sub_attributes(attribute, sub_attr):
    """Verify that sub-attributes are iterable and should be validated."""
    validate = attribute.get('validate')
    return (validate and isinstance(sub_attr, collections.Iterable) and
            any([k.startswith('type:dict') and
                 v for (k, v) in six.iteritems(validate)]))


def _build_subattr_match_rule(attr_name, attr, action, target):
    """Create the rule to match for sub-attribute policy checks."""
    # TODO(salv-orlando): Instead of relying on validator info, introduce
    # typing for API attributes
    # Expect a dict as type descriptor
    validate = attr['validate']
    key = filter(lambda k: k.startswith('type:dict'), validate.keys())
    if not key:
        LOG.warn(_LW("Unable to find data type descriptor for attribute %s"),
                 attr_name)
        return
    data = validate[key[0]]
    if not isinstance(data, dict):
        LOG.debug("Attribute type descriptor is not a dict. Unable to "
                  "generate any sub-attr policy rule for %s.",
                  attr_name)
        return
    sub_attr_rules = [policy.RuleCheck('rule', '%s:%s:%s' %
                                       (action, attr_name,
                                        sub_attr_name)) for
                      sub_attr_name in data if sub_attr_name in
                      target[attr_name]]
    return policy.AndCheck(sub_attr_rules)


def _process_rules_list(rules, match_rule):
    """Recursively walk a policy rule to extract a list of match entries."""
    if isinstance(match_rule, policy.RuleCheck):
        rules.append(match_rule.match)
    elif isinstance(match_rule, policy.AndCheck):
        for rule in match_rule.rules:
            _process_rules_list(rules, rule)
    return rules


def _build_match_rule(action, target, pluralized):
    """Create the rule to match for a given action.

    The policy rule to be matched is built in the following way:
    1) add entries for matching permission on objects
    2) add an entry for the specific action (e.g.: create_network)
    3) add an entry for attributes of a resource for which the action
       is being executed (e.g.: create_network:shared)
    4) add an entry for sub-attributes of a resource for which the
       action is being executed
       (e.g.: create_router:external_gateway_info:network_id)
    """
    match_rule = policy.RuleCheck('rule', action)
    resource, is_write = get_resource_and_action(action, pluralized)
    # Attribute-based checks shall not be enforced on GETs
    if is_write:
        # assigning to variable with short name for improving readability
        res_map = attributes.RESOURCE_ATTRIBUTE_MAP
        if resource in res_map:
            for attribute_name in res_map[resource]:
                if _is_attribute_explicitly_set(attribute_name,
                                                res_map[resource],
                                                target, action):
                    attribute = res_map[resource][attribute_name]
                    if 'enforce_policy' in attribute:
                        attr_rule = policy.RuleCheck('rule', '%s:%s' %
                                                     (action, attribute_name))
                        # Build match entries for sub-attributes
                        if _should_validate_sub_attributes(
                                attribute, target[attribute_name]):
                            attr_rule = policy.AndCheck(
                                [attr_rule, _build_subattr_match_rule(
                                    attribute_name, attribute,
                                    action, target)])
                        match_rule = policy.AndCheck([match_rule, attr_rule])
    return match_rule


# This check is registered as 'tenant_id' so that it can override
# GenericCheck which was used for validating parent resource ownership.
# This will prevent us from having to handling backward compatibility
# for policy.json
# TODO(salv-orlando): Reinstate GenericCheck for simple tenant_id checks
@policy.register('tenant_id')
class OwnerCheck(policy.Check):
    """Resource ownership check.

    This check verifies the owner of the current resource, or of another
    resource referenced by the one under analysis.
    In the former case it falls back to a regular GenericCheck, whereas
    in the latter case it leverages the plugin to load the referenced
    resource and perform the check.
    """
    def __init__(self, kind, match):
        # Process the match
        try:
            self.target_field = re.findall(r'^\%\((.*)\)s$',
                                           match)[0]
        except IndexError:
            err_reason = (_("Unable to identify a target field from:%s. "
                            "Match should be in the form %%(<field_name>)s") %
                          match)
            LOG.exception(err_reason)
            raise exceptions.PolicyInitError(
                policy="%s:%s" % (kind, match),
                reason=err_reason)
        super(OwnerCheck, self).__init__(kind, match)

    def __call__(self, target, creds, enforcer):
        if self.target_field not in target:
            # policy needs a plugin check
            # target field is in the form resource:field
            # however if they're not separated by a colon, use an underscore
            # as a separator for backward compatibility

            def do_split(separator):
                parent_res, parent_field = self.target_field.split(
                    separator, 1)
                return parent_res, parent_field

            for separator in (':', '_'):
                try:
                    parent_res, parent_field = do_split(separator)
                    break
                except ValueError:
                    LOG.debug("Unable to find ':' as separator in %s.",
                              self.target_field)
            else:
                # If we are here split failed with both separators
                err_reason = (_("Unable to find resource name in %s") %
                              self.target_field)
                LOG.exception(err_reason)
                raise exceptions.PolicyCheckError(
                    policy="%s:%s" % (self.kind, self.match),
                    reason=err_reason)
            parent_foreign_key = attributes.RESOURCE_FOREIGN_KEYS.get(
                "%ss" % parent_res, None)
            if not parent_foreign_key:
                err_reason = (_("Unable to verify match:%(match)s as the "
                                "parent resource: %(res)s was not found") %
                              {'match': self.match, 'res': parent_res})
                LOG.exception(err_reason)
                raise exceptions.PolicyCheckError(
                    policy="%s:%s" % (self.kind, self.match),
                    reason=err_reason)
            # NOTE(salv-orlando): This check currently assumes the parent
            # resource is handled by the core plugin. It might be worth
            # having a way to map resources to plugins so to make this
            # check more general
            # NOTE(ihrachys): if import is put in global, circular
            # import failure occurs
            manager = importutils.import_module('neutron.manager')
            f = getattr(manager.NeutronManager.get_instance().plugin,
                        'get_%s' % parent_res)
            # f *must* exist, if not found it is better to let neutron
            # explode. Check will be performed with admin context
            context = importutils.import_module('neutron.context')
            try:
                data = f(context.get_admin_context(),
                         target[parent_foreign_key],
                         fields=[parent_field])
                target[self.target_field] = data[parent_field]
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.exception(_LE('Policy check error while calling %s!'),
                                  f)
        match = self.match % target
        if self.kind in creds:
            return match == six.text_type(creds[self.kind])
        return False


@policy.register('field')
class FieldCheck(policy.Check):
    def __init__(self, kind, match):
        # Process the match
        resource, field_value = match.split(':', 1)
        field, value = field_value.split('=', 1)

        super(FieldCheck, self).__init__(kind, '%s:%s:%s' %
                                         (resource, field, value))

        # Value might need conversion - we need help from the attribute map
        try:
            attr = attributes.RESOURCE_ATTRIBUTE_MAP[resource][field]
            conv_func = attr['convert_to']
        except KeyError:
            conv_func = lambda x: x

        self.field = field
        self.value = conv_func(value)

    def __call__(self, target_dict, cred_dict, enforcer):
        target_value = target_dict.get(self.field)
        # target_value might be a boolean, explicitly compare with None
        if target_value is None:
            LOG.debug("Unable to find requested field: %(field)s in target: "
                      "%(target_dict)s",
                      {'field': self.field, 'target_dict': target_dict})
            return False
        return target_value == self.value


def _prepare_check(context, action, target, pluralized):
    """Prepare rule, target, and credentials for the policy engine."""
    # Compare with None to distinguish case in which target is {}
    if target is None:
        target = {}
    match_rule = _build_match_rule(action, target, pluralized)
    credentials = context.to_dict()
    return match_rule, target, credentials


def log_rule_list(match_rule):
    if LOG.isEnabledFor(std_logging.DEBUG):
        rules = _process_rules_list([], match_rule)
        LOG.debug("Enforcing rules: %s", rules)


def check(context, action, target, plugin=None, might_not_exist=False,
          pluralized=None):
    """Verifies that the action is valid on the target in this context.

    :param context: neutron context
    :param action: string representing the action to be checked
        this should be colon separated for clarity.
    :param target: dictionary representing the object of the action
        for object creation this should be a dictionary representing the
        location of the object e.g. ``{'project_id': context.project_id}``
    :param plugin: currently unused and deprecated.
        Kept for backward compatibility.
    :param might_not_exist: If True the policy check is skipped (and the
        function returns True) if the specified policy does not exist.
        Defaults to false.
    :param pluralized: pluralized case of resource
        e.g. firewall_policy -> pluralized = "firewall_policies"

    :return: Returns True if access is permitted else False.
    """
    # If we already know the context has admin rights do not perform an
    # additional check and authorize the operation
    if context.is_admin:
        return True
    if might_not_exist and not (_ENFORCER.rules and action in _ENFORCER.rules):
        return True
    match_rule, target, credentials = _prepare_check(context,
                                                     action,
                                                     target,
                                                     pluralized)
    result = _ENFORCER.enforce(match_rule,
                               target,
                               credentials,
                               pluralized=pluralized)
    # logging applied rules in case of failure
    if not result:
        log_rule_list(match_rule)
    return result


def enforce(context, action, target, plugin=None, pluralized=None):
    """Verifies that the action is valid on the target in this context.

    :param context: neutron context
    :param action: string representing the action to be checked
        this should be colon separated for clarity.
    :param target: dictionary representing the object of the action
        for object creation this should be a dictionary representing the
        location of the object e.g. ``{'project_id': context.project_id}``
    :param plugin: currently unused and deprecated.
        Kept for backward compatibility.
    :param pluralized: pluralized case of resource
        e.g. firewall_policy -> pluralized = "firewall_policies"

    :raises oslo_policy.policy.PolicyNotAuthorized:
            if verification fails.
    """
    # If we already know the context has admin rights do not perform an
    # additional check and authorize the operation
    if context.is_admin:
        return True
    rule, target, credentials = _prepare_check(context,
                                               action,
                                               target,
                                               pluralized)
    try:
        result = _ENFORCER.enforce(rule, target, credentials, action=action,
                                   do_raise=True)
    except policy.PolicyNotAuthorized:
        with excutils.save_and_reraise_exception():
            log_rule_list(rule)
            LOG.debug("Failed policy check for '%s'", action)
    return result


def check_is_admin(context):
    """Verify context has admin rights according to policy settings."""
    init()
    # the target is user-self
    credentials = context.to_dict()
    if ADMIN_CTX_POLICY not in _ENFORCER.rules:
        return False
    return _ENFORCER.enforce(ADMIN_CTX_POLICY, credentials, credentials)


def check_is_advsvc(context):
    """Verify context has advsvc rights according to policy settings."""
    init()
    # the target is user-self
    credentials = context.to_dict()
    if ADVSVC_CTX_POLICY not in _ENFORCER.rules:
        return False
    return _ENFORCER.enforce(ADVSVC_CTX_POLICY, credentials, credentials)


def _extract_roles(rule, roles):
    if isinstance(rule, policy.RoleCheck):
        roles.append(rule.match.lower())
    elif isinstance(rule, policy.RuleCheck):
        _extract_roles(_ENFORCER.rules[rule.match], roles)
    elif hasattr(rule, 'rules'):
        for rule in rule.rules:
            _extract_roles(rule, roles)
