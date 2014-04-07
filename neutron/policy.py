# vim: tabstop=4 shiftwidth=4 softtabstop=4

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
import itertools
import re

from oslo.config import cfg

from neutron.api.v2 import attributes
from neutron.common import exceptions
import neutron.common.utils as utils
from neutron import manager
from neutron.openstack.common import excutils
from neutron.openstack.common import importutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import policy


LOG = logging.getLogger(__name__)
_POLICY_PATH = None
_POLICY_CACHE = {}
ADMIN_CTX_POLICY = 'context_is_admin'
# Maps deprecated 'extension' policies to new-style policies
DEPRECATED_POLICY_MAP = {
    'extension:provider_network':
    ['network:provider:network_type',
     'network:provider:physical_network',
     'network:provider:segmentation_id'],
    'extension:router':
    ['network:router:external'],
    'extension:port_binding':
    ['port:binding:vif_type', 'port:binding:vif_details',
     'port:binding:profile', 'port:binding:host_id']
}
DEPRECATED_ACTION_MAP = {
    'view': ['get'],
    'set': ['create', 'update']
}

cfg.CONF.import_opt('policy_file', 'neutron.common.config')


def reset():
    global _POLICY_PATH
    global _POLICY_CACHE
    _POLICY_PATH = None
    _POLICY_CACHE = {}
    policy.reset()


def init():
    global _POLICY_PATH
    global _POLICY_CACHE
    if not _POLICY_PATH:
        _POLICY_PATH = utils.find_config_file({}, cfg.CONF.policy_file)
        if not _POLICY_PATH:
            raise exceptions.PolicyFileNotFound(path=cfg.CONF.policy_file)
    # pass _set_brain to read_cached_file so that the policy brain
    # is reset only if the file has changed
    utils.read_cached_file(_POLICY_PATH, _POLICY_CACHE,
                           reload_func=_set_rules)


def get_resource_and_action(action):
    """Extract resource and action (write, read) from api operation."""
    data = action.split(':', 1)[0].split('_', 1)
    return ("%ss" % data[-1], data[0] != 'get')


def _set_rules(data):
    default_rule = 'default'
    LOG.debug(_("Loading policies from file: %s"), _POLICY_PATH)
    # Ensure backward compatibility with folsom/grizzly convention
    # for extension rules
    policies = policy.Rules.load_json(data, default_rule)
    for pol in policies.keys():
        if any([pol.startswith(depr_pol) for depr_pol in
                DEPRECATED_POLICY_MAP.keys()]):
            LOG.warn(_("Found deprecated policy rule:%s. Please consider "
                       "upgrading your policy configuration file"), pol)
            pol_name, action = pol.rsplit(':', 1)
            try:
                new_actions = DEPRECATED_ACTION_MAP[action]
                new_policies = DEPRECATED_POLICY_MAP[pol_name]
                # bind new actions and policies together
                for actual_policy in ['_'.join(item) for item in
                                      itertools.product(new_actions,
                                                        new_policies)]:
                    if actual_policy not in policies:
                        # New policy, same rule
                        LOG.info(_("Inserting policy:%(new_policy)s in place "
                                   "of deprecated policy:%(old_policy)s"),
                                 {'new_policy': actual_policy,
                                  'old_policy': pol})
                        policies[actual_policy] = policies[pol]
                # Remove old-style policy
                del policies[pol]
            except KeyError:
                LOG.error(_("Backward compatibility unavailable for "
                            "deprecated policy %s. The policy will "
                            "not be enforced"), pol)
    policy.set_rules(policies)


def _is_attribute_explicitly_set(attribute_name, resource, target):
    """Verify that an attribute is present and has a non-default value."""
    return ('default' in resource[attribute_name] and
            attribute_name in target and
            target[attribute_name] is not attributes.ATTR_NOT_SPECIFIED and
            target[attribute_name] != resource[attribute_name]['default'])


def _build_subattr_match_rule(attr_name, attr, action, target):
    """Create the rule to match for sub-attribute policy checks."""
    # TODO(salv-orlando): Instead of relying on validator info, introduce
    # typing for API attributes
    # Expect a dict as type descriptor
    validate = attr['validate']
    key = filter(lambda k: k.startswith('type:dict'), validate.keys())
    if not key:
        LOG.warn(_("Unable to find data type descriptor for attribute %s"),
                 attr_name)
        return
    data = validate[key[0]]
    if not isinstance(data, dict):
        LOG.debug(_("Attribute type descriptor is not a dict. Unable to "
                    "generate any sub-attr policy rule for %s."),
                  attr_name)
        return
    sub_attr_rules = [policy.RuleCheck('rule', '%s:%s:%s' %
                                       (action, attr_name,
                                        sub_attr_name)) for
                      sub_attr_name in data if sub_attr_name in
                      target[attr_name]]
    return policy.AndCheck(sub_attr_rules)


def _build_match_rule(action, target):
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
    resource, is_write = get_resource_and_action(action)
    # Attribute-based checks shall not be enforced on GETs
    if is_write:
        # assigning to variable with short name for improving readability
        res_map = attributes.RESOURCE_ATTRIBUTE_MAP
        if resource in res_map:
            for attribute_name in res_map[resource]:
                if _is_attribute_explicitly_set(attribute_name,
                                                res_map[resource],
                                                target):
                    attribute = res_map[resource][attribute_name]
                    if 'enforce_policy' in attribute:
                        attr_rule = policy.RuleCheck('rule', '%s:%s' %
                                                     (action, attribute_name))
                        # Build match entries for sub-attributes, if present
                        validate = attribute.get('validate')
                        if (validate and any([k.startswith('type:dict') and v
                                              for (k, v) in
                                              validate.iteritems()])):
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
            self.target_field = re.findall('^\%\((.*)\)s$',
                                           match)[0]
        except IndexError:
            err_reason = (_("Unable to identify a target field from:%s."
                            "match should be in the form %%(<field_name>)s") %
                          match)
            LOG.exception(err_reason)
            raise exceptions.PolicyInitError(
                policy="%s:%s" % (kind, match),
                reason=err_reason)
        super(OwnerCheck, self).__init__(kind, match)

    def __call__(self, target, creds):
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
                    LOG.debug(_("Unable to find ':' as separator in %s."),
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
                    LOG.exception(_('Policy check error while calling %s!'), f)
        match = self.match % target
        if self.kind in creds:
            return match == unicode(creds[self.kind])
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

    def __call__(self, target_dict, cred_dict):
        target_value = target_dict.get(self.field)
        # target_value might be a boolean, explicitly compare with None
        if target_value is None:
            LOG.debug(_("Unable to find requested field: %(field)s in "
                        "target: %(target_dict)s"),
                      {'field': self.field,
                       'target_dict': target_dict})
            return False
        return target_value == self.value


def _prepare_check(context, action, target):
    """Prepare rule, target, and credentials for the policy engine."""
    # Compare with None to distinguish case in which target is {}
    if target is None:
        target = {}
    match_rule = _build_match_rule(action, target)
    credentials = context.to_dict()
    return match_rule, target, credentials


def check(context, action, target, plugin=None, might_not_exist=False):
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

    :return: Returns True if access is permitted else False.
    """
    if might_not_exist and not (policy._rules and action in policy._rules):
        return True
    return policy.check(*(_prepare_check(context, action, target)))


def enforce(context, action, target, plugin=None):
    """Verifies that the action is valid on the target in this context.

    :param context: neutron context
    :param action: string representing the action to be checked
        this should be colon separated for clarity.
    :param target: dictionary representing the object of the action
        for object creation this should be a dictionary representing the
        location of the object e.g. ``{'project_id': context.project_id}``
    :param plugin: currently unused and deprecated.
        Kept for backward compatibility.

    :raises neutron.exceptions.PolicyNotAuthorized: if verification fails.
    """

    rule, target, credentials = _prepare_check(context, action, target)
    result = policy.check(rule, target, credentials, action=action)
    if not result:
        LOG.debug(_("Failed policy check for '%s'"), action)
        raise exceptions.PolicyNotAuthorized(action=action)
    return result


def check_is_admin(context):
    """Verify context has admin rights according to policy settings."""
    init()
    # the target is user-self
    credentials = context.to_dict()
    target = credentials
    # Backward compatibility: if ADMIN_CTX_POLICY is not
    # found, default to validating role:admin
    admin_policy = (ADMIN_CTX_POLICY in policy._rules
                    and ADMIN_CTX_POLICY or 'role:admin')
    return policy.check(admin_policy, target, credentials)


def _extract_roles(rule, roles):
    if isinstance(rule, policy.RoleCheck):
        roles.append(rule.match.lower())
    elif isinstance(rule, policy.RuleCheck):
        _extract_roles(policy._rules[rule.match], roles)
    elif hasattr(rule, 'rules'):
        for rule in rule.rules:
            _extract_roles(rule, roles)


def get_admin_roles():
    """Return a list of roles which are granted admin rights according
    to policy settings.
    """
    # NOTE(salvatore-orlando): This function provides a solution for
    # populating implicit contexts with the appropriate roles so that
    # they correctly pass policy checks, and will become superseded
    # once all explicit policy checks are removed from db logic and
    # plugin modules. For backward compatibility it returns the literal
    # admin if ADMIN_CTX_POLICY is not defined
    init()
    if not policy._rules or ADMIN_CTX_POLICY not in policy._rules:
        return ['admin']
    try:
        admin_ctx_rule = policy._rules[ADMIN_CTX_POLICY]
    except (KeyError, TypeError):
        return
    roles = []
    _extract_roles(admin_ctx_rule, roles)
    return roles
