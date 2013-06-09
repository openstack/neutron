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
Policy engine for quantum.  Largely copied from nova.
"""
import itertools

from oslo.config import cfg

from quantum.api.v2 import attributes
from quantum.common import exceptions
import quantum.common.utils as utils
from quantum.openstack.common import log as logging
from quantum.openstack.common import policy


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
    ['port:binding:vif_type', 'port:binding:capabilities',
     'port:binding:profile', 'port:binding:host_id']
}
DEPRECATED_ACTION_MAP = {
    'view': ['get'],
    'set': ['create', 'update']
}

cfg.CONF.import_opt('policy_file', 'quantum.common.config')


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
    LOG.debug(_("loading policies from file: %s"), _POLICY_PATH)
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


def _build_target(action, original_target, plugin, context):
    """Augment dictionary of target attributes for policy engine.

    This routine adds to the dictionary attributes belonging to the
    "parent" resource of the targeted one.
    """
    target = original_target.copy()
    resource, _a = get_resource_and_action(action)
    hierarchy_info = attributes.RESOURCE_HIERARCHY_MAP.get(resource, None)
    if hierarchy_info and plugin:
        # use the 'singular' version of the resource name
        parent_resource = hierarchy_info['parent'][:-1]
        parent_id = hierarchy_info['identified_by']
        f = getattr(plugin, 'get_%s' % parent_resource)
        # f *must* exist, if not found it is better to let quantum explode
        # Note: we do not use admin context
        data = f(context, target[parent_id], fields=['tenant_id'])
        target['%s_tenant_id' % parent_resource] = data['tenant_id']
    return target


def _build_match_rule(action, target):
    """Create the rule to match for a given action.

    The policy rule to be matched is built in the following way:
    1) add entries for matching permission on objects
    2) add an entry for the specific action (e.g.: create_network)
    3) add an entry for attributes of a resource for which the action
       is being executed (e.g.: create_network:shared)

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
                    if 'enforce_policy' in attribute and is_write:
                        attr_rule = policy.RuleCheck('rule', '%s:%s' %
                                                     (action, attribute_name))
                        match_rule = policy.AndCheck([match_rule, attr_rule])

    return match_rule


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


def _prepare_check(context, action, target, plugin=None):
    """Prepare rule, target, and credentials for the policy engine."""
    init()
    # Compare with None to distinguish case in which target is {}
    if target is None:
        target = {}
    # Update target only if plugin is provided
    if plugin:
        target = _build_target(action, target, plugin, context)
    match_rule = _build_match_rule(action, target)
    credentials = context.to_dict()
    return match_rule, target, credentials


def check(context, action, target, plugin=None):
    """Verifies that the action is valid on the target in this context.

    :param context: quantum context
    :param action: string representing the action to be checked
        this should be colon separated for clarity.
    :param target: dictionary representing the object of the action
        for object creation this should be a dictionary representing the
        location of the object e.g. ``{'project_id': context.project_id}``
    :param plugin: quantum plugin used to retrieve information required
        for augmenting the target

    :return: Returns True if access is permitted else False.
    """
    return policy.check(*(_prepare_check(context, action, target, plugin)))


def check_if_exists(context, action, target):
    """Verify if the action can be authorized, and raise if it is unknown.

    Check whether the action can be performed on the target within this
    context, and raise a PolicyRuleNotFound exception if the action is
    not defined in the policy engine.
    """
    # TODO(salvatore-orlando): Consider modifying oslo policy engine in
    # order to allow to raise distinct exception when check fails and
    # when policy is missing
    # Raise if there's no match for requested action in the policy engine
    if not policy._rules or action not in policy._rules:
        raise exceptions.PolicyRuleNotFound(rule=action)
    return policy.check(*(_prepare_check(context, action, target)))


def enforce(context, action, target, plugin=None):
    """Verifies that the action is valid on the target in this context.

    :param context: quantum context
    :param action: string representing the action to be checked
        this should be colon separated for clarity.
    :param target: dictionary representing the object of the action
        for object creation this should be a dictionary representing the
        location of the object e.g. ``{'project_id': context.project_id}``
    :param plugin: quantum plugin used to retrieve information required
        for augmenting the target

    :raises quantum.exceptions.PolicyNotAllowed: if verification fails.
    """

    init()
    # Compare with None to distinguish case in which target is {}
    if target is None:
        target = {}
    real_target = _build_target(action, target, plugin, context)
    match_rule = _build_match_rule(action, real_target)
    credentials = context.to_dict()
    return policy.check(match_rule, real_target, credentials,
                        exceptions.PolicyNotAuthorized, action=action)


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
