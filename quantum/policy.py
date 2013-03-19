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

from oslo.config import cfg

from quantum.api.v2 import attributes
from quantum.common import exceptions
import quantum.common.utils as utils
from quantum.openstack.common import log as logging
from quantum.openstack.common import policy


LOG = logging.getLogger(__name__)
_POLICY_PATH = None
_POLICY_CACHE = {}
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
            raise exceptions.PolicyNotFound(path=cfg.CONF.policy_file)
    # pass _set_brain to read_cached_file so that the policy brain
    # is reset only if the file has changed
    LOG.debug(_("loading policy file at %s"), _POLICY_PATH)
    utils.read_cached_file(_POLICY_PATH, _POLICY_CACHE,
                           reload_func=_set_rules)


def get_resource_and_action(action):
    """ Extract resource and action (write, read) from api operation """
    data = action.split(':', 1)[0].split('_', 1)
    return ("%ss" % data[-1], data[0] != 'get')


def _set_rules(data):
    default_rule = 'default'
    policy.set_rules(policy.Rules.load_json(data, default_rule))


def _is_attribute_explicitly_set(attribute_name, resource, target):
    """Verify that an attribute is present and has a non-default value"""
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
    init()
    # Compare with None to distinguish case in which target is {}
    if target is None:
        target = {}
    real_target = _build_target(action, target, plugin, context)
    match_rule = _build_match_rule(action, real_target)
    credentials = context.to_dict()
    return policy.check(match_rule, real_target, credentials)


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
