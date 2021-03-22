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

import collections
import itertools
import re
import sys

from neutron_lib.api import attributes
from neutron_lib.api.definitions import network as net_apidef
from neutron_lib import constants
from neutron_lib import context
from neutron_lib import exceptions
from neutron_lib.plugins import directory
from neutron_lib.services import constants as service_const
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log as logging
from oslo_policy import opts
from oslo_policy import policy
from oslo_utils import excutils
import stevedore

from neutron._i18n import _
from neutron.common import cache_utils as cache


LOG = logging.getLogger(__name__)

_ENFORCER = None
ADMIN_CTX_POLICY = 'context_is_admin'
ADVSVC_CTX_POLICY = 'context_is_advsvc'

# Identify the attribute used by a resource to reference another resource
_RESOURCE_FOREIGN_KEYS = {
    net_apidef.COLLECTION_NAME: 'network_id',
    # TODO(slaweq): use SECURITYGROUPS constant from api def when
    # securitygroups api def will be moved to neutron-lib
    'security_groups': 'security_group_id'
}


# TODO(gmann): Remove setting the default value of config policy_file
# once oslo_policy change the default value to 'policy.yaml'.
# https://github.com/openstack/oslo.policy/blob/a626ad12fe5a3abd49d70e3e5b95589d279ab578/oslo_policy/opts.py#L49
DEFAULT_POLICY_FILE = 'policy.yaml'
opts.set_defaults(cfg.CONF, DEFAULT_POLICY_FILE)


def reset():
    global _ENFORCER
    if _ENFORCER:
        _ENFORCER.clear()
        _ENFORCER = None


def register_rules(enforcer):
    extmgr = stevedore.extension.ExtensionManager('neutron.policies',
                                                  invoke_on_load=True)
    policies = [list(e.obj) for e in extmgr.extensions]
    LOG.debug('Loaded default policies from %s '
              'under neutron.policies entry points',
              [e.name for e in extmgr.extensions])
    enforcer.register_defaults(itertools.chain(*policies))


def init(conf=cfg.CONF, policy_file=None, suppress_deprecation_warnings=False):
    """Init an instance of the Enforcer class."""

    global _ENFORCER
    if not _ENFORCER:
        _ENFORCER = policy.Enforcer(conf, policy_file=policy_file)
        # TODO(slaweq) Explictly disable the warnings for policies
        # changing their default check_str. During policy-defaults-refresh
        # work, all the policy defaults have been changed and warning for
        # each policy started filling the logs limit for various tool.
        # Once we move to new defaults only world then we can enable these
        # warning again.
        _ENFORCER.suppress_default_change_warnings = True
        if suppress_deprecation_warnings:
            _ENFORCER.suppress_deprecation_warnings = True
        register_rules(_ENFORCER)
        _ENFORCER.load_rules(True)


def refresh(policy_file=None):
    """Reset policy and init a new instance of Enforcer."""
    reset()
    init(policy_file=policy_file)


def get_resource_and_action(action, pluralized=None):
    """Return resource and enforce_attr_based_check(boolean) per
       resource and action extracted from api operation.
    """
    data = action.split(':', 1)[0].split('_', 1)
    resource = pluralized or ("%ss" % data[-1])
    enforce_attr_based_check = data[0] not in ('get', 'delete')
    return (resource, enforce_attr_based_check)


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
    if target.get(constants.ATTRIBUTES_TO_UPDATE):
        # In the case of update, the function should not pay attention to a
        # default value of an attribute, but check whether it was explicitly
        # marked as being updated instead.
        return (attribute_name in target[constants.ATTRIBUTES_TO_UPDATE] and
                target[attribute_name] is not constants.ATTR_NOT_SPECIFIED)
    result = (attribute_name in target and
              target[attribute_name] is not constants.ATTR_NOT_SPECIFIED)
    if result and 'default' in resource[attribute_name]:
        return target[attribute_name] != resource[attribute_name]['default']
    return result


def _should_validate_sub_attributes(attribute, sub_attr):
    """Verify that sub-attributes are iterable and should be validated."""
    validate = attribute.get('validate')
    return (validate and isinstance(sub_attr, collections.Iterable) and
            any([k.startswith('type:dict') and
                 v for (k, v) in validate.items()]))


def _build_subattr_match_rule(attr_name, attr, action, target):
    """Create the rule to match for sub-attribute policy checks."""
    # TODO(salv-orlando): Instead of relying on validator info, introduce
    # typing for API attributes
    # Expect a dict as type descriptor
    validate = attr['validate']
    key = [k for k in validate.keys() if k.startswith('type:dict')]
    if not key:
        LOG.warning("Unable to find data type descriptor for attribute %s",
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


def _build_list_of_subattrs_rule(attr_name, attribute_value, action):
    rules = []
    for sub_attr in attribute_value:
        if isinstance(sub_attr, dict):
            for k in sub_attr:
                rules.append(policy.RuleCheck(
                    'rule', '%s:%s:%s' % (action, attr_name, k)))
    if rules:
        return policy.AndCheck(rules)


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
    resource, enforce_attr_based_check = get_resource_and_action(
        action, pluralized)
    if enforce_attr_based_check:
        # assigning to variable with short name for improving readability
        res_map = attributes.RESOURCES
        if resource in res_map:
            for attribute_name in res_map[resource]:
                if _is_attribute_explicitly_set(attribute_name,
                                                res_map[resource],
                                                target, action):
                    attribute = res_map[resource][attribute_name]
                    if 'enforce_policy' in attribute:
                        attr_rule = policy.RuleCheck(
                            'rule', '%s:%s' % (action, attribute_name))
                        # Build match entries for sub-attributes
                        if _should_validate_sub_attributes(
                                attribute, target[attribute_name]):
                            attr_rule = policy.AndCheck(
                                [attr_rule, _build_subattr_match_rule(
                                    attribute_name, attribute,
                                    action, target)])

                        attribute_value = target[attribute_name]
                        if isinstance(attribute_value, list):
                            subattr_rule = _build_list_of_subattrs_rule(
                                attribute_name, attribute_value, action)
                            if subattr_rule:
                                attr_rule = policy.AndCheck(
                                    [attr_rule, subattr_rule])

                        match_rule = policy.AndCheck([match_rule, attr_rule])
    return match_rule


# This check is registered as 'tenant_id' so that it can override
# GenericCheck which was used for validating parent resource ownership.
# This will prevent us from having to handling backward compatibility
# for policy.yaml
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
        self._orig_kind = kind
        self._orig_match = match

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
        self._cache = cache._get_memory_cache_region(expiration_time=5)
        super(OwnerCheck, self).__init__(kind, match)

    # NOTE(slaweq): It seems we need to have it like that, otherwise we hit
    # TypeError: cannot pickle '_thread.RLock' object
    # during initialization of the policy rules when Neutron is run with
    # mod_uwsgi, see bug https://bugs.launchpad.net/neutron/+bug/1915494 for
    # details
    def __deepcopy__(self, memo):
        return OwnerCheck(self._orig_kind, self._orig_match)

    @cache.cache_method_results
    def _extract(self, resource_type, resource_id, field):
        # NOTE(salv-orlando): This check currently assumes the parent
        # resource is handled by the core plugin. It might be worth
        # having a way to map resources to plugins so to make this
        # check more general
        plugin = directory.get_plugin()
        if resource_type in service_const.EXT_PARENT_RESOURCE_MAPPING:
            plugin = directory.get_plugin(
                service_const.EXT_PARENT_RESOURCE_MAPPING[resource_type])
        f = getattr(plugin, 'get_%s' % resource_type)
        # f *must* exist, if not found it is better to let neutron
        # explode. Check will be performed with admin context
        try:
            data = f(context.get_admin_context(),
                     resource_id,
                     fields=[field])
        except exceptions.NotFound as e:
            # NOTE(kevinbenton): a NotFound exception can occur if a
            # list operation is happening at the same time as one of
            # the parents and its children being deleted. So we issue
            # a RetryRequest so the API will redo the lookup and the
            # problem items will be gone.
            raise db_exc.RetryRequest(e)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception('Policy check error while calling %s!', f)
        return data[field]

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
                LOG.error(err_reason)
                raise exceptions.PolicyCheckError(
                    policy="%s:%s" % (self.kind, self.match),
                    reason=err_reason)
            parent_foreign_key = _RESOURCE_FOREIGN_KEYS.get(
                "%ss" % parent_res, None)
            if parent_res == constants.EXT_PARENT_PREFIX:
                for resource in service_const.EXT_PARENT_RESOURCE_MAPPING:
                    key = "%s_%s_id" % (constants.EXT_PARENT_PREFIX, resource)
                    if key in target:
                        parent_foreign_key = key
                        parent_res = resource
                        break
            if not parent_foreign_key:
                err_reason = (_("Unable to verify match:%(match)s as the "
                                "parent resource: %(res)s was not found") %
                              {'match': self.match, 'res': parent_res})
                LOG.error(err_reason)
                raise exceptions.PolicyCheckError(
                    policy="%s:%s" % (self.kind, self.match),
                    reason=err_reason)

            target[self.target_field] = self._extract(
                parent_res, target[parent_foreign_key], parent_field)

        match = self.match % target
        if self.kind in creds:
            return match == str(creds[self.kind])
        return False


@policy.register('field')
class FieldCheck(policy.Check):
    def __init__(self, kind, match):
        self._orig_kind = kind
        self._orig_match = match

        # Process the match
        resource, field_value = match.split(':', 1)
        field, value = field_value.split('=', 1)

        super(FieldCheck, self).__init__(kind, '%s:%s:%s' %
                                         (resource, field, value))

        # Value might need conversion - we need help from the attribute map
        try:
            attr = attributes.RESOURCES[resource][field]
            conv_func = attr['convert_to']
        except KeyError:
            conv_func = lambda x: x

        self.field = field
        self.resource = resource
        self.value = conv_func(value)
        self.regex = re.compile(value[1:]) if value.startswith('~') else None

    # TODO(stephenfin): Remove this when we drop support for Python 3.6, since
    # that supports copying regex objects natively
    def __deepcopy__(self, memo):
        return FieldCheck(self._orig_kind, self._orig_match)

    def __call__(self, target_dict, cred_dict, enforcer):
        target_value = self._get_target_value(target_dict)
        # target_value might be a boolean, explicitly compare with None
        if target_value is None:
            return False
        if self.regex:
            return bool(self.regex.match(target_value))
        return target_value == self.value

    def _get_target_value(self, target_dict):
        if self.field in target_dict:
            return target_dict[self.field]
        # NOTE(slaweq): In case that target field is "networks:shared" we need
        # to treat it in "special" way as it may be used for resources other
        # than network, e.g. for port or subnet
        target_value = None
        if self.resource == "networks" and self.field == constants.SHARED:
            target_network_id = target_dict.get("network_id")
            if not target_network_id:
                LOG.debug("Unable to find network_id field in target: "
                          "%(target_dict)s",
                          {'field': self.field, 'target_dict': target_dict})
                return
            project_id = target_dict.get('project_id')
            ctx = (context.Context(tenant_id=project_id) if project_id
                   else context.get_admin_context())
            plugin = directory.get_plugin()
            network = plugin.get_network(ctx, target_network_id)
            target_value = network.get(self.field)
        if target_value is None:
            LOG.debug("Unable to find requested field: %(field)s in target: "
                      "%(target_dict)s",
                      {'field': self.field, 'target_dict': target_dict})
        return target_value


def _prepare_check(context, action, target, pluralized):
    """Prepare rule, target, and context for the policy engine."""
    # Compare with None to distinguish case in which target is {}
    if target is None:
        target = {}
    match_rule = _build_match_rule(action, target, pluralized)
    return match_rule, target, context


def log_rule_list(match_rule):
    if LOG.isEnabledFor(logging.DEBUG):
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
    # TODO(slaweq): Remove that is_admin check and always perform rules checks
    # when old, deprecated rules will be removed and only rules with new
    # personas will be supported
    if not cfg.CONF.oslo_policy.enforce_new_defaults and context.is_admin:
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
    # TODO(slaweq): Remove that is_admin check and always perform rules checks
    # when old, deprecated rules will be removed and only rules with new
    # personas will be supported
    if not cfg.CONF.oslo_policy.enforce_new_defaults and context.is_admin:
        return True
    rule, target, context = _prepare_check(context, action, target, pluralized)
    try:
        result = _ENFORCER.enforce(rule, target, context, action=action,
                                   do_raise=True)
    except policy.PolicyNotAuthorized:
        with excutils.save_and_reraise_exception():
            log_rule_list(rule)
            LOG.debug("Failed policy check for '%s'", action)
    return result


def get_enforcer():
    # NOTE(amotoki): This was borrowed from nova/policy.py.
    # This method is for use by oslo.policy CLI scripts. Those scripts need the
    # 'output-file' and 'namespace' options, but having those in sys.argv means
    # loading the neutron config options will fail as those are not expected to
    # be present. So we pass in an arg list with those stripped out.
    conf_args = []
    # Start at 1 because cfg.CONF expects the equivalent of sys.argv[1:]
    i = 1
    while i < len(sys.argv):
        if sys.argv[i].strip('-') in ['namespace', 'output-file']:
            i += 2
            continue
        conf_args.append(sys.argv[i])
        i += 1

    cfg.CONF(conf_args, project='neutron')
    init()
    return _ENFORCER
