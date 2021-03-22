# Copyright (c) 2012 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Test of Policy Engine For Neutron"""

import copy
import re
from unittest import mock

from neutron_lib.api import attributes
from neutron_lib import constants
from neutron_lib import context
from neutron_lib import exceptions
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_policy import fixture as op_fixture
from oslo_policy import policy as oslo_policy
from oslo_serialization import jsonutils
from oslo_utils import importutils
from oslo_utils import uuidutils

import neutron
from neutron import policy
from neutron.tests import base

_uuid = uuidutils.generate_uuid


class PolicyFileTestCase(base.BaseTestCase):
    def setUp(self):
        super(PolicyFileTestCase, self).setUp()
        self.context = context.Context('fake', 'fake', is_admin=False)
        self.target = {'tenant_id': 'fake'}

    def test_modified_policy_reloads(self):
        tmpfilename = self.get_temp_file_path('policy')
        action = "example:test"
        with open(tmpfilename, "w") as policyfile:
            policyfile.write("""{"example:test": ""}""")
        policy.refresh(policy_file=tmpfilename)
        policy.enforce(self.context, action, self.target)
        with open(tmpfilename, "w") as policyfile:
            policyfile.write("""{"example:test": "!"}""")
        policy.refresh(policy_file=tmpfilename)
        self.target = {'tenant_id': 'fake_tenant'}
        self.assertRaises(oslo_policy.PolicyNotAuthorized,
                          policy.enforce,
                          self.context,
                          action,
                          self.target)


class PolicyTestCase(base.BaseTestCase):
    def setUp(self):
        super(PolicyTestCase, self).setUp()
        # NOTE(vish): preload rules to circumvent reloading from file
        rules = {
            "true": '@',
            "example:allowed": '@',
            "example:denied": '!',
            "example:get_http": "http:http://www.example.com",
            "example:my_file": "role:compute_admin or tenant_id:%(tenant_id)s",
            "example:early_and_fail": "! and @",
            "example:early_or_success": "@ or !",
            "example:lowercase_admin": "role:admin or role:sysadmin",
            "example:uppercase_admin": "role:ADMIN or role:sysadmin",
            "example:only_system_admin_allowed": (
                "role:admin and system_scope:all"),
        }
        policy.refresh()
        # NOTE(vish): then overload underlying rules
        policy.set_rules(oslo_policy.Rules.from_dict(rules))
        self.context = context.Context('fake', 'fake', roles=['member'])
        self.target = {}

    def _test_check_system_admin_allowed_action(self, enforce_new_defaults):
        action = "example:only_system_admin_allowed"
        cfg.CONF.set_override(
            'enforce_new_defaults', enforce_new_defaults, group='oslo_policy')
        project_admin_ctx = context.Context(
            user="fake", project_id="fake",
            roles=['admin', 'member', 'reader'])
        system_admin_ctx = context.Context(
            user="fake", project_id="fake",
            roles=['admin', 'member', 'reader'],
            system_scope='all')
        self.assertTrue(policy.check(system_admin_ctx, action, self.target))
        if enforce_new_defaults:
            self.assertFalse(
                policy.check(project_admin_ctx, action, self.target))
        else:
            self.assertTrue(
                policy.check(project_admin_ctx, action, self.target))

    def test_check_only_system_admin_new_defaults(self):
        self._test_check_system_admin_allowed_action(enforce_new_defaults=True)

    def test_check_only_system_admin_old_defaults(self):
        self._test_check_system_admin_allowed_action(
            enforce_new_defaults=False)

    def _test_enforce_system_admin_allowed_action(self, enforce_new_defaults):
        action = "example:only_system_admin_allowed"
        cfg.CONF.set_override(
            'enforce_new_defaults', enforce_new_defaults, group='oslo_policy')
        project_admin_ctx = context.Context(
            user="fake", project_id="fake",
            roles=['admin', 'member', 'reader'])
        system_admin_ctx = context.Context(
            user="fake", project_id="fake",
            roles=['admin', 'member', 'reader'],
            system_scope='all')
        self.assertTrue(policy.enforce(system_admin_ctx, action, self.target))
        if enforce_new_defaults:
            self.assertRaises(
                oslo_policy.PolicyNotAuthorized,
                policy.enforce, project_admin_ctx, action, self.target)
        else:
            self.assertTrue(
                policy.enforce(project_admin_ctx, action, self.target))

    def test_enforce_only_system_admin_new_defaults(self):
        self._test_enforce_system_admin_allowed_action(
            enforce_new_defaults=True)

    def test_enforce_only_system_admin_old_defaults(self):
        self._test_enforce_system_admin_allowed_action(
            enforce_new_defaults=False)

    def test_enforce_nonexistent_action_throws(self):
        action = "example:noexist"
        self.assertRaises(oslo_policy.PolicyNotAuthorized, policy.enforce,
                          self.context, action, self.target)

    def test_enforce_bad_action_throws(self):
        action = "example:denied"
        self.assertRaises(oslo_policy.PolicyNotAuthorized, policy.enforce,
                          self.context, action, self.target)

    def test_check_bad_action_noraise(self):
        action = "example:denied"
        result = policy.check(self.context, action, self.target)
        self.assertFalse(result)

    def test_check_non_existent_action(self):
        action = "example:idonotexist"
        result_1 = policy.check(self.context, action, self.target)
        self.assertFalse(result_1)
        result_2 = policy.check(self.context, action, self.target,
                                might_not_exist=True)
        self.assertTrue(result_2)

    def test_enforce_good_action(self):
        action = "example:allowed"
        result = policy.enforce(self.context, action, self.target)
        self.assertTrue(result)

    def test_enforce_http_true(self):
        self.useFixture(op_fixture.HttpCheckFixture())
        action = "example:get_http"
        target = {}
        result = policy.enforce(self.context, action, target)
        self.assertTrue(result)

    def test_enforce_http_false(self):
        self.useFixture(op_fixture.HttpCheckFixture(False))
        action = "example:get_http"
        target = {}
        self.assertRaises(oslo_policy.PolicyNotAuthorized,
                          policy.enforce, self.context,
                          action, target)

    def test_templatized_enforcement(self):
        target_mine = {'tenant_id': 'fake'}
        target_not_mine = {'tenant_id': 'another'}
        action = "example:my_file"
        policy.enforce(self.context, action, target_mine)
        self.assertRaises(oslo_policy.PolicyNotAuthorized, policy.enforce,
                          self.context, action, target_not_mine)

    def test_early_AND_enforcement(self):
        action = "example:early_and_fail"
        self.assertRaises(oslo_policy.PolicyNotAuthorized, policy.enforce,
                          self.context, action, self.target)

    def test_early_OR_enforcement(self):
        action = "example:early_or_success"
        policy.enforce(self.context, action, self.target)

    def test_ignore_case_role_check(self):
        lowercase_action = "example:lowercase_admin"
        uppercase_action = "example:uppercase_admin"
        # NOTE(dprince) we mix case in the Admin role here to ensure
        # case is ignored
        admin_context = context.Context('admin', 'fake', roles=['AdMiN'])
        policy.enforce(admin_context, lowercase_action, self.target)
        policy.enforce(admin_context, uppercase_action, self.target)


class DefaultPolicyTestCase(base.BaseTestCase):

    def setUp(self):
        super(DefaultPolicyTestCase, self).setUp()
        tmpfilename = self.get_temp_file_path('policy.yaml')
        self.rules = {
            "default": '',
            "example:exist": '!',
        }
        with open(tmpfilename, "w") as policyfile:
            jsonutils.dump(self.rules, policyfile)
        policy.refresh(policy_file=tmpfilename)

        self.context = context.Context('fake', 'fake')

    def test_policy_called(self):
        self.assertRaises(oslo_policy.PolicyNotAuthorized, policy.enforce,
                          self.context, "example:exist", {})

    def test_not_found_policy_calls_default(self):
        policy.enforce(self.context, "example:noexist", {})


FAKE_RESOURCE_NAME = 'fake_resource'
FAKE_SPECIAL_RESOURCE_NAME = 'fake_policy'
FAKE_RESOURCES = {"%ss" % FAKE_RESOURCE_NAME:
                  {'attr': {'allow_post': True,
                            'allow_put': True,
                            'is_visible': True,
                            'default': None,
                            'enforce_policy': True,
                            'validate': {'type:dict':
                                         {'sub_attr_1': {'type:string': None},
                                          'sub_attr_2': {'type:string': None}}}
                            },
                   'list_attr': {'allow_post': True,
                                 'allow_put': True,
                                 'is_visible': True,
                                 'default': None,
                                 'enforce_policy': True
                                 }},
                  # special plural name
                  "%s" % FAKE_SPECIAL_RESOURCE_NAME.replace('y', 'ies'):
                  {'attr': {'allow_post': True,
                            'allow_put': True,
                            'is_visible': True,
                            'default': None,
                            'enforce_policy': True,
                            'validate': {'type:dict':
                                         {'sub_attr_1': {'type:string': None},
                                          'sub_attr_2': {'type:string': None}}}
                            }}}


class CustomRulesTestCase(base.BaseTestCase):

    def test_field_check__boolean_value(self):
        check = policy.FieldCheck('field', 'networks:router:external=True')
        self.assertEqual('networks', check.resource)
        self.assertEqual('router:external', check.field)
        # TODO(stephenfin): I expected this to get converted to a boolean :-\
        self.assertEqual('True', check.value)
        self.assertIsNone(check.regex)

    def test_field_check__regex_value(self):
        check = policy.FieldCheck('field', 'port:device_owner=~^network:')
        self.assertEqual('port', check.resource)
        self.assertEqual('device_owner', check.field)
        self.assertEqual('~^network:', check.value)
        self.assertEqual(re.compile('^network:'), check.regex)

    def test_field_check_deepcopy(self):
        check_a = policy.FieldCheck('field', 'port:device_owner=~^network:')
        check_b = copy.deepcopy(check_a)

        self.assertIsNot(check_a, check_b)
        self.assertEqual(check_a.resource, check_b.resource)
        self.assertEqual(check_a.field, check_b.field)
        self.assertEqual(check_a.value, check_b.value)
        self.assertEqual(check_a.regex, check_b.regex)

    def test_owner_check_deepcopy(self):
        check_a = policy.OwnerCheck('tenant_id', '%(tenant_id)s')
        check_b = copy.deepcopy(check_a)

        self.assertIsNot(check_a, check_b)
        self.assertEqual(check_a.target_field, check_b.target_field)


class NeutronPolicyTestCase(base.BaseTestCase):

    def fakepolicyinit(self, **kwargs):
        policy._ENFORCER = oslo_policy.Enforcer(cfg.CONF)
        policy._ENFORCER.set_rules(oslo_policy.Rules(self.rules))

    def setUp(self):
        super(NeutronPolicyTestCase, self).setUp()
        # Add Fake resources to RESOURCE_ATTRIBUTE_MAP
        attributes.RESOURCES.update(FAKE_RESOURCES)
        self._set_rules()

        self.patcher = mock.patch.object(neutron.policy,
                                         'init',
                                         new=self.fakepolicyinit)
        self.patcher.start()
        policy.refresh()
        self.addCleanup(policy.refresh)
        self.context = context.Context('fake', 'fake', roles=['user'])
        plugin_klass = importutils.import_class(
            "neutron.db.db_base_plugin_v2.NeutronDbPluginV2")
        directory.add_plugin(plugin_constants.CORE, plugin_klass())

    def _set_rules(self, **kwargs):
        rules_dict = {
            "context_is_admin": "role:admin",
            "context_is_advsvc": "role:advsvc",
            "admin_or_network_owner": "rule:context_is_admin or "
                                      "tenant_id:%(network:tenant_id)s",
            "admin_or_owner": ("rule:context_is_admin or "
                               "tenant_id:%(tenant_id)s"),
            "admin_only": "rule:context_is_admin",
            "regular_user": "role:user",
            "shared": "field:networks:shared=True",
            "external": "field:networks:router:external=True",
            "network_device": "field:port:device_owner=~^network:",
            "default": '@',

            "create_network": "rule:admin_or_owner",
            "create_network:shared": "rule:admin_only",
            "update_network": '@',
            "update_network:shared": "rule:admin_only",
            "get_network": "rule:admin_or_owner or rule:shared or "
                           "rule:external or rule:context_is_advsvc",
            "create_subnet": "rule:admin_or_network_owner",
            "create_port:mac": "rule:admin_or_network_owner or "
                               "rule:context_is_advsvc",
            "create_port:device_owner": "not rule:network_device",
            "create_port:fixed_ips": (
                "rule:context_is_advsvc or rule:admin_or_network_owner or "
                "rule:shared"),
            "create_port:fixed_ips:ip_address": (
                "rule:context_is_advsvc or rule:admin_or_network_owner"),
            "create_port:fixed_ips:subnet_id": (
                "rule:context_is_advsvc or rule:admin_or_network_owner or "
                "rule:shared"),
            "update_port": "rule:admin_or_owner or rule:context_is_advsvc",
            "get_port": "rule:admin_or_owner or rule:context_is_advsvc",
            "delete_port": "rule:admin_or_owner or rule:context_is_advsvc",
            "create_fake_resource": "rule:admin_or_owner",
            "create_fake_resource:attr": "rule:admin_or_owner",
            "create_fake_resource:attr:sub_attr_1": "rule:admin_or_owner",
            "create_fake_resource:attr:sub_attr_2": "rule:admin_only",
            "create_fake_resource:list_attr": "rule:admin_only_or_owner",
            "create_fake_resource:list_attr:admin_element": "rule:admin_only",
            "create_fake_resource:list_attr:user_element": (
                "rule:admin_or_owner"),

            "create_fake_policy:": "rule:admin_or_owner",
        }
        rules_dict.update(**kwargs)
        self.rules = oslo_policy.Rules.from_dict(rules_dict)

    def _test_action_on_attr(self, context, action, obj, attr, value,
                             exception=None, **kwargs):
        action = "%s_%s" % (action, obj)
        target = {'tenant_id': 'the_owner', attr: value}
        if kwargs:
            target.update(kwargs)
        if exception:
            self.assertRaises(exception, policy.enforce,
                              context, action, target)
        else:
            result = policy.enforce(context, action, target)
            self.assertTrue(result)

    def _test_nonadmin_action_on_attr(self, action, obj, attr, value,
                                      exception=None, **kwargs):
        user_context = context.Context('', "user", roles=['user'])
        self._test_action_on_attr(user_context, action, obj, attr,
                                  value, exception, **kwargs)

    def _test_advsvc_action_on_attr(self, action, obj, attr, value,
                                    exception=None, **kwargs):
        user_context = context.Context('', "user",
                                       roles=['user', 'advsvc'])
        self._test_action_on_attr(user_context, action, obj, attr,
                                  value, exception, **kwargs)

    def test_nonadmin_write_on_private_fails(self):
        self._test_nonadmin_action_on_attr(
            'create', 'network', 'shared', False,
            oslo_policy.PolicyNotAuthorized)

    def test_nonadmin_read_on_private_fails(self):
        self._test_nonadmin_action_on_attr('get', 'network', 'shared', False,
                                           oslo_policy.PolicyNotAuthorized)

    def test_nonadmin_write_on_shared_fails(self):
        self._test_nonadmin_action_on_attr('create', 'network', 'shared', True,
                                           oslo_policy.PolicyNotAuthorized)

    def test_create_port_device_owner_regex(self):
        blocked_values = (constants.DEVICE_OWNER_NETWORK_PREFIX,
                          'network:abdef',
                          constants.DEVICE_OWNER_DHCP,
                          constants.DEVICE_OWNER_ROUTER_INTF)
        for val in blocked_values:
            self._test_advsvc_action_on_attr(
                'create', 'port', 'device_owner', val,
                oslo_policy.PolicyNotAuthorized
            )
        ok_values = ('network', 'networks', 'my_network:test', 'my_network:')
        for val in ok_values:
            self._test_advsvc_action_on_attr(
                'create', 'port', 'device_owner', val
            )

    def test_create_port_fixed_ips_on_shared_network(self):

        def fakegetnetwork(*args, **kwargs):
            return {'tenant_id': 'fake',
                    'shared': True}

        kwargs = {'network_id': _uuid()}
        with mock.patch.object(directory.get_plugin(),
                               'get_network', new=fakegetnetwork):
            self._test_nonadmin_action_on_attr(
                'create', 'port',
                'fixed_ips', [{'subnet_id': 'test-subnet-id'}],
                **kwargs)
            self._test_nonadmin_action_on_attr(
                'create', 'port',
                'fixed_ips', [{'ip_address': '1.2.3.4'}],
                exception=oslo_policy.PolicyNotAuthorized,
                **kwargs)

    def test_create_port_fixed_ips_on_nonshared_network(self):

        def fakegetnetwork(*args, **kwargs):
            return {'tenant_id': 'fake',
                    'shared': False}

        kwargs = {'network_id': _uuid()}
        with mock.patch.object(directory.get_plugin(),
                               'get_network', new=fakegetnetwork):
            self._test_nonadmin_action_on_attr(
                'create', 'port',
                'fixed_ips', [{'subnet_id': 'test-subnet-id'}],
                exception=oslo_policy.PolicyNotAuthorized,
                **kwargs)
            self._test_nonadmin_action_on_attr(
                'create', 'port',
                'fixed_ips', [{'ip_address': '1.2.3.4'}],
                exception=oslo_policy.PolicyNotAuthorized,
                **kwargs)

    def test_advsvc_get_network_works(self):
        self._test_advsvc_action_on_attr('get', 'network', 'shared', False)

    def test_advsvc_create_network_fails(self):
        self._test_advsvc_action_on_attr('create', 'network', 'shared', False,
                                         oslo_policy.PolicyNotAuthorized)

    def test_advsvc_create_port_works(self):
        self._test_advsvc_action_on_attr('create', 'port:mac', 'shared', False)

    def test_advsvc_get_port_works(self):
        self._test_advsvc_action_on_attr('get', 'port', 'shared', False)

    def test_advsvc_update_port_works(self):
        kwargs = {constants.ATTRIBUTES_TO_UPDATE: ['shared']}
        self._test_advsvc_action_on_attr('update', 'port', 'shared', True,
                                         **kwargs)

    def test_advsvc_delete_port_works(self):
        self._test_advsvc_action_on_attr('delete', 'port', 'shared', False)

    def test_advsvc_create_subnet_fails(self):
        self._test_advsvc_action_on_attr('create', 'subnet', 'shared', False,
                                         oslo_policy.PolicyNotAuthorized)

    def test_nonadmin_read_on_shared_succeeds(self):
        self._test_nonadmin_action_on_attr('get', 'network', 'shared', True)

    def _test_enforce_adminonly_attribute(self, action, **kwargs):
        admin_context = context.get_admin_context()
        target = {'shared': True}
        if kwargs:
            target.update(kwargs)
        result = policy.enforce(admin_context, action, target)
        self.assertTrue(result)

    def test_enforce_adminonly_attribute_create(self):
        self._test_enforce_adminonly_attribute('create_network')

    def test_enforce_adminonly_attribute_update(self):
        kwargs = {constants.ATTRIBUTES_TO_UPDATE: ['shared']}
        self._test_enforce_adminonly_attribute('update_network', **kwargs)

    def test_reset_adminonly_attr_to_default_fails(self):
        kwargs = {constants.ATTRIBUTES_TO_UPDATE: ['shared']}
        self._test_nonadmin_action_on_attr(
            'update', 'network', 'shared', False,
            oslo_policy.PolicyNotAuthorized,
            **kwargs)

    def test_enforce_adminonly_attribute_nonadminctx_returns_403(self):
        action = "create_network"
        target = {'shared': True, 'tenant_id': 'somebody_else'}
        self.assertRaises(oslo_policy.PolicyNotAuthorized, policy.enforce,
                          self.context, action, target)

    def _test_build_subattribute_match_rule(self, validate_value):
        bk = FAKE_RESOURCES['%ss' % FAKE_RESOURCE_NAME]['attr']['validate']
        FAKE_RESOURCES['%ss' % FAKE_RESOURCE_NAME]['attr']['validate'] = (
            validate_value)
        action = "create_" + FAKE_RESOURCE_NAME
        target = {'tenant_id': 'fake', 'attr': {'sub_attr_1': 'x'}}
        self.assertFalse(policy._build_subattr_match_rule(
            'attr',
            FAKE_RESOURCES['%ss' % FAKE_RESOURCE_NAME]['attr'],
            action,
            target))
        FAKE_RESOURCES['%ss' % FAKE_RESOURCE_NAME]['attr']['validate'] = bk

    def test_build_subattribute_match_rule_empty_dict_validator(self):
        self._test_build_subattribute_match_rule({})

    def test_build_subattribute_match_rule_wrong_validation_info(self):
        self._test_build_subattribute_match_rule(
            {'type:dict': 'wrong_stuff'})

    def test_build_match_rule_special_pluralized(self):
        action = "create_" + FAKE_SPECIAL_RESOURCE_NAME
        pluralized = "create_fake_policies"
        target = {}
        result = policy._build_match_rule(action, target, pluralized)
        self.assertEqual("rule:" + action, str(result))

    def test_build_match_rule_normal_pluralized_when_create(self):
        action = "create_" + FAKE_RESOURCE_NAME
        target = {}
        result = policy._build_match_rule(action, target, None)
        self.assertEqual("rule:" + action, str(result))

    def test_build_match_rule_normal_pluralized_when_update(self):
        action = "update_" + FAKE_RESOURCE_NAME
        target = {}
        result = policy._build_match_rule(action, target, None)
        self.assertEqual("rule:" + action, str(result))

    def test_enforce_subattribute(self):
        action = "create_" + FAKE_RESOURCE_NAME
        target = {'tenant_id': 'fake', 'attr': {'sub_attr_1': 'x'}}
        result = policy.enforce(self.context, action, target, None)
        self.assertTrue(result)

    def test_enforce_admin_only_subattribute(self):
        action = "create_" + FAKE_RESOURCE_NAME
        target = {'tenant_id': 'fake', 'attr': {'sub_attr_1': 'x',
                                                'sub_attr_2': 'y'}}
        result = policy.enforce(context.get_admin_context(),
                                action, target, None)
        self.assertTrue(result)

    def test_enforce_admin_only_subattribute_nonadminctx_returns_403(self):
        action = "create_" + FAKE_RESOURCE_NAME
        target = {'tenant_id': 'fake', 'attr': {'sub_attr_1': 'x',
                                                'sub_attr_2': 'y'}}
        self.assertRaises(oslo_policy.PolicyNotAuthorized, policy.enforce,
                          self.context, action, target, None)

    def test_enforce_regularuser_on_read(self):
        action = "get_network"
        target = {'shared': True, 'tenant_id': 'somebody_else'}
        result = policy.enforce(self.context, action, target)
        self.assertTrue(result)

    def test_enforce_tenant_id_check(self):
        # Trigger a policy with rule admin_or_owner
        action = "create_network"
        target = {'tenant_id': 'fake'}
        result = policy.enforce(self.context, action, target)
        self.assertTrue(result)

    def test_enforce_tenant_id_check_parent_resource(self):

        def fakegetnetwork(*args, **kwargs):
            return {'tenant_id': 'fake'}

        action = "create_port:mac"
        with mock.patch.object(directory.get_plugin(),
                               'get_network', new=fakegetnetwork):
            target = {'network_id': 'whatever'}
            result = policy.enforce(self.context, action, target)
            self.assertTrue(result)

    def test_enforce_plugin_failure(self):

        def fakegetnetwork(*args, **kwargs):
            raise NotImplementedError('Blast!')

        # the policy check and plugin method we use in this test are irrelevant
        # so long that we verify that, if *f* blows up, the behavior of the
        # policy engine to propagate the exception is preserved
        action = "create_port:mac"
        with mock.patch.object(directory.get_plugin(),
                               'get_network', new=fakegetnetwork):
            target = {'network_id': 'whatever'}
            self.assertRaises(NotImplementedError,
                              policy.enforce,
                              self.context,
                              action,
                              target)

    def test_enforce_subattribute_as_list(self):
        action = "create_" + FAKE_RESOURCE_NAME
        target = {
            'tenant_id': 'fake',
            'list_attr': [{'user_element': 'x'}]}
        result = policy.enforce(self.context,
                                action, target, None)
        self.assertTrue(result)

    def test_enforce_subattribute_as_list_forbiden(self):
        action = "create_" + FAKE_RESOURCE_NAME
        target = {
            'tenant_id': 'fake',
            'list_attr': [{'admin_element': 'x'}]}
        self.assertRaises(oslo_policy.PolicyNotAuthorized, policy.enforce,
                          self.context, action, target, None)

    def test_retryrequest_on_notfound(self):
        failure = exceptions.NetworkNotFound(net_id='whatever')
        action = "create_port:mac"
        with mock.patch.object(directory.get_plugin(),
                               'get_network', side_effect=failure):
            target = {'network_id': 'whatever'}
            try:
                policy.enforce(self.context, action, target)
                self.fail("Did not raise RetryRequest")
            except db_exc.RetryRequest as e:
                self.assertEqual(failure, e.inner_exc)

    def test_enforce_tenant_id_check_parent_resource_bw_compatibility(self):

        def fakegetnetwork(*args, **kwargs):
            return {'tenant_id': 'fake'}

        self._set_rules(
            admin_or_network_owner="role:admin or "
                                   "tenant_id:%(network_tenant_id)s")
        action = "create_port:mac"
        with mock.patch.object(directory.get_plugin(),
                               'get_network', new=fakegetnetwork):
            target = {'network_id': 'whatever'}
            result = policy.enforce(self.context, action, target)
            self.assertTrue(result)

    def test_tenant_id_check_no_target_field_raises(self):
        # Try and add a bad rule
        self.assertRaises(
            exceptions.PolicyInitError,
            oslo_policy.Rules.from_dict,
            {'test_policy': 'tenant_id:(wrong_stuff)'})

    def test_tenant_id_check_caches_extracted_fields(self):

        plugin = directory.get_plugin()
        with mock.patch.object(plugin, 'get_network',
                               return_value={'tenant_id': 'fake'}) as getter:
            action = "create_port:mac"
            for i in range(2):
                target = {'network_id': 'whatever'}
                policy.enforce(self.context, action, target)
        self.assertEqual(1, getter.call_count)

    def _test_enforce_tenant_id_raises(self, bad_rule):
        self._set_rules(admin_or_owner=bad_rule)
        # Trigger a policy with rule admin_or_owner
        action = "create_network"
        target = {'tenant_id': 'fake'}
        self.fakepolicyinit()
        self.assertRaises(exceptions.PolicyCheckError,
                          policy.enforce,
                          self.context, action, target)

    def test_enforce_tenant_id_check_malformed_target_field_raises(self):
        self._test_enforce_tenant_id_raises('tenant_id:%(malformed_field)s')

    def test_enforce_tenant_id_check_invalid_parent_resource_raises(self):
        self._test_enforce_tenant_id_raises('tenant_id:%(foobaz_tenant_id)s')

    def test_process_rules(self):
        action = "create_" + FAKE_RESOURCE_NAME
        # Construct RuleChecks for an action, attribute and subattribute
        match_rule = oslo_policy.RuleCheck('rule', action)
        attr_rule = oslo_policy.RuleCheck(
            'rule', '%s:%ss' % (action, FAKE_RESOURCE_NAME))
        sub_attr_rules = [oslo_policy.RuleCheck(
            'rule', '%s:%s:%s' % (action, 'attr', 'sub_attr_1'))]
        # Build an AndCheck from the given RuleChecks
        # Make the checks nested to better check the recursion
        sub_attr_rules = oslo_policy.AndCheck(sub_attr_rules)
        attr_rule = oslo_policy.AndCheck(
            [attr_rule, sub_attr_rules])

        match_rule = oslo_policy.AndCheck([match_rule, attr_rule])
        # Assert that the rules are correctly extracted from the match_rule
        rules = policy._process_rules_list([], match_rule)
        self.assertEqual(['create_fake_resource',
                          'create_fake_resource:fake_resources',
                          'create_fake_resource:attr:sub_attr_1'], rules)

    @mock.patch.object(policy.LOG, 'isEnabledFor', return_value=True)
    @mock.patch.object(policy.LOG, 'debug')
    def test_log_rule_list(self, mock_debug, mock_is_e):
        policy.log_rule_list(oslo_policy.RuleCheck('rule', 'create_'))
        self.assertTrue(mock_is_e.called)
        self.assertTrue(mock_debug.called)

    def test__is_attribute_explicitly_set(self):
        action = 'create'
        attr = 'attr'

        target = {attr: 'valueA', 'tgt-tenant': 'tenantA'}
        resource = {attr: {'allow_post': True,
                           'allow_put': True,
                           'is_visible': True,
                           'enforce_policy': True,
                           'validate': {'type:string': 10}}}

        result = policy._is_attribute_explicitly_set(
            attr, resource, target, action)
        self.assertTrue(result)

        target = {'tgt-tenant': 'tenantA'}
        result = policy._is_attribute_explicitly_set(
            attr, resource, target, action)
        self.assertFalse(result)

        resource = {attr: {'allow_post': True,
                           'allow_put': True,
                           'is_visible': True,
                           'default': 'DfltValue',
                           'enforce_policy': True,
                           'validate': {'type:string': 10}}}
        result = policy._is_attribute_explicitly_set(
            attr, resource, target, action)
        self.assertFalse(result)

        target = {attr: 'DfltValue', 'tgt-tenant': 'tenantA'}
        result = policy._is_attribute_explicitly_set(
            attr, resource, target, action)
        self.assertFalse(result)

        target = {attr: constants.ATTR_NOT_SPECIFIED, 'tgt-tenant': 'tenantA'}
        result = policy._is_attribute_explicitly_set(
            attr, resource, target, action)
        self.assertFalse(result)

    @mock.patch("neutron_lib.services.constants.EXT_PARENT_RESOURCE_MAPPING",
                {'parentresource': 'registered_plugin_name'})
    @mock.patch("neutron_lib.plugins.directory.get_plugin")
    def test_enforce_tenant_id_check_parent_resource_owner(
            self, mock_get_plugin):

        def fakegetparent(*args, **kwargs):
            return {'tenant_id': 'fake'}
        mock_plugin = mock.Mock()
        mock_plugin.get_parentresource = fakegetparent
        mock_get_plugin.return_value = mock_plugin

        self._set_rules(
            admin_or_ext_parent_owner="rule:context_is_admin or "
                                      "tenant_id:%(ext_parent:tenant_id)s",
            create_parentresource_subresource="rule:admin_or_ext_parent_owner")
        self.fakepolicyinit()
        action = 'create_parentresource_subresource'
        target = {'ext_parent_parentresource_id': 'whatever', 'foo': 'bar'}
        result = policy.enforce(self.context, action, target)
        mock_get_plugin.assert_called_with('registered_plugin_name')
        self.assertTrue(result)
