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

import contextlib
import StringIO
import urllib2

import mock
from oslo_config import cfg
from oslo_serialization import jsonutils
from oslo_utils import importutils
import six
import six.moves.urllib.request as urlrequest

import neutron
from neutron.api.v2 import attributes
from neutron.common import constants as const
from neutron.common import exceptions
from neutron import context
from neutron import manager
from neutron.openstack.common import policy as common_policy
from neutron import policy
from neutron.tests import base


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
        cfg.CONF.set_override('policy_file', tmpfilename)
        policy.refresh()
        policy.enforce(self.context, action, self.target)
        with open(tmpfilename, "w") as policyfile:
            policyfile.write("""{"example:test": "!"}""")
        policy.refresh()
        self.target = {'tenant_id': 'fake_tenant'}
        self.assertRaises(common_policy.PolicyNotAuthorized,
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
        }
        policy.refresh()
        # NOTE(vish): then overload underlying rules
        policy.set_rules(dict((k, common_policy.parse_rule(v))
                              for k, v in rules.items()))
        self.context = context.Context('fake', 'fake', roles=['member'])
        self.target = {}

    def test_enforce_nonexistent_action_throws(self):
        action = "example:noexist"
        self.assertRaises(common_policy.PolicyNotAuthorized, policy.enforce,
                          self.context, action, self.target)

    def test_enforce_bad_action_throws(self):
        action = "example:denied"
        self.assertRaises(common_policy.PolicyNotAuthorized, policy.enforce,
                          self.context, action, self.target)

    def test_check_bad_action_noraise(self):
        action = "example:denied"
        result = policy.check(self.context, action, self.target)
        self.assertEqual(result, False)

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
        self.assertEqual(result, True)

    @mock.patch.object(urlrequest, 'urlopen',
                       return_value=StringIO.StringIO("True"))
    def test_enforce_http_true(self, mock_urlrequest):
        action = "example:get_http"
        target = {}
        result = policy.enforce(self.context, action, target)
        self.assertEqual(result, True)

    def test_enforce_http_false(self):

        def fakeurlopen(url, post_data):
            return six.StringIO("False")

        with mock.patch.object(urllib2, 'urlopen', new=fakeurlopen):
            action = "example:get_http"
            target = {}
            self.assertRaises(common_policy.PolicyNotAuthorized,
                              policy.enforce, self.context,
                              action, target)

    def test_templatized_enforcement(self):
        target_mine = {'tenant_id': 'fake'}
        target_not_mine = {'tenant_id': 'another'}
        action = "example:my_file"
        policy.enforce(self.context, action, target_mine)
        self.assertRaises(common_policy.PolicyNotAuthorized, policy.enforce,
                          self.context, action, target_not_mine)

    def test_early_AND_enforcement(self):
        action = "example:early_and_fail"
        self.assertRaises(common_policy.PolicyNotAuthorized, policy.enforce,
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
        tmpfilename = self.get_temp_file_path('policy.json')
        self.rules = {
            "default": '',
            "example:exist": '!',
        }
        with open(tmpfilename, "w") as policyfile:
            jsonutils.dump(self.rules, policyfile)
        cfg.CONF.set_override('policy_file', tmpfilename)
        policy.refresh()

        self.context = context.Context('fake', 'fake')

    def test_policy_called(self):
        self.assertRaises(common_policy.PolicyNotAuthorized, policy.enforce,
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


class NeutronPolicyTestCase(base.BaseTestCase):

    def fakepolicyinit(self, **kwargs):
        enf = policy._ENFORCER
        enf.set_rules(common_policy.Rules(self.rules))

    def setUp(self):
        super(NeutronPolicyTestCase, self).setUp()
        policy.refresh()
        self.admin_only_legacy = "role:admin"
        self.admin_or_owner_legacy = "role:admin or tenant_id:%(tenant_id)s"
        # Add Fake resources to RESOURCE_ATTRIBUTE_MAP
        attributes.RESOURCE_ATTRIBUTE_MAP.update(FAKE_RESOURCES)
        self.rules = dict((k, common_policy.parse_rule(v)) for k, v in {
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
            "update_port": "rule:admin_or_owner or rule:context_is_advsvc",
            "get_port": "rule:admin_or_owner or rule:context_is_advsvc",
            "delete_port": "rule:admin_or_owner or rule:context_is_advsvc",
            "create_fake_resource": "rule:admin_or_owner",
            "create_fake_resource:attr": "rule:admin_or_owner",
            "create_fake_resource:attr:sub_attr_1": "rule:admin_or_owner",
            "create_fake_resource:attr:sub_attr_2": "rule:admin_only",

            "create_fake_policy:": "rule:admin_or_owner",
            "get_firewall_policy": "rule:admin_or_owner or "
                            "rule:shared",
            "get_firewall_rule": "rule:admin_or_owner or "
                            "rule:shared"
        }.items())

        def remove_fake_resource():
            del attributes.RESOURCE_ATTRIBUTE_MAP["%ss" % FAKE_RESOURCE_NAME]

        self.patcher = mock.patch.object(neutron.policy,
                                         'init',
                                         new=self.fakepolicyinit)
        self.patcher.start()
        self.addCleanup(remove_fake_resource)
        self.context = context.Context('fake', 'fake', roles=['user'])
        plugin_klass = importutils.import_class(
            "neutron.db.db_base_plugin_v2.NeutronDbPluginV2")
        self.manager_patcher = mock.patch('neutron.manager.NeutronManager')
        fake_manager = self.manager_patcher.start()
        fake_manager_instance = fake_manager.return_value
        fake_manager_instance.plugin = plugin_klass()

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
            self.assertEqual(result, True)

    def _test_nonadmin_action_on_attr(self, action, attr, value,
                                      exception=None, **kwargs):
        user_context = context.Context('', "user", roles=['user'])
        self._test_action_on_attr(user_context, action, "network", attr,
                                  value, exception, **kwargs)

    def _test_advsvc_action_on_attr(self, action, obj, attr, value,
                                    exception=None, **kwargs):
        user_context = context.Context('', "user",
                                       roles=['user', 'advsvc'])
        self._test_action_on_attr(user_context, action, obj, attr,
                                  value, exception, **kwargs)

    def test_nonadmin_write_on_private_fails(self):
        self._test_nonadmin_action_on_attr('create', 'shared', False,
                                           common_policy.PolicyNotAuthorized)

    def test_nonadmin_read_on_private_fails(self):
        self._test_nonadmin_action_on_attr('get', 'shared', False,
                                           common_policy.PolicyNotAuthorized)

    def test_nonadmin_write_on_shared_fails(self):
        self._test_nonadmin_action_on_attr('create', 'shared', True,
                                           common_policy.PolicyNotAuthorized)

    def test_create_port_device_owner_regex(self):
        blocked_values = ('network:', 'network:abdef', 'network:dhcp',
                          'network:router_interface')
        for val in blocked_values:
            self._test_advsvc_action_on_attr(
                'create', 'port', 'device_owner', val,
                common_policy.PolicyNotAuthorized
            )
        ok_values = ('network', 'networks', 'my_network:test', 'my_network:')
        for val in ok_values:
            self._test_advsvc_action_on_attr(
                'create', 'port', 'device_owner', val
            )

    def test_advsvc_get_network_works(self):
        self._test_advsvc_action_on_attr('get', 'network', 'shared', False)

    def test_advsvc_create_network_fails(self):
        self._test_advsvc_action_on_attr('create', 'network', 'shared', False,
                                         common_policy.PolicyNotAuthorized)

    def test_advsvc_create_port_works(self):
        self._test_advsvc_action_on_attr('create', 'port:mac', 'shared', False)

    def test_advsvc_get_port_works(self):
        self._test_advsvc_action_on_attr('get', 'port', 'shared', False)

    def test_advsvc_update_port_works(self):
        kwargs = {const.ATTRIBUTES_TO_UPDATE: ['shared']}
        self._test_advsvc_action_on_attr('update', 'port', 'shared', True,
                                         **kwargs)

    def test_advsvc_delete_port_works(self):
        self._test_advsvc_action_on_attr('delete', 'port', 'shared', False)

    def test_advsvc_create_subnet_fails(self):
        self._test_advsvc_action_on_attr('create', 'subnet', 'shared', False,
                                         common_policy.PolicyNotAuthorized)

    def test_nonadmin_read_on_shared_succeeds(self):
        self._test_nonadmin_action_on_attr('get', 'shared', True)

    def _test_enforce_adminonly_attribute(self, action, **kwargs):
        admin_context = context.get_admin_context()
        target = {'shared': True}
        if kwargs:
            target.update(kwargs)
        result = policy.enforce(admin_context, action, target)
        self.assertEqual(result, True)

    def test_enforce_adminonly_attribute_create(self):
        self._test_enforce_adminonly_attribute('create_network')

    def test_enforce_adminonly_attribute_update(self):
        kwargs = {const.ATTRIBUTES_TO_UPDATE: ['shared']}
        self._test_enforce_adminonly_attribute('update_network', **kwargs)

    def test_reset_adminonly_attr_to_default_fails(self):
        kwargs = {const.ATTRIBUTES_TO_UPDATE: ['shared']}
        self._test_nonadmin_action_on_attr('update', 'shared', False,
                                           common_policy.PolicyNotAuthorized,
                                           **kwargs)

    def test_enforce_adminonly_attribute_no_context_is_admin_policy(self):
        del self.rules[policy.ADMIN_CTX_POLICY]
        self.rules['admin_only'] = common_policy.parse_rule(
            self.admin_only_legacy)
        self.rules['admin_or_owner'] = common_policy.parse_rule(
            self.admin_or_owner_legacy)
        self._test_enforce_adminonly_attribute('create_network')

    def test_enforce_adminonly_attribute_nonadminctx_returns_403(self):
        action = "create_network"
        target = {'shared': True, 'tenant_id': 'somebody_else'}
        self.assertRaises(common_policy.PolicyNotAuthorized, policy.enforce,
                          self.context, action, target)

    def test_enforce_adminonly_nonadminctx_no_ctx_is_admin_policy_403(self):
        del self.rules[policy.ADMIN_CTX_POLICY]
        self.rules['admin_only'] = common_policy.parse_rule(
            self.admin_only_legacy)
        self.rules['admin_or_owner'] = common_policy.parse_rule(
            self.admin_or_owner_legacy)
        action = "create_network"
        target = {'shared': True, 'tenant_id': 'somebody_else'}
        self.assertRaises(common_policy.PolicyNotAuthorized, policy.enforce,
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

    def test_enforce_subattribute(self):
        action = "create_" + FAKE_RESOURCE_NAME
        target = {'tenant_id': 'fake', 'attr': {'sub_attr_1': 'x'}}
        result = policy.enforce(self.context, action, target, None)
        self.assertEqual(result, True)

    def test_enforce_admin_only_subattribute(self):
        action = "create_" + FAKE_RESOURCE_NAME
        target = {'tenant_id': 'fake', 'attr': {'sub_attr_1': 'x',
                                                'sub_attr_2': 'y'}}
        result = policy.enforce(context.get_admin_context(),
                                action, target, None)
        self.assertEqual(result, True)

    def test_enforce_admin_only_subattribute_nonadminctx_returns_403(self):
        action = "create_" + FAKE_RESOURCE_NAME
        target = {'tenant_id': 'fake', 'attr': {'sub_attr_1': 'x',
                                                'sub_attr_2': 'y'}}
        self.assertRaises(common_policy.PolicyNotAuthorized, policy.enforce,
                          self.context, action, target, None)

    def test_enforce_regularuser_on_read(self):
        action = "get_network"
        target = {'shared': True, 'tenant_id': 'somebody_else'}
        result = policy.enforce(self.context, action, target)
        self.assertTrue(result)

    def test_enforce_firewall_policy_shared(self):
        action = "get_firewall_policy"
        target = {'shared': True, 'tenant_id': 'somebody_else'}
        result = policy.enforce(self.context, action, target)
        self.assertTrue(result)

    def test_enforce_firewall_rule_shared(self):
        action = "get_firewall_rule"
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
        with mock.patch.object(manager.NeutronManager.get_instance().plugin,
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
        with mock.patch.object(manager.NeutronManager.get_instance().plugin,
                               'get_network', new=fakegetnetwork):
            target = {'network_id': 'whatever'}
            self.assertRaises(NotImplementedError,
                              policy.enforce,
                              self.context,
                              action,
                              target)

    def test_enforce_tenant_id_check_parent_resource_bw_compatibility(self):

        def fakegetnetwork(*args, **kwargs):
            return {'tenant_id': 'fake'}

        del self.rules['admin_or_network_owner']
        self.rules['admin_or_network_owner'] = common_policy.parse_rule(
            "role:admin or tenant_id:%(network_tenant_id)s")
        action = "create_port:mac"
        with mock.patch.object(manager.NeutronManager.get_instance().plugin,
                               'get_network', new=fakegetnetwork):
            target = {'network_id': 'whatever'}
            result = policy.enforce(self.context, action, target)
            self.assertTrue(result)

    def test_tenant_id_check_no_target_field_raises(self):
        # Try and add a bad rule
        self.assertRaises(
            exceptions.PolicyInitError,
            common_policy.parse_rule,
            'tenant_id:(wrong_stuff)')

    def _test_enforce_tenant_id_raises(self, bad_rule):
        self.rules['admin_or_owner'] = common_policy.parse_rule(bad_rule)
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

    def test_get_roles_context_is_admin_rule_missing(self):
        rules = dict((k, common_policy.parse_rule(v)) for k, v in {
            "some_other_rule": "role:admin",
        }.items())
        policy.set_rules(common_policy.Rules(rules))
        # 'admin' role is expected for bw compatibility
        self.assertEqual(['admin'], policy.get_admin_roles())

    def test_get_roles_with_role_check(self):
        rules = dict((k, common_policy.parse_rule(v)) for k, v in {
            policy.ADMIN_CTX_POLICY: "role:admin",
        }.items())
        policy.set_rules(common_policy.Rules(rules))
        self.assertEqual(['admin'], policy.get_admin_roles())

    def test_get_roles_with_rule_check(self):
        rules = dict((k, common_policy.parse_rule(v)) for k, v in {
            policy.ADMIN_CTX_POLICY: "rule:some_other_rule",
            "some_other_rule": "role:admin",
        }.items())
        policy.set_rules(common_policy.Rules(rules))
        self.assertEqual(['admin'], policy.get_admin_roles())

    def test_get_roles_with_or_check(self):
        self.rules = dict((k, common_policy.parse_rule(v)) for k, v in {
            policy.ADMIN_CTX_POLICY: "rule:rule1 or rule:rule2",
            "rule1": "role:admin_1",
            "rule2": "role:admin_2"
        }.items())
        self.assertEqual(['admin_1', 'admin_2'],
                         policy.get_admin_roles())

    def test_get_roles_with_other_rules(self):
        self.rules = dict((k, common_policy.parse_rule(v)) for k, v in {
            policy.ADMIN_CTX_POLICY: "role:xxx or other:value",
        }.items())
        self.assertEqual(['xxx'], policy.get_admin_roles())

    def _test_set_rules_with_deprecated_policy(self, input_rules,
                                               expected_rules):
        policy.set_rules(input_rules.copy())
        # verify deprecated policy has been removed
        for pol in input_rules.keys():
            self.assertNotIn(pol, policy._ENFORCER.rules)
        # verify deprecated policy was correctly translated. Iterate
        # over items for compatibility with unittest2 in python 2.6
        for rule in expected_rules:
            self.assertIn(rule, policy._ENFORCER.rules)
            self.assertEqual(str(policy._ENFORCER.rules[rule]),
                             expected_rules[rule])

    def test_set_rules_with_deprecated_view_policy(self):
        self._test_set_rules_with_deprecated_policy(
            {'extension:router:view': 'rule:admin_or_owner'},
            {'get_network:router:external': 'rule:admin_or_owner'})

    def test_set_rules_with_deprecated_set_policy(self):
        expected_policies = ['create_network:provider:network_type',
                             'create_network:provider:physical_network',
                             'create_network:provider:segmentation_id',
                             'update_network:provider:network_type',
                             'update_network:provider:physical_network',
                             'update_network:provider:segmentation_id']
        self._test_set_rules_with_deprecated_policy(
            {'extension:provider_network:set': 'rule:admin_only'},
            dict((policy, 'rule:admin_only') for policy in
                 expected_policies))

    def test_process_rules(self):
        action = "create_" + FAKE_RESOURCE_NAME
        # Construct RuleChecks for an action, attribute and subattribute
        match_rule = common_policy.RuleCheck('rule', action)
        attr_rule = common_policy.RuleCheck('rule', '%s:%ss' %
                                                    (action,
                                                     FAKE_RESOURCE_NAME))
        sub_attr_rules = [common_policy.RuleCheck('rule', '%s:%s:%s' %
                                                          (action, 'attr',
                                                           'sub_attr_1'))]
        # Build an AndCheck from the given RuleChecks
        # Make the checks nested to better check the recursion
        sub_attr_rules = common_policy.AndCheck(sub_attr_rules)
        attr_rule = common_policy.AndCheck(
            [attr_rule, sub_attr_rules])

        match_rule = common_policy.AndCheck([match_rule, attr_rule])
        # Assert that the rules are correctly extracted from the match_rule
        rules = policy._process_rules_list([], match_rule)
        self.assertEqual(['create_fake_resource',
                          'create_fake_resource:fake_resources',
                          'create_fake_resource:attr:sub_attr_1'], rules)

    def test_log_rule_list(self):
        with contextlib.nested(
            mock.patch.object(policy.LOG, 'isEnabledFor', return_value=True),
            mock.patch.object(policy.LOG, 'debug')
        ) as (is_e, dbg):
            policy.log_rule_list(common_policy.RuleCheck('rule', 'create_'))
            self.assertTrue(is_e.called)
            self.assertTrue(dbg.called)
