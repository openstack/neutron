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

"""Test of Policy Engine For Quantum"""

import StringIO
import urllib2

import fixtures
import mock

import quantum
from quantum.common import exceptions
from quantum import context
from quantum.openstack.common import importutils
from quantum.openstack.common import policy as common_policy
from quantum import policy
from quantum.tests import base


class PolicyFileTestCase(base.BaseTestCase):
    def setUp(self):
        super(PolicyFileTestCase, self).setUp()
        policy.reset()
        self.addCleanup(policy.reset)
        self.context = context.Context('fake', 'fake')
        self.target = {}
        self.tempdir = self.useFixture(fixtures.TempDir())

    def test_modified_policy_reloads(self):
        def fake_find_config_file(_1, _2):
            return self.tempdir.join('policy')

        with mock.patch.object(quantum.common.utils,
                               'find_config_file',
                               new=fake_find_config_file):
            tmpfilename = fake_find_config_file(None, None)
            action = "example:test"
            with open(tmpfilename, "w") as policyfile:
                policyfile.write("""{"example:test": ""}""")
            policy.enforce(self.context, action, self.target)
            with open(tmpfilename, "w") as policyfile:
                policyfile.write("""{"example:test": "!"}""")
            # NOTE(vish): reset stored policy cache so we don't have to
            # sleep(1)
            policy._POLICY_CACHE = {}
            self.assertRaises(exceptions.PolicyNotAuthorized,
                              policy.enforce,
                              self.context,
                              action,
                              self.target)


class PolicyTestCase(base.BaseTestCase):
    def setUp(self):
        super(PolicyTestCase, self).setUp()
        policy.reset()
        self.addCleanup(policy.reset)
        # NOTE(vish): preload rules to circumvent reloading from file
        policy.init()
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
        # NOTE(vish): then overload underlying rules
        common_policy.set_rules(common_policy.Rules(
            dict((k, common_policy.parse_rule(v))
                 for k, v in rules.items())))
        self.context = context.Context('fake', 'fake', roles=['member'])
        self.target = {}

    def test_enforce_nonexistent_action_throws(self):
        action = "example:noexist"
        self.assertRaises(exceptions.PolicyNotAuthorized, policy.enforce,
                          self.context, action, self.target)

    def test_enforce_bad_action_throws(self):
        action = "example:denied"
        self.assertRaises(exceptions.PolicyNotAuthorized, policy.enforce,
                          self.context, action, self.target)

    def test_check_bad_action_noraise(self):
        action = "example:denied"
        result = policy.check(self.context, action, self.target)
        self.assertEqual(result, False)

    def test_enforce_good_action(self):
        action = "example:allowed"
        result = policy.enforce(self.context, action, self.target)
        self.assertEqual(result, True)

    def test_enforce_http_true(self):

        def fakeurlopen(url, post_data):
            return StringIO.StringIO("True")

        with mock.patch.object(urllib2, 'urlopen', new=fakeurlopen):
            action = "example:get_http"
            target = {}
            result = policy.enforce(self.context, action, target)
            self.assertEqual(result, True)

    def test_enforce_http_false(self):

        def fakeurlopen(url, post_data):
            return StringIO.StringIO("False")

        with mock.patch.object(urllib2, 'urlopen', new=fakeurlopen):
            action = "example:get_http"
            target = {}
            self.assertRaises(exceptions.PolicyNotAuthorized, policy.enforce,
                              self.context, action, target)

    def test_templatized_enforcement(self):
        target_mine = {'tenant_id': 'fake'}
        target_not_mine = {'tenant_id': 'another'}
        action = "example:my_file"
        policy.enforce(self.context, action, target_mine)
        self.assertRaises(exceptions.PolicyNotAuthorized, policy.enforce,
                          self.context, action, target_not_mine)

    def test_early_AND_enforcement(self):
        action = "example:early_and_fail"
        self.assertRaises(exceptions.PolicyNotAuthorized, policy.enforce,
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
        policy.reset()
        policy.init()
        self.addCleanup(policy.reset)

        self.rules = {
            "default": '',
            "example:exist": '!',
        }

        self._set_rules('default')

        self.context = context.Context('fake', 'fake')

    def _set_rules(self, default_rule):
        rules = common_policy.Rules(
            dict((k, common_policy.parse_rule(v))
                 for k, v in self.rules.items()), default_rule)
        common_policy.set_rules(rules)

    def test_policy_called(self):
        self.assertRaises(exceptions.PolicyNotAuthorized, policy.enforce,
                          self.context, "example:exist", {})

    def test_not_found_policy_calls_default(self):
        policy.enforce(self.context, "example:noexist", {})

    def test_default_not_found(self):
        self._set_rules("default_noexist")
        self.assertRaises(exceptions.PolicyNotAuthorized, policy.enforce,
                          self.context, "example:noexist", {})


class QuantumPolicyTestCase(base.BaseTestCase):

    def setUp(self):
        super(QuantumPolicyTestCase, self).setUp()
        policy.reset()
        policy.init()
        self.addCleanup(policy.reset)
        self.rules = dict((k, common_policy.parse_rule(v)) for k, v in {
            "admin_or_network_owner": "role:admin or "
                                      "tenant_id:%(network_tenant_id)s",
            "admin_or_owner": "role:admin or tenant_id:%(tenant_id)s",
            "admin_only": "role:admin",
            "regular_user": "role:user",
            "shared": "field:networks:shared=True",
            "external": "field:networks:router:external=True",
            "default": '@',

            "create_network": "rule:admin_or_owner",
            "create_network:shared": "rule:admin_only",
            "update_network": '@',
            "update_network:shared": "rule:admin_only",

            "get_network": "rule:admin_or_owner or "
                           "rule:shared or "
                           "rule:external",
            "create_port:mac": "rule:admin_or_network_owner",
        }.items())

        def fakepolicyinit():
            common_policy.set_rules(common_policy.Rules(self.rules))

        self.patcher = mock.patch.object(quantum.policy,
                                         'init',
                                         new=fakepolicyinit)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        self.context = context.Context('fake', 'fake', roles=['user'])
        plugin_klass = importutils.import_class(
            "quantum.db.db_base_plugin_v2.QuantumDbPluginV2")
        self.plugin = plugin_klass()

    def _test_action_on_attr(self, context, action, attr, value,
                             exception=None):
        action = "%s_network" % action
        target = {'tenant_id': 'the_owner', attr: value}
        if exception:
            self.assertRaises(exception, policy.enforce,
                              context, action, target, None)
        else:
            result = policy.enforce(context, action, target, None)
            self.assertEqual(result, True)

    def _test_nonadmin_action_on_attr(self, action, attr, value,
                                      exception=None):
        user_context = context.Context('', "user", roles=['user'])
        self._test_action_on_attr(user_context, action, attr,
                                  value, exception)

    def test_nonadmin_write_on_private_fails(self):
        self._test_nonadmin_action_on_attr('create', 'shared', False,
                                           exceptions.PolicyNotAuthorized)

    def test_nonadmin_read_on_private_fails(self):
        self._test_nonadmin_action_on_attr('get', 'shared', False,
                                           exceptions.PolicyNotAuthorized)

    def test_nonadmin_write_on_shared_fails(self):
        self._test_nonadmin_action_on_attr('create', 'shared', True,
                                           exceptions.PolicyNotAuthorized)

    def test_nonadmin_read_on_shared_succeeds(self):
        self._test_nonadmin_action_on_attr('get', 'shared', True)

    def _test_enforce_adminonly_attribute(self, action):
        admin_context = context.get_admin_context()
        target = {'shared': True}
        result = policy.enforce(admin_context, action, target, None)
        self.assertEqual(result, True)

    def test_enforce_adminonly_attribute_create(self):
        self._test_enforce_adminonly_attribute('create_network')

    def test_enforce_adminonly_attribute_update(self):
        self._test_enforce_adminonly_attribute('update_network')

    def test_enforce_adminonly_attribute_nonadminctx_returns_403(self):
        action = "create_network"
        target = {'shared': True, 'tenant_id': 'somebody_else'}
        self.assertRaises(exceptions.PolicyNotAuthorized, policy.enforce,
                          self.context, action, target, None)

    def test_enforce_regularuser_on_read(self):
        action = "get_network"
        target = {'shared': True, 'tenant_id': 'somebody_else'}
        result = policy.enforce(self.context, action, target, None)
        self.assertTrue(result)

    def test_enforce_parentresource_owner(self):

        def fakegetnetwork(*args, **kwargs):
            return {'tenant_id': 'fake'}

        action = "create_port:mac"
        with mock.patch.object(self.plugin, 'get_network', new=fakegetnetwork):
            target = {'network_id': 'whatever'}
            result = policy.enforce(self.context, action, target, self.plugin)
            self.assertTrue(result)
