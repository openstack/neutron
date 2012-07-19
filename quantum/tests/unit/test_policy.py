# Copyright (c) 2012 OpenStack, LLC.
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

import contextlib
import os.path
import shutil
import StringIO
import tempfile
import unittest2 as unittest
import urllib2

import mock

import quantum
from quantum.common import exceptions
from quantum.common import utils
from quantum import context
from quantum.openstack.common import policy as common_policy
from quantum import policy


class PolicyFileTestCase(unittest.TestCase):
    def setUp(self):
        super(PolicyFileTestCase, self).setUp()
        policy.reset()
        self.context = context.Context('fake', 'fake')
        self.target = {}

    def tearDown(self):
        super(PolicyFileTestCase, self).tearDown()
        policy.reset()

    @contextlib.contextmanager
    def _tempdir(self, **kwargs):
        tmpdir = tempfile.mkdtemp(**kwargs)
        try:
            yield tmpdir
        finally:
            try:
                shutil.rmtree(tmpdir)
            except OSError, e:
                #TODO: fail test on raise
                pass

    def test_modified_policy_reloads(self):
        with self._tempdir() as tmpdir:
            def fake_find_config_file(_1, _2):
                return os.path.join(tmpdir, 'policy')

            with mock.patch.object(quantum.common.utils,
                                   'find_config_file',
                                   new=fake_find_config_file):
                tmpfilename = os.path.join(tmpdir, 'policy')
                action = "example:test"
                with open(tmpfilename, "w") as policyfile:
                    policyfile.write("""{"example:test": []}""")
                policy.enforce(self.context, action, self.target)
                with open(tmpfilename, "w") as policyfile:
                    policyfile.write("""{"example:test": ["false:false"]}""")
                # NOTE(vish): reset stored policy cache so we don't have to
                # sleep(1)
                policy._POLICY_CACHE = {}
                self.assertRaises(exceptions.PolicyNotAuthorized,
                                  policy.enforce,
                                  self.context,
                                  action,
                                  self.target)


class PolicyTestCase(unittest.TestCase):
    def setUp(self):
        super(PolicyTestCase, self).setUp()
        policy.reset()
        # NOTE(vish): preload rules to circumvent reloading from file
        policy.init()
        rules = {
            "true": [],
            "example:allowed": [],
            "example:denied": [["false:false"]],
            "example:get_http": [["http:http://www.example.com"]],
            "example:my_file": [["role:compute_admin"],
                                ["tenant_id:%(tenant_id)s"]],
            "example:early_and_fail": [["false:false", "rule:true"]],
            "example:early_or_success": [["rule:true"], ["false:false"]],
            "example:lowercase_admin": [["role:admin"], ["role:sysadmin"]],
            "example:uppercase_admin": [["role:ADMIN"], ["role:sysadmin"]],
        }
        # NOTE(vish): then overload underlying brain
        common_policy.set_brain(common_policy.HttpBrain(rules))
        self.context = context.Context('fake', 'fake', roles=['member'])
        self.target = {}

    def tearDown(self):
        policy.reset()
        super(PolicyTestCase, self).tearDown()

    def test_enforce_nonexistent_action_throws(self):
        action = "example:noexist"
        self.assertRaises(exceptions.PolicyNotAuthorized, policy.enforce,
                          self.context, action, self.target)

    def test_enforce_bad_action_throws(self):
        action = "example:denied"
        self.assertRaises(exceptions.PolicyNotAuthorized, policy.enforce,
                          self.context, action, self.target)

    def test_enforce_good_action(self):
        action = "example:allowed"
        policy.enforce(self.context, action, self.target)

    def test_enforce_http_true(self):

        def fakeurlopen(url, post_data):
            return StringIO.StringIO("True")

        with mock.patch.object(urllib2, 'urlopen', new=fakeurlopen):
            action = "example:get_http"
            target = {}
            result = policy.enforce(self.context, action, target)
            self.assertEqual(result, None)

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


class DefaultPolicyTestCase(unittest.TestCase):

    def setUp(self):
        super(DefaultPolicyTestCase, self).setUp()
        policy.reset()
        policy.init()

        self.rules = {
            "default": [],
            "example:exist": [["false:false"]]
        }

        self._set_brain('default')

        self.context = context.Context('fake', 'fake')

    def _set_brain(self, default_rule):
        brain = common_policy.HttpBrain(self.rules, default_rule)
        common_policy.set_brain(brain)

    def tearDown(self):
        super(DefaultPolicyTestCase, self).tearDown()
        policy.reset()

    def test_policy_called(self):
        self.assertRaises(exceptions.PolicyNotAuthorized, policy.enforce,
                          self.context, "example:exist", {})

    def test_not_found_policy_calls_default(self):
        policy.enforce(self.context, "example:noexist", {})

    def test_default_not_found(self):
        self._set_brain("default_noexist")
        self.assertRaises(exceptions.PolicyNotAuthorized, policy.enforce,
                          self.context, "example:noexist", {})
