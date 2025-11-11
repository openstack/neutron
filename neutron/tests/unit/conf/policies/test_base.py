# Copyright (c) 2021 Red Hat Inc.
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

import tempfile
import warnings

from neutron_lib import context
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron import policy
from neutron.tests import base as tests_base


# According to the community goal guidelines
# https://governance.openstack.org/tc/goals/selected/consistent-and-secure-rbac.html#re-evaluate-project-specific-api-policies
# each rule should have only one scope type,
# If for any reason, rule needs to have more than one scope, it should be
# listed in that list of exceptions.
# This is dictionary where key is the rule name and value is list of the
# rule scopes, like e.g.:
#
#     {
#         'rule_name': ["system", "project"],
#         'rule_name_2': ["system", "domain"]
#     }
SCOPE_TYPES_EXCEPTIONS = {
    'get_flavor_service_profile': ['system', 'project'],
    'get_flavor': ['system', 'project'],
    'get_rule_type': ['system', 'project'],
    'get_service_provider': ['system', 'project'],
}


class PolicyBaseTestCase(tests_base.BaseTestCase):

    def setUp(self):
        # NOTE(slaweq): Because of issue with stestr and Python3, we need
        # to avoid too much output to be produced during tests, so we will
        # ignore python warnings in the tests policy tests
        warnings.simplefilter("ignore")

        # NOTE(slaweq): Enforcing new policies has to be done before calling
        # super() as in BaseTestCase policies are initialized and config
        # options has to be set properly at that point already.
        # That tests are testing only new default policies.
        cfg.CONF.set_override(
            'enforce_new_defaults', True, group='oslo_policy')
        super().setUp()
        self.project_id = uuidutils.generate_uuid()
        self.system_user_id = uuidutils.generate_uuid()
        self.user_id = uuidutils.generate_uuid()
        self._prepare_system_scope_personas()
        self._prepare_project_scope_personas()
        self._prepare_service_persona()
        self.alt_project_id = uuidutils.generate_uuid()

    def _prepare_system_scope_personas(self):
        self.system_admin_ctx = context.Context(
            user_id=self.system_user_id,
            roles=['admin', 'member', 'reader'],
            system_scope='all')
        self.system_member_ctx = context.Context(
            user_id=self.system_user_id,
            roles=['member', 'reader'],
            system_scope='all')
        self.system_reader_ctx = context.Context(
            user_id=self.system_user_id,
            roles=['reader'],
            system_scope='all')

    def _prepare_project_scope_personas(self):
        self.project_admin_ctx = context.Context(
            user_id=self.user_id,
            roles=['admin', 'manager', 'member', 'reader'],
            project_id=self.project_id)
        self.project_manager_ctx = context.Context(
            user_id=self.user_id,
            roles=['manager', 'member', 'reader'],
            project_id=self.project_id)
        self.project_member_ctx = context.Context(
            user_id=self.user_id,
            roles=['member', 'reader'],
            project_id=self.project_id)
        self.project_reader_ctx = context.Context(
            user_id=self.user_id,
            roles=['reader'],
            project_id=self.project_id)

    def _prepare_service_persona(self):
        self.service_ctx = context.Context(
            user_id='service',
            roles=['service'],
            project_id='service')


class RuleScopesTestCase(PolicyBaseTestCase):

    def setUp(self):
        super().setUp()
        policy.init()

    def test_rules_are_single_scoped(self):
        for rule_name, rule in policy._ENFORCER.registered_rules.items():
            if not rule.scope_types:
                # If scope types are not set for rule, that's ok
                continue
            if len(rule.scope_types) == 1:
                # If rule has only one scope, it's fine
                continue
            expected_scope_types = SCOPE_TYPES_EXCEPTIONS.get(rule_name, [])
            fail_msg = (
                "Rule %s have scope types %s which are not defined "
                "in the exceptions list: %s" % (
                    rule_name, rule.scope_types, expected_scope_types))
            self.assertListEqual(expected_scope_types,
                                 rule.scope_types,
                                 fail_msg)


def write_policies(policies):
    env_path = tempfile.mkdtemp(prefix='policy_test_', dir='/tmp/')
    with tempfile.NamedTemporaryFile('w+', dir=env_path,
                                     delete=False) as policy_file:
        policy_file.write(str(policies))
    return env_path, policy_file.name


def reload_policies(policy_file):
    policy.reset()
    policy.init(policy_file=policy_file, suppress_deprecation_warnings=True)
