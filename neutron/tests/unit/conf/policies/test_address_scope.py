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

from oslo_policy import policy as base_policy

from neutron import policy
from neutron.tests.unit.conf.policies import base


class AddressScopeAPITestCase(base.PolicyBaseTestCase):

    def setUp(self):
        super(AddressScopeAPITestCase, self).setUp()
        self.target = {
            'project_id': self.project_id}

    def test_system_admin_can_create_address_scope(self):
        # system_admin_ctx don't have project_id set so it's always call to
        # create it for "other project"
        self.assertTrue(
            policy.enforce(self.system_admin_ctx,
                           'create_address_scope', self.target))

    def test_system_member_can_not_create_address_scope(self):
        # If system member is not able to do that, it implies that
        # system_reader also will not be able to do that
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.system_member_ctx, 'create_address_scope', self.target)

    def test_project_member_can_create_address_scope(self):
        self.assertTrue(
            policy.enforce(self.project_member_ctx,
                           'create_address_scope', self.target))

    def test_project_member_can_not_create_address_scope_other_project(self):
        # If project member is not able to do that, it implies that
        # project_reader also will not be able to do that
        target = {'project_id': 'other-project'}
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.project_member_ctx, 'create_address_scope', target)

    def test_system_admin_can_create_shared_address_scope(self):
        # system_admin_ctx don't have project_id set so it's always call to
        # create it for "other project"
        target = self.target.copy()
        target['shared'] = True
        self.assertTrue(
            policy.enforce(self.system_admin_ctx,
                           'create_address_scope:shared', target))

    def test_system_member_can_not_create_shared_address_scope(self):
        # If system member is not able to do that, it implies that
        # system_reader also will not be able to do that
        target = self.target.copy()
        target['shared'] = True
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.system_member_ctx, 'create_address_scope:shared', target)

    def test_project_admin_can_not_create_shared_address_scope(self):
        # If project admin is not able to do that, it implies that
        # project_member and project_reader also will not be able to do that
        target = self.target.copy()
        target['shared'] = True
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.project_admin_ctx, 'create_address_scope:shared', target)

    def test_system_reader_can_get_address_scope(self):
        self.assertTrue(
            policy.enforce(self.system_reader_ctx,
                           'get_address_scope', self.target))

    def test_project_reader_can_get_address_scope(self):
        self.assertTrue(
            policy.enforce(self.project_reader_ctx,
                           'get_address_scope', self.target))

    def test_project_admin_can_not_get_address_scope_other_project(self):
        # If project admin is not able to do that, it implies that
        # project_member and project_reader also will not be able to do that
        target = {'project_id': 'other-project'}
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.project_admin_ctx, 'get_address_scope', target)

    def test_system_admin_can_update_address_scope(self):
        # system_admin_ctx don't have project_id set so it's always call to
        # create it for "other project"
        self.assertTrue(
            policy.enforce(self.system_admin_ctx,
                           'update_address_scope', self.target))

    def test_system_member_can_not_update_address_scope(self):
        # If system member is not able to do that, it implies that
        # system_reader also will not be able to do that
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.system_member_ctx, 'update_address_scope', self.target)

    def test_project_member_can_update_address_scope(self):
        self.assertTrue(
            policy.enforce(self.project_member_ctx,
                           'update_address_scope', self.target))

    def test_project_member_can_not_update_address_scope_other_project(self):
        # If project member is not able to do that, it implies that
        # project_reader also will not be able to do that
        target = {'project_id': 'other-project'}
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.project_member_ctx, 'update_address_scope', target)

    def test_system_admin_can_update_shared_address_scope(self):
        # system_admin_ctx don't have project_id set so it's always call to
        # create it for "other project"
        target = self.target.copy()
        target['shared'] = True
        self.assertTrue(
            policy.enforce(self.system_admin_ctx,
                           'update_address_scope:shared', target))

    def test_system_member_can_not_update_shared_address_scope(self):
        # If system member is not able to do that, it implies that
        # system_reader also will not be able to do that
        target = self.target.copy()
        target['shared'] = True
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.system_member_ctx, 'update_address_scope:shared', target)

    def test_project_admin_can_not_update_shared_address_scope(self):
        # If project admin is not able to do that, it implies that
        # project_member and project_reader also will not be able to do that
        target = self.target.copy()
        target['shared'] = True
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.project_admin_ctx, 'update_address_scope:shared', target)

    def test_system_admin_can_delete_address_scope(self):
        # system_admin_ctx don't have project_id set so it's always call to
        # create it for "other project"
        self.assertTrue(
            policy.enforce(self.system_admin_ctx,
                           'delete_address_scope', self.target))

    def test_system_member_can_not_delete_address_scope(self):
        # If system member is not able to do that, it implies that
        # system_reader also will not be able to do that
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.system_member_ctx, 'delete_address_scope', self.target)

    def test_project_member_can_delete_address_scope(self):
        self.assertTrue(
            policy.enforce(self.project_member_ctx,
                           'delete_address_scope', self.target))

    def test_project_member_can_not_delete_address_scope_other_project(self):
        # If project member is not able to do that, it implies that
        # project_reader also will not be able to do that
        target = {'project_id': 'other-project'}
        self.assertRaises(
            base_policy.PolicyNotAuthorized,
            policy.enforce,
            self.project_member_ctx, 'delete_address_scope', target)
