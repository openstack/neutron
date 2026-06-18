# Copyright (c) 2026 Red Hat, Inc.
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

from neutron_lib import context

from neutron.db import security_groups_default_statefulness as sg_ds_db
from neutron.tests.unit import testlib_api


DB_PLUGIN_KLASS = 'neutron.db.db_base_plugin_v2.NeutronDbPluginV2'


class SecurityGroupDefaultStatefulnessMixinImpl(
        sg_ds_db.SecurityGroupDefaultStatefulnessMixin):
    pass


class SecurityGroupDefaultStatefulnessDbTestCase(testlib_api.SqlTestCase):

    def setUp(self):
        super().setUp()
        self.setup_coreplugin(core_plugin=DB_PLUGIN_KLASS)
        self.ctx = context.get_admin_context()
        self.mixin = SecurityGroupDefaultStatefulnessMixinImpl()

    def _make_body(self, project_id=None, stateful=True):
        return {'security_groups_default_statefulness': {
            'project_id': project_id,
            'stateful': stateful}}

    def test_create_sg_default_statefulness(self):
        body = self._make_body(project_id='project1', stateful=False)
        result = self.mixin.create_security_groups_default_statefulness(
            self.ctx, body)
        self.assertFalse(result['stateful'])
        self.assertEqual('project1', result['project_id'])
        self.assertIn('id', result)

    def test_create_sg_default_statefulness_system_wide(self):
        body = self._make_body(project_id=None, stateful=False)
        result = self.mixin.create_security_groups_default_statefulness(
            self.ctx, body)
        self.assertFalse(result['stateful'])
        self.assertIsNone(result['project_id'])

    def test_create_sg_default_statefulness_duplicate_project(self):
        body = self._make_body(project_id='project1', stateful=False)
        self.mixin.create_security_groups_default_statefulness(
            self.ctx, body)
        self.assertRaises(
            sg_ds_db.SecurityGroupDefaultStatefulnessAlreadyExists,
            self.mixin.create_security_groups_default_statefulness,
            self.ctx, body)

    def test_get_sg_default_statefulness(self):
        body = self._make_body(project_id='project1', stateful=False)
        created = self.mixin.create_security_groups_default_statefulness(
            self.ctx, body)
        result = self.mixin.get_security_groups_default_statefulness(
            self.ctx, created['id'])
        self.assertEqual(created['id'], result['id'])
        self.assertFalse(result['stateful'])

    def test_get_sg_default_statefulness_not_found(self):
        self.assertRaises(
            sg_ds_db.SecurityGroupDefaultStatefulnessNotFound,
            self.mixin.get_security_groups_default_statefulness,
            self.ctx, 'non-existent-id')

    def test_list_sg_default_statefulness(self):
        body1 = self._make_body(project_id='project1', stateful=False)
        body2 = self._make_body(project_id='project2', stateful=True)
        self.mixin.create_security_groups_default_statefulness(
            self.ctx, body1)
        self.mixin.create_security_groups_default_statefulness(
            self.ctx, body2)
        results = self.mixin.get_security_groups_default_statefulness(
            self.ctx)
        self.assertEqual(2, len(results))

    def test_update_sg_default_statefulness(self):
        body = self._make_body(project_id='project1', stateful=False)
        created = self.mixin.create_security_groups_default_statefulness(
            self.ctx, body)
        update_body = {'security_groups_default_statefulness': {
            'stateful': True}}
        result = self.mixin.update_security_groups_default_statefulness(
            self.ctx, created['id'], update_body)
        self.assertTrue(result['stateful'])
        self.assertEqual(created['id'], result['id'])

    def test_delete_sg_default_statefulness(self):
        body = self._make_body(project_id='project1', stateful=False)
        created = self.mixin.create_security_groups_default_statefulness(
            self.ctx, body)
        self.mixin.delete_security_groups_default_statefulness(
            self.ctx, created['id'])
        self.assertRaises(
            sg_ds_db.SecurityGroupDefaultStatefulnessNotFound,
            self.mixin.get_security_groups_default_statefulness,
            self.ctx, created['id'])

    def test_get_default_stateful_for_project_specific(self):
        body = self._make_body(project_id='project1', stateful=False)
        self.mixin.create_security_groups_default_statefulness(
            self.ctx, body)
        result = self.mixin.get_default_stateful_for_project(
            self.ctx, 'project1')
        self.assertFalse(result)

    def test_get_default_stateful_for_project_system_wide(self):
        body = self._make_body(project_id=None, stateful=False)
        self.mixin.create_security_groups_default_statefulness(
            self.ctx, body)
        result = self.mixin.get_default_stateful_for_project(
            self.ctx, 'any-project')
        self.assertFalse(result)

    def test_get_default_stateful_project_overrides_system(self):
        system_body = self._make_body(project_id=None, stateful=False)
        project_body = self._make_body(project_id='project1', stateful=True)
        self.mixin.create_security_groups_default_statefulness(
            self.ctx, system_body)
        self.mixin.create_security_groups_default_statefulness(
            self.ctx, project_body)
        result = self.mixin.get_default_stateful_for_project(
            self.ctx, 'project1')
        self.assertTrue(result)

    def test_get_default_stateful_no_config(self):
        result = self.mixin.get_default_stateful_for_project(
            self.ctx, 'project1')
        self.assertTrue(result)
