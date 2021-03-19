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

from neutron_lib import context
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.tests import base as tests_base


class PolicyBaseTestCase(tests_base.BaseTestCase):

    def setUp(self):
        # NOTE(slaweq): Enforcing new policies has to be done before calling
        # super() as in BaseTestCase policies are initialized and config
        # options has to be set properly at that point already.
        # That tests are testing only new default policies.
        cfg.CONF.set_override(
            'enforce_new_defaults', True, group='oslo_policy')
        cfg.CONF.set_override(
            'enforce_scope', True, group='oslo_policy')
        super(PolicyBaseTestCase, self).setUp()
        self.project_id = uuidutils.generate_uuid()
        self.system_user_id = uuidutils.generate_uuid()
        self.user_id = uuidutils.generate_uuid()
        self._prepare_system_scope_personas()
        self._prepare_project_scope_personas()

    def _prepare_system_scope_personas(self):
        self.system_admin_ctx = context.Context(
            user=self.system_user_id,
            roles=['admin', 'member', 'reader'],
            system_scope='all')
        self.system_member_ctx = context.Context(
            user=self.system_user_id,
            roles=['member', 'reader'],
            system_scope='all')
        self.system_reader_ctx = context.Context(
            user=self.system_user_id,
            roles=['reader'],
            system_scope='all')

    def _prepare_project_scope_personas(self):
        self.project_admin_ctx = context.Context(
            user=self.user_id,
            roles=['admin', 'member', 'reader'],
            project_id=self.project_id)
        self.project_member_ctx = context.Context(
            user=self.user_id,
            roles=['member', 'reader'],
            project_id=self.project_id)
        self.project_reader_ctx = context.Context(
            user=self.user_id,
            roles=['reader'],
            project_id=self.project_id)
