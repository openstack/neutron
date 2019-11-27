# Copyright 2019 Red Hat, Inc.
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

import mock

from neutron_lib import context
from neutron_lib.db import api as db_api
from oslo_db import exception as db_exc

from neutron.db.models import ovn as ovn_models
from neutron.db import ovn_revision_numbers_db as ovn_rn_db
from neutron.tests.unit.db import test_db_base_plugin_v2


class TestRevisionNumber(test_db_base_plugin_v2.NeutronDbPluginV2TestCase):

    def setUp(self):
        super(TestRevisionNumber, self).setUp()
        self.ctx = context.get_admin_context()
        self.addCleanup(self._delete_objs)
        res = self._create_network(fmt=self.fmt, name='net',
                                   admin_state_up=True)
        self.net = self.deserialize(self.fmt, res)['network']

    def _delete_objs(self):
        with db_api.CONTEXT_WRITER.using(self.ctx):
            self.ctx.session.query(
                ovn_models.OVNRevisionNumbers).delete()

    def _create_initial_revision(self, resource_uuid, resource_type,
                                 revision_number=ovn_rn_db.INITIAL_REV_NUM,
                                 may_exist=False):
        with self.ctx.session.begin(subtransactions=True):
            ovn_rn_db.create_initial_revision(
                self.ctx, resource_uuid, resource_type,
                revision_number=revision_number, may_exist=may_exist)

    def test_bump_revision(self):
        self._create_initial_revision(self.net['id'], ovn_rn_db.TYPE_NETWORKS)
        self.net['revision_number'] = 123
        ovn_rn_db.bump_revision(self.ctx, self.net,
                                ovn_rn_db.TYPE_NETWORKS)
        row = ovn_rn_db.get_revision_row(self.ctx, self.net['id'])
        self.assertEqual(123, row.revision_number)

    def test_bump_older_revision(self):
        self._create_initial_revision(self.net['id'], ovn_rn_db.TYPE_NETWORKS,
                                      revision_number=124)
        self.net['revision_number'] = 1
        ovn_rn_db.bump_revision(self.ctx, self.net,
                                ovn_rn_db.TYPE_NETWORKS)
        row = ovn_rn_db.get_revision_row(self.ctx, self.net['id'])
        self.assertEqual(124, row.revision_number)

    @mock.patch.object(ovn_rn_db.LOG, 'warning')
    def test_bump_revision_row_not_found(self, mock_log):
        self.net['revision_number'] = 123
        ovn_rn_db.bump_revision(self.ctx, self.net, ovn_rn_db.TYPE_NETWORKS)
        # Assert the revision number wasn't bumped
        row = ovn_rn_db.get_revision_row(self.ctx, self.net['id'])
        self.assertEqual(123, row.revision_number)
        self.assertIn('No revision row found for', mock_log.call_args[0][0])

    def test_delete_revision(self):
        self._create_initial_revision(self.net['id'], ovn_rn_db.TYPE_NETWORKS)
        ovn_rn_db.delete_revision(self.ctx, self.net['id'],
                                  ovn_rn_db.TYPE_NETWORKS)
        row = ovn_rn_db.get_revision_row(self.ctx, self.net['id'])
        self.assertIsNone(row)

    def test_create_initial_revision_may_exist_duplicated_entry(self):
        args = (self.net['id'], ovn_rn_db.TYPE_NETWORKS)
        self._create_initial_revision(*args)

        # Assert DBDuplicateEntry is raised when may_exist is False (default)
        self.assertRaises(db_exc.DBDuplicateEntry,
                          self._create_initial_revision, *args)

        try:
            self._create_initial_revision(*args, may_exist=True)
        except db_exc.DBDuplicateEntry:
            self.fail("create_initial_revision shouldn't raise "
                      "DBDuplicateEntry when may_exist is True")
