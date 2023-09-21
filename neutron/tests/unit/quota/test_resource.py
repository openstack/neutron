# Copyright (c) 2015 OpenStack Foundation.  All rights reserved.
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

from unittest import mock

from neutron_lib import context
from neutron_lib.db import api as db_api
from neutron_lib.plugins import constants
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_utils import uuidutils
import testtools

from neutron.db.quota import api as quota_api
from neutron.quota import resource
from neutron.tests import base
from neutron.tests.unit import quota as test_quota
from neutron.tests.unit import testlib_api


DB_PLUGIN_KLASS = 'neutron.db.db_base_plugin_v2.NeutronDbPluginV2'
QUOTA_DRIVER = 'neutron.db.quota.DbQuotaDriver'


meh_quota_flag = 'quota_meh'
meh_quota_opts = [cfg.IntOpt(meh_quota_flag, default=99)]


class _BaseResource(resource.BaseResource):

    @property
    def dirty(self):
        return False

    def count(self, context, plugin, project_id, **kwargs):
        pass


class TestResource(base.DietTestCase):
    """Unit tests for neutron.quota.resource.BaseResource"""

    def test_create_resource_without_plural_name(self):
        res = _BaseResource('foo', None)
        self.assertEqual('foos', res.plural_name)
        res = _BaseResource('foy', None)
        self.assertEqual('foies', res.plural_name)

    def test_create_resource_with_plural_name(self):
        res = _BaseResource('foo', None, plural_name='foopsies')
        self.assertEqual('foopsies', res.plural_name)

    def test_resource_default_value(self):
        res = _BaseResource('foo', 'foo_quota')
        with mock.patch('oslo_config.cfg.CONF') as mock_cfg:
            mock_cfg.QUOTAS.foo_quota = 99
            self.assertEqual(99, res.default)

    def test_resource_negative_default_value(self):
        res = _BaseResource('foo', 'foo_quota')
        with mock.patch('oslo_config.cfg.CONF') as mock_cfg:
            mock_cfg.QUOTAS.foo_quota = -99
            self.assertEqual(-1, res.default)


class TestTrackedResource(testlib_api.SqlTestCase):

    def _add_data(self, project_id=None):
        session = db_api.get_writer_session()
        with session.begin():
            project_id = project_id or self.project_id
            session.add(test_quota.MehModel(
                meh='meh_%s' % uuidutils.generate_uuid(),
                project_id=project_id))
            session.add(test_quota.MehModel(
                meh='meh_%s' % uuidutils.generate_uuid(),
                project_id=project_id))

    def _delete_data(self):
        session = db_api.get_writer_session()
        with session.begin():
            query = session.query(test_quota.MehModel).filter_by(
                project_id=self.project_id)
            for item in query:
                session.delete(item)

    def _update_data(self):
        session = db_api.get_writer_session()
        with session.begin():
            query = session.query(test_quota.MehModel).filter_by(
                project_id=self.project_id)
            for item in query:
                item['meh'] = 'meh-%s' % item['meh']
                session.add(item)

    def setUp(self):
        cfg.CONF.set_override('quota_driver', QUOTA_DRIVER, group='QUOTAS')
        super(TestTrackedResource, self).setUp()
        self.setup_coreplugin(DB_PLUGIN_KLASS)
        self.resource = 'meh'
        self.other_resource = 'othermeh'
        self.project_id = 'meh'
        self.context = context.Context(
            user_id='', project_id=self.project_id, is_admin=False)

    def _create_resource(self):
        res = resource.TrackedResource(
            self.resource, test_quota.MehModel, meh_quota_flag)
        res.register_events()
        return res

    def _create_other_resource(self):
        res = resource.TrackedResource(
            self.other_resource, test_quota.OtherMehModel, meh_quota_flag)
        res.register_events()
        return res

    def test_bulk_delete_protection(self):
        self._create_resource()
        with testtools.ExpectedException(RuntimeError):
            ctx = context.get_admin_context()
            ctx.session.query(test_quota.MehModel).delete()

    def test_count_first_call_with_dirty_false(self):
        quota_api.set_quota_usage(
            self.context, self.resource, self.project_id, in_use=1)
        res = self._create_resource()
        self._add_data()
        # explicitly set dirty flag to False
        quota_api.set_all_quota_usage_dirty(
            self.context, self.resource, dirty=False)
        # Expect correct count to be returned anyway since the first call to
        # count() always resyncs with the db
        self.assertEqual(2, res.count(self.context, None, self.project_id))

    def test_count_reserved(self):
        res = self._create_resource()
        quota_api.create_reservation(self.context, self.project_id,
                                     {res.name: 1})
        self.assertEqual(1, res.count_reserved(self.context, self.project_id))

    def test_count_used_first_call_with_dirty_false(self):
        quota_api.set_quota_usage(
            self.context, self.resource, self.project_id, in_use=1)
        res = self._create_resource()
        self._add_data()
        # explicitly set dirty flag to False
        quota_api.set_all_quota_usage_dirty(
            self.context, self.resource, dirty=False)
        # Expect correct count_used to be returned
        # anyway since the first call to
        # count_used() always resyncs with the db
        self.assertEqual(2, res.count_used(self.context, self.project_id))

    def _test_count(self):
        res = self._create_resource()
        quota_api.set_quota_usage(
            self.context, res.name, self.project_id, in_use=0)
        self._add_data()
        return res

    def test_count_with_dirty_false(self):
        res = self._test_count()
        res.count(self.context, None, self.project_id)
        # At this stage count has been invoked, and the dirty flag should be
        # false. Another invocation of count should not query the model class
        set_quota = 'neutron.db.quota.api.set_quota_usage'
        with mock.patch(set_quota) as mock_set_quota:
            self.assertEqual(0, mock_set_quota.call_count)
            self.assertEqual(2, res.count(self.context,
                                          None,
                                          self.project_id))

    def test_count_used_with_dirty_false(self):
        res = self._test_count()
        res.count_used(self.context, self.project_id)
        # At this stage count_used has been invoked,
        # and the dirty flag should be false. Another invocation
        # of count_used should not query the model class
        set_quota = 'neutron.db.quota.api.set_quota_usage'
        with mock.patch(set_quota) as mock_set_quota:
            self.assertEqual(0, mock_set_quota.call_count)
            self.assertEqual(2, res.count_used(self.context,
                                               self.project_id))

    def test_count_with_dirty_true_resync(self):
        res = self._test_count()
        # Expect correct count to be returned, which also implies
        # set_quota_usage has been invoked with the correct parameters
        self.assertEqual(2, res.count(self.context,
                                      None,
                                      self.project_id,
                                      resync_usage=True))

    def test_count_used_with_dirty_true_resync(self):
        res = self._test_count()
        # Expect correct count_used to be returned, which also implies
        # set_quota_usage has been invoked with the correct parameters
        self.assertEqual(2, res.count_used(self.context,
                                           self.project_id,
                                           resync_usage=True))

    def test_count_with_dirty_true_resync_calls_set_quota_usage(self):
        res = self._test_count()
        set_quota_usage = 'neutron.db.quota.api.set_quota_usage'
        with mock.patch(set_quota_usage) as mock_set_quota_usage:
            quota_api.set_resources_quota_usage_dirty(self.context,
                                                      self.resource,
                                                      self.project_id)
            res.count(self.context, None, self.project_id,
                      resync_usage=True)
            mock_set_quota_usage.assert_called_once_with(
                self.context, self.resource, self.project_id, in_use=2)

    def test_count_used_with_dirty_true_resync_calls_set_quota_usage(self):
        res = self._test_count()
        set_quota_usage = 'neutron.db.quota.api.set_quota_usage'
        with mock.patch(set_quota_usage) as mock_set_quota_usage:
            quota_api.set_resources_quota_usage_dirty(self.context,
                                                      self.resource,
                                                      self.project_id)
            res.count_used(self.context, self.project_id,
                           resync_usage=True)
            mock_set_quota_usage.assert_called_once_with(
                self.context, self.resource, self.project_id, in_use=2)

    def test_count_with_dirty_true_no_usage_info(self):
        res = self._create_resource()
        self._add_data()
        # Invoke count without having usage info in DB - Expect correct
        # count to be returned
        self.assertEqual(2, res.count(self.context, None, self.project_id))

    def test_count_used_with_dirty_true_no_usage_info(self):
        res = self._create_resource()
        self._add_data()
        # Invoke count_used without having usage info in DB - Expect correct
        # count_used to be returned
        self.assertEqual(2, res.count_used(self.context, self.project_id))

    def test_count_with_dirty_true_no_usage_info_calls_set_quota_usage(self):
        res = self._create_resource()
        self._add_data()
        set_quota_usage = 'neutron.db.quota.api.set_quota_usage'
        with mock.patch(set_quota_usage) as mock_set_quota_usage:
            quota_api.set_resources_quota_usage_dirty(self.context,
                                                      self.resource,
                                                      self.project_id)
            res.count(self.context, None, self.project_id, resync_usage=True)
            mock_set_quota_usage.assert_called_once_with(
                self.context, self.resource, self.project_id, in_use=2)

    def test_count_used_with_dirty_true_no_usage_info_calls_set_quota_usage(
                                                                     self):
        res = self._create_resource()
        self._add_data()
        set_quota_usage = 'neutron.db.quota.api.set_quota_usage'
        with mock.patch(set_quota_usage) as mock_set_quota_usage:
            quota_api.set_resources_quota_usage_dirty(self.context,
                                                      self.resource,
                                                      self.project_id)
            res.count_used(self.context, self.project_id, resync_usage=True)
            mock_set_quota_usage.assert_called_once_with(
                self.context, self.resource, self.project_id, in_use=2)

    def test_add_delete_data_triggers_event(self):
        res = self._create_resource()
        other_res = self._create_other_resource()
        # Validate dirty projects since mock does not work well with SQLAlchemy
        # event handlers.
        self._add_data()
        self._add_data('someone_else')
        self.assertEqual(2, len(res._dirty_projects))
        # Also, the dirty flag should not be set for other resources
        self.assertEqual(0, len(other_res._dirty_projects))
        self.assertIn(self.project_id, res._dirty_projects)
        self.assertIn('someone_else', res._dirty_projects)

    def test_delete_data_triggers_event(self):
        res = self._create_resource()
        self._add_data()
        self._add_data('someone_else')
        # Artificially clear _dirty_projects
        res._dirty_projects.clear()
        self._delete_data()
        # We did not delete "someone_else", so expect only a single dirty
        # project
        self.assertEqual(1, len(res._dirty_projects))
        self.assertIn(self.project_id, res._dirty_projects)

    def test_update_does_not_trigger_event(self):
        res = self._create_resource()
        self._add_data()
        self._add_data('someone_else')
        # Artificially clear _dirty_projects
        res._dirty_projects.clear()
        self._update_data()
        self.assertEqual(0, len(res._dirty_projects))

    def test_mark_dirty(self):
        res = self._create_resource()
        self._add_data()
        self._add_data('someone_else')
        set_quota_usage = (
            'neutron.db.quota.api.set_resources_quota_usage_dirty')
        with mock.patch(set_quota_usage) as mock_set_quota_usage:
            res.mark_dirty(self.context)
            self.assertEqual(2, mock_set_quota_usage.call_count)
            mock_set_quota_usage.assert_any_call(
                self.context, self.resource, self.project_id)
            mock_set_quota_usage.assert_any_call(
                self.context, self.resource, 'someone_else')

    def test_mark_dirty_no_dirty_project(self):
        res = self._create_resource()
        set_quota_usage = (
            'neutron.db.quota.api.set_resources_quota_usage_dirty')
        with mock.patch(set_quota_usage) as mock_set_quota_usage:
            res.mark_dirty(self.context)
            self.assertFalse(mock_set_quota_usage.call_count)

    def test_resync(self):
        res = self._create_resource()
        self._add_data()
        res.mark_dirty(self.context)
        # self.project_id now is out of sync
        set_quota_usage = 'neutron.db.quota.api.set_quota_usage'
        with mock.patch(set_quota_usage) as mock_set_quota_usage:
            res.resync(self.context, self.project_id)
            # and now it should be in sync
            self.assertNotIn(self.project_id, res._out_of_sync_projects)
            mock_set_quota_usage.assert_called_once_with(
                self.context, self.resource, self.project_id, in_use=2)


class Test_CountResource(base.BaseTestCase):

    def test_all_plugins_checked(self):
        plugin1 = mock.Mock()
        plugin2 = mock.Mock()
        plugins = {'plugin1': plugin1, 'plugin2': plugin2}

        for name, plugin in plugins.items():
            plugin.get_floatingips_count.side_effect = NotImplementedError
            plugin.get_floatingips.side_effect = NotImplementedError
            directory.add_plugin(name, plugin)

        context = mock.Mock()
        collection_name = 'floatingips'
        project_id = 'fakeid'
        self.assertRaises(
            NotImplementedError,
            resource._count_resource, context, collection_name, project_id)

        for plugin in plugins.values():
            for func in (plugin.get_floatingips_count, plugin.get_floatingips):
                func.assert_called_with(
                    context, filters={'project_id': [project_id]})

    def test_core_plugin_checked_first(self):
        plugin1 = mock.Mock()
        plugin2 = mock.Mock()

        plugin1.get_floatingips_count.side_effect = NotImplementedError
        plugin1.get_floatingips.side_effect = NotImplementedError
        directory.add_plugin('plugin1', plugin1)

        plugin2.get_floatingips_count.return_value = 10
        directory.add_plugin(constants.CORE, plugin2)

        context = mock.Mock()
        collection_name = 'floatingips'
        project_id = 'fakeid'
        self.assertEqual(
            10, resource._count_resource(context, collection_name, project_id))
