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

import mock
from oslo_config import cfg
from oslo_utils import uuidutils
import testtools

from neutron import context
from neutron.db import api as db_api
from neutron.db.quota import api as quota_api
from neutron.quota import resource
from neutron.tests import base
from neutron.tests.unit import quota as test_quota
from neutron.tests.unit import testlib_api


meh_quota_flag = 'quota_meh'
meh_quota_opts = [cfg.IntOpt(meh_quota_flag, default=99)]


class TestResource(base.DietTestCase):
    """Unit tests for neutron.quota.resource.BaseResource"""

    def test_create_resource_without_plural_name(self):
        res = resource.BaseResource('foo', None)
        self.assertEqual('foos', res.plural_name)
        res = resource.BaseResource('foy', None)
        self.assertEqual('foies', res.plural_name)

    def test_create_resource_with_plural_name(self):
        res = resource.BaseResource('foo', None,
                                    plural_name='foopsies')
        self.assertEqual('foopsies', res.plural_name)

    def test_resource_default_value(self):
        res = resource.BaseResource('foo', 'foo_quota')
        with mock.patch('oslo_config.cfg.CONF') as mock_cfg:
            mock_cfg.QUOTAS.foo_quota = 99
            self.assertEqual(99, res.default)

    def test_resource_negative_default_value(self):
        res = resource.BaseResource('foo', 'foo_quota')
        with mock.patch('oslo_config.cfg.CONF') as mock_cfg:
            mock_cfg.QUOTAS.foo_quota = -99
            self.assertEqual(-1, res.default)


class TestTrackedResource(testlib_api.SqlTestCaseLight):

    def _add_data(self, tenant_id=None):
        session = db_api.get_writer_session()
        with session.begin():
            tenant_id = tenant_id or self.tenant_id
            session.add(test_quota.MehModel(
                meh='meh_%s' % uuidutils.generate_uuid(),
                tenant_id=tenant_id))
            session.add(test_quota.MehModel(
                meh='meh_%s' % uuidutils.generate_uuid(),
                tenant_id=tenant_id))

    def _delete_data(self):
        session = db_api.get_writer_session()
        with session.begin():
            query = session.query(test_quota.MehModel).filter_by(
                tenant_id=self.tenant_id)
            for item in query:
                session.delete(item)

    def _update_data(self):
        session = db_api.get_writer_session()
        with session.begin():
            query = session.query(test_quota.MehModel).filter_by(
                tenant_id=self.tenant_id)
            for item in query:
                item['meh'] = 'meh-%s' % item['meh']
                session.add(item)

    def setUp(self):
        base.BaseTestCase.config_parse()
        cfg.CONF.register_opts(meh_quota_opts, 'QUOTAS')
        self.addCleanup(cfg.CONF.reset)
        self.resource = 'meh'
        self.other_resource = 'othermeh'
        self.tenant_id = 'meh'
        self.context = context.Context(
            user_id='', tenant_id=self.tenant_id, is_admin=False)
        super(TestTrackedResource, self).setUp()

    def _register_events(self, res):
        res.register_events()
        self.addCleanup(res.unregister_events)

    def _create_resource(self):
        res = resource.TrackedResource(
            self.resource, test_quota.MehModel, meh_quota_flag)
        self._register_events(res)
        return res

    def _create_other_resource(self):
        res = resource.TrackedResource(
            self.other_resource, test_quota.OtherMehModel, meh_quota_flag)
        self._register_events(res)
        return res

    def test_bulk_delete_protection(self):
        self._create_resource()
        with testtools.ExpectedException(RuntimeError):
            ctx = context.get_admin_context()
            ctx.session.query(test_quota.MehModel).delete()

    def test_count_first_call_with_dirty_false(self):
        quota_api.set_quota_usage(
            self.context, self.resource, self.tenant_id, in_use=1)
        res = self._create_resource()
        self._add_data()
        # explicitly set dirty flag to False
        quota_api.set_all_quota_usage_dirty(
            self.context, self.resource, dirty=False)
        # Expect correct count to be returned anyway since the first call to
        # count() always resyncs with the db
        self.assertEqual(2, res.count(self.context, None, self.tenant_id))

    def _test_count(self):
        res = self._create_resource()
        quota_api.set_quota_usage(
            self.context, res.name, self.tenant_id, in_use=0)
        self._add_data()
        return res

    def test_count_with_dirty_false(self):
        res = self._test_count()
        res.count(self.context, None, self.tenant_id)
        # At this stage count has been invoked, and the dirty flag should be
        # false. Another invocation of count should not query the model class
        set_quota = 'neutron.db.quota.api.set_quota_usage'
        with mock.patch(set_quota) as mock_set_quota:
            self.assertEqual(0, mock_set_quota.call_count)
            self.assertEqual(2, res.count(self.context,
                                          None,
                                          self.tenant_id))

    def test_count_with_dirty_true_resync(self):
        res = self._test_count()
        # Expect correct count to be returned, which also implies
        # set_quota_usage has been invoked with the correct parameters
        self.assertEqual(2, res.count(self.context,
                                      None,
                                      self.tenant_id,
                                      resync_usage=True))

    def test_count_with_dirty_true_resync_calls_set_quota_usage(self):
        res = self._test_count()
        set_quota_usage = 'neutron.db.quota.api.set_quota_usage'
        with mock.patch(set_quota_usage) as mock_set_quota_usage:
            quota_api.set_quota_usage_dirty(self.context,
                                            self.resource,
                                            self.tenant_id)
            res.count(self.context, None, self.tenant_id,
                      resync_usage=True)
            mock_set_quota_usage.assert_called_once_with(
                self.context, self.resource, self.tenant_id, in_use=2)

    def test_count_with_dirty_true_no_usage_info(self):
        res = self._create_resource()
        self._add_data()
        # Invoke count without having usage info in DB - Expect correct
        # count to be returned
        self.assertEqual(2, res.count(self.context, None, self.tenant_id))

    def test_count_with_dirty_true_no_usage_info_calls_set_quota_usage(self):
        res = self._create_resource()
        self._add_data()
        set_quota_usage = 'neutron.db.quota.api.set_quota_usage'
        with mock.patch(set_quota_usage) as mock_set_quota_usage:
            quota_api.set_quota_usage_dirty(self.context,
                                            self.resource,
                                            self.tenant_id)
            res.count(self.context, None, self.tenant_id, resync_usage=True)
            mock_set_quota_usage.assert_called_once_with(
                self.context, self.resource, self.tenant_id, in_use=2)

    def test_add_delete_data_triggers_event(self):
        res = self._create_resource()
        other_res = self._create_other_resource()
        # Validate dirty tenants since mock does not work well with SQLAlchemy
        # event handlers.
        self._add_data()
        self._add_data('someone_else')
        self.assertEqual(2, len(res._dirty_tenants))
        # Also, the dirty flag should not be set for other resources
        self.assertEqual(0, len(other_res._dirty_tenants))
        self.assertIn(self.tenant_id, res._dirty_tenants)
        self.assertIn('someone_else', res._dirty_tenants)

    def test_delete_data_triggers_event(self):
        res = self._create_resource()
        self._add_data()
        self._add_data('someone_else')
        # Artificially clear _dirty_tenants
        res._dirty_tenants.clear()
        self._delete_data()
        # We did not delete "someone_else", so expect only a single dirty
        # tenant
        self.assertEqual(1, len(res._dirty_tenants))
        self.assertIn(self.tenant_id, res._dirty_tenants)

    def test_update_does_not_trigger_event(self):
        res = self._create_resource()
        self._add_data()
        self._add_data('someone_else')
        # Artificially clear _dirty_tenants
        res._dirty_tenants.clear()
        self._update_data()
        self.assertEqual(0, len(res._dirty_tenants))

    def test_mark_dirty(self):
        res = self._create_resource()
        self._add_data()
        self._add_data('someone_else')
        set_quota_usage = 'neutron.db.quota.api.set_quota_usage_dirty'
        with mock.patch(set_quota_usage) as mock_set_quota_usage:
            res.mark_dirty(self.context)
            self.assertEqual(2, mock_set_quota_usage.call_count)
            mock_set_quota_usage.assert_any_call(
                self.context, self.resource, self.tenant_id)
            mock_set_quota_usage.assert_any_call(
                self.context, self.resource, 'someone_else')

    def test_mark_dirty_no_dirty_tenant(self):
        res = self._create_resource()
        set_quota_usage = 'neutron.db.quota.api.set_quota_usage_dirty'
        with mock.patch(set_quota_usage) as mock_set_quota_usage:
            res.mark_dirty(self.context)
            self.assertFalse(mock_set_quota_usage.call_count)

    def test_resync(self):
        res = self._create_resource()
        self._add_data()
        res.mark_dirty(self.context)
        # self.tenant_id now is out of sync
        set_quota_usage = 'neutron.db.quota.api.set_quota_usage'
        with mock.patch(set_quota_usage) as mock_set_quota_usage:
            res.resync(self.context, self.tenant_id)
            # and now it should be in sync
            self.assertNotIn(self.tenant_id, res._out_of_sync_tenants)
            mock_set_quota_usage.assert_called_once_with(
                self.context, self.resource, self.tenant_id, in_use=2)
