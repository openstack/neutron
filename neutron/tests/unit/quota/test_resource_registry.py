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
from oslo_config import cfg
import testtools

from neutron.quota import resource
from neutron.quota import resource_registry
from neutron.tests import base
from neutron.tests.unit import quota as test_quota


class TestResourceRegistry(base.DietTestCase):

    def setUp(self):
        super(TestResourceRegistry, self).setUp()
        self.registry = resource_registry.ResourceRegistry.get_instance()
        # clean up the registry at every test
        self.registry.unregister_resources()

    def test_set_tracked_resource_new_resource(self):
        self.registry.set_tracked_resource('meh', test_quota.MehModel)
        self.assertEqual(test_quota.MehModel,
                         self.registry._tracked_resource_mappings['meh'])

    def test_set_tracked_resource_existing_with_override(self):
        self.test_set_tracked_resource_new_resource()
        self.registry.set_tracked_resource('meh', test_quota.OtherMehModel,
                                           override=True)
        # Override is set to True, the model class should change
        self.assertEqual(test_quota.OtherMehModel,
                         self.registry._tracked_resource_mappings['meh'])

    def test_set_tracked_resource_existing_no_override(self):
        self.test_set_tracked_resource_new_resource()
        self.registry.set_tracked_resource('meh', test_quota.OtherMehModel)
        # Override is set to false, the model class should not change
        self.assertEqual(test_quota.MehModel,
                         self.registry._tracked_resource_mappings['meh'])

    def _test_register_resource_by_name(self, resource_name, expected_type):
        self.assertNotIn(resource_name, self.registry._resources)
        self.registry.register_resource_by_name(resource_name)
        self.assertIn(resource_name, self.registry._resources)
        self.assertIsInstance(self.registry.get_resource(resource_name),
                              expected_type)

    def test_register_resource_by_name_tracked(self):
        self.test_set_tracked_resource_new_resource()
        self._test_register_resource_by_name('meh', resource.TrackedResource)

    def test_register_resource_by_name_not_tracked(self):
        self._test_register_resource_by_name('meh', resource.CountableResource)

    def test_tracked_resource_error_if_already_registered_as_untracked(self):
        self.registry.register_resource_by_name('meh')
        with testtools.ExpectedException(RuntimeError):
            self.registry.set_tracked_resource('meh', test_quota.MehModel)
        # ensure unregister works
        self.registry.unregister_resources()

    def test_register_resource_by_name_with_tracking_disabled_by_config(self):
        cfg.CONF.set_override('track_quota_usage', False,
                              group='QUOTAS')
        self.registry.set_tracked_resource('meh', test_quota.MehModel)
        self.assertNotIn(
            'meh', self.registry._tracked_resource_mappings)
        self._test_register_resource_by_name('meh', resource.CountableResource)


class TestAuxiliaryFunctions(base.DietTestCase):

    def setUp(self):
        super(TestAuxiliaryFunctions, self).setUp()
        self.registry = resource_registry.ResourceRegistry.get_instance()
        # clean up the registry at every test
        self.registry.unregister_resources()

    def test_resync_tracking_disabled(self):
        cfg.CONF.set_override('track_quota_usage', False,
                              group='QUOTAS')
        with mock.patch('neutron.quota.resource.'
                        'TrackedResource.resync') as mock_resync:
            self.registry.set_tracked_resource('meh', test_quota.MehModel)
            self.registry.register_resource_by_name('meh')
            resource_registry.resync_resource(mock.ANY, 'meh', 'project_id')
            self.assertEqual(0, mock_resync.call_count)

    def test_resync_tracked_resource(self):
        with mock.patch('neutron.quota.resource.'
                        'TrackedResource.resync') as mock_resync:
            self.registry.set_tracked_resource('meh', test_quota.MehModel)
            self.registry.register_resource_by_name('meh')
            resource_registry.resync_resource(mock.ANY, 'meh', 'project_id')
            mock_resync.assert_called_once_with(mock.ANY, 'project_id')

    def test_resync_non_tracked_resource(self):
        with mock.patch('neutron.quota.resource.'
                        'TrackedResource.resync') as mock_resync:
            self.registry.register_resource_by_name('meh')
            resource_registry.resync_resource(mock.ANY, 'meh', 'project_id')
            self.assertEqual(0, mock_resync.call_count)

    def test_set_resources_dirty_invoked_with_tracking_disabled(self):
        cfg.CONF.set_override('track_quota_usage', False,
                              group='QUOTAS')
        with mock.patch('neutron.quota.resource.'
                        'TrackedResource.mark_dirty') as mock_mark_dirty:
            self.registry.set_tracked_resource('meh', test_quota.MehModel)
            self.registry.register_resource_by_name('meh')
            resource_registry.set_resources_dirty(mock.ANY)
            self.assertEqual(0, mock_mark_dirty.call_count)

    def test_set_resources_dirty_no_dirty_resource(self):
        ctx = context.Context('user_id', 'project_id',
                              is_admin=False, is_advsvc=False)
        with mock.patch('neutron.quota.resource.'
                        'TrackedResource.mark_dirty') as mock_mark_dirty:
            self.registry.set_tracked_resource('meh', test_quota.MehModel)
            self.registry.register_resource_by_name('meh')
            res = self.registry.get_resource('meh')
            # This ensures dirty is false
            res._dirty_projects.clear()
            resource_registry.set_resources_dirty(ctx)
            self.assertEqual(0, mock_mark_dirty.call_count)

    def test_set_resources_dirty_no_tracked_resource(self):
        ctx = context.Context('user_id', 'project_id',
                              is_admin=False, is_advsvc=False)
        with mock.patch('neutron.quota.resource.'
                        'TrackedResource.mark_dirty') as mock_mark_dirty:
            self.registry.register_resource_by_name('meh')
            resource_registry.set_resources_dirty(ctx)
            self.assertEqual(0, mock_mark_dirty.call_count)

    def test_set_resources_dirty(self):
        ctx = context.Context('user_id', 'project_id',
                              is_admin=False, is_advsvc=False)
        with mock.patch('neutron.quota.resource.'
                        'TrackedResource.mark_dirty') as mock_mark_dirty:
            self.registry.set_tracked_resource('meh', test_quota.MehModel)
            self.registry.register_resource_by_name('meh')
            self.registry.resources['meh']._track_resource_events = True
            res = self.registry.get_resource('meh')
            # This ensures dirty is true
            res._dirty_projects.add('project_id')
            resource_registry.set_resources_dirty(ctx)
            mock_mark_dirty.assert_called_once_with(ctx)
