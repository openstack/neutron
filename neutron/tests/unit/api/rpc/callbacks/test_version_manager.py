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

from neutron.api.rpc.callbacks import exceptions
from neutron.api.rpc.callbacks import resources
from neutron.api.rpc.callbacks import version_manager
from neutron.db import agents_db
from neutron.tests import base


TEST_RESOURCE_TYPE = 'TestResourceType'
TEST_VERSION_A = '1.11'
TEST_VERSION_B = '1.12'

TEST_RESOURCE_TYPE_2 = 'AnotherResource'

AGENT_HOST_1 = 'host-1'
AGENT_HOST_2 = 'host-2'
AGENT_TYPE_1 = 'dhcp-agent'
AGENT_TYPE_2 = 'openvswitch-agent'
CONSUMER_1 = version_manager.AgentConsumer(AGENT_TYPE_1, AGENT_HOST_1)
CONSUMER_2 = version_manager.AgentConsumer(AGENT_TYPE_2, AGENT_HOST_2)


class ResourceConsumerTrackerTest(base.BaseTestCase):

    def test_consumer_set_versions(self):
        cv = version_manager.ResourceConsumerTracker()

        cv.set_versions(CONSUMER_1, {TEST_RESOURCE_TYPE: TEST_VERSION_A})
        self.assertIn(TEST_VERSION_A,
                      cv.get_resource_versions(TEST_RESOURCE_TYPE))

    def test_consumer_updates_version(self):
        cv = version_manager.ResourceConsumerTracker()

        for version in [TEST_VERSION_A, TEST_VERSION_B]:
            cv.set_versions(CONSUMER_1, {TEST_RESOURCE_TYPE: version})

        self.assertEqual(set([TEST_VERSION_B]),
                         cv.get_resource_versions(TEST_RESOURCE_TYPE))

    def test_multiple_consumer_version_update(self):
        cv = version_manager.ResourceConsumerTracker()

        cv.set_versions(CONSUMER_1, {TEST_RESOURCE_TYPE: TEST_VERSION_A})
        cv.set_versions(CONSUMER_2, {TEST_RESOURCE_TYPE: TEST_VERSION_A})
        cv.set_versions(CONSUMER_1, {TEST_RESOURCE_TYPE: TEST_VERSION_B})

        self.assertEqual(set([TEST_VERSION_A, TEST_VERSION_B]),
                         cv.get_resource_versions(TEST_RESOURCE_TYPE))

    def test_consumer_downgrades_removing_resource(self):
        cv = version_manager.ResourceConsumerTracker()

        cv.set_versions(CONSUMER_1, {TEST_RESOURCE_TYPE: TEST_VERSION_B,
                                     TEST_RESOURCE_TYPE_2: TEST_VERSION_A})
        cv.set_versions(CONSUMER_1, {TEST_RESOURCE_TYPE: TEST_VERSION_A})

        self.assertEqual(set(),
                         cv.get_resource_versions(TEST_RESOURCE_TYPE_2))
        self.assertEqual(set([TEST_VERSION_A]),
                         cv.get_resource_versions(TEST_RESOURCE_TYPE))

    def test_consumer_downgrades_stops_reporting(self):
        cv = version_manager.ResourceConsumerTracker()

        cv.set_versions(CONSUMER_1, {TEST_RESOURCE_TYPE: TEST_VERSION_B,
                                     TEST_RESOURCE_TYPE_2: TEST_VERSION_A})
        cv.set_versions(CONSUMER_1, {})

        for resource_type in [TEST_RESOURCE_TYPE, TEST_RESOURCE_TYPE_2]:
            self.assertEqual(set(),
                             cv.get_resource_versions(resource_type))

    def test_different_adds_triggers_recalculation(self):
        cv = version_manager.ResourceConsumerTracker()

        for version in [TEST_VERSION_A, TEST_VERSION_B]:
            cv.set_versions(CONSUMER_1, {TEST_RESOURCE_TYPE: version})

        self.assertTrue(cv._needs_recalculation)
        cv._recalculate_versions = mock.Mock()
        cv.get_resource_versions(TEST_RESOURCE_TYPE)
        cv._recalculate_versions.assert_called_once_with()


class CachedResourceConsumerTrackerTest(base.BaseTestCase):

    def setUp(self):
        super(CachedResourceConsumerTrackerTest, self).setUp()

        self.refreshed = False

        class _FakePlugin(agents_db.AgentDbMixin):
            @staticmethod
            def get_agents_resource_versions(tracker):
                self.refreshed = True
                tracker.set_versions(CONSUMER_1,
                                     {TEST_RESOURCE_TYPE: TEST_VERSION_A})

        self.get_plugin = mock.patch('neutron_lib.plugins.directory'
                                     '.get_plugin').start()

        self.get_plugin.return_value = _FakePlugin()

    def test_plugin_does_not_implement_agentsdb_exception(self):
        self.get_plugin.return_value = object()
        cached_tracker = version_manager.CachedResourceConsumerTracker()
        self.assertRaises(exceptions.NoAgentDbMixinImplemented,
                          cached_tracker.get_resource_versions,
                          resources.QOS_POLICY)

    def test_consumer_versions_callback(self):
        cached_tracker = version_manager.CachedResourceConsumerTracker()

        self.assertIn(TEST_VERSION_A,
                      cached_tracker.get_resource_versions(
                          TEST_RESOURCE_TYPE))

    def test_update_versions(self):
        cached_tracker = version_manager.CachedResourceConsumerTracker()

        initial_versions = cached_tracker.get_resource_versions(
            TEST_RESOURCE_TYPE)

        initial_versions_2 = cached_tracker.get_resource_versions(
            TEST_RESOURCE_TYPE_2)

        cached_tracker.update_versions(
            CONSUMER_1, {TEST_RESOURCE_TYPE: TEST_VERSION_B,
                         TEST_RESOURCE_TYPE_2: TEST_VERSION_A})

        final_versions = cached_tracker.get_resource_versions(
            TEST_RESOURCE_TYPE)
        final_versions_2 = cached_tracker.get_resource_versions(
            TEST_RESOURCE_TYPE_2)

        self.assertNotEqual(initial_versions, final_versions)
        self.assertNotEqual(initial_versions_2, final_versions_2)

    def test_versions_ttl(self):

        cached_tracker = version_manager.CachedResourceConsumerTracker()
        with mock.patch('time.time') as time_patch:
            time_patch.return_value = 1
            cached_tracker.get_resource_versions(TEST_RESOURCE_TYPE)
            self.assertTrue(self.refreshed)
            self.refreshed = False

            time_patch.return_value = 2
            cached_tracker.get_resource_versions(TEST_RESOURCE_TYPE)
            self.assertFalse(self.refreshed)

            time_patch.return_value = 2 + version_manager.VERSIONS_TTL
            cached_tracker.get_resource_versions(TEST_RESOURCE_TYPE)
            self.assertTrue(self.refreshed)
