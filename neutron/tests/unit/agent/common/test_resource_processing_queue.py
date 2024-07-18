# Copyright 2014 Hewlett-Packard Development Company, L.P.
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
#

import datetime

from oslo_utils import timeutils
from oslo_utils import uuidutils

from neutron.agent.common import resource_processing_queue as queue
from neutron.tests import base

_uuid = uuidutils.generate_uuid
FAKE_ID = _uuid()
FAKE_ID_2 = _uuid()

PRIORITY_RPC = 0


class TestExclusiveResourceProcessor(base.BaseTestCase):

    def test_i_am_primary(self):
        primary = queue.ExclusiveResourceProcessor(FAKE_ID)
        not_primary = queue.ExclusiveResourceProcessor(FAKE_ID)
        primary_2 = queue.ExclusiveResourceProcessor(FAKE_ID_2)
        not_primary_2 = queue.ExclusiveResourceProcessor(FAKE_ID_2)

        self.assertTrue(primary._i_am_primary())
        self.assertFalse(not_primary._i_am_primary())
        self.assertTrue(primary_2._i_am_primary())
        self.assertFalse(not_primary_2._i_am_primary())

        primary.__exit__(None, None, None)
        primary_2.__exit__(None, None, None)

    def test_primary(self):
        primary = queue.ExclusiveResourceProcessor(FAKE_ID)
        not_primary = queue.ExclusiveResourceProcessor(FAKE_ID)
        primary_2 = queue.ExclusiveResourceProcessor(FAKE_ID_2)
        not_primary_2 = queue.ExclusiveResourceProcessor(FAKE_ID_2)

        self.assertEqual(primary, primary._primary)
        self.assertEqual(primary, not_primary._primary)
        self.assertEqual(primary_2, primary_2._primary)
        self.assertEqual(primary_2, not_primary_2._primary)

        primary.__exit__(None, None, None)
        primary_2.__exit__(None, None, None)

    def test__enter__(self):
        self.assertNotIn(FAKE_ID, queue.ExclusiveResourceProcessor._primaries)
        primary = queue.ExclusiveResourceProcessor(FAKE_ID)
        primary.__enter__()
        self.assertIn(FAKE_ID, queue.ExclusiveResourceProcessor._primaries)
        primary.__exit__(None, None, None)

    def test__exit__(self):
        primary = queue.ExclusiveResourceProcessor(FAKE_ID)
        not_primary = queue.ExclusiveResourceProcessor(FAKE_ID)
        primary.__enter__()
        self.assertIn(FAKE_ID, queue.ExclusiveResourceProcessor._primaries)
        not_primary.__enter__()
        not_primary.__exit__(None, None, None)
        self.assertIn(FAKE_ID, queue.ExclusiveResourceProcessor._primaries)
        primary.__exit__(None, None, None)
        self.assertNotIn(FAKE_ID, queue.ExclusiveResourceProcessor._primaries)

    def test_data_fetched_since(self):
        primary = queue.ExclusiveResourceProcessor(FAKE_ID)
        self.assertEqual(datetime.datetime.min,
                         primary._get_resource_data_timestamp())

        ts1 = timeutils.utcnow() - datetime.timedelta(seconds=10)
        ts2 = timeutils.utcnow()

        primary.fetched_and_processed(ts2)
        self.assertEqual(ts2, primary._get_resource_data_timestamp())
        primary.fetched_and_processed(ts1)
        self.assertEqual(ts2, primary._get_resource_data_timestamp())

        primary.__exit__(None, None, None)

    def test_updates(self):
        primary = queue.ExclusiveResourceProcessor(FAKE_ID)
        not_primary = queue.ExclusiveResourceProcessor(FAKE_ID)

        primary.queue_update(queue.ResourceUpdate(FAKE_ID, 0))
        not_primary.queue_update(queue.ResourceUpdate(FAKE_ID, 0))

        for update in not_primary.updates():
            raise Exception("Only the primary should process a resource")

        self.assertEqual(2, len(list(primary.updates())))

    def test_hit_retry_limit(self):
        tries = 1
        rpqueue = queue.ResourceProcessingQueue()
        update = queue.ResourceUpdate(FAKE_ID, PRIORITY_RPC, tries=tries)
        rpqueue.add(update)
        self.assertFalse(update.hit_retry_limit())
        rpqueue.add(update)
        self.assertTrue(update.hit_retry_limit())

    def test_qsize(self):
        rpqueue = queue.ResourceProcessingQueue()
        for idx in range(5):
            rpqueue.add(queue.ResourceUpdate(FAKE_ID, PRIORITY_RPC))
            self.assertEqual(idx + 1, rpqueue.qsize)
        for idx in reversed(range(5)):
            rpqueue._queue.get()
            self.assertEqual(idx, rpqueue.qsize)
