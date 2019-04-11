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

from oslo_utils import uuidutils

from neutron.agent.common import resource_processing_queue as queue
from neutron.tests import base

_uuid = uuidutils.generate_uuid
FAKE_ID = _uuid()
FAKE_ID_2 = _uuid()

PRIORITY_RPC = 0


class TestExclusiveResourceProcessor(base.BaseTestCase):

    def test_i_am_master(self):
        master = queue.ExclusiveResourceProcessor(FAKE_ID)
        not_master = queue.ExclusiveResourceProcessor(FAKE_ID)
        master_2 = queue.ExclusiveResourceProcessor(FAKE_ID_2)
        not_master_2 = queue.ExclusiveResourceProcessor(FAKE_ID_2)

        self.assertTrue(master._i_am_master())
        self.assertFalse(not_master._i_am_master())
        self.assertTrue(master_2._i_am_master())
        self.assertFalse(not_master_2._i_am_master())

        master.__exit__(None, None, None)
        master_2.__exit__(None, None, None)

    def test_master(self):
        master = queue.ExclusiveResourceProcessor(FAKE_ID)
        not_master = queue.ExclusiveResourceProcessor(FAKE_ID)
        master_2 = queue.ExclusiveResourceProcessor(FAKE_ID_2)
        not_master_2 = queue.ExclusiveResourceProcessor(FAKE_ID_2)

        self.assertEqual(master, master._master)
        self.assertEqual(master, not_master._master)
        self.assertEqual(master_2, master_2._master)
        self.assertEqual(master_2, not_master_2._master)

        master.__exit__(None, None, None)
        master_2.__exit__(None, None, None)

    def test__enter__(self):
        self.assertNotIn(FAKE_ID, queue.ExclusiveResourceProcessor._masters)
        master = queue.ExclusiveResourceProcessor(FAKE_ID)
        master.__enter__()
        self.assertIn(FAKE_ID, queue.ExclusiveResourceProcessor._masters)
        master.__exit__(None, None, None)

    def test__exit__(self):
        master = queue.ExclusiveResourceProcessor(FAKE_ID)
        not_master = queue.ExclusiveResourceProcessor(FAKE_ID)
        master.__enter__()
        self.assertIn(FAKE_ID, queue.ExclusiveResourceProcessor._masters)
        not_master.__enter__()
        not_master.__exit__(None, None, None)
        self.assertIn(FAKE_ID, queue.ExclusiveResourceProcessor._masters)
        master.__exit__(None, None, None)
        self.assertNotIn(FAKE_ID, queue.ExclusiveResourceProcessor._masters)

    def test_data_fetched_since(self):
        master = queue.ExclusiveResourceProcessor(FAKE_ID)
        self.assertEqual(datetime.datetime.min,
                         master._get_resource_data_timestamp())

        ts1 = datetime.datetime.utcnow() - datetime.timedelta(seconds=10)
        ts2 = datetime.datetime.utcnow()

        master.fetched_and_processed(ts2)
        self.assertEqual(ts2, master._get_resource_data_timestamp())
        master.fetched_and_processed(ts1)
        self.assertEqual(ts2, master._get_resource_data_timestamp())

        master.__exit__(None, None, None)

    def test_updates(self):
        master = queue.ExclusiveResourceProcessor(FAKE_ID)
        not_master = queue.ExclusiveResourceProcessor(FAKE_ID)

        master.queue_update(queue.ResourceUpdate(FAKE_ID, 0))
        not_master.queue_update(queue.ResourceUpdate(FAKE_ID, 0))

        for update in not_master.updates():
            raise Exception("Only the master should process a resource")

        self.assertEqual(2, len([i for i in master.updates()]))

    def test_hit_retry_limit(self):
        tries = 1
        rpqueue = queue.ResourceProcessingQueue()
        update = queue.ResourceUpdate(FAKE_ID, PRIORITY_RPC, tries=tries)
        rpqueue.add(update)
        self.assertFalse(update.hit_retry_limit())
        rpqueue.add(update)
        self.assertTrue(update.hit_retry_limit())
