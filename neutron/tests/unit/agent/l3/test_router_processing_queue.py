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

from neutron.agent.l3 import router_processing_queue as l3_queue
from neutron.openstack.common import uuidutils
from neutron.tests import base

_uuid = uuidutils.generate_uuid
FAKE_ID = _uuid()
FAKE_ID_2 = _uuid()


class TestExclusiveRouterProcessor(base.BaseTestCase):
    def setUp(self):
        super(TestExclusiveRouterProcessor, self).setUp()

    def test_i_am_master(self):
        master = l3_queue.ExclusiveRouterProcessor(FAKE_ID)
        not_master = l3_queue.ExclusiveRouterProcessor(FAKE_ID)
        master_2 = l3_queue.ExclusiveRouterProcessor(FAKE_ID_2)
        not_master_2 = l3_queue.ExclusiveRouterProcessor(FAKE_ID_2)

        self.assertTrue(master._i_am_master())
        self.assertFalse(not_master._i_am_master())
        self.assertTrue(master_2._i_am_master())
        self.assertFalse(not_master_2._i_am_master())

        master.__exit__(None, None, None)
        master_2.__exit__(None, None, None)

    def test_master(self):
        master = l3_queue.ExclusiveRouterProcessor(FAKE_ID)
        not_master = l3_queue.ExclusiveRouterProcessor(FAKE_ID)
        master_2 = l3_queue.ExclusiveRouterProcessor(FAKE_ID_2)
        not_master_2 = l3_queue.ExclusiveRouterProcessor(FAKE_ID_2)

        self.assertEqual(master._master, master)
        self.assertEqual(not_master._master, master)
        self.assertEqual(master_2._master, master_2)
        self.assertEqual(not_master_2._master, master_2)

        master.__exit__(None, None, None)
        master_2.__exit__(None, None, None)

    def test__enter__(self):
        self.assertFalse(FAKE_ID in l3_queue.ExclusiveRouterProcessor._masters)
        master = l3_queue.ExclusiveRouterProcessor(FAKE_ID)
        master.__enter__()
        self.assertTrue(FAKE_ID in l3_queue.ExclusiveRouterProcessor._masters)
        master.__exit__(None, None, None)

    def test__exit__(self):
        master = l3_queue.ExclusiveRouterProcessor(FAKE_ID)
        not_master = l3_queue.ExclusiveRouterProcessor(FAKE_ID)
        master.__enter__()
        self.assertTrue(FAKE_ID in l3_queue.ExclusiveRouterProcessor._masters)
        not_master.__enter__()
        not_master.__exit__(None, None, None)
        self.assertTrue(FAKE_ID in l3_queue.ExclusiveRouterProcessor._masters)
        master.__exit__(None, None, None)
        self.assertFalse(FAKE_ID in l3_queue.ExclusiveRouterProcessor._masters)

    def test_data_fetched_since(self):
        master = l3_queue.ExclusiveRouterProcessor(FAKE_ID)
        self.assertEqual(master._get_router_data_timestamp(),
                         datetime.datetime.min)

        ts1 = datetime.datetime.utcnow() - datetime.timedelta(seconds=10)
        ts2 = datetime.datetime.utcnow()

        master.fetched_and_processed(ts2)
        self.assertEqual(master._get_router_data_timestamp(), ts2)
        master.fetched_and_processed(ts1)
        self.assertEqual(master._get_router_data_timestamp(), ts2)

        master.__exit__(None, None, None)

    def test_updates(self):
        master = l3_queue.ExclusiveRouterProcessor(FAKE_ID)
        not_master = l3_queue.ExclusiveRouterProcessor(FAKE_ID)

        master.queue_update(l3_queue.RouterUpdate(FAKE_ID, 0))
        not_master.queue_update(l3_queue.RouterUpdate(FAKE_ID, 0))

        for update in not_master.updates():
            raise Exception("Only the master should process a router")

        self.assertEqual(2, len([i for i in master.updates()]))
