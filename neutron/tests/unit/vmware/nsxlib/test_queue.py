# Copyright (c) 2014 VMware, Inc.
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
#

import mock

from neutron.common import exceptions
from neutron.plugins.vmware.api_client import exception as api_exc
from neutron.plugins.vmware import nsxlib
from neutron.plugins.vmware.nsxlib import queue as queuelib
from neutron.tests.unit.vmware.nsxlib import base


class TestLogicalQueueLib(base.NsxlibTestCase):

    def setUp(self):
        super(TestLogicalQueueLib, self).setUp()
        self.fake_queue = {
            'name': 'fake_queue',
            'min': 0, 'max': 256,
            'dscp': 0, 'qos_marking': False
        }

    def test_create_and_get_lqueue(self):
        queue_id = queuelib.create_lqueue(
            self.fake_cluster, self.fake_queue)
        queue_res = nsxlib.do_request(
            'GET',
            nsxlib._build_uri_path('lqueue', resource_id=queue_id),
            cluster=self.fake_cluster)
        self.assertEqual(queue_id, queue_res['uuid'])
        self.assertEqual('fake_queue', queue_res['display_name'])

    def test_create_lqueue_nsx_error_raises(self):
        def raise_nsx_exc(*args, **kwargs):
            raise api_exc.NsxApiException()

        with mock.patch.object(nsxlib, 'do_request', new=raise_nsx_exc):
            self.assertRaises(
                exceptions.NeutronException, queuelib.create_lqueue,
                self.fake_cluster, self.fake_queue)

    def test_delete_lqueue(self):
        queue_id = queuelib.create_lqueue(
            self.fake_cluster, self.fake_queue)
        queuelib.delete_lqueue(self.fake_cluster, queue_id)
        self.assertRaises(exceptions.NotFound,
                          nsxlib.do_request,
                          'GET',
                          nsxlib._build_uri_path(
                              'lqueue', resource_id=queue_id),
                          cluster=self.fake_cluster)

    def test_delete_non_existing_lqueue_raises(self):
        self.assertRaises(exceptions.NeutronException,
                          queuelib.delete_lqueue,
                          self.fake_cluster, 'whatever')
