# Copyright (c) 2016 IBM Corp.
#
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

from neutron.db import segments_db
from neutron.tests import base


class TestSegmentsDb(base.BaseTestCase):

    def test_get_networks_segments_with_empty_networks(self):
        context = mock.MagicMock()
        net_segs = segments_db.get_networks_segments(context, [])
        self.assertFalse(context.session.query.called)
        self.assertEqual({}, net_segs)
