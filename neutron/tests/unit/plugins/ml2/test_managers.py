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

from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2 import managers
from neutron.tests import base


class TestManagers(base.BaseTestCase):

    def test__check_driver_to_bind(self):
        manager = managers.MechanismManager()
        bindinglevel = mock.Mock()
        bindinglevel.driver = 'fake_driver'
        bindinglevel.segment_id = 'fake_seg_id'
        binding_levels = [bindinglevel]
        segments_to_bind = [{api.SEGMENTATION_ID: 'fake_seg_id'}]
        self.assertFalse(manager._check_driver_to_bind(
            'fake_driver', segments_to_bind, binding_levels))

        bindinglevel.segment_id = 'fake_seg_id1'
        self.assertTrue(manager._check_driver_to_bind(
            'fake_driver', segments_to_bind, binding_levels))
