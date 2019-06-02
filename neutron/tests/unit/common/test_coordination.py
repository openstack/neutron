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
from oslo_concurrency import lockutils

from neutron.common import coordination
from neutron.tests import base


@mock.patch.object(lockutils, 'lock')
class CoordinationTestCase(base.BaseTestCase):
    def test_synchronized(self, get_lock):
        @coordination.synchronized('lock-{f_name}-{foo.val}-{bar[val]}')
        def func(foo, bar):
            pass

        foo = mock.Mock()
        foo.val = 7
        bar = mock.MagicMock()
        bar.__getitem__.return_value = 8
        func(foo, bar)
        get_lock.assert_called_with('lock-func-7-8')
