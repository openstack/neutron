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

import mock

from neutron.common import utils
from neutron.tests import base
from neutron import worker as neutron_worker


class PeriodicWorkerTestCase(base.BaseTestCase):

    def test_periodic_worker_lifecycle(self):
        check_function = mock.Mock()
        worker = neutron_worker.PeriodicWorker(
            check_function, interval=1, initial_delay=1)
        self.addCleanup(worker.stop)
        worker.wait()
        self.assertFalse(check_function.called)
        worker.start()
        utils.wait_until_true(
            lambda: check_function.called,
            timeout=5,
            exception=RuntimeError("check_function not called"))
        worker.stop()
        check_function.reset_mock()
        worker.wait()
        self.assertFalse(check_function.called)
        worker.reset()
        utils.wait_until_true(
            lambda: check_function.called,
            timeout=5,
            exception=RuntimeError("check_function not called"))
