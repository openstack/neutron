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

from neutron_lib import worker
from oslo_config import cfg
from oslo_service import loopingcall


class NeutronBaseWorker(worker.BaseWorker):

    def __init__(self, worker_process_count=1, set_proctitle=None):
        set_proctitle = set_proctitle or cfg.CONF.setproctitle
        super(NeutronBaseWorker, self).__init__(
            worker_process_count=worker_process_count,
            set_proctitle=set_proctitle
        )

    def start(self, name="neutron-server", desc=None):
        super(NeutronBaseWorker, self).start(name=name, desc=desc)


class PeriodicWorker(NeutronBaseWorker):
    """A worker that runs a function at a fixed interval."""

    def __init__(self, check_func, interval, initial_delay):
        super(PeriodicWorker, self).__init__(worker_process_count=0)

        self._check_func = check_func
        self._loop = None
        self._interval = interval
        self._initial_delay = initial_delay

    def start(self):
        super(PeriodicWorker, self).start(desc="periodic worker")
        if self._loop is None:
            self._loop = loopingcall.FixedIntervalLoopingCall(self._check_func)
        self._loop.start(interval=self._interval,
                         initial_delay=self._initial_delay)

    def wait(self):
        if self._loop is not None:
            self._loop.wait()

    def stop(self):
        if self._loop is not None:
            self._loop.stop()

    def reset(self):
        self.stop()
        self.wait()
        self.start()
