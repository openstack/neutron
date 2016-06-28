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

from oslo_service import service

from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources


class WorkerSupportServiceMixin(object):

    @property
    def _workers(self):
        try:
            return self.__workers
        except AttributeError:
            self.__workers = []
        return self.__workers

    def get_workers(self):
        """Returns a collection NeutronWorker instances needed by this service
        """
        return list(self._workers)

    def add_worker(self, worker):
        """Adds NeutronWorker needed for this service

        If a object needs to define workers thread/processes outside of API/RPC
        workers then it will call this method to register worker. Should be
        called on initialization stage before running services
        """
        self._workers.append(worker)

    def add_workers(self, workers):
        """Adds NeutronWorker list needed for this service

        The same as add_worker but adds a list of workers
        """
        self._workers.extend(workers)


class NeutronWorker(service.ServiceBase):
    """Partial implementation of the ServiceBase ABC

    Subclasses will still need to add the other abstract methods defined in
    service.ServiceBase. See oslo_service for more details.

    If a plugin needs to handle synchronization with the Neutron database and
    do this only once instead of in every API worker, for instance, it would
    define a NeutronWorker class and the plugin would have get_workers return
    an array of NeutronWorker instances. For example:
        class MyPlugin(...):
            def get_workers(self):
                return [MyPluginWorker()]

        class MyPluginWorker(NeutronWorker):
            def start(self):
                super(MyPluginWorker, self).start()
                do_sync()
    """

    # default class value for case when super().__init__ is not called
    _worker_process_count = 1

    def __init__(self, worker_process_count=_worker_process_count):
        """
        Initialize worker

        :param worker_process_count: Defines how many processes to spawn for
            worker:
                0 - spawn 1 new worker thread,
                1..N - spawn N new worker processes
        """
        self._worker_process_count = worker_process_count

    @property
    def worker_process_count(self):
        return self._worker_process_count

    def start(self):
        if self.worker_process_count > 0:
            registry.notify(resources.PROCESS, events.AFTER_INIT, self.start)
