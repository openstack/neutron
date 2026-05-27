# Copyright 2025 Red Hat, Inc.
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

from neutron.common import utils as common_utils
from neutron.services.bgp import reconciler
from neutron import worker


class BGPWorker(worker.NeutronBaseWorker):
    def __init__(self):
        self._reconciler = reconciler.BGPTopologyReconciler()
        super().__init__(worker_process_count=0, desc="bgp worker")

    @common_utils.log_worker_lifecycle(lambda self: self.desc)
    def start(self):
        super().start(desc=self.desc)
        self._reconciler.start()

    @common_utils.log_worker_lifecycle(lambda self: self.desc)
    def wait(self):
        self._reconciler.full_sync()

    @common_utils.log_worker_lifecycle(lambda self: self.desc)
    def stop(self):
        self._reconciler.stop()

    @common_utils.log_worker_lifecycle(lambda self: self.desc,
                                       finished_only=True)
    def reset(self):
        pass
