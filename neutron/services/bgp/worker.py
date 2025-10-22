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

from neutron.services.bgp import reconciler
from neutron import worker


class BGPWorker(worker.NeutronBaseWorker):
    def __init__(self):
        super().__init__(worker_process_count=0)

    def start(self):
        super().start(desc="bgp worker")
        self._reconciler = reconciler.BGPTopologyReconciler()

    def wait(self):
        self._reconciler.full_sync()

    def stop(self):
        self._reconciler.stop()

    def reset(self):
        pass
