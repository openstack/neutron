# Copyright 2019 Red Hat, Inc.
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

from neutron_lib import worker

from neutron.common import config


class MaintenanceWorker(worker.BaseWorker):
    desc = 'maintenance worker'

    def __init__(self, **kwargs):
        super().__init__(desc=self.desc, **kwargs)

    def start(self, **kwargs):
        super().start()
        # NOTE(twilson) The super class will trigger the post_fork_initialize
        # in the driver, which starts the connection/IDL notify loop which
        # keeps the process from exiting

    def stop(self):
        """Stop service."""
        pass

    def wait(self):
        """Wait for service to complete."""
        pass

    @staticmethod
    def reset():
        config.reset_service()
