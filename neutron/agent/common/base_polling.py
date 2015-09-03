# Copyright 2015 Cloudbase Solutions.
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


class BasePollingManager(object):

    def __init__(self):
        self._force_polling = False
        self._polling_completed = True

    def force_polling(self):
        self._force_polling = True

    def polling_completed(self):
        self._polling_completed = True

    def _is_polling_required(self):
        raise NotImplementedError()

    @property
    def is_polling_required(self):
        # Always consume the updates to minimize polling.
        polling_required = self._is_polling_required()

        # Polling is required regardless of whether updates have been
        # detected.
        if self._force_polling:
            self._force_polling = False
            polling_required = True

        # Polling is required if not yet done for previously detected
        # updates.
        if not self._polling_completed:
            polling_required = True

        if polling_required:
            # Track whether polling has been completed to ensure that
            # polling can be required until the caller indicates via a
            # call to polling_completed() that polling has been
            # successfully performed.
            self._polling_completed = False

        return polling_required


class AlwaysPoll(BasePollingManager):

    @property
    def is_polling_required(self):
        return True
