# Copyright 2013 Red Hat, Inc.
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

import contextlib

import eventlet

from neutron.agent.linux import ovsdb_monitor
from neutron.plugins.openvswitch.common import constants


@contextlib.contextmanager
def get_polling_manager(minimize_polling=False,
                        ovsdb_monitor_respawn_interval=(
                            constants.DEFAULT_OVSDBMON_RESPAWN)):
    if minimize_polling:
        pm = InterfacePollingMinimizer(
            ovsdb_monitor_respawn_interval=ovsdb_monitor_respawn_interval)
        pm.start()
    else:
        pm = AlwaysPoll()
    try:
        yield pm
    finally:
        if minimize_polling:
            pm.stop()


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


class InterfacePollingMinimizer(BasePollingManager):
    """Monitors ovsdb to determine when polling is required."""

    def __init__(
            self,
            ovsdb_monitor_respawn_interval=constants.DEFAULT_OVSDBMON_RESPAWN):

        super(InterfacePollingMinimizer, self).__init__()
        self._monitor = ovsdb_monitor.SimpleInterfaceMonitor(
            respawn_interval=ovsdb_monitor_respawn_interval)

    def start(self):
        self._monitor.start()

    def stop(self):
        self._monitor.stop()

    def _is_polling_required(self):
        # Maximize the chances of update detection having a chance to
        # collect output.
        eventlet.sleep()
        return self._monitor.has_updates
