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

from neutron.agent.common import base_polling
from neutron.agent.linux import ovsdb_monitor
from neutron.plugins.ml2.drivers.openvswitch.agent.common import constants


@contextlib.contextmanager
def get_polling_manager(minimize_polling=False,
                        ovsdb_monitor_respawn_interval=(
                            constants.DEFAULT_OVSDBMON_RESPAWN)):
    if minimize_polling:
        pm = InterfacePollingMinimizer(
            ovsdb_monitor_respawn_interval=ovsdb_monitor_respawn_interval)
        pm.start()
    else:
        pm = base_polling.AlwaysPoll()
    try:
        yield pm
    finally:
        if minimize_polling:
            pm.stop()


class InterfacePollingMinimizer(base_polling.BasePollingManager):
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

    def get_events(self):
        return self._monitor.get_events()
