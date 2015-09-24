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

import eventlet
from oslo_log import log as logging
from oslo_serialization import jsonutils

from neutron.agent.linux import async_process
from neutron.agent.ovsdb import api as ovsdb
from neutron.i18n import _LE


LOG = logging.getLogger(__name__)

OVSDB_ACTION_INITIAL = 'initial'
OVSDB_ACTION_INSERT = 'insert'
OVSDB_ACTION_DELETE = 'delete'


class OvsdbMonitor(async_process.AsyncProcess):
    """Manages an invocation of 'ovsdb-client monitor'."""

    def __init__(self, table_name, columns=None, format=None,
                 respawn_interval=None):

        cmd = ['ovsdb-client', 'monitor', table_name]
        if columns:
            cmd.append(','.join(columns))
        if format:
            cmd.append('--format=%s' % format)
        super(OvsdbMonitor, self).__init__(cmd, run_as_root=True,
                                           respawn_interval=respawn_interval,
                                           log_output=True,
                                           die_on_error=True)


class SimpleInterfaceMonitor(OvsdbMonitor):
    """Monitors the Interface table of the local host's ovsdb for changes.

    The has_updates() method indicates whether changes to the ovsdb
    Interface table have been detected since the monitor started or
    since the previous access.
    """

    def __init__(self, respawn_interval=None):
        super(SimpleInterfaceMonitor, self).__init__(
            'Interface',
            columns=['name', 'ofport', 'external_ids'],
            format='json',
            respawn_interval=respawn_interval,
        )
        self.new_events = {'added': [], 'removed': []}

    @property
    def has_updates(self):
        """Indicate whether the ovsdb Interface table has been updated.

        If the monitor process is not active an error will be logged since
        it won't be able to communicate any update. This situation should be
        temporary if respawn_interval is set.
        """
        if not self.is_active():
            LOG.error(_LE("Interface monitor is not active"))
        else:
            self.process_events()
        return bool(self.new_events['added'] or self.new_events['removed'])

    def get_events(self):
        self.process_events()
        events = self.new_events
        self.new_events = {'added': [], 'removed': []}
        return events

    def process_events(self):
        devices_added = []
        devices_removed = []
        for row in self.iter_stdout():
            json = jsonutils.loads(row).get('data')
            for ovs_id, action, name, ofport, external_ids in json:
                if external_ids:
                    external_ids = ovsdb.val_to_py(external_ids)
                if ofport:
                    ofport = ovsdb.val_to_py(ofport)
                device = {'name': name,
                          'ofport': ofport,
                          'external_ids': external_ids}
                if action in (OVSDB_ACTION_INITIAL, OVSDB_ACTION_INSERT):
                    devices_added.append(device)
                elif action == OVSDB_ACTION_DELETE:
                    devices_removed.append(device)
        self.new_events['added'].extend(devices_added)
        self.new_events['removed'].extend(devices_removed)

    def start(self, block=False, timeout=5):
        super(SimpleInterfaceMonitor, self).start()
        if block:
            with eventlet.timeout.Timeout(timeout):
                while not self.is_active():
                    eventlet.sleep()
