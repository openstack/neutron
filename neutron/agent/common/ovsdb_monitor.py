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

import collections

from oslo_log import log as logging
from oslo_serialization import jsonutils

from neutron.agent.common import async_process
from neutron.agent.ovsdb import api as ovsdb
from neutron.agent.ovsdb.native import helpers
from neutron.common import utils


LOG = logging.getLogger(__name__)

OVSDB_ACTION_INITIAL = 'initial'
OVSDB_ACTION_INSERT = 'insert'
OVSDB_ACTION_DELETE = 'delete'
OVSDB_ACTION_NEW = 'new'


class OvsdbMonitor(async_process.AsyncProcess):
    """Manages an invocation of 'ovsdb-client monitor'."""

    def __init__(self, table_name, columns=None, format=None,
                 respawn_interval=None, ovsdb_connection=None):
        self.table_name = table_name
        if ovsdb_connection:
            # if ovsdb connection is configured (e.g. tcp:ip:port), use it,
            # and there is no need to run as root
            helpers.enable_connection_uri(ovsdb_connection)
            cmd = ['ovsdb-client', 'monitor', ovsdb_connection, table_name]
            run_as_root = False
        else:
            cmd = ['ovsdb-client', 'monitor', table_name]
            run_as_root = True
        if columns:
            cmd.append(','.join(columns))
        if format:
            cmd.append('--format=%s' % format)
        super(OvsdbMonitor, self).__init__(cmd, run_as_root=run_as_root,
                                           respawn_interval=respawn_interval,
                                           log_output=True,
                                           die_on_error=False)
        self.new_events = {'added': [], 'removed': [], 'modified': []}

    def get_events(self):
        self.process_events()
        events = self.new_events
        self.new_events = {'added': [], 'removed': [], 'modified': []}
        return events

    def start(self, block=False, timeout=60):
        super(OvsdbMonitor, self).start()
        if block:
            utils.wait_until_true(self.is_active, timeout=timeout)


class SimpleInterfaceMonitor(OvsdbMonitor):
    """Monitors the Interface table of the local host's ovsdb for changes.

    The has_updates() method indicates whether changes to the ovsdb
    Interface table have been detected since the monitor started or
    since the previous access.
    """

    def __init__(self, respawn_interval=None, ovsdb_connection=None,
                 bridge_names=None, ovs=None):
        self._bridge_names = bridge_names or []
        self._ovs = ovs
        super(SimpleInterfaceMonitor, self).__init__(
            'Interface',
            columns=['name', 'ofport', 'external_ids'],
            format='json',
            respawn_interval=respawn_interval,
            ovsdb_connection=ovsdb_connection
        )
        if self._bridge_names and self._ovs:
            LOG.warning(
                'Interface monitor is filtering events only for interfaces of '
                'ports belonging these bridges: %s. This filtering has a '
                'negative impact on the performance and is not needed in '
                'production environment!', self._bridge_names)

    @property
    def has_updates(self):
        """Indicate whether the ovsdb Interface table has been updated.

        If the monitor process is not active an error will be logged since
        it won't be able to communicate any update. This situation should be
        temporary if respawn_interval is set.
        """
        if not self.is_active():
            LOG.error("%s monitor is not active", self.table_name)
        else:
            self.process_events()
        return bool(self.new_events['added'] or
                    self.new_events['removed'] or
                    self.new_events['modified'])

    def process_events(self):
        devices_added = []
        devices_removed = []
        devices_modified = []
        dev_to_ofport = {}
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
                elif action == OVSDB_ACTION_NEW:
                    # We'll receive this event for "initial", "insert"
                    # and "modify" actions. If ever needed, the old state
                    # can also be included in the processed event as per
                    # https://tools.ietf.org/html/rfc7047#section-4.1.6
                    if device not in devices_added:
                        devices_modified.append(device)
                    dev_to_ofport[name] = ofport

        self.new_events['added'].extend(devices_added)
        self.new_events['removed'].extend(devices_removed)
        self.new_events['modified'].extend(devices_modified)
        # update any events with ofports received from 'new' action
        for event in self.new_events['added']:
            event['ofport'] = dev_to_ofport.get(event['name'], event['ofport'])

        self.new_events = self._filter_events(self.new_events)

    def _filter_events(self, events):
        if not (self._bridge_names and self._ovs):
            return events

        port_to_bridge = {}
        events_filtered = collections.defaultdict(list)
        for device in events['added']:
            bridge_name = self._ovs.get_bridge_for_iface(device['name'])
            if bridge_name in self._bridge_names:
                port_to_bridge[device['name']] = bridge_name
                events_filtered['added'].append(device)

        for (etype, devs) in ((etype, devs) for (etype, devs) in events.items()
                              if etype in ('removed', 'modified')):
            for device in devs:
                bridge_name = port_to_bridge.get(device['name'])
                if etype == 'removed':
                    port_to_bridge.pop(device['name'], None)
                if bridge_name in self._bridge_names:
                    events_filtered[etype].append(device)

        return events_filtered
