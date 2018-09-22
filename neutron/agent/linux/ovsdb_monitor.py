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
from oslo_config import cfg
from oslo_log import log as logging
from oslo_serialization import jsonutils

from neutron.agent.linux import async_process
from neutron.agent.ovsdb import api as ovsdb
from neutron.agent.ovsdb.native import helpers
from neutron.common import utils
from neutron.plugins.ml2.drivers.openvswitch.agent.common import constants


LOG = logging.getLogger(__name__)

OVSDB_ACTION_INITIAL = 'initial'
OVSDB_ACTION_INSERT = 'insert'
OVSDB_ACTION_DELETE = 'delete'
OVSDB_ACTION_NEW = 'new'


@contextlib.contextmanager
def get_bridges_monitor(
        bridges, ovsdb_monitor_respawn_interval=(
            constants.DEFAULT_OVSDBMON_RESPAWN)):

    mon = SimpleBridgesMonitor(
        bridges,
        respawn_interval=ovsdb_monitor_respawn_interval,
        ovsdb_connection=cfg.CONF.OVS.ovsdb_connection)
    mon.start()
    try:
        yield mon
    finally:
        mon.stop()


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
        self.new_events = {'added': [], 'removed': []}

    def get_events(self):
        self.process_events()
        events = self.new_events
        self.new_events = {'added': [], 'removed': []}
        return events

    def start(self, block=False, timeout=5):
        super(OvsdbMonitor, self).start()
        if block:
            utils.wait_until_true(self.is_active)


class SimpleInterfaceMonitor(OvsdbMonitor):
    """Monitors the Interface table of the local host's ovsdb for changes.

    The has_updates() method indicates whether changes to the ovsdb
    Interface table have been detected since the monitor started or
    since the previous access.
    """

    def __init__(self, respawn_interval=None, ovsdb_connection=None):
        super(SimpleInterfaceMonitor, self).__init__(
            'Interface',
            columns=['name', 'ofport', 'external_ids'],
            format='json',
            respawn_interval=respawn_interval,
            ovsdb_connection=ovsdb_connection
        )

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
        return bool(self.new_events['added'] or self.new_events['removed'])

    def process_events(self):
        devices_added = []
        devices_removed = []
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
                    dev_to_ofport[name] = ofport

        self.new_events['added'].extend(devices_added)
        self.new_events['removed'].extend(devices_removed)
        # update any events with ofports received from 'new' action
        for event in self.new_events['added']:
            event['ofport'] = dev_to_ofport.get(event['name'], event['ofport'])


class SimpleBridgesMonitor(OvsdbMonitor):
    """Monitors the Bridge table of the local host's ovsdb for changes.

    The bridges_added() method returns all newly created bridges in ovsdb
    since the monitor started or since the previous access.
    """

    def __init__(self, bridges, respawn_interval=None, ovsdb_connection=None):
        super(SimpleBridgesMonitor, self).__init__(
            'Bridge',
            columns=['name'],
            format='json',
            respawn_interval=respawn_interval,
            ovsdb_connection=ovsdb_connection
        )
        self.bridges = bridges

    @property
    def bridges_added(self):
        eventlet.sleep()
        return self.get_events()['added']

    def process_events(self):
        bridges_added = []
        for row in self.iter_stdout():
            json = jsonutils.loads(row).get('data')
            for ovs_id, action, name in json:
                if name in self.bridges and action == OVSDB_ACTION_INSERT:
                    bridges_added.append(name)

        self.new_events['added'].extend(bridges_added)
