# Copyright (c) 2015 Red Hat, Inc.
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

import logging
import os
import threading

from debtcollector import moves
from oslo_config import cfg
from ovs.db import idl
from ovs.stream import Stream
from ovsdbapp.backend.ovs_idl import connection as _connection
from ovsdbapp.backend.ovs_idl import event as idl_event
from ovsdbapp.backend.ovs_idl import idlutils
from ovsdbapp import event as ovsdb_event
import tenacity

from neutron.agent.ovsdb.native import exceptions as ovsdb_exc
from neutron.agent.ovsdb.native import helpers
from neutron.conf.agent import ovsdb_api

TransactionQueue = moves.moved_class(_connection.TransactionQueue,
                                     'TransactionQueue', __name__)
Connection = moves.moved_class(_connection.Connection, 'Connection', __name__)
LOG = logging.getLogger(__name__)


ovsdb_api.register_ovsdb_api_opts()


def configure_ssl_conn():
    """Configures required settings for an SSL based OVSDB client connection

    :return: None
    """

    req_ssl_opts = {'ssl_key_file': cfg.CONF.OVS.ssl_key_file,
                    'ssl_cert_file': cfg.CONF.OVS.ssl_cert_file,
                    'ssl_ca_cert_file': cfg.CONF.OVS.ssl_ca_cert_file}
    for ssl_opt, ssl_file in req_ssl_opts.items():
        if not ssl_file:
            raise ovsdb_exc.OvsdbSslRequiredOptError(ssl_opt=ssl_opt)
        elif not os.path.exists(ssl_file):
            raise ovsdb_exc.OvsdbSslConfigNotFound(ssl_file=ssl_file)
    # TODO(ihrachys): move to ovsdbapp
    Stream.ssl_set_private_key_file(req_ssl_opts['ssl_key_file'])
    Stream.ssl_set_certificate_file(req_ssl_opts['ssl_cert_file'])
    Stream.ssl_set_ca_cert_file(req_ssl_opts['ssl_ca_cert_file'])


class BridgeCreateEvent(idl_event.RowEvent):

    def __init__(self, agent):
        self.agent = agent
        table = 'Bridge'
        super(BridgeCreateEvent, self).__init__((self.ROW_CREATE, ),
                                                table, None)
        self.event_name = 'BridgeCreateEvent'

    def run(self, event, row, old):
        LOG.debug('%s, bridge name: %s', self.event_name, row.name)
        self.agent.add_bridge(str(row.name))


class OvsIdl(idl.Idl):

    SCHEMA = 'Open_vSwitch'

    def __init__(self):
        self._ovsdb_connection = cfg.CONF.OVS.ovsdb_connection
        if self._ovsdb_connection.startswith('ssl:'):
            configure_ssl_conn()
        helper = self._get_ovsdb_helper(self._ovsdb_connection)
        helper.register_all()
        super(OvsIdl, self).__init__(self._ovsdb_connection, helper)
        self.notify_handler = ovsdb_event.RowEventHandler()

    @tenacity.retry(wait=tenacity.wait_exponential(multiplier=0.01),
                    stop=tenacity.stop_after_delay(1),
                    reraise=True)
    def _do_get_schema_helper(self, connection):
        return idlutils.get_schema_helper(connection, self.SCHEMA)

    def _get_ovsdb_helper(self, connection):
        try:
            return idlutils.get_schema_helper(connection, self.SCHEMA)
        except Exception:
            helpers.enable_connection_uri(connection)
            return self._do_get_schema_helper(connection)

    def notify(self, event, row, updates=None):
        self.notify_handler.notify(event, row, updates)


class OvsIdlMonitor(OvsIdl):

    def __init__(self):
        super(OvsIdlMonitor, self).__init__()
        self._lock = threading.Lock()
        self._bridges_to_monitor = []
        self._bridges_added_list = []

    def start_bridge_monitor(self, bridge_names):
        if not bridge_names:
            return
        self._bridges_to_monitor = bridge_names
        event = BridgeCreateEvent(self)
        self.notify_handler.watch_event(event)

    def add_bridge(self, bridge_name):
        with self._lock:
            if bridge_name in self._bridges_to_monitor:
                self._bridges_added_list.append(bridge_name)

    @property
    def bridges_added(self):
        with self._lock:
            bridges = self._bridges_added_list
            self._bridges_added_list = []
        return bridges
