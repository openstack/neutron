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

from neutron_lib.plugins.ml2 import ovs_constants
from oslo_config import cfg
from ovsdbapp.backend.ovs_idl import command
from ovsdbapp.backend.ovs_idl import connection
from ovsdbapp.backend.ovs_idl import idlutils
from ovsdbapp.backend.ovs_idl import vlog
from ovsdbapp.schema.open_vswitch import impl_idl

from neutron.agent.ovsdb.native import connection as n_connection
from neutron.common import utils
from neutron.conf.agent import ovs_conf


ovs_conf.register_ovs_agent_opts()
_connection = None
_idl_monitor = None


def api_factory():
    global _connection
    global _idl_monitor
    if _connection is None:
        _idl_monitor = n_connection.OvsIdlMonitor()
        _connection = connection.Connection(
            idl=_idl_monitor,
            timeout=cfg.CONF.OVS.ovsdb_timeout)
    return NeutronOvsdbIdl(_connection, _idl_monitor)


class OvsCleanup(command.BaseCommand):
    def __init__(self, api, bridge, all_ports=False):
        super(OvsCleanup, self).__init__(api)
        self.bridge = bridge
        self.all_ports = all_ports

    def run_idl(self, txn):
        br = idlutils.row_by_value(self.api.idl, 'Bridge', 'name', self.bridge)
        for port in br.ports:
            if not any(self.is_deletable_port(iface)
                       for iface in port.interfaces):
                continue
            br.delvalue('ports', port)
            for iface in port.interfaces:
                iface.delete()
            port.delete()

    def is_deletable_port(self, port):
        # Deletable defined as "looks like vif port and not set to skip delete"
        if self.all_ports:
            return True
        if ovs_constants.SKIP_CLEANUP in port.external_ids:
            return False
        if not all(field in port.external_ids
                   for field in ('iface-id', 'attached-mac')):
            return False
        return True


@utils.SingletonDecorator
class NeutronOvsdbIdl(impl_idl.OvsdbIdl):
    def __init__(self, connection, idl_monitor):
        max_level = None if cfg.CONF.OVS.ovsdb_debug else vlog.INFO
        vlog.use_python_logger(max_level=max_level)
        self.idl_monitor = idl_monitor
        super().__init__(connection)

    def ovs_cleanup(self, bridges, all_ports=False):
        return OvsCleanup(self, bridges, all_ports)
