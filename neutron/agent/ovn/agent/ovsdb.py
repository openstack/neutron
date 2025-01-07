# Copyright 2023 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from neutron_lib import constants
from oslo_log import log
from ovsdbapp.backend.ovs_idl import connection
from ovsdbapp.backend.ovs_idl import idlutils
from ovsdbapp.schema.open_vswitch import impl_idl as impl_idl_ovs

from neutron.agent.ovsdb.native import connection as ovsdb_conn
from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils as ovn_utils
from neutron.common import utils as n_utils
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf as config
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import impl_idl_ovn
from neutron.plugins.ml2.drivers.ovn.mech_driver.ovsdb import ovsdb_monitor


LOG = log.getLogger(__name__)


class MonitorAgentOvnSbIdl(ovsdb_monitor.OvnIdl):

    SCHEMA = 'OVN_Southbound'

    def __init__(self, tables, events, chassis=None):
        connection_string = config.get_ovn_sb_connection()
        ovsdb_monitor._check_and_set_ssl_files(self.SCHEMA)
        helper = self._get_ovsdb_helper(connection_string)
        for table in tables:
            helper.register_table(table)
        super().__init__(None, connection_string, helper, leader_only=False)
        if chassis:
            for table in set(tables).intersection({'Chassis',
                                                   'Chassis_Private'}):
                self.set_table_condition(table, [['name', '==', chassis]])
        if events:
            self.notify_handler.watch_events(events)

    @ovn_utils.retry(max_=180)
    def _get_ovsdb_helper(self, connection_string):
        return idlutils.get_schema_helper(connection_string, self.SCHEMA)

    @ovn_utils.retry()
    def start(self):
        LOG.info('Getting OvsdbSbOvnIdl for OVN monitor with retry')
        conn = connection.Connection(
            self, timeout=config.get_ovn_ovsdb_timeout())
        return impl_idl_ovn.OvsdbSbOvnIdl(conn)

    def post_connect(self):
        pass


class MonitorAgentOvnNbIdl(ovsdb_monitor.OvnIdl):

    SCHEMA = 'OVN_Northbound'

    def __init__(self, tables, events):
        connection_string = config.get_ovn_nb_connection()
        ovsdb_monitor._check_and_set_ssl_files(self.SCHEMA)
        helper = self._get_ovsdb_helper(connection_string)
        for table in tables:
            helper.register_table(table)
        super().__init__(None, connection_string, helper, leader_only=False)
        if events:
            self.notify_handler.watch_events(events)

    @ovn_utils.retry(max_=180)
    def _get_ovsdb_helper(self, connection_string):
        return idlutils.get_schema_helper(connection_string, self.SCHEMA)

    @ovn_utils.retry()
    def start(self):
        LOG.info('Getting OvsdbNbOvnIdl for OVN monitor with retry')
        conn = connection.Connection(
            self, timeout=config.get_ovn_ovsdb_timeout())
        return impl_idl_ovn.OvsdbNbOvnIdl(conn)

    def post_connect(self):
        pass


class MonitorAgentOvsIdl(ovsdb_conn.OvsIdl):

    def __init__(self, events):
        super().__init__()
        if events:
            self.notify_handler.watch_events(events)

    @ovn_utils.retry()
    def start(self):
        LOG.info('Getting OvsdbIdl for OVN monitor with retry')
        conn = connection.Connection(self,
                                     timeout=config.get_ovn_ovsdb_timeout())
        return impl_idl_ovs.OvsdbIdl(conn)

    def post_connect(self):
        pass


def get_ovn_bridge(ovs_idl):
    """Return the external_ids:ovn-bridge value of the Open_vSwitch table.

    This is the OVS bridge used to plug the metadata ports to.
    If the key doesn't exist, this method will return 'br-int' as default.
    """
    ext_ids = ovs_idl.db_get('Open_vSwitch', '.', 'external_ids').execute()
    try:
        return ext_ids['ovn-bridge']
    except KeyError:
        LOG.warning("Can't read ovn-bridge external-id from OVSDB. Using "
                    "br-int instead.")
        return 'br-int'


def get_own_chassis_name(ovs_idl):
    """Return the external_ids:system-id value of the Open_vSwitch table.

    As long as ovn-controller is running on this node, the key is
    guaranteed to exist and will include the chassis name.
    """
    ext_ids = ovs_idl.db_get('Open_vSwitch', '.', 'external_ids').execute()
    return ext_ids['system-id']


def get_ovs_port_name(ovs_idl, port_id):
    """Return the OVS port name given the Neutron port ID"""
    int_list = ovs_idl.db_list('Interface', columns=['name', 'external_ids'],
                               if_exists=True).execute(check_error=True,
                                                       log_errors=False)
    for interface in int_list:
        if interface['external_ids'].get('iface-id') == port_id:
            return interface['name']


def get_port_qos(nb_idl, port_id):
    """Retrieve the QoS egress max-bw and min-bw values (in kbps) of a LSP

    Depending on the network type (tunnelled or not), the max-bw value can be
    defined in a QoS register (tunnelled network) or in the LSP.options
    (physical network).

    There could be max-bw rules ingress (to-lport) and egress (from-lport);
    this method is only returning the egress one. The min-bw rule is only
    implemented for egress traffic.
    """
    try:
        lsp = nb_idl.lsp_get(port_id).execute(check_error=True)
    except idlutils.RowNotFound:
        # If the LSP is not present, we can't retrieve any QoS info. The
        # default values are (0, 0).
        return 0, 0

    net_name = lsp.external_ids[ovn_const.OVN_NETWORK_NAME_EXT_ID_KEY]
    ls = nb_idl.lookup('Logical_Switch', net_name)
    for qos_rule in iter(r for r in ls.qos_rules if
                         r.external_ids[ovn_const.OVN_PORT_EXT_ID_KEY]):
        if qos_rule.direction != 'from-lport':
            continue

        max_kbps = int(qos_rule.bandwidth.get('rate', 0))
        break
    else:
        # The "qos_max_rate" is stored in bits/s
        max_kbps = n_utils.bits_to_kilobits(
            int(lsp.options.get(ovn_const.LSP_OPTIONS_QOS_MAX_RATE, 0)),
            constants.SI_BASE)
    # The "qos_min_rate" is stored in bits/s
    min_kbps = n_utils.bits_to_kilobits(
            int(lsp.options.get(ovn_const.LSP_OPTIONS_QOS_MIN_RATE, 0)),
            constants.SI_BASE)
    return max_kbps, min_kbps
