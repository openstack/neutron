# Copyright (c) 2023 Red Hat, Inc.
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

from oslo_log import log as logging
from ovsdbapp.backend.ovs_idl import event as row_event

from neutron.agent.linux import devlink
from neutron.agent.ovn.agent import ovsdb as agent_ovsdb
from neutron.agent.ovn.extensions import extension_manager
from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils as ovn_utils
from neutron.plugins.ml2.drivers.mech_sriov.agent import eswitch_manager
# NOTE(ralonsoh): move ``pci_lib`` to ``neutron.agent.linux``.
from neutron.plugins.ml2.drivers.mech_sriov.agent import pci_lib


LOG = logging.getLogger(__name__)
# NOTE(ralonsoh): move these constants from ``eswitch_manager`` to ``pci_lib``.
MAX_TX_RATE = eswitch_manager.IP_LINK_CAPABILITY_RATE
MIN_TX_RATE = eswitch_manager.IP_LINK_CAPABILITY_MIN_TX_RATE
TX_RATES = eswitch_manager.IP_LINK_CAPABILITY_RATES
NB_IDL_TABLES = ['QoS',
                 'Logical_Switch_Port',
                 'Logical_Switch',
                 ]
SB_IDL_TABLES = ['Chassis',
                 'Chassis_Private',
                 'Encap',
                 'Port_Binding',
                 'Datapath_Binding',
                 ]


class OVSInterfaceEvent(row_event.RowEvent):
    LOG_MSG = 'Port ID %s, port name %s (event: %s)'

    def __init__(self, ovn_agent):
        self.ovn_agent = ovn_agent
        events = (self.ROW_CREATE, self.ROW_DELETE)
        table = 'Interface'
        super().__init__(events, table, None)

    def match_fn(self, event, row, old):
        if not row.external_ids.get('iface-id'):
            return False
        return True

    def run(self, event, row, old):
        if event == self.ROW_CREATE:
            self.ovn_agent.qos_hwol_ext.add_port(
                row.external_ids['iface-id'], row.name)
        elif event == self.ROW_DELETE:
            self.ovn_agent.qos_hwol_ext.remove_egress(
                row.external_ids['iface-id'])
        LOG.debug(self.LOG_MSG, row.external_ids['iface-id'], row.name, event)


class QoSBandwidthLimitEvent(row_event.RowEvent):
    LOG_MSG = 'QoS register %s, port ID %s, max_kbps: %s (event: %s)'

    def __init__(self, ovn_agent):
        self.ovn_agent = ovn_agent
        table = 'QoS'
        events = (self.ROW_CREATE, self.ROW_UPDATE, self.ROW_DELETE)
        super().__init__(events, table, None)

    def match_fn(self, event, row, old):
        if not self.ovn_agent.sb_post_fork_event.is_set():
            return False

        # Check if the port has a Port ID and if this ID is bound to this host.
        port_id = row.external_ids.get(ovn_const.OVN_PORT_EXT_ID_KEY)
        if not port_id or not self.ovn_agent.qos_hwol_ext.get_port(port_id):
            return False

        if event in (self.ROW_CREATE, self.ROW_DELETE):
            # Check direction, only egress rules ('from-lport') accepted.
            if row.direction != 'from-lport':
                return False
        elif event == self.ROW_UPDATE:
            try:
                if row.bandwidth['rate'] == old.bandwidth['rate']:
                    return False
            except (KeyError, AttributeError):
                # No "rate" update.
                return False

        return True

    def run(self, event, row, old):
        port_id = row.external_ids[ovn_const.OVN_PORT_EXT_ID_KEY]
        max_kbps, min_kbps = agent_ovsdb.get_port_qos(self.ovn_agent.nb_idl,
                                                      port_id)
        LOG.debug(self.LOG_MSG, str(row.uuid), port_id, max_kbps, event)
        self.ovn_agent.qos_hwol_ext.update_egress(port_id, max_kbps, min_kbps)


class QoSMinimumBandwidthEvent(row_event.RowEvent):
    LOG_MSG = 'Port ID %s, min_kbps: %s (event: %s)'

    def __init__(self, ovn_agent):
        self.ovn_agent = ovn_agent
        table = 'Logical_Switch_Port'
        events = (self.ROW_UPDATE, )
        super().__init__(events, table, None)

    def match_fn(self, event, row, old):
        if not self.ovn_agent.sb_post_fork_event.is_set():
            return False

        # The "qos_min_rate" set on the LSP has always egress direction.
        # Check if "options:qos_min_rate" has changed.
        try:
            ovn_min_rate = ovn_const.LSP_OPTIONS_QOS_MIN_RATE
            if row.options.get(ovn_min_rate) == old.options.get(ovn_min_rate):
                return False
        except (KeyError, AttributeError):
            return False

        if not self.ovn_agent.qos_hwol_ext.get_port(row.name):
            return False

        return True

    def run(self, event, row, old):
        max_kbps, min_kbps = agent_ovsdb.get_port_qos(self.ovn_agent.nb_idl,
                                                      row.name)
        LOG.debug(self.LOG_MSG, row.name, min_kbps, event)
        self.ovn_agent.qos_hwol_ext.update_egress(row.name, max_kbps, min_kbps)


class _PortBindingChassisEvent(row_event.RowEvent):

    def __init__(self, ovn_agent, events):
        self.ovn_agent = ovn_agent
        self.ovs_idl = self.ovn_agent.ovs_idl
        table = 'Port_Binding'
        super().__init__(events, table, None)
        self.event_name = self.__class__.__name__

    def run(self, event, row, old):
        pass


class PortBindingChassisCreatedEvent(_PortBindingChassisEvent):
    LOG_MSG = 'Port ID %s, datapath %s, OVS port name: %s (event: %s)'

    def __init__(self, ovn_agent):
        events = (self.ROW_UPDATE,)
        super().__init__(ovn_agent, events)

    def match_fn(self, event, row, old):
        try:
            return (row.chassis[0].name == self.ovn_agent.chassis and
                    not old.chassis)
        except (IndexError, AttributeError):
            return False

    def run(self, event, row, old):
        ovs_port_name = agent_ovsdb.get_ovs_port_name(self.ovs_idl,
                                                      row.logical_port)
        net_name = ovn_utils.get_network_name_from_datapath(row.datapath)
        LOG.debug(self.LOG_MSG, row.logical_port, net_name, ovs_port_name,
                  event)
        max_kbps, min_kbps = agent_ovsdb.get_port_qos(self.ovn_agent.nb_idl,
                                                      row.logical_port)
        self.ovn_agent.qos_hwol_ext.update_egress(row.logical_port, max_kbps,
                                                  min_kbps)


class QoSHardwareOffloadExtension(extension_manager.OVNAgentExtension):

    def __init__(self):
        super().__init__()
        # _ovs_ports = {Neutron port ID: OVS port name}
        self._ovs_ports = {}

    @property
    def ovs_idl_events(self):
        return [OVSInterfaceEvent,
                ]

    @property
    def nb_idl_tables(self):
        return NB_IDL_TABLES

    @property
    def nb_idl_events(self):
        return [QoSBandwidthLimitEvent,
                QoSMinimumBandwidthEvent,
                ]

    @property
    def sb_idl_tables(self):
        return SB_IDL_TABLES

    @property
    def sb_idl_events(self):
        return [PortBindingChassisCreatedEvent,
                ]

    def add_port(self, port_id, port_name):
        self._ovs_ports[port_id] = port_name

    def del_port(self, port_id):
        return self._ovs_ports.pop(port_id, None)

    def get_port(self, port_id):
        return self._ovs_ports.get(port_id)

    @staticmethod
    def _set_device_rate(pf_name, vf_index, rates):
        """Set device rate: max_tx_rate, min_tx_rate

        @param pf_name: Physical Function name
        @param vf_index: Virtual Function index
        @param rates: dictionary with rate type (str) and the value (int)
                      in Kbps. Example:
                        {'max_tx_rate': 20000, 'min_tx_rate': 10000}
                        {'max_tx_rate': 30000}
                        {'min_tx_rate': 5000}
        """
        LOG.debug('Setting rates on device %(pf_name)s, VF number '
                  '%(vf_index)s: %(rates)s',
                  {'pf_name': pf_name, 'vf_index': vf_index, 'rates': rates})
        if not pf_name:
            LOG.warning('Empty PF name, rates cannot be set')
            return

        pci_dev_wrapper = pci_lib.PciDeviceIPWrapper(pf_name)
        return pci_dev_wrapper.set_vf_rate(vf_index, rates)

    @staticmethod
    def _kbps_2_mbps(rate_kbps):
        if rate_kbps == 0:  # Delete the BW setting.
            return 0
        elif 0 < rate_kbps < 1000:  # Any value under 1000kbps --> 1Mbps
            return 1
        else:
            return int(rate_kbps / 1000.0)

    def _get_port_representor(self, port_id):
        port_name = self.get_port(port_id)
        if not port_name:
            return

        pr = devlink.get_port(port_name)
        if not pr:
            return

        return pr

    def update_egress(self, port_id, max_kbps, min_kbps):
        pr = self._get_port_representor(port_id)
        if not pr:
            return

        _qos = {MAX_TX_RATE: self._kbps_2_mbps(int(max_kbps)),
                MIN_TX_RATE: self._kbps_2_mbps(int(min_kbps))}
        self._set_device_rate(pr['pf_name'], pr['vf_num'], _qos)

    def reset_egress(self, port_id):
        pr = self._get_port_representor(port_id)
        if not pr:
            return

        self._set_device_rate(pr['pf_name'], pr['vf_num'],
                              {MAX_TX_RATE: 0, MIN_TX_RATE: 0})

    def remove_egress(self, port_id):
        pr = self._get_port_representor(port_id)
        self.del_port(port_id)
        if not pr:
            return

        self._set_device_rate(pr['pf_name'], pr['vf_num'],
                              {MAX_TX_RATE: 0, MIN_TX_RATE: 0})
