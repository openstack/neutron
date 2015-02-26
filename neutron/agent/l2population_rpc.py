# Copyright (c) 2013 OpenStack Foundation.
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

import abc

from oslo_config import cfg
from oslo_log import log as logging
import six

from neutron.common import constants as n_const
from neutron.common import log
from neutron.plugins.ml2.drivers.l2pop import rpc as l2pop_rpc

LOG = logging.getLogger(__name__)


@six.add_metaclass(abc.ABCMeta)
class L2populationRpcCallBackMixin(object):
    '''General mixin class of L2-population RPC call back.

    The following methods are called through RPC.
        add_fdb_entries(), remove_fdb_entries(), update_fdb_entries()
    The following methods are used in an agent as internal methods.
        fdb_add(), fdb_remove(), fdb_update()
    '''

    @log.log
    def add_fdb_entries(self, context, fdb_entries, host=None):
        if not host or host == cfg.CONF.host:
            self.fdb_add(context, self._unmarshall_fdb_entries(fdb_entries))

    @log.log
    def remove_fdb_entries(self, context, fdb_entries, host=None):
        if not host or host == cfg.CONF.host:
            self.fdb_remove(context, self._unmarshall_fdb_entries(fdb_entries))

    @log.log
    def update_fdb_entries(self, context, fdb_entries, host=None):
        if not host or host == cfg.CONF.host:
            self.fdb_update(context, self._unmarshall_fdb_entries(fdb_entries))

    @staticmethod
    def _unmarshall_fdb_entries(fdb_entries):
        """Prepares fdb_entries from JSON.

        All methods in this class that receive messages should call this to
        unmarshall fdb_entries from the wire.

        :param fdb_entries: Original fdb_entries data-structure.  Looks like:
            {
                <uuid>: {
                    ...,
                    'ports': {
                        <ip address>: [ [<mac>, <ip>], ...  ],
                        ...

        :returns: Deep copy with [<mac>, <ip>] converted to PortInfo
        """
        unmarshalled = dict(fdb_entries)
        for value in unmarshalled.values():
            if 'ports' in value:
                value['ports'] = dict(
                    (address, [l2pop_rpc.PortInfo(*pi) for pi in port_infos])
                    for address, port_infos in value['ports'].items()
                )
        return unmarshalled

    @abc.abstractmethod
    def fdb_add(self, context, fdb_entries):
        pass

    @abc.abstractmethod
    def fdb_remove(self, context, fdb_entries):
        pass

    @abc.abstractmethod
    def fdb_update(self, context, fdb_entries):
        pass


class L2populationRpcCallBackTunnelMixin(L2populationRpcCallBackMixin):
    '''Mixin class of L2-population call back for Tunnel.

    The following methods are all used in agents as internal methods.

    Some of the methods in this class use Local VLAN Mapping, aka lvm.
    It's a python object with at least the following attributes:

    ============ =========================================================
    Attribute    Description
    ============ =========================================================
    vlan         An identifier used by the agent to identify a neutron
                 network.
    network_type A network type found in neutron.plugins.common.constants.
    ============ =========================================================

    NOTE(yamamoto): "Local VLAN" is an OVS-agent term.  OVS-agent internally
    uses 802.1q VLAN tagging to isolate networks.  While this class inherited
    the terms from OVS-agent, it does not assume the specific underlying
    technologies.  E.g. this class is also used by ofagent, where a different
    mechanism is used.
    '''

    @abc.abstractmethod
    def add_fdb_flow(self, br, port_info, remote_ip, lvm, ofport):
        '''Add flow for fdb

        This method is assumed to be used by method fdb_add_tun.
        We expect to add a flow entry to send a packet to specified port
        on bridge.
        And you may edit some information for local arp response.

        :param br: represent the bridge on which add_fdb_flow should be
        applied.
        :param port_info: PortInfo instance to include mac and ip.
            .mac_address
            .ip_address

        :remote_ip: remote ip address.
        :param lvm: a local VLAN map of network.
        :param ofport: a port to add.
        '''
        pass

    @abc.abstractmethod
    def del_fdb_flow(self, br, port_info, remote_ip, lvm, ofport):
        '''Delete flow for fdb

        This method is assumed to be used by method fdb_remove_tun.
        We expect to delete a flow entry to send a packet to specified port
        from bridge.
        And you may delete some information for local arp response.

        :param br: represent the bridge on which del_fdb_flow should be
        applied.
        :param port_info: PortInfo instance to include mac and ip.
            .mac_address
            .ip_address

        :remote_ip: remote ip address.
        :param lvm: local VLAN map of a network. See add_fdb_flow for
            more explanation.
        :param ofport: a port to delete.
        '''
        pass

    @abc.abstractmethod
    def setup_tunnel_port(self, br, remote_ip, network_type):
        '''Setup an added tunnel port.

        This method is assumed to be used by method fdb_add_tun.
        We expect to prepare to call add_fdb_flow. It will be mainly adding
        a port to a bridge.
        If you need, you may do some preparations for a bridge.

        :param br: represent the bridge on which setup_tunnel_port should be
        applied.
        :param remote_ip: an ip for a port to setup.
        :param network_type: a type of a network.
        :returns: an ofport value. value 0 means the port is unavailable.
        '''
        pass

    @abc.abstractmethod
    def cleanup_tunnel_port(self, br, tun_ofport, tunnel_type):
        '''Clean up a deleted tunnel port.

        This method is assumed to be used by method fdb_remove_tun.
        We expect to clean up after calling del_fdb_flow. It will be mainly
        deleting a port from a bridge.
        If you need, you may do some cleanup for a bridge.

        :param br: represent the bridge on which cleanup_tunnel_port should be
        applied.
        :param tun_ofport: a port value to cleanup.
        :param tunnel_type: a type of a tunnel.
        '''
        pass

    @abc.abstractmethod
    def setup_entry_for_arp_reply(self, br, action, local_vid, mac_address,
                                  ip_address):
        '''Operate the ARP respond information.

        Update MAC/IPv4 associations, which is typically used by
        the local ARP responder.  For example, OVS-agent sets up
        flow entries to perform ARP responses.

        :param br: represent the bridge on which setup_entry_for_arp_reply
        should be applied.
        :param action: add/remove flow for arp response information.
        :param local_vid: id in local VLAN map of network's ARP entry.
        :param mac_address: MAC string value.
        :param ip_address: IP string value.
        '''
        pass

    def get_agent_ports(self, fdb_entries, local_vlan_map):
        """Generator to yield port info.

        For each known (i.e found in local_vlan_map) network in
        fdb_entries, yield (lvm, fdb_entries[network_id]['ports']) pair.

        :param fdb_entries: l2pop fdb entries
        :param local_vlan_map: A dict to map network_id to
            the corresponding lvm entry.
        """
        for network_id, values in fdb_entries.items():
            lvm = local_vlan_map.get(network_id)
            if lvm is None:
                continue
            agent_ports = values.get('ports')
            yield (lvm, agent_ports)

    @log.log
    def fdb_add_tun(self, context, br, lvm, agent_ports, lookup_port):
        for remote_ip, ports in agent_ports.items():
            # Ensure we have a tunnel port with this remote agent
            ofport = lookup_port(lvm.network_type, remote_ip)
            if not ofport:
                ofport = self.setup_tunnel_port(br, remote_ip,
                                                lvm.network_type)
                if ofport == 0:
                    continue
            for port in ports:
                self.add_fdb_flow(br, port, remote_ip, lvm, ofport)

    @log.log
    def fdb_remove_tun(self, context, br, lvm, agent_ports, lookup_port):
        for remote_ip, ports in agent_ports.items():
            ofport = lookup_port(lvm.network_type, remote_ip)
            if not ofport:
                continue
            for port in ports:
                self.del_fdb_flow(br, port, remote_ip, lvm, ofport)
                if port == n_const.FLOODING_ENTRY:
                    # Check if this tunnel port is still used
                    self.cleanup_tunnel_port(br, ofport, lvm.network_type)

    @log.log
    def fdb_update(self, context, fdb_entries):
        '''Call methods named '_fdb_<action>'.

        This method assumes that methods '_fdb_<action>' are defined in class.
        Currently the following actions are available.
            chg_ip
        '''
        for action, values in fdb_entries.items():
            method = '_fdb_' + action
            if not hasattr(self, method):
                raise NotImplementedError()

            getattr(self, method)(context, values)

    @log.log
    def fdb_chg_ip_tun(self, context, br, fdb_entries, local_ip,
                       local_vlan_map):
        '''fdb update when an IP of a port is updated.

        The ML2 l2-pop mechanism driver sends an fdb update rpc message when an
        IP of a port is updated.

        :param context: RPC context.
        :param br: represent the bridge on which fdb_chg_ip_tun should be
        applied.
        :param fdb_entries: fdb dicts that contain all mac/IP information per
                            agent and network.
                               {'net1':
                                {'agent_ip':
                                 {'before': PortInfo,
                                  'after': PortInfo
                                 }
                                }
                                'net2':
                                ...
                               }

                             PortInfo has .mac_address and .ip_address attrs.

        :param local_ip: local IP address of this agent.
        :param local_vlan_map: A dict to map network_id to
            the corresponding lvm entry.
        '''

        for network_id, agent_ports in fdb_entries.items():
            lvm = local_vlan_map.get(network_id)
            if not lvm:
                continue

            for agent_ip, state in agent_ports.items():
                if agent_ip == local_ip:
                    continue

                after = state.get('after', [])
                for mac_ip in after:
                    self.setup_entry_for_arp_reply(br, 'add', lvm.vlan,
                                                   mac_ip.mac_address,
                                                   mac_ip.ip_address)

                before = state.get('before', [])
                for mac_ip in before:
                    self.setup_entry_for_arp_reply(br, 'remove', lvm.vlan,
                                                   mac_ip.mac_address,
                                                   mac_ip.ip_address)
