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

from oslo.config import cfg
import six

from neutron.common import constants as n_const
from neutron.common import log
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)


@six.add_metaclass(abc.ABCMeta)
class L2populationRpcCallBackMixin(object):
    '''General mixin class of L2-population RPC call back.

    The following methods are called through RPC.
        add_fdb_entries(), remove_fdb_entries(), update_fdb_entries()
    The following methods are used in a agent as an internal method.
        fdb_add(), fdb_remove(), fdb_update()
    '''

    @log.log
    def add_fdb_entries(self, context, fdb_entries, host=None):
        if not host or host == cfg.CONF.host:
            self.fdb_add(context, fdb_entries)

    @log.log
    def remove_fdb_entries(self, context, fdb_entries, host=None):
        if not host or host == cfg.CONF.host:
            self.fdb_remove(context, fdb_entries)

    @log.log
    def update_fdb_entries(self, context, fdb_entries, host=None):
        if not host or host == cfg.CONF.host:
            self.fdb_update(context, fdb_entries)

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

    The following all methods are used in a agent as an internal method.
    '''

    @abc.abstractmethod
    def add_fdb_flow(self, br, port_info, remote_ip, lvm, ofport):
        '''Add flow for fdb

        This method assumes to be used by method fdb_add_tun.
        We expect to add a flow entry to send a packet to specified port
        on bridge.
        And you may edit some information for local arp respond.

        :param br: represent the bridge on which add_fdb_flow should be
        applied.
        :param port_info: list to include mac and ip.

            [mac, ip]
        :remote_ip: remote ip address.
        :param lvm: a local VLAN map of network.
        :param ofport: a port to add.
        '''
        pass

    @abc.abstractmethod
    def del_fdb_flow(self, br, port_info, remote_ip, lvm, ofport):
        '''Delete flow for fdb

        This method assumes to be used by method fdb_remove_tun.
        We expect to delete a flow entry to send a packet to specified port
        from bridge.
        And you may delete some information for local arp respond.

        :param br: represent the bridge on which del_fdb_flow should be
        applied.
        :param port_info: a list to contain mac and ip.
            [mac, ip]
        :remote_ip: remote ip address.
        :param lvm: local VLAN map of network.
        :param ofport: a port to delete.
        '''
        pass

    @abc.abstractmethod
    def setup_tunnel_port(self, br, remote_ip, network_type):
        '''Setup an added tunnel port.

        This method assumes to be used by method fdb_add_tun.
        We expect to prepare to call add_fdb_flow. It will be mainly adding
        a port to a bridge.
        If you need, you may do some preparation for a bridge.

        :param br: represent the bridge on which setup_tunnel_port should be
        applied.
        :param remote_ip: an ip for port to setup.
        :param network_type: a type of network.
        :returns: a ofport value. the value 0 means to be unavailable port.
        '''
        pass

    @abc.abstractmethod
    def cleanup_tunnel_port(self, br, tun_ofport, tunnel_type):
        '''Clean up a deleted tunnel port.

        This method assumes to be used by method fdb_remove_tun.
        We expect to clean up after calling del_fdb_flow. It will be mainly
        deleting a port from a bridge.
        If you need, you may do some cleanup for a bridge.

        :param br: represent the bridge on which cleanup_tunnel_port should be
        applied.
        :param tun_ofport: a port value to cleanup.
        :param tunnel_type: a type of tunnel.
        '''
        pass

    @abc.abstractmethod
    def setup_entry_for_arp_reply(self, br, action, local_vid, mac_address,
                                  ip_address):
        '''Operate the ARP respond information.

        Do operation of arp respond information for an action
        In ovs do adding or removing flow entry to edit an arp reply.

        :param br: represent the bridge on which setup_entry_for_arp_reply
        should be applied.
        :param action: an action to operate for arp respond infomation.
            "add" or "remove"
        :param local_vid: id in local VLAN map of network's ARP entry.
        :param mac_address: MAC string value.
        :param ip_address: IP string value.
        '''
        pass

    def get_agent_ports(self, fdb_entries, local_vlan_map):
        for network_id, values in fdb_entries.items():
            lvm = local_vlan_map.get(network_id)
            if lvm is None:
                continue
            agent_ports = values.get('ports')
            yield (lvm, agent_ports)

    @log.log
    def fdb_add_tun(self, context, br, lvm, agent_ports, ofports):
        for remote_ip, ports in agent_ports.items():
            # Ensure we have a tunnel port with this remote agent
            ofport = ofports[lvm.network_type].get(remote_ip)
            if not ofport:
                ofport = self.setup_tunnel_port(br, remote_ip,
                                                lvm.network_type)
                if ofport == 0:
                    continue
            for port in ports:
                self.add_fdb_flow(br, port, remote_ip, lvm, ofport)

    @log.log
    def fdb_remove_tun(self, context, br, lvm, agent_ports, ofports):
        for remote_ip, ports in agent_ports.items():
            ofport = ofports[lvm.network_type].get(remote_ip)
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
        :param fdb_entries: fdb dicts that contain all mac/IP informations per
                            agent and network.
                               {'net1':
                                {'agent_ip':
                                 {'before': [[mac, ip]],
                                  'after': [[mac, ip]]
                                 }
                                }
                                'net2':
                                ...
                               }
        :param local_ip: local IP address of this agent.
        :local_vlan_map: local VLAN map of network.
        '''

        for network_id, agent_ports in fdb_entries.items():
            lvm = local_vlan_map.get(network_id)
            if not lvm:
                continue

            for agent_ip, state in agent_ports.items():
                if agent_ip == local_ip:
                    continue

                after = state.get('after')
                for mac, ip in after:
                    self.setup_entry_for_arp_reply(br, 'add', lvm.vlan, mac,
                                                   ip)

                before = state.get('before')
                for mac, ip in before:
                    self.setup_entry_for_arp_reply(br, 'remove', lvm.vlan, mac,
                                                   ip)
