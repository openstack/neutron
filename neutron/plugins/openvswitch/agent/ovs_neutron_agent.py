#!/usr/bin/env python
# Copyright 2011 VMware, Inc.
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

import hashlib
import signal
import sys
import time

import eventlet
import netaddr
from oslo.config import cfg
from six.moves import xrange

from neutron.agent import l2population_rpc
from neutron.agent.linux import ip_lib
from neutron.agent.linux import ovs_lib
from neutron.agent.linux import polling
from neutron.agent.linux import utils
from neutron.agent import rpc as agent_rpc
from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.common import config as logging_config
from neutron.common import constants as q_const
from neutron.common import exceptions
from neutron.common import legacy
from neutron.common import topics
from neutron.common import utils as q_utils
from neutron import context
from neutron.openstack.common import log as logging
from neutron.openstack.common import loopingcall
from neutron.openstack.common.rpc import dispatcher
from neutron.plugins.common import constants as p_const
from neutron.plugins.openvswitch.common import config  # noqa
from neutron.plugins.openvswitch.common import constants


LOG = logging.getLogger(__name__)

# A placeholder for dead vlans.
DEAD_VLAN_TAG = str(q_const.MAX_VLAN_TAG + 1)


class DeviceListRetrievalError(exceptions.NeutronException):
    message = _("Unable to retrieve port details for devices: %(devices)s "
                "because of error: %(error)s")


# A class to represent a VIF (i.e., a port that has 'iface-id' and 'vif-mac'
# attributes set).
class LocalVLANMapping:
    def __init__(self, vlan, network_type, physical_network, segmentation_id,
                 vif_ports=None):
        if vif_ports is None:
            vif_ports = {}
        self.vlan = vlan
        self.network_type = network_type
        self.physical_network = physical_network
        self.segmentation_id = segmentation_id
        self.vif_ports = vif_ports
        # set of tunnel ports on which packets should be flooded
        self.tun_ofports = set()

    def __str__(self):
        return ("lv-id = %s type = %s phys-net = %s phys-id = %s" %
                (self.vlan, self.network_type, self.physical_network,
                 self.segmentation_id))


class Port(object):
    """Represents a neutron port.

    Class stores port data in a ORM-free way, so attributres are
    still available even if a row has been deleted.
    """

    def __init__(self, p):
        self.id = p.id
        self.network_id = p.network_id
        self.device_id = p.device_id
        self.admin_state_up = p.admin_state_up
        self.status = p.status

    def __eq__(self, other):
        '''Compare only fields that will cause us to re-wire.'''
        try:
            return (self and other
                    and self.id == other.id
                    and self.admin_state_up == other.admin_state_up)
        except Exception:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.id)


class OVSPluginApi(agent_rpc.PluginApi,
                   sg_rpc.SecurityGroupServerRpcApiMixin):
    pass


class OVSSecurityGroupAgent(sg_rpc.SecurityGroupAgentRpcMixin):
    def __init__(self, context, plugin_rpc, root_helper):
        self.context = context
        self.plugin_rpc = plugin_rpc
        self.root_helper = root_helper
        self.init_firewall(defer_refresh_firewall=True)


class OVSNeutronAgent(sg_rpc.SecurityGroupAgentRpcCallbackMixin,
                      l2population_rpc.L2populationRpcCallBackMixin):
    '''Implements OVS-based tunneling, VLANs and flat networks.

    Two local bridges are created: an integration bridge (defaults to
    'br-int') and a tunneling bridge (defaults to 'br-tun'). An
    additional bridge is created for each physical network interface
    used for VLANs and/or flat networks.

    All VM VIFs are plugged into the integration bridge. VM VIFs on a
    given virtual network share a common "local" VLAN (i.e. not
    propagated externally). The VLAN id of this local VLAN is mapped
    to the physical networking details realizing that virtual network.

    For virtual networks realized as GRE tunnels, a Logical Switch
    (LS) identifier and is used to differentiate tenant traffic on
    inter-HV tunnels. A mesh of tunnels is created to other
    Hypervisors in the cloud. These tunnels originate and terminate on
    the tunneling bridge of each hypervisor. Port patching is done to
    connect local VLANs on the integration bridge to inter-hypervisor
    tunnels on the tunnel bridge.

    For each virtual networks realized as a VLANs or flat network, a
    veth is used to connect the local VLAN on the integration bridge
    with the physical network bridge, with flow rules adding,
    modifying, or stripping VLAN tags as necessary.
    '''

    # history
    #   1.0 Initial version
    #   1.1 Support Security Group RPC
    RPC_API_VERSION = '1.1'

    def __init__(self, integ_br, tun_br, local_ip,
                 bridge_mappings, root_helper,
                 polling_interval, tunnel_types=None,
                 veth_mtu=None, l2_population=False,
                 minimize_polling=False,
                 ovsdb_monitor_respawn_interval=(
                     constants.DEFAULT_OVSDBMON_RESPAWN)):
        '''Constructor.

        :param integ_br: name of the integration bridge.
        :param tun_br: name of the tunnel bridge.
        :param local_ip: local IP address of this hypervisor.
        :param bridge_mappings: mappings from physical network name to bridge.
        :param root_helper: utility to use when running shell cmds.
        :param polling_interval: interval (secs) to poll DB.
        :param tunnel_types: A list of tunnel types to enable support for in
               the agent. If set, will automatically set enable_tunneling to
               True.
        :param veth_mtu: MTU size for veth interfaces.
        :param minimize_polling: Optional, whether to minimize polling by
               monitoring ovsdb for interface changes.
        :param ovsdb_monitor_respawn_interval: Optional, when using polling
               minimization, the number of seconds to wait before respawning
               the ovsdb monitor.
        '''
        self.veth_mtu = veth_mtu
        self.root_helper = root_helper
        self.available_local_vlans = set(xrange(q_const.MIN_VLAN_TAG,
                                                q_const.MAX_VLAN_TAG))
        self.tunnel_types = tunnel_types or []
        self.l2_pop = l2_population
        self.agent_state = {
            'binary': 'neutron-openvswitch-agent',
            'host': cfg.CONF.host,
            'topic': q_const.L2_AGENT_TOPIC,
            'configurations': {'bridge_mappings': bridge_mappings,
                               'tunnel_types': self.tunnel_types,
                               'tunneling_ip': local_ip,
                               'l2_population': self.l2_pop},
            'agent_type': q_const.AGENT_TYPE_OVS,
            'start_flag': True}

        # Keep track of int_br's device count for use by _report_state()
        self.int_br_device_count = 0

        self.int_br = ovs_lib.OVSBridge(integ_br, self.root_helper)
        self.setup_integration_br()
        # Stores port update notifications for processing in main rpc loop
        self.updated_ports = set()
        self.setup_rpc()
        self.bridge_mappings = bridge_mappings
        self.setup_physical_bridges(self.bridge_mappings)
        self.local_vlan_map = {}
        self.tun_br_ofports = {p_const.TYPE_GRE: {},
                               p_const.TYPE_VXLAN: {}}

        self.polling_interval = polling_interval
        self.minimize_polling = minimize_polling
        self.ovsdb_monitor_respawn_interval = ovsdb_monitor_respawn_interval

        if tunnel_types:
            self.enable_tunneling = True
        else:
            self.enable_tunneling = False
        self.local_ip = local_ip
        self.tunnel_count = 0
        self.vxlan_udp_port = cfg.CONF.AGENT.vxlan_udp_port
        self._check_ovs_version()
        self.tun_br = None
        if self.enable_tunneling:
            self.setup_tunnel_br(tun_br)
        # Collect additional bridges to monitor
        self.ancillary_brs = self.setup_ancillary_bridges(integ_br, tun_br)

        # Security group agent supprot
        self.sg_agent = OVSSecurityGroupAgent(self.context,
                                              self.plugin_rpc,
                                              root_helper)
        # Initialize iteration counter
        self.iter_num = 0
        self.run_daemon_loop = True

    def _check_ovs_version(self):
        if p_const.TYPE_VXLAN in self.tunnel_types:
            try:
                ovs_lib.check_ovs_vxlan_version(self.root_helper)
            except SystemError:
                LOG.exception(_("Agent terminated"))
                raise SystemExit(1)

    def _report_state(self):
        # How many devices are likely used by a VM
        self.agent_state.get('configurations')['devices'] = (
            self.int_br_device_count)
        try:
            self.state_rpc.report_state(self.context,
                                        self.agent_state)
            self.agent_state.pop('start_flag', None)
        except Exception:
            LOG.exception(_("Failed reporting state!"))

    def setup_rpc(self):
        mac = self.int_br.get_local_port_mac()
        self.agent_id = '%s%s' % ('ovs', (mac.replace(":", "")))
        self.topic = topics.AGENT
        self.plugin_rpc = OVSPluginApi(topics.PLUGIN)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)

        # RPC network init
        self.context = context.get_admin_context_without_session()
        # Handle updates from service
        self.dispatcher = self.create_rpc_dispatcher()
        # Define the listening consumers for the agent
        consumers = [[topics.PORT, topics.UPDATE],
                     [topics.NETWORK, topics.DELETE],
                     [constants.TUNNEL, topics.UPDATE],
                     [topics.SECURITY_GROUP, topics.UPDATE]]
        if self.l2_pop:
            consumers.append([topics.L2POPULATION,
                              topics.UPDATE, cfg.CONF.host])
        self.connection = agent_rpc.create_consumers(self.dispatcher,
                                                     self.topic,
                                                     consumers)
        report_interval = cfg.CONF.AGENT.report_interval
        if report_interval:
            heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            heartbeat.start(interval=report_interval)

    def get_net_uuid(self, vif_id):
        for network_id, vlan_mapping in self.local_vlan_map.iteritems():
            if vif_id in vlan_mapping.vif_ports:
                return network_id

    def network_delete(self, context, **kwargs):
        LOG.debug(_("network_delete received"))
        network_id = kwargs.get('network_id')
        LOG.debug(_("Delete %s"), network_id)
        # The network may not be defined on this agent
        lvm = self.local_vlan_map.get(network_id)
        if lvm:
            self.reclaim_local_vlan(network_id)
        else:
            LOG.debug(_("Network %s not used on agent."), network_id)

    def port_update(self, context, **kwargs):
        port = kwargs.get('port')
        # Put the port identifier in the updated_ports set.
        # Even if full port details might be provided to this call,
        # they are not used since there is no guarantee the notifications
        # are processed in the same order as the relevant API requests
        self.updated_ports.add(port['id'])
        LOG.debug(_("port_update message processed for port %s"), port['id'])

    def tunnel_update(self, context, **kwargs):
        LOG.debug(_("tunnel_update received"))
        if not self.enable_tunneling:
            return
        tunnel_ip = kwargs.get('tunnel_ip')
        tunnel_id = kwargs.get('tunnel_id', self.get_ip_in_hex(tunnel_ip))
        if not tunnel_id:
            return
        tunnel_type = kwargs.get('tunnel_type')
        if not tunnel_type:
            LOG.error(_("No tunnel_type specified, cannot create tunnels"))
            return
        if tunnel_type not in self.tunnel_types:
            LOG.error(_("tunnel_type %s not supported by agent"), tunnel_type)
            return
        if tunnel_ip == self.local_ip:
            return
        tun_name = '%s-%s' % (tunnel_type, tunnel_id)
        if not self.l2_pop:
            self.setup_tunnel_port(tun_name, tunnel_ip, tunnel_type)

    def fdb_add(self, context, fdb_entries):
        LOG.debug(_("fdb_add received"))
        for network_id, values in fdb_entries.items():
            lvm = self.local_vlan_map.get(network_id)
            if not lvm:
                # Agent doesn't manage any port in this network
                continue
            agent_ports = values.get('ports')
            agent_ports.pop(self.local_ip, None)
            if len(agent_ports):
                self.tun_br.defer_apply_on()
                for agent_ip, ports in agent_ports.items():
                    # Ensure we have a tunnel port with this remote agent
                    ofport = self.tun_br_ofports[
                        lvm.network_type].get(agent_ip)
                    if not ofport:
                        remote_ip_hex = self.get_ip_in_hex(agent_ip)
                        if not remote_ip_hex:
                            continue
                        port_name = '%s-%s' % (lvm.network_type, remote_ip_hex)
                        ofport = self.setup_tunnel_port(port_name, agent_ip,
                                                        lvm.network_type)
                        if ofport == 0:
                            continue
                    for port in ports:
                        self._add_fdb_flow(port, agent_ip, lvm, ofport)
                self.tun_br.defer_apply_off()

    def fdb_remove(self, context, fdb_entries):
        LOG.debug(_("fdb_remove received"))
        for network_id, values in fdb_entries.items():
            lvm = self.local_vlan_map.get(network_id)
            if not lvm:
                # Agent doesn't manage any more ports in this network
                continue
            agent_ports = values.get('ports')
            agent_ports.pop(self.local_ip, None)
            if len(agent_ports):
                self.tun_br.defer_apply_on()
                for agent_ip, ports in agent_ports.items():
                    ofport = self.tun_br_ofports[
                        lvm.network_type].get(agent_ip)
                    if not ofport:
                        continue
                    for port in ports:
                        self._del_fdb_flow(port, agent_ip, lvm, ofport)
                self.tun_br.defer_apply_off()

    def _add_fdb_flow(self, port_info, agent_ip, lvm, ofport):
        if port_info == q_const.FLOODING_ENTRY:
            lvm.tun_ofports.add(ofport)
            ofports = ','.join(lvm.tun_ofports)
            self.tun_br.mod_flow(table=constants.FLOOD_TO_TUN,
                                 dl_vlan=lvm.vlan,
                                 actions="strip_vlan,set_tunnel:%s,"
                                 "output:%s" % (lvm.segmentation_id, ofports))
        else:
            # TODO(feleouet): add ARP responder entry
            self.tun_br.add_flow(table=constants.UCAST_TO_TUN,
                                 priority=2,
                                 dl_vlan=lvm.vlan,
                                 dl_dst=port_info[0],
                                 actions="strip_vlan,set_tunnel:%s,output:%s" %
                                 (lvm.segmentation_id, ofport))

    def _del_fdb_flow(self, port_info, agent_ip, lvm, ofport):
        if port_info == q_const.FLOODING_ENTRY:
            lvm.tun_ofports.remove(ofport)
            if len(lvm.tun_ofports) > 0:
                ofports = ','.join(lvm.tun_ofports)
                self.tun_br.mod_flow(table=constants.FLOOD_TO_TUN,
                                     dl_vlan=lvm.vlan,
                                     actions="strip_vlan,"
                                     "set_tunnel:%s,output:%s" %
                                     (lvm.segmentation_id, ofports))
            else:
                # This local vlan doesn't require any more tunelling
                self.tun_br.delete_flows(table=constants.FLOOD_TO_TUN,
                                         dl_vlan=lvm.vlan)
            # Check if this tunnel port is still used
            self.cleanup_tunnel_port(ofport, lvm.network_type)
        else:
            #TODO(feleouet): remove ARP responder entry
            self.tun_br.delete_flows(table=constants.UCAST_TO_TUN,
                                     dl_vlan=lvm.vlan,
                                     dl_dst=port_info[0])

    def fdb_update(self, context, fdb_entries):
        LOG.debug(_("fdb_update received"))
        for action, values in fdb_entries.items():
            method = '_fdb_' + action
            if not hasattr(self, method):
                raise NotImplementedError()

            getattr(self, method)(context, values)

    def create_rpc_dispatcher(self):
        '''Get the rpc dispatcher for this manager.

        If a manager would like to set an rpc API version, or support more than
        one class as the target of rpc messages, override this method.
        '''
        return dispatcher.RpcDispatcher([self])

    def provision_local_vlan(self, net_uuid, network_type, physical_network,
                             segmentation_id):
        '''Provisions a local VLAN.

        :param net_uuid: the uuid of the network associated with this vlan.
        :param network_type: the network type ('gre', 'vxlan', 'vlan', 'flat',
                                               'local')
        :param physical_network: the physical network for 'vlan' or 'flat'
        :param segmentation_id: the VID for 'vlan' or tunnel ID for 'tunnel'
        '''

        # On a restart or crash of OVS, the network associated with this VLAN
        # will already be assigned, so check for that here before assigning a
        # new one.
        lvm = self.local_vlan_map.get(net_uuid)
        if lvm:
            lvid = lvm.vlan
        else:
            if not self.available_local_vlans:
                LOG.error(_("No local VLAN available for net-id=%s"), net_uuid)
                return
            lvid = self.available_local_vlans.pop()
            self.local_vlan_map[net_uuid] = LocalVLANMapping(lvid,
                                                             network_type,
                                                             physical_network,
                                                             segmentation_id)

        LOG.info(_("Assigning %(vlan_id)s as local vlan for "
                   "net-id=%(net_uuid)s"),
                 {'vlan_id': lvid, 'net_uuid': net_uuid})

        if network_type in constants.TUNNEL_NETWORK_TYPES:
            if self.enable_tunneling:
                # outbound broadcast/multicast
                ofports = ','.join(self.tun_br_ofports[network_type].values())
                if ofports:
                    self.tun_br.mod_flow(table=constants.FLOOD_TO_TUN,
                                         dl_vlan=lvid,
                                         actions="strip_vlan,"
                                         "set_tunnel:%s,output:%s" %
                                         (segmentation_id, ofports))
                # inbound from tunnels: set lvid in the right table
                # and resubmit to Table LEARN_FROM_TUN for mac learning
                self.tun_br.add_flow(table=constants.TUN_TABLE[network_type],
                                     priority=1,
                                     tun_id=segmentation_id,
                                     actions="mod_vlan_vid:%s,resubmit(,%s)" %
                                     (lvid, constants.LEARN_FROM_TUN))
            else:
                LOG.error(_("Cannot provision %(network_type)s network for "
                          "net-id=%(net_uuid)s - tunneling disabled"),
                          {'network_type': network_type,
                           'net_uuid': net_uuid})
        elif network_type == p_const.TYPE_FLAT:
            if physical_network in self.phys_brs:
                # outbound
                br = self.phys_brs[physical_network]
                br.add_flow(priority=4,
                            in_port=self.phys_ofports[physical_network],
                            dl_vlan=lvid,
                            actions="strip_vlan,normal")
                # inbound
                self.int_br.add_flow(
                    priority=3,
                    in_port=self.int_ofports[physical_network],
                    dl_vlan=0xffff,
                    actions="mod_vlan_vid:%s,normal" % lvid)
            else:
                LOG.error(_("Cannot provision flat network for "
                            "net-id=%(net_uuid)s - no bridge for "
                            "physical_network %(physical_network)s"),
                          {'net_uuid': net_uuid,
                           'physical_network': physical_network})
        elif network_type == p_const.TYPE_VLAN:
            if physical_network in self.phys_brs:
                # outbound
                br = self.phys_brs[physical_network]
                br.add_flow(priority=4,
                            in_port=self.phys_ofports[physical_network],
                            dl_vlan=lvid,
                            actions="mod_vlan_vid:%s,normal" % segmentation_id)
                # inbound
                self.int_br.add_flow(priority=3,
                                     in_port=self.
                                     int_ofports[physical_network],
                                     dl_vlan=segmentation_id,
                                     actions="mod_vlan_vid:%s,normal" % lvid)
            else:
                LOG.error(_("Cannot provision VLAN network for "
                            "net-id=%(net_uuid)s - no bridge for "
                            "physical_network %(physical_network)s"),
                          {'net_uuid': net_uuid,
                           'physical_network': physical_network})
        elif network_type == p_const.TYPE_LOCAL:
            # no flows needed for local networks
            pass
        else:
            LOG.error(_("Cannot provision unknown network type "
                        "%(network_type)s for net-id=%(net_uuid)s"),
                      {'network_type': network_type,
                       'net_uuid': net_uuid})

    def reclaim_local_vlan(self, net_uuid):
        '''Reclaim a local VLAN.

        :param net_uuid: the network uuid associated with this vlan.
        :param lvm: a LocalVLANMapping object that tracks (vlan, lsw_id,
            vif_ids) mapping.
        '''
        lvm = self.local_vlan_map.pop(net_uuid, None)
        if lvm is None:
            LOG.debug(_("Network %s not used on agent."), net_uuid)
            return

        LOG.info(_("Reclaiming vlan = %(vlan_id)s from net-id = %(net_uuid)s"),
                 {'vlan_id': lvm.vlan,
                  'net_uuid': net_uuid})

        if lvm.network_type in constants.TUNNEL_NETWORK_TYPES:
            if self.enable_tunneling:
                self.tun_br.delete_flows(
                    table=constants.TUN_TABLE[lvm.network_type],
                    tun_id=lvm.segmentation_id)
                self.tun_br.delete_flows(dl_vlan=lvm.vlan)
                if self.l2_pop:
                    # Try to remove tunnel ports if not used by other networks
                    for ofport in lvm.tun_ofports:
                        self.cleanup_tunnel_port(ofport, lvm.network_type)
        elif lvm.network_type == p_const.TYPE_FLAT:
            if lvm.physical_network in self.phys_brs:
                # outbound
                br = self.phys_brs[lvm.physical_network]
                br.delete_flows(in_port=self.phys_ofports[lvm.
                                                          physical_network],
                                dl_vlan=lvm.vlan)
                # inbound
                br = self.int_br
                br.delete_flows(in_port=self.int_ofports[lvm.physical_network],
                                dl_vlan=0xffff)
        elif lvm.network_type == p_const.TYPE_VLAN:
            if lvm.physical_network in self.phys_brs:
                # outbound
                br = self.phys_brs[lvm.physical_network]
                br.delete_flows(in_port=self.phys_ofports[lvm.
                                                          physical_network],
                                dl_vlan=lvm.vlan)
                # inbound
                br = self.int_br
                br.delete_flows(in_port=self.int_ofports[lvm.physical_network],
                                dl_vlan=lvm.segmentation_id)
        elif lvm.network_type == p_const.TYPE_LOCAL:
            # no flows needed for local networks
            pass
        else:
            LOG.error(_("Cannot reclaim unknown network type "
                        "%(network_type)s for net-id=%(net_uuid)s"),
                      {'network_type': lvm.network_type,
                       'net_uuid': net_uuid})

        self.available_local_vlans.add(lvm.vlan)

    def port_bound(self, port, net_uuid,
                   network_type, physical_network, segmentation_id,
                   ovs_restarted):
        '''Bind port to net_uuid/lsw_id and install flow for inbound traffic
        to vm.

        :param port: a ovslib.VifPort object.
        :param net_uuid: the net_uuid this port is to be associated with.
        :param network_type: the network type ('gre', 'vlan', 'flat', 'local')
        :param physical_network: the physical network for 'vlan' or 'flat'
        :param segmentation_id: the VID for 'vlan' or tunnel ID for 'tunnel'
        :param ovs_restarted: indicates if this is called for an OVS restart.
        '''
        if net_uuid not in self.local_vlan_map or ovs_restarted:
            self.provision_local_vlan(net_uuid, network_type,
                                      physical_network, segmentation_id)
        lvm = self.local_vlan_map[net_uuid]
        lvm.vif_ports[port.vif_id] = port
        # Do not bind a port if it's already bound
        cur_tag = self.int_br.db_get_val("Port", port.port_name, "tag")
        if cur_tag != str(lvm.vlan):
            self.int_br.set_db_attribute("Port", port.port_name, "tag",
                                         str(lvm.vlan))
            if port.ofport != -1:
                self.int_br.delete_flows(in_port=port.ofport)

    def port_unbound(self, vif_id, net_uuid=None):
        '''Unbind port.

        Removes corresponding local vlan mapping object if this is its last
        VIF.

        :param vif_id: the id of the vif
        :param net_uuid: the net_uuid this port is associated with.
        '''
        if net_uuid is None:
            net_uuid = self.get_net_uuid(vif_id)

        if not self.local_vlan_map.get(net_uuid):
            LOG.info(_('port_unbound() net_uuid %s not in local_vlan_map'),
                     net_uuid)
            return

        lvm = self.local_vlan_map[net_uuid]
        lvm.vif_ports.pop(vif_id, None)

        if not lvm.vif_ports:
            self.reclaim_local_vlan(net_uuid)

    def port_dead(self, port):
        '''Once a port has no binding, put it on the "dead vlan".

        :param port: a ovs_lib.VifPort object.
        '''
        # Don't kill a port if it's already dead
        cur_tag = self.int_br.db_get_val("Port", port.port_name, "tag")
        if cur_tag != DEAD_VLAN_TAG:
            self.int_br.set_db_attribute("Port", port.port_name, "tag",
                                         DEAD_VLAN_TAG)
            self.int_br.add_flow(priority=2, in_port=port.ofport,
                                 actions="drop")

    def setup_integration_br(self):
        '''Setup the integration bridge.

        Create patch ports and remove all existing flows.

        :param bridge_name: the name of the integration bridge.
        :returns: the integration bridge
        '''
        # Ensure the integration bridge is created.
        # ovs_lib.OVSBridge.create() will run
        #   ovs-vsctl -- --may-exist add-br BRIDGE_NAME
        # which does nothing if bridge already exists.
        self.int_br.create()
        self.int_br.set_secure_mode()

        self.int_br.delete_port(cfg.CONF.OVS.int_peer_patch_port)
        self.int_br.remove_all_flows()
        # switch all traffic using L2 learning
        self.int_br.add_flow(priority=1, actions="normal")
        # Add a canary flow to int_br to track OVS restarts
        self.int_br.add_flow(table=constants.CANARY_TABLE, priority=0,
                             actions="drop")

    def setup_ancillary_bridges(self, integ_br, tun_br):
        '''Setup ancillary bridges - for example br-ex.'''
        ovs_bridges = set(ovs_lib.get_bridges(self.root_helper))
        # Remove all known bridges
        ovs_bridges.remove(integ_br)
        if self.enable_tunneling:
            ovs_bridges.remove(tun_br)
        br_names = [self.phys_brs[physical_network].br_name for
                    physical_network in self.phys_brs]
        ovs_bridges.difference_update(br_names)
        # Filter list of bridges to those that have external
        # bridge-id's configured
        br_names = []
        for bridge in ovs_bridges:
            id = ovs_lib.get_bridge_external_bridge_id(self.root_helper,
                                                       bridge)
            if id != bridge:
                br_names.append(bridge)
        ovs_bridges.difference_update(br_names)
        ancillary_bridges = []
        for bridge in ovs_bridges:
            br = ovs_lib.OVSBridge(bridge, self.root_helper)
            LOG.info(_('Adding %s to list of bridges.'), bridge)
            ancillary_bridges.append(br)
        return ancillary_bridges

    def setup_tunnel_br(self, tun_br=None):
        '''Setup the tunnel bridge.

        Creates tunnel bridge, and links it to the integration bridge
        using a patch port.

        :param tun_br: the name of the tunnel bridge.
        '''
        if not self.tun_br:
            self.tun_br = ovs_lib.OVSBridge(tun_br, self.root_helper)

        self.tun_br.reset_bridge()
        self.patch_tun_ofport = self.int_br.add_patch_port(
            cfg.CONF.OVS.int_peer_patch_port, cfg.CONF.OVS.tun_peer_patch_port)
        self.patch_int_ofport = self.tun_br.add_patch_port(
            cfg.CONF.OVS.tun_peer_patch_port, cfg.CONF.OVS.int_peer_patch_port)
        if int(self.patch_tun_ofport) < 0 or int(self.patch_int_ofport) < 0:
            LOG.error(_("Failed to create OVS patch port. Cannot have "
                        "tunneling enabled on this agent, since this version "
                        "of OVS does not support tunnels or patch ports. "
                        "Agent terminated!"))
            exit(1)
        self.tun_br.remove_all_flows()

        # Table 0 (default) will sort incoming traffic depending on in_port
        self.tun_br.add_flow(priority=1,
                             in_port=self.patch_int_ofport,
                             actions="resubmit(,%s)" %
                             constants.PATCH_LV_TO_TUN)
        self.tun_br.add_flow(priority=0, actions="drop")
        # PATCH_LV_TO_TUN table will handle packets coming from patch_int
        # unicasts go to table UCAST_TO_TUN where remote adresses are learnt
        self.tun_br.add_flow(table=constants.PATCH_LV_TO_TUN,
                             dl_dst="00:00:00:00:00:00/01:00:00:00:00:00",
                             actions="resubmit(,%s)" % constants.UCAST_TO_TUN)
        # Broadcasts/multicasts go to table FLOOD_TO_TUN that handles flooding
        self.tun_br.add_flow(table=constants.PATCH_LV_TO_TUN,
                             dl_dst="01:00:00:00:00:00/01:00:00:00:00:00",
                             actions="resubmit(,%s)" % constants.FLOOD_TO_TUN)
        # Tables [tunnel_type]_TUN_TO_LV will set lvid depending on tun_id
        # for each tunnel type, and resubmit to table LEARN_FROM_TUN where
        # remote mac adresses will be learnt
        for tunnel_type in constants.TUNNEL_NETWORK_TYPES:
            self.tun_br.add_flow(table=constants.TUN_TABLE[tunnel_type],
                                 priority=0,
                                 actions="drop")
        # LEARN_FROM_TUN table will have a single flow using a learn action to
        # dynamically set-up flows in UCAST_TO_TUN corresponding to remote mac
        # adresses (assumes that lvid has already been set by a previous flow)
        learned_flow = ("table=%s,"
                        "priority=1,"
                        "hard_timeout=300,"
                        "NXM_OF_VLAN_TCI[0..11],"
                        "NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],"
                        "load:0->NXM_OF_VLAN_TCI[],"
                        "load:NXM_NX_TUN_ID[]->NXM_NX_TUN_ID[],"
                        "output:NXM_OF_IN_PORT[]" %
                        constants.UCAST_TO_TUN)
        # Once remote mac adresses are learnt, packet is outputed to patch_int
        self.tun_br.add_flow(table=constants.LEARN_FROM_TUN,
                             priority=1,
                             actions="learn(%s),output:%s" %
                             (learned_flow, self.patch_int_ofport))
        # Egress unicast will be handled in table UCAST_TO_TUN, where remote
        # mac adresses will be learned. For now, just add a default flow that
        # will resubmit unknown unicasts to table FLOOD_TO_TUN to treat them
        # as broadcasts/multicasts
        self.tun_br.add_flow(table=constants.UCAST_TO_TUN,
                             priority=0,
                             actions="resubmit(,%s)" %
                             constants.FLOOD_TO_TUN)
        # FLOOD_TO_TUN will handle flooding in tunnels based on lvid,
        # for now, add a default drop action
        self.tun_br.add_flow(table=constants.FLOOD_TO_TUN,
                             priority=0,
                             actions="drop")

    def get_veth_name(self, prefix, name):
        """Construct a veth name based on the prefix and name that does not
           exceed the maximum length allowed for a linux device. Longer names
           are hashed to help ensure uniqueness.
        """
        if len(prefix + name) <= ip_lib.VETH_MAX_NAME_LENGTH:
            return prefix + name
        # We can't just truncate because bridges may be distinguished
        # by an ident at the end. A hash over the name should be unique.
        # Leave part of the bridge name on for easier identification
        hashlen = 6
        namelen = ip_lib.VETH_MAX_NAME_LENGTH - len(prefix) - hashlen
        new_name = ('%(prefix)s%(truncated)s%(hash)s' %
                    {'prefix': prefix, 'truncated': name[0:namelen],
                     'hash': hashlib.sha1(name).hexdigest()[0:hashlen]})
        LOG.warning(_("Creating an interface named %(name)s exceeds the "
                      "%(limit)d character limitation. It was shortened to "
                      "%(new_name)s to fit."),
                    {'name': name, 'limit': ip_lib.VETH_MAX_NAME_LENGTH,
                     'new_name': new_name})
        return new_name

    def setup_physical_bridges(self, bridge_mappings):
        '''Setup the physical network bridges.

        Creates physical network bridges and links them to the
        integration bridge using veths.

        :param bridge_mappings: map physical network names to bridge names.
        '''
        self.phys_brs = {}
        self.int_ofports = {}
        self.phys_ofports = {}
        ip_wrapper = ip_lib.IPWrapper(self.root_helper)
        for physical_network, bridge in bridge_mappings.iteritems():
            LOG.info(_("Mapping physical network %(physical_network)s to "
                       "bridge %(bridge)s"),
                     {'physical_network': physical_network,
                      'bridge': bridge})
            # setup physical bridge
            if not ip_lib.device_exists(bridge, self.root_helper):
                LOG.error(_("Bridge %(bridge)s for physical network "
                            "%(physical_network)s does not exist. Agent "
                            "terminated!"),
                          {'physical_network': physical_network,
                           'bridge': bridge})
                sys.exit(1)
            br = ovs_lib.OVSBridge(bridge, self.root_helper)
            br.remove_all_flows()
            br.add_flow(priority=1, actions="normal")
            self.phys_brs[physical_network] = br

            # create veth to patch physical bridge with integration bridge
            int_veth_name = self.get_veth_name(
                constants.VETH_INTEGRATION_PREFIX, bridge)
            self.int_br.delete_port(int_veth_name)
            phys_veth_name = self.get_veth_name(
                constants.VETH_PHYSICAL_PREFIX, bridge)
            br.delete_port(phys_veth_name)
            if ip_lib.device_exists(int_veth_name, self.root_helper):
                ip_lib.IPDevice(int_veth_name, self.root_helper).link.delete()
                # Give udev a chance to process its rules here, to avoid
                # race conditions between commands launched by udev rules
                # and the subsequent call to ip_wrapper.add_veth
                utils.execute(['/sbin/udevadm', 'settle', '--timeout=10'])
            int_veth, phys_veth = ip_wrapper.add_veth(int_veth_name,
                                                      phys_veth_name)
            self.int_ofports[physical_network] = self.int_br.add_port(int_veth)
            self.phys_ofports[physical_network] = br.add_port(phys_veth)

            # block all untranslated traffic over veth between bridges
            self.int_br.add_flow(priority=2,
                                 in_port=self.int_ofports[physical_network],
                                 actions="drop")
            br.add_flow(priority=2,
                        in_port=self.phys_ofports[physical_network],
                        actions="drop")

            # enable veth to pass traffic
            int_veth.link.set_up()
            phys_veth.link.set_up()

            if self.veth_mtu:
                # set up mtu size for veth interfaces
                int_veth.link.set_mtu(self.veth_mtu)
                phys_veth.link.set_mtu(self.veth_mtu)

    def scan_ports(self, registered_ports, updated_ports=None):
        cur_ports = self.int_br.get_vif_port_set()
        self.int_br_device_count = len(cur_ports)
        port_info = {'current': cur_ports}
        if updated_ports is None:
            updated_ports = set()
        updated_ports.update(self.check_changed_vlans(registered_ports))
        if updated_ports:
            # Some updated ports might have been removed in the
            # meanwhile, and therefore should not be processed.
            # In this case the updated port won't be found among
            # current ports.
            updated_ports &= cur_ports
            if updated_ports:
                port_info['updated'] = updated_ports

        # FIXME(salv-orlando): It's not really necessary to return early
        # if nothing has changed.
        if cur_ports == registered_ports:
            # No added or removed ports to set, just return here
            return port_info

        port_info['added'] = cur_ports - registered_ports
        # Remove all the known ports not found on the integration bridge
        port_info['removed'] = registered_ports - cur_ports
        return port_info

    def check_changed_vlans(self, registered_ports):
        """Return ports which have lost their vlan tag.

        The returned value is a set of port ids of the ports concerned by a
        vlan tag loss.
        """
        port_tags = self.int_br.get_port_tag_dict()
        changed_ports = set()
        for lvm in self.local_vlan_map.values():
            for port in registered_ports:
                if (
                    port in lvm.vif_ports
                    and lvm.vif_ports[port].port_name in port_tags
                    and port_tags[lvm.vif_ports[port].port_name] != lvm.vlan
                ):
                    LOG.info(
                        _("Port '%(port_name)s' has lost "
                            "its vlan tag '%(vlan_tag)d'!"),
                        {'port_name': lvm.vif_ports[port].port_name,
                         'vlan_tag': lvm.vlan}
                    )
                    changed_ports.add(port)
        return changed_ports

    def update_ancillary_ports(self, registered_ports):
        ports = set()
        for bridge in self.ancillary_brs:
            ports |= bridge.get_vif_port_set()

        if ports == registered_ports:
            return
        added = ports - registered_ports
        removed = registered_ports - ports
        return {'current': ports,
                'added': added,
                'removed': removed}

    def treat_vif_port(self, vif_port, port_id, network_id, network_type,
                       physical_network, segmentation_id, admin_state_up,
                       ovs_restarted):
        # When this function is called for a port, the port should have
        # an OVS ofport configured, as only these ports were considered
        # for being treated. If that does not happen, it is a potential
        # error condition of which operators should be aware
        if not vif_port.ofport:
            LOG.warn(_("VIF port: %s has no ofport configured, and might not "
                       "be able to transmit"), vif_port.vif_id)
        if vif_port:
            if admin_state_up:
                self.port_bound(vif_port, network_id, network_type,
                                physical_network, segmentation_id,
                                ovs_restarted)
            else:
                self.port_dead(vif_port)
        else:
            LOG.debug(_("No VIF port for port %s defined on agent."), port_id)

    def setup_tunnel_port(self, port_name, remote_ip, tunnel_type):
        ofport = self.tun_br.add_tunnel_port(port_name,
                                             remote_ip,
                                             self.local_ip,
                                             tunnel_type,
                                             self.vxlan_udp_port)
        ofport_int = -1
        try:
            ofport_int = int(ofport)
        except (TypeError, ValueError):
            LOG.exception(_("ofport should have a value that can be "
                            "interpreted as an integer"))
        if ofport_int < 0:
            LOG.error(_("Failed to set-up %(type)s tunnel port to %(ip)s"),
                      {'type': tunnel_type, 'ip': remote_ip})
            return 0

        self.tun_br_ofports[tunnel_type][remote_ip] = ofport
        # Add flow in default table to resubmit to the right
        # tunelling table (lvid will be set in the latter)
        self.tun_br.add_flow(priority=1,
                             in_port=ofport,
                             actions="resubmit(,%s)" %
                             constants.TUN_TABLE[tunnel_type])

        ofports = ','.join(self.tun_br_ofports[tunnel_type].values())
        if ofports and not self.l2_pop:
            # Update flooding flows to include the new tunnel
            for network_id, vlan_mapping in self.local_vlan_map.iteritems():
                if vlan_mapping.network_type == tunnel_type:
                    self.tun_br.mod_flow(table=constants.FLOOD_TO_TUN,
                                         dl_vlan=vlan_mapping.vlan,
                                         actions="strip_vlan,"
                                         "set_tunnel:%s,output:%s" %
                                         (vlan_mapping.segmentation_id,
                                          ofports))
        return ofport

    def cleanup_tunnel_port(self, tun_ofport, tunnel_type):
        # Check if this tunnel port is still used
        for lvm in self.local_vlan_map.values():
            if tun_ofport in lvm.tun_ofports:
                break
        # If not, remove it
        else:
            for remote_ip, ofport in self.tun_br_ofports[tunnel_type].items():
                if ofport == tun_ofport:
                    port_name = '%s-%s' % (tunnel_type,
                                           self.get_ip_in_hex(remote_ip))
                    self.tun_br.delete_port(port_name)
                    self.tun_br_ofports[tunnel_type].pop(remote_ip, None)

    def treat_devices_added_or_updated(self, devices, ovs_restarted):
        skipped_devices = []
        devices_details_list = []
        for device in devices:
            try:
                # TODO(salv-orlando): Provide bulk API for retrieving
                # details for all devices in one call
                devices_details_list.append(
                    self.plugin_rpc.get_device_details(
                        self.context, device, self.agent_id))
            except Exception as e:
                LOG.debug(_("Unable to get port details for "
                            "%(device)s: %(e)s"),
                          {'device': device, 'e': e})
                raise DeviceListRetrievalError(devices=devices, error=e)

        for details in devices_details_list:
            device = details['device']
            LOG.debug(_("Processing port %s"), device)
            port = self.int_br.get_vif_port_by_id(device)
            if not port:
                # The port disappeared and cannot be processed
                LOG.info(_("Port %s was not found on the integration bridge "
                           "and will therefore not be processed"), device)
                skipped_devices.append(device)
                continue

            if 'port_id' in details:
                LOG.info(_("Port %(device)s updated. Details: %(details)s"),
                         {'device': device, 'details': details})
                self.treat_vif_port(port, details['port_id'],
                                    details['network_id'],
                                    details['network_type'],
                                    details['physical_network'],
                                    details['segmentation_id'],
                                    details['admin_state_up'],
                                    ovs_restarted)
                # update plugin about port status
                # FIXME(salv-orlando): Failures while updating device status
                # must be handled appropriately. Otherwise this might prevent
                # neutron server from sending network-vif-* events to the nova
                # API server, thus possibly preventing instance spawn.
                if details.get('admin_state_up'):
                    LOG.debug(_("Setting status for %s to UP"), device)
                    self.plugin_rpc.update_device_up(
                        self.context, device, self.agent_id, cfg.CONF.host)
                else:
                    LOG.debug(_("Setting status for %s to DOWN"), device)
                    self.plugin_rpc.update_device_down(
                        self.context, device, self.agent_id, cfg.CONF.host)
                LOG.info(_("Configuration for device %s completed."), device)
            else:
                LOG.warn(_("Device %s not defined on plugin"), device)
                if (port and port.ofport != -1):
                    self.port_dead(port)
        return skipped_devices

    def treat_ancillary_devices_added(self, devices):
        devices_details_list = []
        for device in devices:
            try:
                # TODO(salv-orlando): Provide bulk API for retrieving
                # details for all devices in one call
                devices_details_list.append(
                    self.plugin_rpc.get_device_details(
                        self.context, device, self.agent_id))
            except Exception as e:
                LOG.debug(_("Unable to get port details for "
                            "%(device)s: %(e)s"),
                          {'device': device, 'e': e})
                raise DeviceListRetrievalError(devices=devices, error=e)

        for details in devices_details_list:
            device = details['device']
            LOG.info(_("Ancillary Port %s added"), device)

            # update plugin about port status
            self.plugin_rpc.update_device_up(self.context,
                                             device,
                                             self.agent_id,
                                             cfg.CONF.host)

    def treat_devices_removed(self, devices):
        resync = False
        self.sg_agent.remove_devices_filter(devices)
        for device in devices:
            LOG.info(_("Attachment %s removed"), device)
            try:
                self.plugin_rpc.update_device_down(self.context,
                                                   device,
                                                   self.agent_id,
                                                   cfg.CONF.host)
            except Exception as e:
                LOG.debug(_("port_removed failed for %(device)s: %(e)s"),
                          {'device': device, 'e': e})
                resync = True
                continue
            self.port_unbound(device)
        return resync

    def treat_ancillary_devices_removed(self, devices):
        resync = False
        for device in devices:
            LOG.info(_("Attachment %s removed"), device)
            try:
                details = self.plugin_rpc.update_device_down(self.context,
                                                             device,
                                                             self.agent_id,
                                                             cfg.CONF.host)
            except Exception as e:
                LOG.debug(_("port_removed failed for %(device)s: %(e)s"),
                          {'device': device, 'e': e})
                resync = True
                continue
            if details['exists']:
                LOG.info(_("Port %s updated."), device)
                # Nothing to do regarding local networking
            else:
                LOG.debug(_("Device %s not defined on plugin"), device)
        return resync

    def process_network_ports(self, port_info, ovs_restarted):
        resync_a = False
        resync_b = False
        # TODO(salv-orlando): consider a solution for ensuring notifications
        # are processed exactly in the same order in which they were
        # received. This is tricky because there are two notification
        # sources: the neutron server, and the ovs db monitor process
        # If there is an exception while processing security groups ports
        # will not be wired anyway, and a resync will be triggered
        # TODO(salv-orlando): Optimize avoiding applying filters unnecessarily
        # (eg: when there are no IP address changes)
        self.sg_agent.setup_port_filters(port_info.get('added', set()),
                                         port_info.get('updated', set()))
        # VIF wiring needs to be performed always for 'new' devices.
        # For updated ports, re-wiring is not needed in most cases, but needs
        # to be performed anyway when the admin state of a device is changed.
        # A device might be both in the 'added' and 'updated'
        # list at the same time; avoid processing it twice.
        devices_added_updated = (port_info.get('added', set()) |
                                 port_info.get('updated', set()))
        if devices_added_updated:
            start = time.time()
            try:
                skipped_devices = self.treat_devices_added_or_updated(
                    devices_added_updated, ovs_restarted)
                LOG.debug(_("process_network_ports - iteration:%(iter_num)d -"
                            "treat_devices_added_or_updated completed. "
                            "Skipped %(num_skipped)d devices of "
                            "%(num_current)d devices currently available. "
                            "Time elapsed: %(elapsed).3f"),
                          {'iter_num': self.iter_num,
                           'num_skipped': len(skipped_devices),
                           'num_current': len(port_info['current']),
                           'elapsed': time.time() - start})
                # Update the list of current ports storing only those which
                # have been actually processed.
                port_info['current'] = (port_info['current'] -
                                        set(skipped_devices))
            except DeviceListRetrievalError:
                # Need to resync as there was an error with server
                # communication.
                LOG.exception(_("process_network_ports - iteration:%d - "
                                "failure while retrieving port details "
                                "from server"), self.iter_num)
                resync_a = True
        if 'removed' in port_info:
            start = time.time()
            resync_b = self.treat_devices_removed(port_info['removed'])
            LOG.debug(_("process_network_ports - iteration:%(iter_num)d -"
                        "treat_devices_removed completed in %(elapsed).3f"),
                      {'iter_num': self.iter_num,
                       'elapsed': time.time() - start})
        # If one of the above opertaions fails => resync with plugin
        return (resync_a | resync_b)

    def process_ancillary_network_ports(self, port_info):
        resync_a = False
        resync_b = False
        if 'added' in port_info:
            start = time.time()
            try:
                self.treat_ancillary_devices_added(port_info['added'])
                LOG.debug(_("process_ancillary_network_ports - iteration: "
                            "%(iter_num)d - treat_ancillary_devices_added "
                            "completed in %(elapsed).3f"),
                          {'iter_num': self.iter_num,
                           'elapsed': time.time() - start})
            except DeviceListRetrievalError:
                # Need to resync as there was an error with server
                # communication.
                LOG.exception(_("process_ancillary_network_ports - "
                                "iteration:%d - failure while retrieving "
                                "port details from server"), self.iter_num)
                resync_a = True
        if 'removed' in port_info:
            start = time.time()
            resync_b = self.treat_ancillary_devices_removed(
                port_info['removed'])
            LOG.debug(_("process_ancillary_network_ports - iteration: "
                        "%(iter_num)d - treat_ancillary_devices_removed "
                        "completed in %(elapsed).3f"),
                      {'iter_num': self.iter_num,
                       'elapsed': time.time() - start})

        # If one of the above opertaions fails => resync with plugin
        return (resync_a | resync_b)

    def get_ip_in_hex(self, ip_address):
        try:
            return '%08x' % netaddr.IPAddress(ip_address, version=4)
        except Exception:
            LOG.warn(_("Unable to create tunnel port. Invalid remote IP: %s"),
                     ip_address)
            return

    def tunnel_sync(self):
        resync = False
        try:
            for tunnel_type in self.tunnel_types:
                details = self.plugin_rpc.tunnel_sync(self.context,
                                                      self.local_ip,
                                                      tunnel_type)
                if not self.l2_pop:
                    tunnels = details['tunnels']
                    for tunnel in tunnels:
                        if self.local_ip != tunnel['ip_address']:
                            tunnel_id = tunnel.get('id')
                            # Unlike the OVS plugin, ML2 doesn't return an id
                            # key. So use ip_address to form port name instead.
                            # Port name must be <=15 chars, so use shorter hex.
                            remote_ip = tunnel['ip_address']
                            remote_ip_hex = self.get_ip_in_hex(remote_ip)
                            if not tunnel_id and not remote_ip_hex:
                                continue
                            tun_name = '%s-%s' % (tunnel_type,
                                                  tunnel_id or remote_ip_hex)
                            self.setup_tunnel_port(tun_name,
                                                   tunnel['ip_address'],
                                                   tunnel_type)
        except Exception as e:
            LOG.debug(_("Unable to sync tunnel IP %(local_ip)s: %(e)s"),
                      {'local_ip': self.local_ip, 'e': e})
            resync = True
        return resync

    def _agent_has_updates(self, polling_manager):
        return (polling_manager.is_polling_required or
                self.updated_ports or
                self.sg_agent.firewall_refresh_needed())

    def _port_info_has_changes(self, port_info):
        return (port_info.get('added') or
                port_info.get('removed') or
                port_info.get('updated'))

    def check_ovs_restart(self):
        # Check for the canary flow
        canary_flow = self.int_br.dump_flows_for_table(constants.CANARY_TABLE)
        return not canary_flow

    def rpc_loop(self, polling_manager=None):
        if not polling_manager:
            polling_manager = polling.AlwaysPoll()

        sync = True
        ports = set()
        updated_ports_copy = set()
        ancillary_ports = set()
        tunnel_sync = True
        ovs_restarted = False
        while self.run_daemon_loop:
            start = time.time()
            port_stats = {'regular': {'added': 0,
                                      'updated': 0,
                                      'removed': 0},
                          'ancillary': {'added': 0,
                                        'removed': 0}}
            LOG.debug(_("Agent rpc_loop - iteration:%d started"),
                      self.iter_num)
            if sync:
                LOG.info(_("Agent out of sync with plugin!"))
                ports.clear()
                ancillary_ports.clear()
                sync = False
                polling_manager.force_polling()
            ovs_restarted = self.check_ovs_restart()
            if ovs_restarted:
                self.setup_integration_br()
                self.setup_physical_bridges(self.bridge_mappings)
                if self.enable_tunneling:
                    self.setup_tunnel_br()
                    tunnel_sync = True
            # Notify the plugin of tunnel IP
            if self.enable_tunneling and tunnel_sync:
                LOG.info(_("Agent tunnel out of sync with plugin!"))
                try:
                    tunnel_sync = self.tunnel_sync()
                except Exception:
                    LOG.exception(_("Error while synchronizing tunnels"))
                    tunnel_sync = True
            if self._agent_has_updates(polling_manager) or ovs_restarted:
                try:
                    LOG.debug(_("Agent rpc_loop - iteration:%(iter_num)d - "
                                "starting polling. Elapsed:%(elapsed).3f"),
                              {'iter_num': self.iter_num,
                               'elapsed': time.time() - start})
                    # Save updated ports dict to perform rollback in
                    # case resync would be needed, and then clear
                    # self.updated_ports. As the greenthread should not yield
                    # between these two statements, this will be thread-safe
                    updated_ports_copy = self.updated_ports
                    self.updated_ports = set()
                    reg_ports = (set() if ovs_restarted else ports)
                    port_info = self.scan_ports(reg_ports, updated_ports_copy)
                    LOG.debug(_("Agent rpc_loop - iteration:%(iter_num)d - "
                                "port information retrieved. "
                                "Elapsed:%(elapsed).3f"),
                              {'iter_num': self.iter_num,
                               'elapsed': time.time() - start})
                    # Secure and wire/unwire VIFs and update their status
                    # on Neutron server
                    if (self._port_info_has_changes(port_info) or
                        self.sg_agent.firewall_refresh_needed() or
                        ovs_restarted):
                        LOG.debug(_("Starting to process devices in:%s"),
                                  port_info)
                        # If treat devices fails - must resync with plugin
                        sync = self.process_network_ports(port_info,
                                                          ovs_restarted)
                        LOG.debug(_("Agent rpc_loop - iteration:%(iter_num)d -"
                                    "ports processed. Elapsed:%(elapsed).3f"),
                                  {'iter_num': self.iter_num,
                                   'elapsed': time.time() - start})
                        port_stats['regular']['added'] = (
                            len(port_info.get('added', [])))
                        port_stats['regular']['updated'] = (
                            len(port_info.get('updated', [])))
                        port_stats['regular']['removed'] = (
                            len(port_info.get('removed', [])))
                    ports = port_info['current']
                    # Treat ancillary devices if they exist
                    if self.ancillary_brs:
                        port_info = self.update_ancillary_ports(
                            ancillary_ports)
                        LOG.debug(_("Agent rpc_loop - iteration:%(iter_num)d -"
                                    "ancillary port info retrieved. "
                                    "Elapsed:%(elapsed).3f"),
                                  {'iter_num': self.iter_num,
                                   'elapsed': time.time() - start})

                        if port_info:
                            rc = self.process_ancillary_network_ports(
                                port_info)
                            LOG.debug(_("Agent rpc_loop - iteration:"
                                        "%(iter_num)d - ancillary ports "
                                        "processed. Elapsed:%(elapsed).3f"),
                                      {'iter_num': self.iter_num,
                                       'elapsed': time.time() - start})
                            ancillary_ports = port_info['current']
                            port_stats['ancillary']['added'] = (
                                len(port_info.get('added', [])))
                            port_stats['ancillary']['removed'] = (
                                len(port_info.get('removed', [])))
                            sync = sync | rc

                    polling_manager.polling_completed()
                except Exception:
                    LOG.exception(_("Error while processing VIF ports"))
                    # Put the ports back in self.updated_port
                    self.updated_ports |= updated_ports_copy
                    sync = True

            # sleep till end of polling interval
            elapsed = (time.time() - start)
            LOG.debug(_("Agent rpc_loop - iteration:%(iter_num)d "
                        "completed. Processed ports statistics: "
                        "%(port_stats)s. Elapsed:%(elapsed).3f"),
                      {'iter_num': self.iter_num,
                       'port_stats': port_stats,
                       'elapsed': elapsed})
            if (elapsed < self.polling_interval):
                time.sleep(self.polling_interval - elapsed)
            else:
                LOG.debug(_("Loop iteration exceeded interval "
                            "(%(polling_interval)s vs. %(elapsed)s)!"),
                          {'polling_interval': self.polling_interval,
                           'elapsed': elapsed})
            self.iter_num = self.iter_num + 1

    def daemon_loop(self):
        with polling.get_polling_manager(
            self.minimize_polling,
            self.root_helper,
            self.ovsdb_monitor_respawn_interval) as pm:

            self.rpc_loop(polling_manager=pm)

    def _handle_sigterm(self, signum, frame):
        LOG.debug("Agent caught SIGTERM, quitting daemon loop.")
        self.run_daemon_loop = False


def create_agent_config_map(config):
    """Create a map of agent config parameters.

    :param config: an instance of cfg.CONF
    :returns: a map of agent configuration parameters
    """
    try:
        bridge_mappings = q_utils.parse_mappings(config.OVS.bridge_mappings)
    except ValueError as e:
        raise ValueError(_("Parsing bridge_mappings failed: %s.") % e)

    kwargs = dict(
        integ_br=config.OVS.integration_bridge,
        tun_br=config.OVS.tunnel_bridge,
        local_ip=config.OVS.local_ip,
        bridge_mappings=bridge_mappings,
        root_helper=config.AGENT.root_helper,
        polling_interval=config.AGENT.polling_interval,
        minimize_polling=config.AGENT.minimize_polling,
        tunnel_types=config.AGENT.tunnel_types,
        veth_mtu=config.AGENT.veth_mtu,
        l2_population=config.AGENT.l2_population,
    )

    # If enable_tunneling is TRUE, set tunnel_type to default to GRE
    if config.OVS.enable_tunneling and not kwargs['tunnel_types']:
        kwargs['tunnel_types'] = [p_const.TYPE_GRE]

    # Verify the tunnel_types specified are valid
    for tun in kwargs['tunnel_types']:
        if tun not in constants.TUNNEL_NETWORK_TYPES:
            msg = _('Invalid tunnel type specificed: %s'), tun
            raise ValueError(msg)
        if not kwargs['local_ip']:
            msg = _('Tunneling cannot be enabled without a valid local_ip.')
            raise ValueError(msg)

    return kwargs


def main():
    eventlet.monkey_patch()
    cfg.CONF.register_opts(ip_lib.OPTS)
    cfg.CONF(project='neutron')
    logging_config.setup_logging(cfg.CONF)
    q_utils.log_opt_values(LOG)
    legacy.modernize_quantum_config(cfg.CONF)

    try:
        agent_config = create_agent_config_map(cfg.CONF)
    except ValueError as e:
        LOG.error(_('%s Agent terminated!'), e)
        sys.exit(1)

    is_xen_compute_host = 'rootwrap-xen-dom0' in agent_config['root_helper']
    if is_xen_compute_host:
        # Force ip_lib to always use the root helper to ensure that ip
        # commands target xen dom0 rather than domU.
        cfg.CONF.set_default('ip_lib_force_root', True)

    agent = OVSNeutronAgent(**agent_config)
    signal.signal(signal.SIGTERM, agent._handle_sigterm)

    # Start everything.
    LOG.info(_("Agent initialized successfully, now running... "))
    agent.daemon_loop()


if __name__ == "__main__":
    main()
