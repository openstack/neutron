# Copyright (C) 2014 VA Linux Systems Japan K.K.
# Based on openvswitch agent.
#
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
# @author: Fumihiko Kakuma, VA Linux Systems Japan K.K.

import time

import netaddr
from oslo.config import cfg
from ryu.app.ofctl import api as ryu_api
from ryu.base import app_manager
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_3 as ryu_ofp13

from neutron.agent.linux import ip_lib
from neutron.agent.linux import ovs_lib
from neutron.agent.linux import polling
from neutron.agent.linux import utils
from neutron.agent import rpc as agent_rpc
from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.common import constants as n_const
from neutron.common import topics
from neutron.common import utils as n_utils
from neutron import context
from neutron.openstack.common import log as logging
from neutron.openstack.common import loopingcall
from neutron.openstack.common.rpc import dispatcher
from neutron.plugins.common import constants as p_const
from neutron.plugins.ofagent.common import config  # noqa
from neutron.plugins.openvswitch.common import constants


LOG = logging.getLogger(__name__)

# A placeholder for dead vlans.
DEAD_VLAN_TAG = str(n_const.MAX_VLAN_TAG + 1)


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
        """Compare only fields that will cause us to re-wire."""
        try:
            return (other and self.id == other.id
                    and self.admin_state_up == other.admin_state_up)
        except Exception:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.id)


class OVSBridge(ovs_lib.OVSBridge):
    def __init__(self, br_name, root_helper, ryuapp):
        super(OVSBridge, self).__init__(br_name, root_helper)
        self.datapath_id = None
        self.datapath = None
        self.ofparser = None
        self.ryuapp = ryuapp

    def find_datapath_id(self):
        self.datapath_id = self.get_datapath_id()

    def get_datapath(self, retry_max=cfg.CONF.AGENT.get_datapath_retry_times):
        retry = 0
        while self.datapath is None:
            self.datapath = ryu_api.get_datapath(self.ryuapp,
                                                 int(self.datapath_id, 16))
            retry += 1
            if retry >= retry_max:
                LOG.error(_('Agent terminated!: Failed to get a datapath.'))
                raise SystemExit(1)
            time.sleep(1)
        self.ofparser = self.datapath.ofproto_parser

    def setup_ofp(self, controller_names=None,
                  protocols='OpenFlow13',
                  retry_max=cfg.CONF.AGENT.get_datapath_retry_times):
        if not controller_names:
            host = cfg.CONF.ofp_listen_host
            if not host:
                # 127.0.0.1 is a default for agent style of controller
                host = '127.0.0.1'
            controller_names = ["tcp:%s:%d" % (host,
                                               cfg.CONF.ofp_tcp_listen_port)]
        try:
            self.set_protocols(protocols)
            self.set_controller(controller_names)
        except RuntimeError:
            LOG.exception(_("Agent terminated"))
            raise SystemExit(1)
        self.find_datapath_id()
        self.get_datapath(retry_max)


class OFAPluginApi(agent_rpc.PluginApi,
                   sg_rpc.SecurityGroupServerRpcApiMixin):
    pass


class OFASecurityGroupAgent(sg_rpc.SecurityGroupAgentRpcMixin):
    def __init__(self, context, plugin_rpc, root_helper):
        self.context = context
        self.plugin_rpc = plugin_rpc
        self.root_helper = root_helper
        self.init_firewall(defer_refresh_firewall=True)


class OFANeutronAgentRyuApp(app_manager.RyuApp):
    OFP_VERSIONS = [ryu_ofp13.OFP_VERSION]

    def start(self):

        super(OFANeutronAgentRyuApp, self).start()
        return hub.spawn(self._agent_main, self)

    def _agent_main(self, ryuapp):
        cfg.CONF.register_opts(ip_lib.OPTS)
        n_utils.log_opt_values(LOG)

        try:
            agent_config = create_agent_config_map(cfg.CONF)
        except ValueError:
            LOG.exception(_("Agent failed to create agent config map"))
            raise SystemExit(1)

        is_xen_compute_host = ('rootwrap-xen-dom0' in
                               agent_config['root_helper'])
        if is_xen_compute_host:
            # Force ip_lib to always use the root helper to ensure that ip
            # commands target xen dom0 rather than domU.
            cfg.CONF.set_default('ip_lib_force_root', True)

        agent = OFANeutronAgent(ryuapp, **agent_config)

        # Start everything.
        LOG.info(_("Agent initialized successfully, now running... "))
        agent.daemon_loop()


class OFANeutronAgent(sg_rpc.SecurityGroupAgentRpcCallbackMixin):
    """A agent for OpenFlow Agent ML2 mechanism driver.

    OFANeutronAgent is a OpenFlow Agent agent for a ML2 plugin.
    This is as a ryu application thread.
    - An agent acts as an OpenFlow controller on each compute nodes.
    - OpenFlow 1.3 (vendor agnostic unlike OVS extensions).
    """

    # history
    #   1.0 Initial version
    #   1.1 Support Security Group RPC
    RPC_API_VERSION = '1.1'

    def __init__(self, ryuapp, integ_br, tun_br, local_ip,
                 bridge_mappings, root_helper,
                 polling_interval, tunnel_types=None,
                 veth_mtu=None, l2_population=False,
                 minimize_polling=False,
                 ovsdb_monitor_respawn_interval=(
                     constants.DEFAULT_OVSDBMON_RESPAWN)):
        """Constructor.

        :param ryuapp: object of the ryu app.
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
        """
        self.ryuapp = ryuapp
        self.veth_mtu = veth_mtu
        self.root_helper = root_helper
        self.available_local_vlans = set(xrange(n_const.MIN_VLAN_TAG,
                                                n_const.MAX_VLAN_TAG))
        self.tunnel_types = tunnel_types or []
        self.l2_pop = l2_population
        self.agent_state = {
            'binary': 'neutron-ofa-agent',
            'host': cfg.CONF.host,
            'topic': n_const.L2_AGENT_TOPIC,
            'configurations': {'bridge_mappings': bridge_mappings,
                               'tunnel_types': self.tunnel_types,
                               'tunneling_ip': local_ip,
                               'l2_population': self.l2_pop},
            'agent_type': n_const.AGENT_TYPE_OFA,
            'start_flag': True}

        # Keep track of int_br's device count for use by _report_state()
        self.int_br_device_count = 0

        self.int_br = OVSBridge(integ_br, self.root_helper, self.ryuapp)
        # Stores port update notifications for processing in main loop
        self.updated_ports = set()
        self.setup_rpc()
        self.setup_integration_br()
        self.setup_physical_bridges(bridge_mappings)
        self.local_vlan_map = {}
        self.tun_br_ofports = {p_const.TYPE_GRE: {},
                               p_const.TYPE_VXLAN: {}}

        self.polling_interval = polling_interval
        self.minimize_polling = minimize_polling
        self.ovsdb_monitor_respawn_interval = ovsdb_monitor_respawn_interval

        self.enable_tunneling = bool(self.tunnel_types)
        self.local_ip = local_ip
        self.tunnel_count = 0
        self.vxlan_udp_port = cfg.CONF.AGENT.vxlan_udp_port
        self._check_ovs_version()
        if self.enable_tunneling:
            self.setup_tunnel_br(tun_br)
        # Collect additional bridges to monitor
        self.ancillary_brs = self.setup_ancillary_bridges(integ_br, tun_br)

        # Security group agent support
        self.sg_agent = OFASecurityGroupAgent(self.context,
                                              self.plugin_rpc,
                                              self.root_helper)
        # Initialize iteration counter
        self.iter_num = 0

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

    def _create_tunnel_port_name(self, tunnel_type, ip_address):
        try:
            ip_hex = '%08x' % netaddr.IPAddress(ip_address, version=4)
            return '%s-%s' % (tunnel_type, ip_hex)
        except Exception:
            LOG.warn(_("Unable to create tunnel port. Invalid remote IP: %s"),
                     ip_address)

    def ryu_send_msg(self, msg):
        result = ryu_api.send_msg(self.ryuapp, msg)
        LOG.info(_("ryu send_msg() result: %s"), result)

    def setup_rpc(self):
        mac = self.int_br.get_local_port_mac()
        self.agent_id = '%s%s' % ('ovs', (mac.replace(":", "")))
        self.topic = topics.AGENT
        self.plugin_rpc = OFAPluginApi(topics.PLUGIN)
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
        network_id = kwargs.get('network_id')
        LOG.debug(_("network_delete received network %s"), network_id)
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
        LOG.debug(_("port_update received port %s"), port['id'])

    def tunnel_update(self, context, **kwargs):
        LOG.debug(_("tunnel_update received"))
        if not self.enable_tunneling:
            return
        tunnel_ip = kwargs.get('tunnel_ip')
        tunnel_type = kwargs.get('tunnel_type')
        if not tunnel_type:
            LOG.error(_("No tunnel_type specified, cannot create tunnels"))
            return
        if tunnel_type not in self.tunnel_types:
            LOG.error(_("tunnel_type %s not supported by agent"), tunnel_type)
            return
        if tunnel_ip == self.local_ip:
            return
        tun_name = self._create_tunnel_port_name(tunnel_type, tunnel_ip)
        if not tun_name:
            return
        self.setup_tunnel_port(tun_name, tunnel_ip, tunnel_type)

    def create_rpc_dispatcher(self):
        """Get the rpc dispatcher for this manager.

        If a manager would like to set an rpc API version, or support more than
        one class as the target of rpc messages, override this method.
        """
        return dispatcher.RpcDispatcher([self])

    def _provision_local_vlan_outbound_for_tunnel(self, lvid,
                                                  segmentation_id, ofports):
        br = self.tun_br
        match = br.ofparser.OFPMatch(
            vlan_vid=int(lvid) | ryu_ofp13.OFPVID_PRESENT)
        actions = [br.ofparser.OFPActionPopVlan(),
                   br.ofparser.OFPActionSetField(
                       tunnel_id=int(segmentation_id))]
        for ofport in ofports:
            actions.append(br.ofparser.OFPActionOutput(ofport, 0))
        instructions = [br.ofparser.OFPInstructionActions(
                        ryu_ofp13.OFPIT_APPLY_ACTIONS, actions)]
        msg = br.ofparser.OFPFlowMod(
            br.datapath,
            table_id=constants.FLOOD_TO_TUN,
            priority=1,
            match=match, instructions=instructions)
        self.ryu_send_msg(msg)

    def _provision_local_vlan_inbound_for_tunnel(self, lvid, network_type,
                                                 segmentation_id):
        br = self.tun_br
        match = br.ofparser.OFPMatch(
            tunnel_id=int(segmentation_id))
        actions = [
            br.ofparser.OFPActionPushVlan(),
            br.ofparser.OFPActionSetField(
                vlan_vid=int(lvid) | ryu_ofp13.OFPVID_PRESENT)]
        instructions = [
            br.ofparser.OFPInstructionActions(
                ryu_ofp13.OFPIT_APPLY_ACTIONS, actions),
            br.ofparser.OFPInstructionGotoTable(
                table_id=constants.LEARN_FROM_TUN)]
        msg = br.ofparser.OFPFlowMod(
            br.datapath,
            table_id=constants.TUN_TABLE[network_type],
            priority=1,
            match=match,
            instructions=instructions)
        self.ryu_send_msg(msg)

    def _local_vlan_for_tunnel(self, lvid, network_type, segmentation_id):
        ofports = [int(ofport) for ofport in
                   self.tun_br_ofports[network_type].values()]
        if ofports:
            self._provision_local_vlan_outbound_for_tunnel(
                lvid, segmentation_id, ofports)
        self._provision_local_vlan_inbound_for_tunnel(lvid, network_type,
                                                      segmentation_id)

    def _provision_local_vlan_outbound(self, lvid, vlan_vid, physical_network):
        br = self.phys_brs[physical_network]
        datapath = br.datapath
        ofp = datapath.ofproto
        ofpp = datapath.ofproto_parser
        match = ofpp.OFPMatch(in_port=int(self.phys_ofports[physical_network]),
                              vlan_vid=int(lvid) | ofp.OFPVID_PRESENT)
        if vlan_vid == ofp.OFPVID_NONE:
            actions = [ofpp.OFPActionPopVlan()]
        else:
            actions = [ofpp.OFPActionSetField(vlan_vid=vlan_vid)]
        actions += [ofpp.OFPActionOutput(ofp.OFPP_NORMAL, 0)]
        instructions = [
            ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions),
        ]
        msg = ofpp.OFPFlowMod(datapath, priority=4, match=match,
                              instructions=instructions)
        self.ryu_send_msg(msg)

    def _provision_local_vlan_inbound(self, lvid, vlan_vid, physical_network):
        datapath = self.int_br.datapath
        ofp = datapath.ofproto
        ofpp = datapath.ofproto_parser
        match = ofpp.OFPMatch(in_port=int(self.int_ofports[physical_network]),
                              vlan_vid=vlan_vid)
        if vlan_vid == ofp.OFPVID_NONE:
            actions = [ofpp.OFPActionPushVlan()]
        else:
            actions = []
        actions += [
            ofpp.OFPActionSetField(vlan_vid=int(lvid) | ofp.OFPVID_PRESENT),
            ofpp.OFPActionOutput(ofp.OFPP_NORMAL, 0),
        ]
        instructions = [
            ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions),
        ]
        msg = ofpp.OFPFlowMod(datapath, priority=3, match=match,
                              instructions=instructions)
        self.ryu_send_msg(msg)

    def _local_vlan_for_flat(self, lvid, physical_network):
        vlan_vid = ryu_ofp13.OFPVID_NONE
        self._provision_local_vlan_outbound(lvid, vlan_vid, physical_network)
        self._provision_local_vlan_inbound(lvid, vlan_vid, physical_network)

    def _local_vlan_for_vlan(self, lvid, physical_network, segmentation_id):
        vlan_vid = int(segmentation_id) | ryu_ofp13.OFPVID_PRESENT
        self._provision_local_vlan_outbound(lvid, vlan_vid, physical_network)
        self._provision_local_vlan_inbound(lvid, vlan_vid, physical_network)

    def provision_local_vlan(self, net_uuid, network_type, physical_network,
                             segmentation_id):
        """Provisions a local VLAN.

        :param net_uuid: the uuid of the network associated with this vlan.
        :param network_type: the network type ('gre', 'vxlan', 'vlan', 'flat',
                                               'local')
        :param physical_network: the physical network for 'vlan' or 'flat'
        :param segmentation_id: the VID for 'vlan' or tunnel ID for 'tunnel'
        """

        if not self.available_local_vlans:
            LOG.error(_("No local VLAN available for net-id=%s"), net_uuid)
            return
        lvid = self.available_local_vlans.pop()
        LOG.info(_("Assigning %(vlan_id)s as local vlan for "
                   "net-id=%(net_uuid)s"),
                 {'vlan_id': lvid, 'net_uuid': net_uuid})
        self.local_vlan_map[net_uuid] = LocalVLANMapping(lvid, network_type,
                                                         physical_network,
                                                         segmentation_id)

        if network_type in constants.TUNNEL_NETWORK_TYPES:
            if self.enable_tunneling:
                self._local_vlan_for_tunnel(lvid, network_type,
                                            segmentation_id)
            else:
                LOG.error(_("Cannot provision %(network_type)s network for "
                          "net-id=%(net_uuid)s - tunneling disabled"),
                          {'network_type': network_type,
                           'net_uuid': net_uuid})
        elif network_type == p_const.TYPE_FLAT:
            if physical_network in self.phys_brs:
                self._local_vlan_for_flat(lvid, physical_network)
            else:
                LOG.error(_("Cannot provision flat network for "
                            "net-id=%(net_uuid)s - no bridge for "
                            "physical_network %(physical_network)s"),
                          {'net_uuid': net_uuid,
                           'physical_network': physical_network})
        elif network_type == p_const.TYPE_VLAN:
            if physical_network in self.phys_brs:
                self._local_vlan_for_vlan(lvid, physical_network,
                                          segmentation_id)
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

    def _reclaim_local_vlan_outbound(self, lvm):
        br = self.phys_brs[lvm.physical_network]
        datapath = br.datapath
        ofp = datapath.ofproto
        ofpp = datapath.ofproto_parser
        match = ofpp.OFPMatch(
            in_port=int(self.phys_ofports[lvm.physical_network]),
            vlan_vid=int(lvm.vlan) | ofp.OFPVID_PRESENT)
        msg = ofpp.OFPFlowMod(datapath, table_id=ofp.OFPTT_ALL,
                              command=ofp.OFPFC_DELETE, out_group=ofp.OFPG_ANY,
                              out_port=ofp.OFPP_ANY, match=match)
        self.ryu_send_msg(msg)

    def _reclaim_local_vlan_inbound(self, lvm):
        datapath = self.int_br.datapath
        ofp = datapath.ofproto
        ofpp = datapath.ofproto_parser
        if lvm.network_type == p_const.TYPE_FLAT:
            vid = ofp.OFPVID_NONE
        else:  # p_const.TYPE_VLAN
            vid = lvm.segmentation_id | ofp.OFPVID_PRESENT
        match = ofpp.OFPMatch(
            in_port=int(self.int_ofports[lvm.physical_network]),
            vlan_vid=vid)
        msg = ofpp.OFPFlowMod(datapath, table_id=ofp.OFPTT_ALL,
                              command=ofp.OFPFC_DELETE, out_group=ofp.OFPG_ANY,
                              out_port=ofp.OFPP_ANY, match=match)
        self.ryu_send_msg(msg)

    def reclaim_local_vlan(self, net_uuid):
        """Reclaim a local VLAN.

        :param net_uuid: the network uuid associated with this vlan.
        :param lvm: a LocalVLANMapping object that tracks (vlan, lsw_id,
            vif_ids) mapping.
        """
        lvm = self.local_vlan_map.pop(net_uuid, None)
        if lvm is None:
            LOG.debug(_("Network %s not used on agent."), net_uuid)
            return

        LOG.info(_("Reclaiming vlan = %(vlan_id)s from net-id = %(net_uuid)s"),
                 {'vlan_id': lvm.vlan,
                  'net_uuid': net_uuid})

        if lvm.network_type in constants.TUNNEL_NETWORK_TYPES:
            if self.enable_tunneling:
                match = self.tun_br.ofparser.OFPMatch(
                    tunnel_id=int(lvm.segmentation_id))
                msg = self.tun_br.ofparser.OFPFlowMod(
                    self.tun_br.datapath,
                    table_id=constants.TUN_TABLE[lvm.network_type],
                    command=ryu_ofp13.OFPFC_DELETE,
                    out_group=ryu_ofp13.OFPG_ANY,
                    out_port=ryu_ofp13.OFPP_ANY,
                    match=match)
                self.ryu_send_msg(msg)
                match = self.tun_br.ofparser.OFPMatch(
                    vlan_vid=int(lvm.vlan) | ryu_ofp13.OFPVID_PRESENT)
                msg = self.tun_br.ofparser.OFPFlowMod(
                    self.tun_br.datapath,
                    table_id=ryu_ofp13.OFPTT_ALL,
                    command=ryu_ofp13.OFPFC_DELETE,
                    out_group=ryu_ofp13.OFPG_ANY,
                    out_port=ryu_ofp13.OFPP_ANY,
                    match=match)
                self.ryu_send_msg(msg)
        elif lvm.network_type in (p_const.TYPE_FLAT, p_const.TYPE_VLAN):
            if lvm.physical_network in self.phys_brs:
                self._reclaim_local_vlan_outbound(lvm)
                self._reclaim_local_vlan_inbound(lvm)
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
                   network_type, physical_network, segmentation_id):
        """Bind port to net_uuid/lsw_id and install flow for inbound traffic
        to vm.

        :param port: a ovs_lib.VifPort object.
        :param net_uuid: the net_uuid this port is to be associated with.
        :param network_type: the network type ('gre', 'vlan', 'flat', 'local')
        :param physical_network: the physical network for 'vlan' or 'flat'
        :param segmentation_id: the VID for 'vlan' or tunnel ID for 'tunnel'
        """
        if net_uuid not in self.local_vlan_map:
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
                match = self.int_br.ofparser.OFPMatch(in_port=port.ofport)
                msg = self.int_br.ofparser.OFPFlowMod(
                    self.int_br.datapath,
                    table_id=ryu_ofp13.OFPTT_ALL,
                    command=ryu_ofp13.OFPFC_DELETE,
                    out_group=ryu_ofp13.OFPG_ANY,
                    out_port=ryu_ofp13.OFPP_ANY,
                    match=match)
                self.ryu_send_msg(msg)

    def port_unbound(self, vif_id, net_uuid=None):
        """Unbind port.

        Removes corresponding local vlan mapping object if this is its last
        VIF.

        :param vif_id: the id of the vif
        :param net_uuid: the net_uuid this port is associated with.
        """
        net_uuid = net_uuid or self.get_net_uuid(vif_id)

        if not self.local_vlan_map.get(net_uuid):
            LOG.info(_('port_unbound() net_uuid %s not in local_vlan_map'),
                     net_uuid)
            return

        lvm = self.local_vlan_map[net_uuid]
        lvm.vif_ports.pop(vif_id, None)

        if not lvm.vif_ports:
            self.reclaim_local_vlan(net_uuid)

    def port_dead(self, port):
        """Once a port has no binding, put it on the "dead vlan".

        :param port: a ovs_lib.VifPort object.
        """
        # Don't kill a port if it's already dead
        cur_tag = self.int_br.db_get_val("Port", port.port_name, "tag")
        if cur_tag != DEAD_VLAN_TAG:
            self.int_br.set_db_attribute("Port", port.port_name, "tag",
                                         DEAD_VLAN_TAG)
            match = self.int_br.ofparser.OFPMatch(in_port=port.ofport)
            msg = self.int_br.ofparser.OFPFlowMod(self.int_br.datapath,
                                                  priority=2, match=match)
            self.ryu_send_msg(msg)

    def setup_integration_br(self):
        """Setup the integration bridge.

        Create patch ports and remove all existing flows.

        :param bridge_name: the name of the integration bridge.
        :returns: the integration bridge
        """
        self.int_br.setup_ofp()
        self.int_br.delete_port(cfg.CONF.OVS.int_peer_patch_port)
        msg = self.int_br.ofparser.OFPFlowMod(self.int_br.datapath,
                                              table_id=ryu_ofp13.OFPTT_ALL,
                                              command=ryu_ofp13.OFPFC_DELETE,
                                              out_group=ryu_ofp13.OFPG_ANY,
                                              out_port=ryu_ofp13.OFPP_ANY)
        self.ryu_send_msg(msg)
        # switch all traffic using L2 learning
        actions = [self.int_br.ofparser.OFPActionOutput(
            ryu_ofp13.OFPP_NORMAL, 0)]
        instructions = [self.int_br.ofparser.OFPInstructionActions(
            ryu_ofp13.OFPIT_APPLY_ACTIONS,
            actions)]
        msg = self.int_br.ofparser.OFPFlowMod(self.int_br.datapath,
                                              priority=1,
                                              instructions=instructions)
        self.ryu_send_msg(msg)

    def setup_ancillary_bridges(self, integ_br, tun_br):
        """Setup ancillary bridges - for example br-ex."""
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
        br_names = [
            bridge for bridge in ovs_bridges
            if bridge != ovs_lib.get_bridge_external_bridge_id(
                self.root_helper, bridge)
        ]
        ovs_bridges.difference_update(br_names)
        ancillary_bridges = []
        for bridge in ovs_bridges:
            br = OVSBridge(bridge, self.root_helper, self.ryuapp)
            ancillary_bridges.append(br)
        LOG.info(_('ancillary bridge list: %s.'), ancillary_bridges)
        return ancillary_bridges

    def _tun_br_sort_incoming_traffic_depend_in_port(self, br):
        match = br.ofparser.OFPMatch(
            in_port=int(self.patch_int_ofport))
        instructions = [br.ofparser.OFPInstructionGotoTable(
            table_id=constants.PATCH_LV_TO_TUN)]
        msg = br.ofparser.OFPFlowMod(br.datapath,
                                     priority=1,
                                     match=match,
                                     instructions=instructions)
        self.ryu_send_msg(msg)
        msg = br.ofparser.OFPFlowMod(br.datapath, priority=0)
        self.ryu_send_msg(msg)

    def _tun_br_goto_table_ucast_unicast(self, br):
        match = br.ofparser.OFPMatch(eth_dst=('00:00:00:00:00:00',
                                              '01:00:00:00:00:00'))
        instructions = [br.ofparser.OFPInstructionGotoTable(
            table_id=constants.UCAST_TO_TUN)]
        msg = br.ofparser.OFPFlowMod(br.datapath,
                                     table_id=constants.PATCH_LV_TO_TUN,
                                     match=match,
                                     instructions=instructions)
        self.ryu_send_msg(msg)

    def _tun_br_goto_table_flood_broad_multi_cast(self, br):
        match = br.ofparser.OFPMatch(eth_dst=('01:00:00:00:00:00',
                                              '01:00:00:00:00:00'))
        instructions = [br.ofparser.OFPInstructionGotoTable(
            table_id=constants.FLOOD_TO_TUN)]
        msg = br.ofparser.OFPFlowMod(br.datapath,
                                     table_id=constants.PATCH_LV_TO_TUN,
                                     match=match,
                                     instructions=instructions)
        self.ryu_send_msg(msg)

    def _tun_br_set_table_tun_by_tunnel_type(self, br):
        for tunnel_type in constants.TUNNEL_NETWORK_TYPES:
            msg = br.ofparser.OFPFlowMod(
                br.datapath,
                table_id=constants.TUN_TABLE[tunnel_type],
                priority=0)
            self.ryu_send_msg(msg)

    def _tun_br_output_patch_int(self, br):
        actions = [br.ofparser.OFPActionOutput(
            int(self.patch_int_ofport), 0)]
        instructions = [br.ofparser.OFPInstructionActions(
            ryu_ofp13.OFPIT_APPLY_ACTIONS,
            actions)]
        msg = br.ofparser.OFPFlowMod(br.datapath,
                                     table_id=constants.LEARN_FROM_TUN,
                                     priority=1,
                                     instructions=instructions)
        self.ryu_send_msg(msg)

    def _tun_br_goto_table_flood_unknown_unicast(self, br):
        instructions = [br.ofparser.OFPInstructionGotoTable(
            table_id=constants.FLOOD_TO_TUN)]
        msg = br.ofparser.OFPFlowMod(br.datapath,
                                     table_id=constants.UCAST_TO_TUN,
                                     priority=0,
                                     instructions=instructions)
        self.ryu_send_msg(msg)

    def _tun_br_default_drop(self, br):
        msg = br.ofparser.OFPFlowMod(
            br.datapath,
            table_id=constants.FLOOD_TO_TUN,
            priority=0)
        self.ryu_send_msg(msg)

    def setup_tunnel_br(self, tun_br):
        """Setup the tunnel bridge.

        Creates tunnel bridge, and links it to the integration bridge
        using a patch port.

        :param tun_br: the name of the tunnel bridge.
        """
        self.tun_br = OVSBridge(tun_br, self.root_helper, self.ryuapp)
        self.tun_br.reset_bridge()
        self.tun_br.setup_ofp()
        self.patch_tun_ofport = self.int_br.add_patch_port(
            cfg.CONF.OVS.int_peer_patch_port, cfg.CONF.OVS.tun_peer_patch_port)
        self.patch_int_ofport = self.tun_br.add_patch_port(
            cfg.CONF.OVS.tun_peer_patch_port, cfg.CONF.OVS.int_peer_patch_port)
        if int(self.patch_tun_ofport) < 0 or int(self.patch_int_ofport) < 0:
            LOG.error(_("Failed to create OVS patch port. Cannot have "
                        "tunneling enabled on this agent, since this version "
                        "of OVS does not support tunnels or patch ports. "
                        "Agent terminated!"))
            raise SystemExit(1)
        msg = self.tun_br.ofparser.OFPFlowMod(self.tun_br.datapath,
                                              table_id=ryu_ofp13.OFPTT_ALL,
                                              command=ryu_ofp13.OFPFC_DELETE,
                                              out_group=ryu_ofp13.OFPG_ANY,
                                              out_port=ryu_ofp13.OFPP_ANY)
        self.ryu_send_msg(msg)

        self._tun_br_sort_incoming_traffic_depend_in_port(self.tun_br)
        self._tun_br_goto_table_ucast_unicast(self.tun_br)
        self._tun_br_goto_table_flood_broad_multi_cast(self.tun_br)
        self._tun_br_set_table_tun_by_tunnel_type(self.tun_br)
        self._tun_br_output_patch_int(self.tun_br)
        self._tun_br_goto_table_flood_unknown_unicast(self.tun_br)
        self._tun_br_default_drop(self.tun_br)

    def _phys_br_prepare_create_veth(self, br, int_veth_name, phys_veth_name):
        self.int_br.delete_port(int_veth_name)
        br.delete_port(phys_veth_name)
        if ip_lib.device_exists(int_veth_name, self.root_helper):
            ip_lib.IPDevice(int_veth_name, self.root_helper).link.delete()
            # Give udev a chance to process its rules here, to avoid
            # race conditions between commands launched by udev rules
            # and the subsequent call to ip_wrapper.add_veth
            utils.execute(['/sbin/udevadm', 'settle', '--timeout=10'])

    def _phys_br_create_veth(self, br, int_veth_name,
                             phys_veth_name, physical_network, ip_wrapper):
        int_veth, phys_veth = ip_wrapper.add_veth(int_veth_name,
                                                  phys_veth_name)
        self.int_ofports[physical_network] = self.int_br.add_port(int_veth)
        self.phys_ofports[physical_network] = br.add_port(phys_veth)
        return (int_veth, phys_veth)

    def _phys_br_block_untranslated_traffic(self, br, physical_network):
        match = self.int_br.ofparser.OFPMatch(in_port=int(
            self.int_ofports[physical_network]))
        msg = self.int_br.ofparser.OFPFlowMod(self.int_br.datapath,
                                              priority=2, match=match)
        self.ryu_send_msg(msg)
        match = br.ofparser.OFPMatch(in_port=int(
            self.phys_ofports[physical_network]))
        msg = br.ofparser.OFPFlowMod(br.datapath, priority=2, match=match)
        self.ryu_send_msg(msg)

    def _phys_br_enable_veth_to_pass_traffic(self, int_veth, phys_veth):
        # enable veth to pass traffic
        int_veth.link.set_up()
        phys_veth.link.set_up()

        if self.veth_mtu:
            # set up mtu size for veth interfaces
            int_veth.link.set_mtu(self.veth_mtu)
            phys_veth.link.set_mtu(self.veth_mtu)

    def _phys_br_patch_physical_bridge_with_integration_bridge(
            self, br, physical_network, bridge, ip_wrapper):
        int_veth_name = constants.VETH_INTEGRATION_PREFIX + bridge
        phys_veth_name = constants.VETH_PHYSICAL_PREFIX + bridge
        self._phys_br_prepare_create_veth(br, int_veth_name, phys_veth_name)
        int_veth, phys_veth = self._phys_br_create_veth(br, int_veth_name,
                                                        phys_veth_name,
                                                        physical_network,
                                                        ip_wrapper)
        self._phys_br_block_untranslated_traffic(br, physical_network)
        self._phys_br_enable_veth_to_pass_traffic(int_veth, phys_veth)

    def setup_physical_bridges(self, bridge_mappings):
        """Setup the physical network bridges.

        Creates physical network bridges and links them to the
        integration bridge using veths.

        :param bridge_mappings: map physical network names to bridge names.
        """
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
                raise SystemExit(1)
            br = OVSBridge(bridge, self.root_helper, self.ryuapp)
            br.setup_ofp()
            msg = br.ofparser.OFPFlowMod(br.datapath,
                                         table_id=ryu_ofp13.OFPTT_ALL,
                                         command=ryu_ofp13.OFPFC_DELETE,
                                         out_group=ryu_ofp13.OFPG_ANY,
                                         out_port=ryu_ofp13.OFPP_ANY)
            self.ryu_send_msg(msg)
            actions = [br.ofparser.OFPActionOutput(ryu_ofp13.OFPP_NORMAL, 0)]
            instructions = [br.ofparser.OFPInstructionActions(
                ryu_ofp13.OFPIT_APPLY_ACTIONS,
                actions)]
            msg = br.ofparser.OFPFlowMod(br.datapath,
                                         priority=1,
                                         instructions=instructions)
            self.ryu_send_msg(msg)
            self.phys_brs[physical_network] = br

            self._phys_br_patch_physical_bridge_with_integration_bridge(
                br, physical_network, bridge, ip_wrapper)

    def scan_ports(self, registered_ports, updated_ports=None):
        cur_ports = self.int_br.get_vif_port_set()
        self.int_br_device_count = len(cur_ports)
        port_info = {'current': cur_ports}
        if updated_ports is None:
            updated_ports = set()
        updated_ports.update(self._find_lost_vlan_port(registered_ports))
        if updated_ports:
            # Some updated ports might have been removed in the
            # meanwhile, and therefore should not be processed.
            # In this case the updated port won't be found among
            # current ports.
            updated_ports &= cur_ports
            if updated_ports:
                port_info['updated'] = updated_ports

        if cur_ports == registered_ports:
            # No added or removed ports to set, just return here
            return port_info

        port_info['added'] = cur_ports - registered_ports
        # Remove all the known ports not found on the integration bridge
        port_info['removed'] = registered_ports - cur_ports
        return port_info

    def _find_lost_vlan_port(self, registered_ports):
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
                       physical_network, segmentation_id, admin_state_up):
        if vif_port:
            # When this function is called for a port, the port should have
            # an OVS ofport configured, as only these ports were considered
            # for being treated. If that does not happen, it is a potential
            # error condition of which operators should be aware
            if not vif_port.ofport:
                LOG.warn(_("VIF port: %s has no ofport configured, and might "
                           "not be able to transmit"), vif_port.vif_id)
            if admin_state_up:
                self.port_bound(vif_port, network_id, network_type,
                                physical_network, segmentation_id)
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
        match = self.tun_br.ofparser.OFPMatch(in_port=int(ofport))
        instructions = [self.tun_br.ofparser.OFPInstructionGotoTable(
            table_id=constants.TUN_TABLE[tunnel_type])]
        msg = self.tun_br.ofparser.OFPFlowMod(self.tun_br.datapath,
                                              priority=1,
                                              match=match,
                                              instructions=instructions)
        self.ryu_send_msg(msg)

        ofports = [int(p) for p in self.tun_br_ofports[tunnel_type].values()]
        if ofports:
            # Update flooding flows to include the new tunnel
            for network_id, vlan_mapping in self.local_vlan_map.iteritems():
                if vlan_mapping.network_type == tunnel_type:
                    match = self.tun_br.ofparser.OFPMatch(
                        vlan_vid=int(vlan_mapping.vlan) |
                        ryu_ofp13.OFPVID_PRESENT)
                    actions = [
                        self.tun_br.ofparser.OFPActionPopVlan(),
                        self.tun_br.ofparser.OFPActionSetField(
                            tunnel_id=int(vlan_mapping.segmentation_id))]
                    actions.extend(
                        self.tun_br.ofparser.OFPActionOutput(p, 0)
                        for p in ofports
                    )
                    instructions = [
                        self.tun_br.ofparser.OFPInstructionActions(
                            ryu_ofp13.OFPIT_APPLY_ACTIONS,
                            actions)]
                    msg = self.tun_br.ofparser.OFPFlowMod(
                        self.tun_br.datapath,
                        table_id=constants.FLOOD_TO_TUN,
                        priority=1,
                        match=match,
                        instructions=instructions)
                    self.ryu_send_msg(msg)
        return ofport

    def treat_devices_added_or_updated(self, devices):
        resync = False
        for device in devices:
            LOG.debug(_("Processing port %s"), device)
            port = self.int_br.get_vif_port_by_id(device)
            if not port:
                # The port has disappeared and should not be processed
                # There is no need to put the port DOWN in the plugin as
                # it never went up in the first place
                LOG.info(_("Port %s was not found on the integration bridge "
                           "and will therefore not be processed"), device)
                continue
            try:
                details = self.plugin_rpc.get_device_details(self.context,
                                                             device,
                                                             self.agent_id)
            except Exception as e:
                LOG.debug(_("Unable to get port details for "
                            "%(device)s: %(e)s"),
                          {'device': device, 'e': e})
                resync = True
                continue
            if 'port_id' in details:
                LOG.info(_("Port %(device)s updated. Details: %(details)s"),
                         {'device': device, 'details': details})
                self.treat_vif_port(port, details['port_id'],
                                    details['network_id'],
                                    details['network_type'],
                                    details['physical_network'],
                                    details['segmentation_id'],
                                    details['admin_state_up'])

                # update plugin about port status
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
        return resync

    def treat_ancillary_devices_added(self, devices):
        resync = False
        for device in devices:
            LOG.info(_("Ancillary Port %s added"), device)
            try:
                self.plugin_rpc.get_device_details(self.context, device,
                                                   self.agent_id)
            except Exception as e:
                LOG.debug(_("Unable to get port details for "
                            "%(device)s: %(e)s"),
                          {'device': device, 'e': e})
                resync = True
                continue

            # update plugin about port status
            self.plugin_rpc.update_device_up(self.context,
                                             device,
                                             self.agent_id,
                                             cfg.CONF.host)
        return resync

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

    def process_network_ports(self, port_info):
        resync_add = False
        resync_removed = False
        # If there is an exception while processing security groups ports
        # will not be wired anyway, and a resync will be triggered
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
            resync_add = self.treat_devices_added_or_updated(
                devices_added_updated)
            LOG.debug(_("process_network_ports - iteration:%(iter_num)d - "
                        "treat_devices_added_or_updated completed "
                        "in %(elapsed).3f"),
                      {'iter_num': self.iter_num,
                       'elapsed': time.time() - start})
        if 'removed' in port_info:
            start = time.time()
            resync_removed = self.treat_devices_removed(port_info['removed'])
            LOG.debug(_("process_network_ports - iteration:%(iter_num)d - "
                        "treat_devices_removed completed in %(elapsed).3f"),
                      {'iter_num': self.iter_num,
                       'elapsed': time.time() - start})
        # If one of the above opertaions fails => resync with plugin
        return (resync_add | resync_removed)

    def process_ancillary_network_ports(self, port_info):
        resync_add = False
        resync_removed = False
        if 'added' in port_info:
            start = time.time()
            resync_add = self.treat_ancillary_devices_added(port_info['added'])
            LOG.debug(_("process_ancillary_network_ports - iteration: "
                        "%(iter_num)d - treat_ancillary_devices_added "
                        "completed in %(elapsed).3f"),
                      {'iter_num': self.iter_num,
                       'elapsed': time.time() - start})
        if 'removed' in port_info:
            start = time.time()
            resync_removed = self.treat_ancillary_devices_removed(
                port_info['removed'])
            LOG.debug(_("process_ancillary_network_ports - iteration: "
                        "%(iter_num)d - treat_ancillary_devices_removed "
                        "completed in %(elapsed).3f"),
                      {'iter_num': self.iter_num,
                       'elapsed': time.time() - start})

        # If one of the above opertaions fails => resync with plugin
        return (resync_add | resync_removed)

    def tunnel_sync(self):
        resync = False
        try:
            for tunnel_type in self.tunnel_types:
                details = self.plugin_rpc.tunnel_sync(self.context,
                                                      self.local_ip,
                                                      tunnel_type)
                tunnels = details['tunnels']
                for tunnel in tunnels:
                    if self.local_ip != tunnel['ip_address']:
                        tun_name = self._create_tunnel_port_name(
                            tunnel_type, tunnel['ip_address'])
                        if not tun_name:
                            continue
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

    def ovsdb_monitor_loop(self, polling_manager=None):
        if not polling_manager:
            polling_manager = polling.AlwaysPoll()

        sync = True
        ports = set()
        updated_ports_copy = set()
        ancillary_ports = set()
        tunnel_sync = True
        while True:
            start = time.time()
            port_stats = {'regular': {'added': 0, 'updated': 0, 'removed': 0},
                          'ancillary': {'added': 0, 'removed': 0}}
            LOG.debug(_("Agent ovsdb_monitor_loop - "
                      "iteration:%d started"),
                      self.iter_num)
            if sync:
                LOG.info(_("Agent out of sync with plugin!"))
                ports.clear()
                ancillary_ports.clear()
                sync = False
                polling_manager.force_polling()
            # Notify the plugin of tunnel IP
            if self.enable_tunneling and tunnel_sync:
                LOG.info(_("Agent tunnel out of sync with plugin!"))
                try:
                    tunnel_sync = self.tunnel_sync()
                except Exception:
                    LOG.exception(_("Error while synchronizing tunnels"))
                    tunnel_sync = True
            if self._agent_has_updates(polling_manager):
                try:
                    LOG.debug(_("Agent ovsdb_monitor_loop - "
                                "iteration:%(iter_num)d - "
                                "starting polling. Elapsed:%(elapsed).3f"),
                              {'iter_num': self.iter_num,
                               'elapsed': time.time() - start})
                    # Save updated ports dict to perform rollback in
                    # case resync would be needed, and then clear
                    # self.updated_ports. As the greenthread should not yield
                    # between these two statements, this will be thread-safe
                    updated_ports_copy = self.updated_ports
                    self.updated_ports = set()
                    port_info = self.scan_ports(ports, updated_ports_copy)
                    ports = port_info['current']
                    LOG.debug(_("Agent ovsdb_monitor_loop - "
                                "iteration:%(iter_num)d - "
                                "port information retrieved. "
                                "Elapsed:%(elapsed).3f"),
                              {'iter_num': self.iter_num,
                               'elapsed': time.time() - start})
                    # Secure and wire/unwire VIFs and update their status
                    # on Neutron server
                    if (self._port_info_has_changes(port_info) or
                        self.sg_agent.firewall_refresh_needed()):
                        LOG.debug(_("Starting to process devices in:%s"),
                                  port_info)
                        # If treat devices fails - must resync with plugin
                        sync = self.process_network_ports(port_info)
                        LOG.debug(_("Agent ovsdb_monitor_loop - "
                                    "iteration:%(iter_num)d - "
                                    "ports processed. Elapsed:%(elapsed).3f"),
                                  {'iter_num': self.iter_num,
                                   'elapsed': time.time() - start})
                        port_stats['regular']['added'] = (
                            len(port_info.get('added', [])))
                        port_stats['regular']['updated'] = (
                            len(port_info.get('updated', [])))
                        port_stats['regular']['removed'] = (
                            len(port_info.get('removed', [])))
                    # Treat ancillary devices if they exist
                    if self.ancillary_brs:
                        port_info = self.update_ancillary_ports(
                            ancillary_ports)
                        LOG.debug(_("Agent ovsdb_monitor_loop - "
                                    "iteration:%(iter_num)d - "
                                    "ancillary port info retrieved. "
                                    "Elapsed:%(elapsed).3f"),
                                  {'iter_num': self.iter_num,
                                   'elapsed': time.time() - start})

                        if port_info:
                            rc = self.process_ancillary_network_ports(
                                port_info)
                            LOG.debug(_("Agent ovsdb_monitor_loop - "
                                        "iteration:"
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
            LOG.debug(_("Agent ovsdb_monitor_loop - iteration:%(iter_num)d "
                        "completed. Processed ports statistics:"
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

            self.ovsdb_monitor_loop(polling_manager=pm)


def create_agent_config_map(config):
    """Create a map of agent config parameters.

    :param config: an instance of cfg.CONF
    :returns: a map of agent configuration parameters
    """
    try:
        bridge_mappings = n_utils.parse_mappings(config.OVS.bridge_mappings)
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
        l2_population=False,
        ovsdb_monitor_respawn_interval=constants.DEFAULT_OVSDBMON_RESPAWN,
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
