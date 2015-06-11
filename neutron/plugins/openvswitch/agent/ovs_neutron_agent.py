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
import logging as std_logging
import signal
import sys
import time

import netaddr
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
import six
from six import moves

from neutron.agent.common import ovs_lib
from neutron.agent.common import polling
from neutron.agent.common import utils
from neutron.agent import l2population_rpc
from neutron.agent.linux import ip_lib
from neutron.agent import rpc as agent_rpc
from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.api.rpc.handlers import dvr_rpc
from neutron.common import config
from neutron.common import constants as q_const
from neutron.common import exceptions
from neutron.common import topics
from neutron.common import utils as q_utils
from neutron import context
from neutron.i18n import _LE, _LI, _LW
from neutron.openstack.common import loopingcall
from neutron.plugins.common import constants as p_const
from neutron.plugins.openvswitch.agent import ovs_dvr_neutron_agent
from neutron.plugins.openvswitch.common import constants


LOG = logging.getLogger(__name__)
cfg.CONF.import_group('AGENT', 'neutron.plugins.openvswitch.common.config')
cfg.CONF.import_group('OVS', 'neutron.plugins.openvswitch.common.config')

# A placeholder for dead vlans.
DEAD_VLAN_TAG = p_const.MAX_VLAN_TAG + 1


class _mac_mydialect(netaddr.mac_unix):
    word_fmt = '%.2x'


class DeviceListRetrievalError(exceptions.NeutronException):
    message = _("Unable to retrieve port details for devices: %(devices)s "
                "because of error: %(error)s")


# A class to represent a VIF (i.e., a port that has 'iface-id' and 'vif-mac'
# attributes set).
class LocalVLANMapping(object):
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


class OVSPluginApi(agent_rpc.PluginApi):
    pass


class OVSNeutronAgent(sg_rpc.SecurityGroupAgentRpcCallbackMixin,
                      l2population_rpc.L2populationRpcCallBackTunnelMixin,
                      dvr_rpc.DVRAgentRpcCallbackMixin):
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
    (LS) identifier is used to differentiate tenant traffic on
    inter-HV tunnels. A mesh of tunnels is created to other
    Hypervisors in the cloud. These tunnels originate and terminate on
    the tunneling bridge of each hypervisor. Port patching is done to
    connect local VLANs on the integration bridge to inter-hypervisor
    tunnels on the tunnel bridge.

    For each virtual network realized as a VLAN or flat network, a
    veth or a pair of patch ports is used to connect the local VLAN on
    the integration bridge with the physical network bridge, with flow
    rules adding, modifying, or stripping VLAN tags as necessary.
    '''

    # history
    #   1.0 Initial version
    #   1.1 Support Security Group RPC
    #   1.2 Support DVR (Distributed Virtual Router) RPC
    target = oslo_messaging.Target(version='1.2')

    def __init__(self, bridge_classes, integ_br, tun_br, local_ip,
                 bridge_mappings, polling_interval, tunnel_types=None,
                 veth_mtu=None, l2_population=False,
                 enable_distributed_routing=False,
                 minimize_polling=False,
                 ovsdb_monitor_respawn_interval=(
                     constants.DEFAULT_OVSDBMON_RESPAWN),
                 arp_responder=False,
                 prevent_arp_spoofing=True,
                 use_veth_interconnection=False,
                 quitting_rpc_timeout=None,
                 conf=None):
        '''Constructor.

        :param bridge_classes: a dict for bridge classes.
        :param integ_br: name of the integration bridge.
        :param tun_br: name of the tunnel bridge.
        :param local_ip: local IP address of this hypervisor.
        :param bridge_mappings: mappings from physical network name to bridge.
        :param polling_interval: interval (secs) to poll DB.
        :param tunnel_types: A list of tunnel types to enable support for in
               the agent. If set, will automatically set enable_tunneling to
               True.
        :param veth_mtu: MTU size for veth interfaces.
        :param l2_population: Optional, whether L2 population is turned on
        :param minimize_polling: Optional, whether to minimize polling by
               monitoring ovsdb for interface changes.
        :param ovsdb_monitor_respawn_interval: Optional, when using polling
               minimization, the number of seconds to wait before respawning
               the ovsdb monitor.
        :param arp_responder: Optional, enable local ARP responder if it is
               supported.
        :param prevent_arp_spoofing: Optional, enable suppression of any ARP
               responses from ports that don't match an IP address that belongs
               to the ports. Spoofing rules will not be added to ports that
               have port security disabled.
        :param use_veth_interconnection: use veths instead of patch ports to
               interconnect the integration bridge to physical bridges.
        :param quitting_rpc_timeout: timeout in seconds for rpc calls after
               SIGTERM is received
        :param conf: an instance of ConfigOpts
        '''
        super(OVSNeutronAgent, self).__init__()
        self.br_int_cls = bridge_classes['br_int']
        self.br_phys_cls = bridge_classes['br_phys']
        self.br_tun_cls = bridge_classes['br_tun']
        self.use_veth_interconnection = use_veth_interconnection
        self.veth_mtu = veth_mtu
        self.available_local_vlans = set(moves.range(p_const.MIN_VLAN_TAG,
                                                     p_const.MAX_VLAN_TAG))
        self.use_call = True
        self.tunnel_types = tunnel_types or []
        self.l2_pop = l2_population
        # TODO(ethuleau): Change ARP responder so it's not dependent on the
        #                 ML2 l2 population mechanism driver.
        self.enable_distributed_routing = enable_distributed_routing
        self.arp_responder_enabled = arp_responder and self.l2_pop
        self.prevent_arp_spoofing = prevent_arp_spoofing
        self.conf = conf or cfg.CONF

        self.agent_state = {
            'binary': 'neutron-openvswitch-agent',
            'host': self.conf.host,
            'topic': q_const.L2_AGENT_TOPIC,
            'configurations': {'bridge_mappings': bridge_mappings,
                               'tunnel_types': self.tunnel_types,
                               'tunneling_ip': local_ip,
                               'l2_population': self.l2_pop,
                               'arp_responder_enabled':
                               self.arp_responder_enabled,
                               'enable_distributed_routing':
                               self.enable_distributed_routing},
            'agent_type': q_const.AGENT_TYPE_OVS,
            'start_flag': True}

        if tunnel_types:
            self.enable_tunneling = True
        else:
            self.enable_tunneling = False

        # Validate agent configurations
        self._check_agent_configurations()

        # Keep track of int_br's device count for use by _report_state()
        self.int_br_device_count = 0

        self.int_br = self.br_int_cls(integ_br)
        self.setup_integration_br()
        # Stores port update notifications for processing in main rpc loop
        self.updated_ports = set()
        # Stores port delete notifications
        self.deleted_ports = set()
        # keeps association between ports and ofports to detect ofport change
        self.vifname_to_ofport_map = {}
        self.setup_rpc()
        self.bridge_mappings = bridge_mappings
        self.setup_physical_bridges(self.bridge_mappings)
        self.local_vlan_map = {}
        self.tun_br_ofports = {p_const.TYPE_GRE: {},
                               p_const.TYPE_VXLAN: {}}

        self.polling_interval = polling_interval
        self.minimize_polling = minimize_polling
        self.ovsdb_monitor_respawn_interval = ovsdb_monitor_respawn_interval
        self.local_ip = local_ip
        self.tunnel_count = 0
        self.vxlan_udp_port = self.conf.AGENT.vxlan_udp_port
        self.dont_fragment = self.conf.AGENT.dont_fragment
        self.tun_br = None
        self.patch_int_ofport = constants.OFPORT_INVALID
        self.patch_tun_ofport = constants.OFPORT_INVALID
        if self.enable_tunneling:
            # The patch_int_ofport and patch_tun_ofport are updated
            # here inside the call to reset_tunnel_br()
            self.reset_tunnel_br(tun_br)

        self.dvr_agent = ovs_dvr_neutron_agent.OVSDVRNeutronAgent(
            self.context,
            self.dvr_plugin_rpc,
            self.int_br,
            self.tun_br,
            self.bridge_mappings,
            self.phys_brs,
            self.int_ofports,
            self.phys_ofports,
            self.patch_int_ofport,
            self.patch_tun_ofport,
            self.conf.host,
            self.enable_tunneling,
            self.enable_distributed_routing)

        report_interval = self.conf.AGENT.report_interval
        if report_interval:
            heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            heartbeat.start(interval=report_interval)

        if self.enable_tunneling:
            self.setup_tunnel_br()

        self.dvr_agent.setup_dvr_flows()

        # Collect additional bridges to monitor
        self.ancillary_brs = self.setup_ancillary_bridges(integ_br, tun_br)

        # In order to keep existed device's local vlan unchanged,
        # restore local vlan mapping at start
        self._restore_local_vlan_map()

        # Security group agent support
        self.sg_agent = sg_rpc.SecurityGroupAgentRpc(self.context,
                self.sg_plugin_rpc, self.local_vlan_map,
                defer_refresh_firewall=True)

        # Initialize iteration counter
        self.iter_num = 0
        self.run_daemon_loop = True

        # The initialization is complete; we can start receiving messages
        self.connection.consume_in_threads()

        self.quitting_rpc_timeout = quitting_rpc_timeout

    def _report_state(self):
        # How many devices are likely used by a VM
        self.agent_state.get('configurations')['devices'] = (
            self.int_br_device_count)
        self.agent_state.get('configurations')['in_distributed_mode'] = (
            self.dvr_agent.in_distributed_mode())

        try:
            self.state_rpc.report_state(self.context,
                                        self.agent_state,
                                        self.use_call)
            self.use_call = False
            self.agent_state.pop('start_flag', None)
        except Exception:
            LOG.exception(_LE("Failed reporting state!"))

    def _restore_local_vlan_map(self):
        cur_ports = self.int_br.get_vif_ports()
        for port in cur_ports:
            local_vlan_map = self.int_br.db_get_val("Port", port.port_name,
                                                    "other_config")
            local_vlan = self.int_br.db_get_val("Port", port.port_name, "tag")
            if not local_vlan:
                continue
            net_uuid = local_vlan_map.get('net_uuid')
            if (net_uuid and net_uuid not in self.local_vlan_map
                and local_vlan != DEAD_VLAN_TAG):
                self.provision_local_vlan(local_vlan_map['net_uuid'],
                                          local_vlan_map['network_type'],
                                          local_vlan_map['physical_network'],
                                          local_vlan_map['segmentation_id'],
                                          local_vlan)

    def setup_rpc(self):
        self.agent_id = 'ovs-agent-%s' % self.conf.host
        self.topic = topics.AGENT
        self.plugin_rpc = OVSPluginApi(topics.PLUGIN)
        self.sg_plugin_rpc = sg_rpc.SecurityGroupServerRpcApi(topics.PLUGIN)
        self.dvr_plugin_rpc = dvr_rpc.DVRServerRpcApi(topics.PLUGIN)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)

        # RPC network init
        self.context = context.get_admin_context_without_session()
        # Handle updates from service
        self.endpoints = [self]
        # Define the listening consumers for the agent
        consumers = [[topics.PORT, topics.UPDATE],
                     [topics.PORT, topics.DELETE],
                     [topics.NETWORK, topics.DELETE],
                     [constants.TUNNEL, topics.UPDATE],
                     [constants.TUNNEL, topics.DELETE],
                     [topics.SECURITY_GROUP, topics.UPDATE],
                     [topics.DVR, topics.UPDATE]]
        if self.l2_pop:
            consumers.append([topics.L2POPULATION,
                              topics.UPDATE, self.conf.host])
        self.connection = agent_rpc.create_consumers(self.endpoints,
                                                     self.topic,
                                                     consumers,
                                                     start_listening=False)

    def get_net_uuid(self, vif_id):
        for network_id, vlan_mapping in six.iteritems(self.local_vlan_map):
            if vif_id in vlan_mapping.vif_ports:
                return network_id

    def network_delete(self, context, **kwargs):
        LOG.debug("network_delete received")
        network_id = kwargs.get('network_id')
        LOG.debug("Delete %s", network_id)
        # The network may not be defined on this agent
        lvm = self.local_vlan_map.get(network_id)
        if lvm:
            self.reclaim_local_vlan(network_id)
        else:
            LOG.debug("Network %s not used on agent.", network_id)

    def port_update(self, context, **kwargs):
        port = kwargs.get('port')
        # Put the port identifier in the updated_ports set.
        # Even if full port details might be provided to this call,
        # they are not used since there is no guarantee the notifications
        # are processed in the same order as the relevant API requests
        self.updated_ports.add(port['id'])
        LOG.debug("port_update message processed for port %s", port['id'])

    def port_delete(self, context, **kwargs):
        port_id = kwargs.get('port_id')
        self.deleted_ports.add(port_id)
        LOG.debug("port_delete message processed for port %s", port_id)

    def process_deleted_ports(self, port_info):
        # don't try to process removed ports as deleted ports since
        # they are already gone
        if 'removed' in port_info:
            self.deleted_ports -= port_info['removed']
        while self.deleted_ports:
            port_id = self.deleted_ports.pop()
            # Flush firewall rules and move to dead VLAN so deleted ports no
            # longer have access to the network
            self.sg_agent.remove_devices_filter([port_id])
            port = self.int_br.get_vif_port_by_id(port_id)
            if port:
                # don't log errors since there is a chance someone will be
                # removing the port from the bridge at the same time
                self.port_dead(port, log_errors=False)
            self.port_unbound(port_id)

    def tunnel_update(self, context, **kwargs):
        LOG.debug("tunnel_update received")
        if not self.enable_tunneling:
            return
        tunnel_ip = kwargs.get('tunnel_ip')
        tunnel_ip_hex = self.get_ip_in_hex(tunnel_ip)
        if not tunnel_ip_hex:
            return
        tunnel_type = kwargs.get('tunnel_type')
        if not tunnel_type:
            LOG.error(_LE("No tunnel_type specified, cannot create tunnels"))
            return
        if tunnel_type not in self.tunnel_types:
            LOG.error(_LE("tunnel_type %s not supported by agent"),
                      tunnel_type)
            return
        if tunnel_ip == self.local_ip:
            return
        tun_name = '%s-%s' % (tunnel_type, tunnel_ip_hex)
        if not self.l2_pop:
            self._setup_tunnel_port(self.tun_br, tun_name, tunnel_ip,
                                    tunnel_type)

    def tunnel_delete(self, context, **kwargs):
        LOG.debug("tunnel_delete received")
        if not self.enable_tunneling:
            return
        tunnel_ip = kwargs.get('tunnel_ip')
        if not tunnel_ip:
            LOG.error(_LE("No tunnel_ip specified, cannot delete tunnels"))
            return
        tunnel_type = kwargs.get('tunnel_type')
        if not tunnel_type:
            LOG.error(_LE("No tunnel_type specified, cannot delete tunnels"))
            return
        if tunnel_type not in self.tunnel_types:
            LOG.error(_LE("tunnel_type %s not supported by agent"),
                      tunnel_type)
            return
        ofport = self.tun_br_ofports[tunnel_type].get(tunnel_ip)
        self.cleanup_tunnel_port(self.tun_br, ofport, tunnel_type)

    def _tunnel_port_lookup(self, network_type, remote_ip):
        return self.tun_br_ofports[network_type].get(remote_ip)

    def fdb_add(self, context, fdb_entries):
        LOG.debug("fdb_add received")
        for lvm, agent_ports in self.get_agent_ports(fdb_entries,
                                                     self.local_vlan_map):
            agent_ports.pop(self.local_ip, None)
            if len(agent_ports):
                if not self.enable_distributed_routing:
                    with self.tun_br.deferred() as deferred_br:
                        self.fdb_add_tun(context, deferred_br, lvm,
                                         agent_ports, self._tunnel_port_lookup)
                else:
                    self.fdb_add_tun(context, self.tun_br, lvm,
                                     agent_ports, self._tunnel_port_lookup)

    def fdb_remove(self, context, fdb_entries):
        LOG.debug("fdb_remove received")
        for lvm, agent_ports in self.get_agent_ports(fdb_entries,
                                                     self.local_vlan_map):
            agent_ports.pop(self.local_ip, None)
            if len(agent_ports):
                if not self.enable_distributed_routing:
                    with self.tun_br.deferred() as deferred_br:
                        self.fdb_remove_tun(context, deferred_br, lvm,
                                            agent_ports,
                                            self._tunnel_port_lookup)
                else:
                    self.fdb_remove_tun(context, self.tun_br, lvm,
                                        agent_ports, self._tunnel_port_lookup)

    def add_fdb_flow(self, br, port_info, remote_ip, lvm, ofport):
        if port_info == q_const.FLOODING_ENTRY:
            lvm.tun_ofports.add(ofport)
            br.install_flood_to_tun(lvm.vlan, lvm.segmentation_id,
                                    lvm.tun_ofports)
        else:
            self.setup_entry_for_arp_reply(br, 'add', lvm.vlan,
                                           port_info.mac_address,
                                           port_info.ip_address)
            br.install_unicast_to_tun(lvm.vlan,
                                      lvm.segmentation_id,
                                      ofport,
                                      port_info.mac_address)

    def del_fdb_flow(self, br, port_info, remote_ip, lvm, ofport):
        if port_info == q_const.FLOODING_ENTRY:
            if ofport not in lvm.tun_ofports:
                LOG.debug("attempt to remove a non-existent port %s", ofport)
                return
            lvm.tun_ofports.remove(ofport)
            if len(lvm.tun_ofports) > 0:
                br.install_flood_to_tun(lvm.vlan, lvm.segmentation_id,
                                        lvm.tun_ofports)
            else:
                # This local vlan doesn't require any more tunnelling
                br.delete_flood_to_tun(lvm.vlan)
        else:
            self.setup_entry_for_arp_reply(br, 'remove', lvm.vlan,
                                           port_info.mac_address,
                                           port_info.ip_address)
            br.delete_unicast_to_tun(lvm.vlan, port_info.mac_address)

    def _fdb_chg_ip(self, context, fdb_entries):
        LOG.debug("update chg_ip received")
        with self.tun_br.deferred() as deferred_br:
            self.fdb_chg_ip_tun(context, deferred_br, fdb_entries,
                                self.local_ip, self.local_vlan_map)

    def setup_entry_for_arp_reply(self, br, action, local_vid, mac_address,
                                  ip_address):
        '''Set the ARP respond entry.

        When the l2 population mechanism driver and OVS supports to edit ARP
        fields, a table (ARP_RESPONDER) to resolve ARP locally is added to the
        tunnel bridge.
        '''
        if not self.arp_responder_enabled:
            return

        mac = str(netaddr.EUI(mac_address, dialect=_mac_mydialect))
        ip = str(netaddr.IPAddress(ip_address))

        if action == 'add':
            br.install_arp_responder(local_vid, ip, mac)
        elif action == 'remove':
            br.delete_arp_responder(local_vid, ip)
        else:
            LOG.warning(_LW('Action %s not supported'), action)

    def _local_vlan_for_flat(self, lvid, physical_network):
        phys_br = self.phys_brs[physical_network]
        phys_port = self.phys_ofports[physical_network]
        int_br = self.int_br
        int_port = self.int_ofports[physical_network]
        phys_br.provision_local_vlan(port=phys_port, lvid=lvid,
                                     segmentation_id=None,
                                     distributed=False)
        int_br.provision_local_vlan(port=int_port, lvid=lvid,
                                    segmentation_id=None)

    def _local_vlan_for_vlan(self, lvid, physical_network, segmentation_id):
        distributed = self.enable_distributed_routing
        phys_br = self.phys_brs[physical_network]
        phys_port = self.phys_ofports[physical_network]
        int_br = self.int_br
        int_port = self.int_ofports[physical_network]
        phys_br.provision_local_vlan(port=phys_port, lvid=lvid,
                                     segmentation_id=segmentation_id,
                                     distributed=distributed)
        int_br.provision_local_vlan(port=int_port, lvid=lvid,
                                    segmentation_id=segmentation_id)

    def provision_local_vlan(self, net_uuid, network_type, physical_network,
                             segmentation_id, local_vlan=None):
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
            if local_vlan in self.available_local_vlans:
                lvid = local_vlan
                self.available_local_vlans.remove(local_vlan)
            else:
                if not self.available_local_vlans:
                    LOG.error(_LE("No local VLAN available for net-id=%s"),
                              net_uuid)
                    return
                lvid = self.available_local_vlans.pop()
            self.local_vlan_map[net_uuid] = LocalVLANMapping(lvid,
                                                             network_type,
                                                             physical_network,
                                                             segmentation_id)

        LOG.info(_LI("Assigning %(vlan_id)s as local vlan for "
                     "net-id=%(net_uuid)s"),
                 {'vlan_id': lvid, 'net_uuid': net_uuid})

        if network_type in constants.TUNNEL_NETWORK_TYPES:
            if self.enable_tunneling:
                # outbound broadcast/multicast
                ofports = self.tun_br_ofports[network_type].values()
                if ofports:
                    self.tun_br.install_flood_to_tun(lvid,
                                                     segmentation_id,
                                                     ofports)
                # inbound from tunnels: set lvid in the right table
                # and resubmit to Table LEARN_FROM_TUN for mac learning
                if self.enable_distributed_routing:
                    self.dvr_agent.process_tunneled_network(
                        network_type, lvid, segmentation_id)
                else:
                    self.tun_br.provision_local_vlan(
                        network_type=network_type, lvid=lvid,
                        segmentation_id=segmentation_id)
            else:
                LOG.error(_LE("Cannot provision %(network_type)s network for "
                              "net-id=%(net_uuid)s - tunneling disabled"),
                          {'network_type': network_type,
                           'net_uuid': net_uuid})
        elif network_type == p_const.TYPE_FLAT:
            if physical_network in self.phys_brs:
                self._local_vlan_for_flat(lvid, physical_network)
            else:
                LOG.error(_LE("Cannot provision flat network for "
                              "net-id=%(net_uuid)s - no bridge for "
                              "physical_network %(physical_network)s"),
                          {'net_uuid': net_uuid,
                           'physical_network': physical_network})
        elif network_type == p_const.TYPE_VLAN:
            if physical_network in self.phys_brs:
                self._local_vlan_for_vlan(lvid, physical_network,
                                          segmentation_id)
            else:
                LOG.error(_LE("Cannot provision VLAN network for "
                              "net-id=%(net_uuid)s - no bridge for "
                              "physical_network %(physical_network)s"),
                          {'net_uuid': net_uuid,
                           'physical_network': physical_network})
        elif network_type == p_const.TYPE_LOCAL:
            # no flows needed for local networks
            pass
        else:
            LOG.error(_LE("Cannot provision unknown network type "
                          "%(network_type)s for net-id=%(net_uuid)s"),
                      {'network_type': network_type,
                       'net_uuid': net_uuid})

    def reclaim_local_vlan(self, net_uuid):
        '''Reclaim a local VLAN.

        :param net_uuid: the network uuid associated with this vlan.
        '''
        lvm = self.local_vlan_map.pop(net_uuid, None)
        if lvm is None:
            LOG.debug("Network %s not used on agent.", net_uuid)
            return

        LOG.info(_LI("Reclaiming vlan = %(vlan_id)s from "
                     "net-id = %(net_uuid)s"),
                 {'vlan_id': lvm.vlan, 'net_uuid': net_uuid})

        if lvm.network_type in constants.TUNNEL_NETWORK_TYPES:
            if self.enable_tunneling:
                self.tun_br.reclaim_local_vlan(
                    network_type=lvm.network_type,
                    segmentation_id=lvm.segmentation_id)
                self.tun_br.delete_flood_to_tun(lvm.vlan)
                self.tun_br.delete_unicast_to_tun(lvm.vlan, None)
                self.tun_br.delete_arp_responder(lvm.vlan, None)
                if self.l2_pop:
                    # Try to remove tunnel ports if not used by other networks
                    for ofport in lvm.tun_ofports:
                        self.cleanup_tunnel_port(self.tun_br, ofport,
                                                 lvm.network_type)
        elif lvm.network_type == p_const.TYPE_FLAT:
            if lvm.physical_network in self.phys_brs:
                # outbound
                br = self.phys_brs[lvm.physical_network]
                br.reclaim_local_vlan(
                    port=self.phys_ofports[lvm.physical_network],
                    lvid=lvm.vlan)
                # inbound
                br = self.int_br
                br.reclaim_local_vlan(
                    port=self.int_ofports[lvm.physical_network],
                    segmentation_id=None)
        elif lvm.network_type == p_const.TYPE_VLAN:
            if lvm.physical_network in self.phys_brs:
                # outbound
                br = self.phys_brs[lvm.physical_network]
                br.reclaim_local_vlan(
                    port=self.phys_ofports[lvm.physical_network],
                    lvid=lvm.vlan)
                # inbound
                br = self.int_br
                br.reclaim_local_vlan(
                    port=self.int_ofports[lvm.physical_network],
                    segmentation_id=lvm.segmentation_id)
        elif lvm.network_type == p_const.TYPE_LOCAL:
            # no flows needed for local networks
            pass
        else:
            LOG.error(_LE("Cannot reclaim unknown network type "
                          "%(network_type)s for net-id=%(net_uuid)s"),
                      {'network_type': lvm.network_type,
                       'net_uuid': net_uuid})

        self.available_local_vlans.add(lvm.vlan)

    def port_bound(self, port, net_uuid,
                   network_type, physical_network,
                   segmentation_id, fixed_ips, device_owner,
                   ovs_restarted):
        '''Bind port to net_uuid/lsw_id and install flow for inbound traffic
        to vm.

        :param port: a ovslib.VifPort object.
        :param net_uuid: the net_uuid this port is to be associated with.
        :param network_type: the network type ('gre', 'vlan', 'flat', 'local')
        :param physical_network: the physical network for 'vlan' or 'flat'
        :param segmentation_id: the VID for 'vlan' or tunnel ID for 'tunnel'
        :param fixed_ips: the ip addresses assigned to this port
        :param device_owner: the string indicative of owner of this port
        :param ovs_restarted: indicates if this is called for an OVS restart.
        '''
        if net_uuid not in self.local_vlan_map or ovs_restarted:
            self.provision_local_vlan(net_uuid, network_type,
                                      physical_network, segmentation_id)
        lvm = self.local_vlan_map[net_uuid]
        lvm.vif_ports[port.vif_id] = port

        self.dvr_agent.bind_port_to_dvr(port, lvm,
                                        fixed_ips,
                                        device_owner)
        port_other_config = self.int_br.db_get_val("Port", port.port_name,
                                                   "other_config")
        vlan_mapping = {'net_uuid': net_uuid,
                        'network_type': network_type,
                        'physical_network': physical_network,
                        'segmentation_id': segmentation_id}
        port_other_config.update(vlan_mapping)
        self.int_br.set_db_attribute("Port", port.port_name, "other_config",
                                     port_other_config)

    def _bind_devices(self, need_binding_ports):
        for port_detail in need_binding_ports:
            lvm = self.local_vlan_map.get(port_detail['network_id'])
            if not lvm:
                # network for port was deleted. skip this port since it
                # will need to be handled as a DEAD port in the next scan
                continue
            port = port_detail['vif_port']
            device = port_detail['device']
            # Do not bind a port if it's already bound
            cur_tag = self.int_br.db_get_val("Port", port.port_name, "tag")
            if cur_tag != lvm.vlan:
                self.int_br.set_db_attribute(
                    "Port", port.port_name, "tag", lvm.vlan)
                if port.ofport != -1:
                    # NOTE(yamamoto): Remove possible drop_port flow
                    # installed by port_dead.
                    self.int_br.delete_flows(in_port=port.ofport)

            # update plugin about port status
            # FIXME(salv-orlando): Failures while updating device status
            # must be handled appropriately. Otherwise this might prevent
            # neutron server from sending network-vif-* events to the nova
            # API server, thus possibly preventing instance spawn.
            if port_detail.get('admin_state_up'):
                LOG.debug("Setting status for %s to UP", device)
                self.plugin_rpc.update_device_up(
                    self.context, device, self.agent_id, self.conf.host)
            else:
                LOG.debug("Setting status for %s to DOWN", device)
                self.plugin_rpc.update_device_down(
                    self.context, device, self.agent_id, self.conf.host)
            LOG.info(_LI("Configuration for device %s completed."), device)

    @staticmethod
    def setup_arp_spoofing_protection(bridge, vif, port_details):
        # clear any previous flows related to this port in our ARP table
        bridge.delete_arp_spoofing_protection(port=vif.ofport)
        if not port_details.get('port_security_enabled', True):
            LOG.info(_LI("Skipping ARP spoofing rules for port '%s' because "
                         "it has port security disabled"), vif.port_name)
            return
        # collect all of the addresses and cidrs that belong to the port
        addresses = {f['ip_address'] for f in port_details['fixed_ips']}
        if port_details.get('allowed_address_pairs'):
            addresses |= {p['ip_address']
                          for p in port_details['allowed_address_pairs']}

        addresses = {ip for ip in addresses
                     if netaddr.IPNetwork(ip).version == 4}

        bridge.install_arp_spoofing_protection(port=vif.ofport,
                                               ip_addresses=addresses)

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
            LOG.info(_LI('port_unbound(): net_uuid %s not in local_vlan_map'),
                     net_uuid)
            return

        lvm = self.local_vlan_map[net_uuid]

        if vif_id in lvm.vif_ports:
            vif_port = lvm.vif_ports[vif_id]
            self.dvr_agent.unbind_port_from_dvr(vif_port, lvm)
        lvm.vif_ports.pop(vif_id, None)

        if not lvm.vif_ports:
            self.reclaim_local_vlan(net_uuid)

    def port_dead(self, port, log_errors=True):
        '''Once a port has no binding, put it on the "dead vlan".

        :param port: a ovs_lib.VifPort object.
        '''
        # Don't kill a port if it's already dead
        cur_tag = self.int_br.db_get_val("Port", port.port_name, "tag",
                                         log_errors=log_errors)
        if cur_tag != DEAD_VLAN_TAG:
            self.int_br.set_db_attribute("Port", port.port_name, "tag",
                                         DEAD_VLAN_TAG, log_errors=log_errors)
            self.int_br.drop_port(in_port=port.ofport)

    def setup_integration_br(self):
        '''Setup the integration bridge.

        Delete patch ports and remove all existing flows.
        '''
        # Ensure the integration bridge is created.
        # ovs_lib.OVSBridge.create() will run
        #   ovs-vsctl -- --may-exist add-br BRIDGE_NAME
        # which does nothing if bridge already exists.
        self.int_br.create()
        self.int_br.set_secure_mode()
        self.int_br.setup_controllers(self.conf)

        self.int_br.delete_port(self.conf.OVS.int_peer_patch_port)

        self.int_br.setup_default_table()

    def setup_ancillary_bridges(self, integ_br, tun_br):
        '''Setup ancillary bridges - for example br-ex.'''
        ovs = ovs_lib.BaseOVS()
        ovs_bridges = set(ovs.get_bridges())
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
            bridge_id = ovs.get_bridge_external_bridge_id(bridge)
            if bridge_id != bridge:
                br_names.append(bridge)
        ovs_bridges.difference_update(br_names)
        ancillary_bridges = []
        for bridge in ovs_bridges:
            br = ovs_lib.OVSBridge(bridge)
            LOG.info(_LI('Adding %s to list of bridges.'), bridge)
            ancillary_bridges.append(br)
        return ancillary_bridges

    def reset_tunnel_br(self, tun_br_name=None):
        '''(re)initialize the tunnel bridge.

        Creates tunnel bridge, and links it to the integration bridge
        using a patch port.

        :param tun_br_name: the name of the tunnel bridge.
        '''
        if not self.tun_br:
            self.tun_br = self.br_tun_cls(tun_br_name)

        self.tun_br.reset_bridge(secure_mode=True)
        self.tun_br.setup_controllers(self.conf)
        self.patch_tun_ofport = self.int_br.add_patch_port(
            self.conf.OVS.int_peer_patch_port,
            self.conf.OVS.tun_peer_patch_port)
        self.patch_int_ofport = self.tun_br.add_patch_port(
            self.conf.OVS.tun_peer_patch_port,
            self.conf.OVS.int_peer_patch_port)
        if ovs_lib.INVALID_OFPORT in (self.patch_tun_ofport,
                                      self.patch_int_ofport):
            LOG.error(_LE("Failed to create OVS patch port. Cannot have "
                          "tunneling enabled on this agent, since this "
                          "version of OVS does not support tunnels or patch "
                          "ports. Agent terminated!"))
            exit(1)
        self.tun_br.delete_flows()

    def setup_tunnel_br(self):
        '''Setup the tunnel bridge.

        Add all flows to the tunnel bridge.
        '''
        self.tun_br.setup_default_table(self.patch_int_ofport,
                                        self.arp_responder_enabled)

    def get_peer_name(self, prefix, name):
        """Construct a peer name based on the prefix and name.

        The peer name can not exceed the maximum length allowed for a linux
        device. Longer names are hashed to help ensure uniqueness.
        """
        if len(prefix + name) <= q_const.DEVICE_NAME_MAX_LEN:
            return prefix + name
        # We can't just truncate because bridges may be distinguished
        # by an ident at the end. A hash over the name should be unique.
        # Leave part of the bridge name on for easier identification
        hashlen = 6
        namelen = q_const.DEVICE_NAME_MAX_LEN - len(prefix) - hashlen
        new_name = ('%(prefix)s%(truncated)s%(hash)s' %
                    {'prefix': prefix, 'truncated': name[0:namelen],
                     'hash': hashlib.sha1(name).hexdigest()[0:hashlen]})
        LOG.warning(_LW("Creating an interface named %(name)s exceeds the "
                        "%(limit)d character limitation. It was shortened to "
                        "%(new_name)s to fit."),
                    {'name': name, 'limit': q_const.DEVICE_NAME_MAX_LEN,
                     'new_name': new_name})
        return new_name

    def setup_physical_bridges(self, bridge_mappings):
        '''Setup the physical network bridges.

        Creates physical network bridges and links them to the
        integration bridge using veths or patch ports.

        :param bridge_mappings: map physical network names to bridge names.
        '''
        self.phys_brs = {}
        self.int_ofports = {}
        self.phys_ofports = {}
        ip_wrapper = ip_lib.IPWrapper()
        ovs = ovs_lib.BaseOVS()
        ovs_bridges = ovs.get_bridges()
        for physical_network, bridge in six.iteritems(bridge_mappings):
            LOG.info(_LI("Mapping physical network %(physical_network)s to "
                         "bridge %(bridge)s"),
                     {'physical_network': physical_network,
                      'bridge': bridge})
            # setup physical bridge
            if bridge not in ovs_bridges:
                LOG.error(_LE("Bridge %(bridge)s for physical network "
                              "%(physical_network)s does not exist. Agent "
                              "terminated!"),
                          {'physical_network': physical_network,
                           'bridge': bridge})
                sys.exit(1)
            br = self.br_phys_cls(bridge)
            br.setup_controllers(self.conf)
            br.setup_default_table()
            self.phys_brs[physical_network] = br

            # interconnect physical and integration bridges using veth/patchs
            int_if_name = self.get_peer_name(constants.PEER_INTEGRATION_PREFIX,
                                             bridge)
            phys_if_name = self.get_peer_name(constants.PEER_PHYSICAL_PREFIX,
                                              bridge)
            self.int_br.delete_port(int_if_name)
            br.delete_port(phys_if_name)
            if self.use_veth_interconnection:
                if ip_lib.device_exists(int_if_name):
                    ip_lib.IPDevice(int_if_name).link.delete()
                    # Give udev a chance to process its rules here, to avoid
                    # race conditions between commands launched by udev rules
                    # and the subsequent call to ip_wrapper.add_veth
                    utils.execute(['udevadm', 'settle', '--timeout=10'])
                int_veth, phys_veth = ip_wrapper.add_veth(int_if_name,
                                                          phys_if_name)
                int_ofport = self.int_br.add_port(int_veth)
                phys_ofport = br.add_port(phys_veth)
            else:
                # Create patch ports without associating them in order to block
                # untranslated traffic before association
                int_ofport = self.int_br.add_patch_port(
                    int_if_name, constants.NONEXISTENT_PEER)
                phys_ofport = br.add_patch_port(
                    phys_if_name, constants.NONEXISTENT_PEER)

            self.int_ofports[physical_network] = int_ofport
            self.phys_ofports[physical_network] = phys_ofport

            # block all untranslated traffic between bridges
            self.int_br.drop_port(in_port=int_ofport)
            br.drop_port(in_port=phys_ofport)

            if self.use_veth_interconnection:
                # enable veth to pass traffic
                int_veth.link.set_up()
                phys_veth.link.set_up()
                if self.veth_mtu:
                    # set up mtu size for veth interfaces
                    int_veth.link.set_mtu(self.veth_mtu)
                    phys_veth.link.set_mtu(self.veth_mtu)
            else:
                # associate patch ports to pass traffic
                self.int_br.set_db_attribute('Interface', int_if_name,
                                             'options:peer', phys_if_name)
                br.set_db_attribute('Interface', phys_if_name,
                                    'options:peer', int_if_name)

    def update_stale_ofport_rules(self):
        # right now the ARP spoofing rules are the only thing that utilizes
        # ofport-based rules, so make arp_spoofing protection a conditional
        # until something else uses ofport
        if not self.prevent_arp_spoofing:
            return
        previous = self.vifname_to_ofport_map
        current = self.int_br.get_vif_port_to_ofport_map()

        # if any ofport numbers have changed, re-process the devices as
        # added ports so any rules based on ofport numbers are updated.
        moved_ports = self._get_ofport_moves(current, previous)
        if moved_ports:
            self.treat_devices_added_or_updated(moved_ports,
                                                ovs_restarted=False)

        # delete any stale rules based on removed ofports
        ofports_deleted = set(previous.values()) - set(current.values())
        for ofport in ofports_deleted:
            self.int_br.delete_arp_spoofing_protection(port=ofport)

        # store map for next iteration
        self.vifname_to_ofport_map = current

    @staticmethod
    def _get_ofport_moves(current, previous):
        """Returns a list of moved ports.

        Takes two port->ofport maps and returns a list ports that moved to a
        different ofport. Deleted ports are not included.
        """
        port_moves = []
        for name, ofport in previous.items():
            if name not in current:
                continue
            current_ofport = current[name]
            if ofport != current_ofport:
                port_moves.append(name)
        return port_moves

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
                        _LI("Port '%(port_name)s' has lost "
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
                       fixed_ips, device_owner, ovs_restarted):
        # When this function is called for a port, the port should have
        # an OVS ofport configured, as only these ports were considered
        # for being treated. If that does not happen, it is a potential
        # error condition of which operators should be aware
        port_needs_binding = True
        if not vif_port.ofport:
            LOG.warn(_LW("VIF port: %s has no ofport configured, "
                         "and might not be able to transmit"), vif_port.vif_id)
        if vif_port:
            if admin_state_up:
                self.port_bound(vif_port, network_id, network_type,
                                physical_network, segmentation_id,
                                fixed_ips, device_owner, ovs_restarted)
            else:
                self.port_dead(vif_port)
                port_needs_binding = False
        else:
            LOG.debug("No VIF port for port %s defined on agent.", port_id)
        return port_needs_binding

    def _setup_tunnel_port(self, br, port_name, remote_ip, tunnel_type):
        ofport = br.add_tunnel_port(port_name,
                                    remote_ip,
                                    self.local_ip,
                                    tunnel_type,
                                    self.vxlan_udp_port,
                                    self.dont_fragment)
        if ofport == ovs_lib.INVALID_OFPORT:
            LOG.error(_LE("Failed to set-up %(type)s tunnel port to %(ip)s"),
                      {'type': tunnel_type, 'ip': remote_ip})
            return 0

        self.tun_br_ofports[tunnel_type][remote_ip] = ofport
        # Add flow in default table to resubmit to the right
        # tunnelling table (lvid will be set in the latter)
        br.setup_tunnel_port(tunnel_type, ofport)

        ofports = self.tun_br_ofports[tunnel_type].values()
        if ofports and not self.l2_pop:
            # Update flooding flows to include the new tunnel
            for vlan_mapping in list(self.local_vlan_map.values()):
                if vlan_mapping.network_type == tunnel_type:
                    br.install_flood_to_tun(vlan_mapping.vlan,
                                            vlan_mapping.segmentation_id,
                                            ofports)
        return ofport

    def setup_tunnel_port(self, br, remote_ip, network_type):
        remote_ip_hex = self.get_ip_in_hex(remote_ip)
        if not remote_ip_hex:
            return 0
        port_name = '%s-%s' % (network_type, remote_ip_hex)
        ofport = self._setup_tunnel_port(br,
                                         port_name,
                                         remote_ip,
                                         network_type)
        return ofport

    def cleanup_tunnel_port(self, br, tun_ofport, tunnel_type):
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
                    br.delete_port(port_name)
                    br.cleanup_tunnel_port(ofport)
                    self.tun_br_ofports[tunnel_type].pop(remote_ip, None)

    def treat_devices_added_or_updated(self, devices, ovs_restarted):
        skipped_devices = []
        need_binding_devices = []
        try:
            devices_details_list = self.plugin_rpc.get_devices_details_list(
                self.context,
                devices,
                self.agent_id,
                self.conf.host)
        except Exception as e:
            raise DeviceListRetrievalError(devices=devices, error=e)
        for details in devices_details_list:
            device = details['device']
            LOG.debug("Processing port: %s", device)
            port = self.int_br.get_vif_port_by_id(device)
            if not port:
                # The port disappeared and cannot be processed
                LOG.info(_LI("Port %s was not found on the integration bridge "
                             "and will therefore not be processed"), device)
                skipped_devices.append(device)
                continue

            if 'port_id' in details:
                LOG.info(_LI("Port %(device)s updated. Details: %(details)s"),
                         {'device': device, 'details': details})
                need_binding = self.treat_vif_port(port, details['port_id'],
                                                   details['network_id'],
                                                   details['network_type'],
                                                   details['physical_network'],
                                                   details['segmentation_id'],
                                                   details['admin_state_up'],
                                                   details['fixed_ips'],
                                                   details['device_owner'],
                                                   ovs_restarted)
                if self.prevent_arp_spoofing:
                    self.setup_arp_spoofing_protection(self.int_br,
                                                       port, details)
                if need_binding:
                    details['vif_port'] = port
                    need_binding_devices.append(details)
            else:
                LOG.warn(_LW("Device %s not defined on plugin"), device)
                if (port and port.ofport != -1):
                    self.port_dead(port)
        return skipped_devices, need_binding_devices

    def treat_ancillary_devices_added(self, devices):
        try:
            devices_details_list = self.plugin_rpc.get_devices_details_list(
                self.context,
                devices,
                self.agent_id,
                self.conf.host)
        except Exception as e:
            raise DeviceListRetrievalError(devices=devices, error=e)

        for details in devices_details_list:
            device = details['device']
            LOG.info(_LI("Ancillary Port %s added"), device)

            # update plugin about port status
            self.plugin_rpc.update_device_up(self.context,
                                             device,
                                             self.agent_id,
                                             self.conf.host)

    def treat_devices_removed(self, devices):
        resync = False
        self.sg_agent.remove_devices_filter(devices)
        for device in devices:
            LOG.info(_LI("Attachment %s removed"), device)
            try:
                self.plugin_rpc.update_device_down(self.context,
                                                   device,
                                                   self.agent_id,
                                                   self.conf.host)
            except Exception as e:
                LOG.debug("port_removed failed for %(device)s: %(e)s",
                          {'device': device, 'e': e})
                resync = True
                continue
            self.port_unbound(device)
        return resync

    def treat_ancillary_devices_removed(self, devices):
        resync = False
        for device in devices:
            LOG.info(_LI("Attachment %s removed"), device)
            try:
                details = self.plugin_rpc.update_device_down(self.context,
                                                             device,
                                                             self.agent_id,
                                                             self.conf.host)
            except Exception as e:
                LOG.debug("port_removed failed for %(device)s: %(e)s",
                          {'device': device, 'e': e})
                resync = True
                continue
            if details['exists']:
                LOG.info(_LI("Port %s updated."), device)
                # Nothing to do regarding local networking
            else:
                LOG.debug("Device %s not defined on plugin", device)
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
        # VIF wiring needs to be performed always for 'new' devices.
        # For updated ports, re-wiring is not needed in most cases, but needs
        # to be performed anyway when the admin state of a device is changed.
        # A device might be both in the 'added' and 'updated'
        # list at the same time; avoid processing it twice.
        devices_added_updated = (port_info.get('added', set()) |
                                 port_info.get('updated', set()))
        need_binding_devices = []
        if devices_added_updated:
            start = time.time()
            try:
                skipped_devices, need_binding_devices = (
                    self.treat_devices_added_or_updated(
                        devices_added_updated, ovs_restarted))
                LOG.debug("process_network_ports - iteration:%(iter_num)d - "
                          "treat_devices_added_or_updated completed. "
                          "Skipped %(num_skipped)d devices of "
                          "%(num_current)d devices currently available. "
                          "Time elapsed: %(elapsed).3f",
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
                LOG.exception(_LE("process_network_ports - iteration:%d - "
                                  "failure while retrieving port details "
                                  "from server"), self.iter_num)
                resync_a = True

        # TODO(salv-orlando): Optimize avoiding applying filters
        # unnecessarily, (eg: when there are no IP address changes)
        self.sg_agent.setup_port_filters(port_info.get('added', set()),
                                         port_info.get('updated', set()))
        self._bind_devices(need_binding_devices)

        if 'removed' in port_info:
            start = time.time()
            resync_b = self.treat_devices_removed(port_info['removed'])
            LOG.debug("process_network_ports - iteration:%(iter_num)d - "
                      "treat_devices_removed completed in %(elapsed).3f",
                      {'iter_num': self.iter_num,
                       'elapsed': time.time() - start})
        # If one of the above operations fails => resync with plugin
        return (resync_a | resync_b)

    def process_ancillary_network_ports(self, port_info):
        resync_a = False
        resync_b = False
        if 'added' in port_info:
            start = time.time()
            try:
                self.treat_ancillary_devices_added(port_info['added'])
                LOG.debug("process_ancillary_network_ports - iteration: "
                          "%(iter_num)d - treat_ancillary_devices_added "
                          "completed in %(elapsed).3f",
                        {'iter_num': self.iter_num,
                        'elapsed': time.time() - start})
            except DeviceListRetrievalError:
                # Need to resync as there was an error with server
                # communication.
                LOG.exception(_LE("process_ancillary_network_ports - "
                                  "iteration:%d - failure while retrieving "
                                  "port details from server"), self.iter_num)
                resync_a = True
        if 'removed' in port_info:
            start = time.time()
            resync_b = self.treat_ancillary_devices_removed(
                port_info['removed'])
            LOG.debug("process_ancillary_network_ports - iteration: "
                      "%(iter_num)d - treat_ancillary_devices_removed "
                      "completed in %(elapsed).3f",
                      {'iter_num': self.iter_num,
                       'elapsed': time.time() - start})

        # If one of the above operations fails => resync with plugin
        return (resync_a | resync_b)

    def get_ip_in_hex(self, ip_address):
        try:
            return '%08x' % netaddr.IPAddress(ip_address, version=4)
        except Exception:
            LOG.warn(_LW("Invalid remote IP: %s"), ip_address)
            return

    def tunnel_sync(self):
        try:
            for tunnel_type in self.tunnel_types:
                details = self.plugin_rpc.tunnel_sync(self.context,
                                                      self.local_ip,
                                                      tunnel_type,
                                                      self.conf.host)
                if not self.l2_pop:
                    tunnels = details['tunnels']
                    for tunnel in tunnels:
                        if self.local_ip != tunnel['ip_address']:
                            remote_ip = tunnel['ip_address']
                            remote_ip_hex = self.get_ip_in_hex(remote_ip)
                            if not remote_ip_hex:
                                continue
                            tun_name = '%s-%s' % (tunnel_type, remote_ip_hex)
                            self._setup_tunnel_port(self.tun_br,
                                                    tun_name,
                                                    tunnel['ip_address'],
                                                    tunnel_type)
        except Exception as e:
            LOG.debug("Unable to sync tunnel IP %(local_ip)s: %(e)s",
                      {'local_ip': self.local_ip, 'e': e})
            return True
        return False

    def _agent_has_updates(self, polling_manager):
        return (polling_manager.is_polling_required or
                self.updated_ports or
                self.sg_agent.firewall_refresh_needed())

    def _port_info_has_changes(self, port_info):
        return (port_info.get('added') or
                port_info.get('removed') or
                port_info.get('updated'))

    def check_ovs_status(self):
        # Check for the canary flow
        status = self.int_br.check_canary_table()
        if status == constants.OVS_RESTARTED:
            LOG.warn(_LW("OVS is restarted. OVSNeutronAgent will reset "
                         "bridges and recover ports."))
        elif status == constants.OVS_DEAD:
            LOG.warn(_LW("OVS is dead. OVSNeutronAgent will keep running "
                         "and checking OVS status periodically."))
        return status

    def loop_count_and_wait(self, start_time, port_stats):
        # sleep till end of polling interval
        elapsed = time.time() - start_time
        LOG.debug("Agent rpc_loop - iteration:%(iter_num)d "
                  "completed. Processed ports statistics: "
                  "%(port_stats)s. Elapsed:%(elapsed).3f",
                  {'iter_num': self.iter_num,
                   'port_stats': port_stats,
                   'elapsed': elapsed})
        if elapsed < self.polling_interval:
            time.sleep(self.polling_interval - elapsed)
        else:
            LOG.debug("Loop iteration exceeded interval "
                      "(%(polling_interval)s vs. %(elapsed)s)!",
                      {'polling_interval': self.polling_interval,
                       'elapsed': elapsed})
        self.iter_num = self.iter_num + 1

    def rpc_loop(self, polling_manager=None):
        if not polling_manager:
            polling_manager = polling.get_polling_manager(
                minimize_polling=False)

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
            LOG.debug("Agent rpc_loop - iteration:%d started",
                      self.iter_num)
            if sync:
                LOG.info(_LI("Agent out of sync with plugin!"))
                ports.clear()
                ancillary_ports.clear()
                sync = False
                polling_manager.force_polling()
            ovs_status = self.check_ovs_status()
            if ovs_status == constants.OVS_RESTARTED:
                self.setup_integration_br()
                self.setup_physical_bridges(self.bridge_mappings)
                if self.enable_tunneling:
                    self.reset_tunnel_br()
                    self.setup_tunnel_br()
                    tunnel_sync = True
                if self.enable_distributed_routing:
                    self.dvr_agent.reset_ovs_parameters(self.int_br,
                                                 self.tun_br,
                                                 self.patch_int_ofport,
                                                 self.patch_tun_ofport)
                    self.dvr_agent.reset_dvr_parameters()
                    self.dvr_agent.setup_dvr_flows()
            elif ovs_status == constants.OVS_DEAD:
                # Agent doesn't apply any operations when ovs is dead, to
                # prevent unexpected failure or crash. Sleep and continue
                # loop in which ovs status will be checked periodically.
                self.loop_count_and_wait(start, port_stats)
                continue
            # Notify the plugin of tunnel IP
            if self.enable_tunneling and tunnel_sync:
                LOG.info(_LI("Agent tunnel out of sync with plugin!"))
                try:
                    tunnel_sync = self.tunnel_sync()
                except Exception:
                    LOG.exception(_LE("Error while synchronizing tunnels"))
                    tunnel_sync = True
            ovs_restarted |= (ovs_status == constants.OVS_RESTARTED)
            if self._agent_has_updates(polling_manager) or ovs_restarted:
                try:
                    LOG.debug("Agent rpc_loop - iteration:%(iter_num)d - "
                              "starting polling. Elapsed:%(elapsed).3f",
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
                    self.process_deleted_ports(port_info)
                    self.update_stale_ofport_rules()
                    LOG.debug("Agent rpc_loop - iteration:%(iter_num)d - "
                              "port information retrieved. "
                              "Elapsed:%(elapsed).3f",
                              {'iter_num': self.iter_num,
                               'elapsed': time.time() - start})
                    # Secure and wire/unwire VIFs and update their status
                    # on Neutron server
                    if (self._port_info_has_changes(port_info) or
                        self.sg_agent.firewall_refresh_needed() or
                        ovs_restarted):
                        LOG.debug("Starting to process devices in:%s",
                                  port_info)
                        # If treat devices fails - must resync with plugin
                        sync = self.process_network_ports(port_info,
                                                          ovs_restarted)
                        LOG.debug("Agent rpc_loop - iteration:%(iter_num)d - "
                                  "ports processed. Elapsed:%(elapsed).3f",
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
                        LOG.debug("Agent rpc_loop - iteration:%(iter_num)d - "
                                  "ancillary port info retrieved. "
                                  "Elapsed:%(elapsed).3f",
                                  {'iter_num': self.iter_num,
                                   'elapsed': time.time() - start})

                        if port_info:
                            rc = self.process_ancillary_network_ports(
                                port_info)
                            LOG.debug("Agent rpc_loop - iteration: "
                                      "%(iter_num)d - ancillary ports "
                                      "processed. Elapsed:%(elapsed).3f",
                                      {'iter_num': self.iter_num,
                                       'elapsed': time.time() - start})
                            ancillary_ports = port_info['current']
                            port_stats['ancillary']['added'] = (
                                len(port_info.get('added', [])))
                            port_stats['ancillary']['removed'] = (
                                len(port_info.get('removed', [])))
                            sync = sync | rc

                    polling_manager.polling_completed()
                    # Keep this flag in the last line of "try" block,
                    # so we can sure that no other Exception occurred.
                    if not sync:
                        ovs_restarted = False
                except Exception:
                    LOG.exception(_LE("Error while processing VIF ports"))
                    # Put the ports back in self.updated_port
                    self.updated_ports |= updated_ports_copy
                    sync = True

            self.loop_count_and_wait(start, port_stats)

    def daemon_loop(self):
        # Start everything.
        LOG.info(_LI("Agent initialized successfully, now running... "))
        signal.signal(signal.SIGTERM, self._handle_sigterm)
        signal.signal(signal.SIGHUP, self._handle_sighup)
        with polling.get_polling_manager(
            self.minimize_polling,
            self.ovsdb_monitor_respawn_interval) as pm:

            self.rpc_loop(polling_manager=pm)

    def _handle_sigterm(self, signum, frame):
        LOG.info(_LI("Agent caught SIGTERM, quitting daemon loop."))
        self.run_daemon_loop = False
        if self.quitting_rpc_timeout:
            self.set_rpc_timeout(self.quitting_rpc_timeout)

    def _handle_sighup(self, signum, frame):
        LOG.info(_LI("Agent caught SIGHUP, resetting."))
        self.conf.reload_config_files()
        config.setup_logging()
        LOG.debug('Full set of CONF:')
        self.conf.log_opt_values(LOG, std_logging.DEBUG)

    def set_rpc_timeout(self, timeout):
        for rpc_api in (self.plugin_rpc, self.sg_plugin_rpc,
                        self.dvr_plugin_rpc, self.state_rpc):
            rpc_api.client.timeout = timeout

    def _check_agent_configurations(self):
        if (self.enable_distributed_routing and self.enable_tunneling
            and not self.l2_pop):
            raise ValueError(_("DVR deployments for VXLAN/GRE underlays "
                               "require L2-pop to be enabled, in both the "
                               "Agent and Server side."))


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
        polling_interval=config.AGENT.polling_interval,
        minimize_polling=config.AGENT.minimize_polling,
        tunnel_types=config.AGENT.tunnel_types,
        veth_mtu=config.AGENT.veth_mtu,
        enable_distributed_routing=config.AGENT.enable_distributed_routing,
        l2_population=config.AGENT.l2_population,
        arp_responder=config.AGENT.arp_responder,
        prevent_arp_spoofing=config.AGENT.prevent_arp_spoofing,
        use_veth_interconnection=config.OVS.use_veth_interconnection,
        quitting_rpc_timeout=config.AGENT.quitting_rpc_timeout
    )

    # Verify the tunnel_types specified are valid
    for tun in kwargs['tunnel_types']:
        if tun not in constants.TUNNEL_NETWORK_TYPES:
            msg = _('Invalid tunnel type specified: %s'), tun
            raise ValueError(msg)
        if not kwargs['local_ip']:
            msg = _('Tunneling cannot be enabled without a valid local_ip.')
            raise ValueError(msg)

    return kwargs


def prepare_xen_compute():
    is_xen_compute_host = 'rootwrap-xen-dom0' in cfg.CONF.AGENT.root_helper
    if is_xen_compute_host:
        # Force ip_lib to always use the root helper to ensure that ip
        # commands target xen dom0 rather than domU.
        cfg.CONF.register_opts(ip_lib.OPTS)
        cfg.CONF.set_default('ip_lib_force_root', True)


def main(bridge_classes):
    try:
        agent_config = create_agent_config_map(cfg.CONF)
    except ValueError:
        LOG.exception(_LE("Agent failed to create agent config map"))
        raise SystemExit(1)
    prepare_xen_compute()
    try:
        agent = OVSNeutronAgent(bridge_classes, **agent_config)
    except RuntimeError as e:
        LOG.error(_LE("%s Agent terminated!"), e)
        sys.exit(1)
    agent.daemon_loop()
