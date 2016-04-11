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

import collections
import functools
import signal
import sys
import time

import netaddr
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_service import loopingcall
from oslo_service import systemd
import six
from six import moves

from neutron._i18n import _, _LE, _LI, _LW
from neutron.agent.common import ip_lib
from neutron.agent.common import ovs_lib
from neutron.agent.common import polling
from neutron.agent.common import utils
from neutron.agent.l2.extensions import manager as ext_manager
from neutron.agent import rpc as agent_rpc
from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.api.rpc.callbacks import resources
from neutron.api.rpc.handlers import dvr_rpc
from neutron.common import config
from neutron.common import constants as n_const
from neutron.common import ipv6_utils as ipv6
from neutron.common import topics
from neutron.common import utils as n_utils
from neutron import context
from neutron.plugins.common import constants as p_const
from neutron.plugins.common import utils as p_utils
from neutron.plugins.ml2.drivers.l2pop.rpc_manager import l2population_rpc
from neutron.plugins.ml2.drivers.openvswitch.agent.common \
    import constants
from neutron.plugins.ml2.drivers.openvswitch.agent \
    import ovs_agent_extension_api as ovs_ext_api
from neutron.plugins.ml2.drivers.openvswitch.agent \
    import ovs_dvr_neutron_agent


LOG = logging.getLogger(__name__)
cfg.CONF.import_group('AGENT', 'neutron.plugins.ml2.drivers.openvswitch.'
                      'agent.common.config')
cfg.CONF.import_group('OVS', 'neutron.plugins.ml2.drivers.openvswitch.agent.'
                      'common.config')


class _mac_mydialect(netaddr.mac_unix):
    word_fmt = '%.2x'


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


def has_zero_prefixlen_address(ip_addresses):
    return any(netaddr.IPNetwork(ip).prefixlen == 0 for ip in ip_addresses)


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
    #   1.3 Added param devices_to_update to security_groups_provider_updated
    #   1.4 Added support for network_update
    target = oslo_messaging.Target(version='1.4')

    def __init__(self, bridge_classes, conf=None):
        '''Constructor.

        :param bridge_classes: a dict for bridge classes.
        :param conf: an instance of ConfigOpts
        '''
        super(OVSNeutronAgent, self).__init__()
        self.conf = conf or cfg.CONF
        self.ovs = ovs_lib.BaseOVS()
        agent_conf = self.conf.AGENT
        ovs_conf = self.conf.OVS

        self.fullsync = False
        # init bridge classes with configured datapath type.
        self.br_int_cls, self.br_phys_cls, self.br_tun_cls = (
            functools.partial(bridge_classes[b],
                              datapath_type=ovs_conf.datapath_type)
            for b in ('br_int', 'br_phys', 'br_tun'))

        self.use_veth_interconnection = ovs_conf.use_veth_interconnection
        self.veth_mtu = agent_conf.veth_mtu
        self.available_local_vlans = set(moves.range(p_const.MIN_VLAN_TAG,
                                                     p_const.MAX_VLAN_TAG))
        self.tunnel_types = agent_conf.tunnel_types or []
        self.l2_pop = agent_conf.l2_population
        # TODO(ethuleau): Change ARP responder so it's not dependent on the
        #                 ML2 l2 population mechanism driver.
        self.enable_distributed_routing = agent_conf.enable_distributed_routing
        self.arp_responder_enabled = agent_conf.arp_responder and self.l2_pop

        host = self.conf.host
        self.agent_id = 'ovs-agent-%s' % host

        if self.tunnel_types:
            self.enable_tunneling = True
        else:
            self.enable_tunneling = False

        # Validate agent configurations
        self._check_agent_configurations()

        # Keep track of int_br's device count for use by _report_state()
        self.int_br_device_count = 0

        self.int_br = self.br_int_cls(ovs_conf.integration_bridge)
        self.setup_integration_br()
        # Stores port update notifications for processing in main rpc loop
        self.updated_ports = set()
        # Stores port delete notifications
        self.deleted_ports = set()

        self.network_ports = collections.defaultdict(set)
        # keeps association between ports and ofports to detect ofport change
        self.vifname_to_ofport_map = {}
        self.setup_rpc()
        self.bridge_mappings = self._parse_bridge_mappings(
            ovs_conf.bridge_mappings)
        self.setup_physical_bridges(self.bridge_mappings)
        self.local_vlan_map = {}

        self._reset_tunnel_ofports()

        self.polling_interval = agent_conf.polling_interval
        self.minimize_polling = agent_conf.minimize_polling
        self.ovsdb_monitor_respawn_interval = (
            agent_conf.ovsdb_monitor_respawn_interval or
            constants.DEFAULT_OVSDBMON_RESPAWN)
        self.local_ip = ovs_conf.local_ip
        self.tunnel_count = 0
        self.vxlan_udp_port = agent_conf.vxlan_udp_port
        self.dont_fragment = agent_conf.dont_fragment
        self.tunnel_csum = agent_conf.tunnel_csum
        self.tun_br = None
        self.patch_int_ofport = constants.OFPORT_INVALID
        self.patch_tun_ofport = constants.OFPORT_INVALID
        if self.enable_tunneling:
            # The patch_int_ofport and patch_tun_ofport are updated
            # here inside the call to setup_tunnel_br()
            self.setup_tunnel_br(ovs_conf.tunnel_bridge)

        self.init_extension_manager(self.connection)

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
            host,
            self.enable_tunneling,
            self.enable_distributed_routing)

        #TODO(mangelajo): optimize resource_versions to only report
        #                 versions about resources which are common,
        #                 or which are used by specific extensions.
        self.agent_state = {
            'binary': 'neutron-openvswitch-agent',
            'host': host,
            'topic': n_const.L2_AGENT_TOPIC,
            'configurations': {'bridge_mappings': self.bridge_mappings,
                               'tunnel_types': self.tunnel_types,
                               'tunneling_ip': self.local_ip,
                               'l2_population': self.l2_pop,
                               'arp_responder_enabled':
                               self.arp_responder_enabled,
                               'enable_distributed_routing':
                               self.enable_distributed_routing,
                               'log_agent_heartbeats':
                               agent_conf.log_agent_heartbeats,
                               'extensions': self.ext_manager.names(),
                               'datapath_type': ovs_conf.datapath_type,
                               'ovs_capabilities': self.ovs.capabilities,
                               'vhostuser_socket_dir':
                               ovs_conf.vhostuser_socket_dir},
            'resource_versions': resources.LOCAL_RESOURCE_VERSIONS,
            'agent_type': agent_conf.agent_type,
            'start_flag': True}

        report_interval = agent_conf.report_interval
        if report_interval:
            heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            heartbeat.start(interval=report_interval)

        if self.enable_tunneling:
            self.setup_tunnel_br_flows()

        self.dvr_agent.setup_dvr_flows()

        # Collect additional bridges to monitor
        self.ancillary_brs = self.setup_ancillary_bridges(
            ovs_conf.integration_bridge, ovs_conf.tunnel_bridge)

        # In order to keep existed device's local vlan unchanged,
        # restore local vlan mapping at start
        self._restore_local_vlan_map()

        # Security group agent support
        self.sg_agent = sg_rpc.SecurityGroupAgentRpc(self.context,
                self.sg_plugin_rpc, self.local_vlan_map,
                defer_refresh_firewall=True, integration_bridge=self.int_br)

        self.prevent_arp_spoofing = (
            agent_conf.prevent_arp_spoofing and
            not self.sg_agent.firewall.provides_arp_spoofing_protection)

        # Initialize iteration counter
        self.iter_num = 0
        self.run_daemon_loop = True

        self.catch_sigterm = False
        self.catch_sighup = False

        # The initialization is complete; we can start receiving messages
        self.connection.consume_in_threads()

        self.quitting_rpc_timeout = agent_conf.quitting_rpc_timeout

    def _parse_bridge_mappings(self, bridge_mappings):
        try:
            return n_utils.parse_mappings(bridge_mappings)
        except ValueError as e:
            raise ValueError(_("Parsing bridge_mappings failed: %s.") % e)

    def _report_state(self):
        # How many devices are likely used by a VM
        self.agent_state.get('configurations')['devices'] = (
            self.int_br_device_count)
        self.agent_state.get('configurations')['in_distributed_mode'] = (
            self.dvr_agent.in_distributed_mode())

        try:
            agent_status = self.state_rpc.report_state(self.context,
                                                       self.agent_state,
                                                       True)
            if agent_status == n_const.AGENT_REVIVED:
                LOG.info(_LI('Agent has just been revived. '
                             'Doing a full sync.'))
                self.fullsync = True

            if self.agent_state.pop('start_flag', None):
                # On initial start, we notify systemd after initialization
                # is complete.
                systemd.notify_once()
        except Exception:
            LOG.exception(_LE("Failed reporting state!"))

    def _restore_local_vlan_map(self):
        self._local_vlan_hints = {}
        cur_ports = self.int_br.get_vif_ports()
        port_names = [p.port_name for p in cur_ports]
        port_info = self.int_br.get_ports_attributes(
            "Port", columns=["name", "other_config", "tag"], ports=port_names)
        by_name = {x['name']: x for x in port_info}
        for port in cur_ports:
            # if a port was deleted between get_vif_ports and
            # get_ports_attributes, we
            # will get a KeyError
            try:
                local_vlan_map = by_name[port.port_name]['other_config']
                local_vlan = by_name[port.port_name]['tag']
            except KeyError:
                continue
            if not local_vlan:
                continue
            net_uuid = local_vlan_map.get('net_uuid')
            if (net_uuid and net_uuid not in self._local_vlan_hints
                and local_vlan != constants.DEAD_VLAN_TAG):
                self.available_local_vlans.remove(local_vlan)
                self._local_vlan_hints[local_vlan_map['net_uuid']] = \
                    local_vlan

    def _dispose_local_vlan_hints(self):
        self.available_local_vlans.update(self._local_vlan_hints.values())
        self._local_vlan_hints = {}

    def _reset_tunnel_ofports(self):
        self.tun_br_ofports = {p_const.TYPE_GENEVE: {},
                               p_const.TYPE_GRE: {},
                               p_const.TYPE_VXLAN: {}}

    def setup_rpc(self):
        self.plugin_rpc = OVSPluginApi(topics.PLUGIN)
        self.sg_plugin_rpc = sg_rpc.SecurityGroupServerRpcApi(topics.PLUGIN)
        self.dvr_plugin_rpc = dvr_rpc.DVRServerRpcApi(topics.PLUGIN)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.REPORTS)

        # RPC network init
        self.context = context.get_admin_context_without_session()
        # Define the listening consumers for the agent
        consumers = [[topics.PORT, topics.UPDATE],
                     [topics.PORT, topics.DELETE],
                     [constants.TUNNEL, topics.UPDATE],
                     [constants.TUNNEL, topics.DELETE],
                     [topics.SECURITY_GROUP, topics.UPDATE],
                     [topics.DVR, topics.UPDATE],
                     [topics.NETWORK, topics.UPDATE]]
        if self.l2_pop:
            consumers.append([topics.L2POPULATION, topics.UPDATE])
        self.connection = agent_rpc.create_consumers([self],
                                                     topics.AGENT,
                                                     consumers,
                                                     start_listening=False)

    def init_extension_manager(self, connection):
        ext_manager.register_opts(self.conf)
        self.ext_manager = (
            ext_manager.AgentExtensionsManager(self.conf))
        self.agent_api = ovs_ext_api.OVSAgentExtensionAPI(self.int_br,
                                                          self.tun_br)
        self.ext_manager.initialize(
            connection, constants.EXTENSION_DRIVER_TYPE,
            self.agent_api)

    def get_net_uuid(self, vif_id):
        for network_id, vlan_mapping in six.iteritems(self.local_vlan_map):
            if vif_id in vlan_mapping.vif_ports:
                return network_id

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
        self.updated_ports.discard(port_id)
        LOG.debug("port_delete message processed for port %s", port_id)

    def network_update(self, context, **kwargs):
        network_id = kwargs['network']['id']
        for port_id in self.network_ports[network_id]:
            # notifications could arrive out of order, if the port is deleted
            # we don't want to update it anymore
            if port_id not in self.deleted_ports:
                self.updated_ports.add(port_id)
        LOG.debug("network_update message processed for network "
                  "%(network_id)s, with ports: %(ports)s",
                  {'network_id': network_id,
                   'ports': self.network_ports[network_id]})

    def _clean_network_ports(self, port_id):
        for port_set in self.network_ports.values():
            if port_id in port_set:
                port_set.remove(port_id)
                break

    def process_deleted_ports(self, port_info):
        # don't try to process removed ports as deleted ports since
        # they are already gone
        if 'removed' in port_info:
            self.deleted_ports -= port_info['removed']
        deleted_ports = list(self.deleted_ports)
        while self.deleted_ports:
            port_id = self.deleted_ports.pop()
            port = self.int_br.get_vif_port_by_id(port_id)
            self._clean_network_ports(port_id)
            self.ext_manager.delete_port(self.context,
                                         {"vif_port": port,
                                          "port_id": port_id})
            # move to dead VLAN so deleted ports no
            # longer have access to the network
            if port:
                # don't log errors since there is a chance someone will be
                # removing the port from the bridge at the same time
                self.port_dead(port, log_errors=False)
            self.port_unbound(port_id)
        # Flush firewall rules after ports are put on dead VLAN to be
        # more secure
        self.sg_agent.remove_devices_filter(deleted_ports)

    def tunnel_update(self, context, **kwargs):
        LOG.debug("tunnel_update received")
        if not self.enable_tunneling:
            return
        tunnel_ip = kwargs.get('tunnel_ip')
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
        tun_name = self.get_tunnel_name(tunnel_type, self.local_ip, tunnel_ip)
        if tun_name is None:
            return
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
        if port_info == n_const.FLOODING_ENTRY:
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
        if port_info == n_const.FLOODING_ENTRY:
            if ofport not in lvm.tun_ofports:
                LOG.debug("attempt to remove a non-existent port %s", ofport)
                return
            lvm.tun_ofports.remove(ofport)
            if len(lvm.tun_ofports) > 0:
                br.install_flood_to_tun(lvm.vlan, lvm.segmentation_id,
                                        lvm.tun_ofports)
            else:
                # This local vlan doesn't require any more tunneling
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

        ip = netaddr.IPAddress(ip_address)
        if ip.version == 6:
            return

        ip = str(ip)
        mac = str(netaddr.EUI(mac_address, dialect=_mac_mydialect))

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
                             segmentation_id):
        '''Provisions a local VLAN.

        :param net_uuid: the uuid of the network associated with this vlan.
        :param network_type: the network type ('gre', 'vxlan', 'vlan', 'flat',
                                               'local', 'geneve')
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
            lvid = self._local_vlan_hints.pop(net_uuid, None)
            if lvid is None:
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
                ofports = list(self.tun_br_ofports[network_type].values())
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

        :param port: an ovs_lib.VifPort object.
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
        if port_other_config is None:
            if port.vif_id in self.deleted_ports:
                LOG.debug("Port %s deleted concurrently", port.vif_id)
            elif port.vif_id in self.updated_ports:
                LOG.error(_LE("Expected port %s not found"), port.vif_id)
            else:
                LOG.debug("Unable to get config for port %s", port.vif_id)
            return False

        vlan_mapping = {'net_uuid': net_uuid,
                        'network_type': network_type,
                        'physical_network': physical_network}
        if segmentation_id is not None:
            vlan_mapping['segmentation_id'] = segmentation_id
        port_other_config.update(vlan_mapping)
        self.int_br.set_db_attribute("Port", port.port_name, "other_config",
                                     port_other_config)
        return True

    def _add_port_tag_info(self, need_binding_ports):
        port_names = [p['vif_port'].port_name for p in need_binding_ports]
        port_info = self.int_br.get_ports_attributes(
            "Port", columns=["name", "tag", "other_config"],
            ports=port_names, if_exists=True)
        info_by_port = {x['name']: [x['tag'], x['other_config']]
                        for x in port_info}
        for port_detail in need_binding_ports:
            lvm = self.local_vlan_map.get(port_detail['network_id'])
            if not lvm:
                continue
            port = port_detail['vif_port']
            cur_info = info_by_port.get(port.port_name)
            if cur_info is not None and cur_info[0] != lvm.vlan:
                other_config = cur_info[1] or {}
                other_config['tag'] = lvm.vlan
                self.int_br.set_db_attribute(
                    "Port", port.port_name, "other_config", other_config)

    def _bind_devices(self, need_binding_ports):
        devices_up = []
        devices_down = []
        failed_devices = []
        port_names = [p['vif_port'].port_name for p in need_binding_ports]
        port_info = self.int_br.get_ports_attributes(
            "Port", columns=["name", "tag"], ports=port_names, if_exists=True)
        tags_by_name = {x['name']: x['tag'] for x in port_info}
        for port_detail in need_binding_ports:
            lvm = self.local_vlan_map.get(port_detail['network_id'])
            if not lvm:
                # network for port was deleted. skip this port since it
                # will need to be handled as a DEAD port in the next scan
                continue
            port = port_detail['vif_port']
            device = port_detail['device']
            # Do not bind a port if it's already bound
            cur_tag = tags_by_name.get(port.port_name)
            if cur_tag is None:
                LOG.debug("Port %s was deleted concurrently, skipping it",
                          port.port_name)
                continue
            # Uninitialized port has tag set to []
            if cur_tag and cur_tag != lvm.vlan:
                self.int_br.delete_flows(in_port=port.ofport)
            if self.prevent_arp_spoofing:
                self.setup_arp_spoofing_protection(self.int_br,
                                                   port, port_detail)
            if cur_tag != lvm.vlan:
                self.int_br.set_db_attribute(
                    "Port", port.port_name, "tag", lvm.vlan)

            # update plugin about port status
            # FIXME(salv-orlando): Failures while updating device status
            # must be handled appropriately. Otherwise this might prevent
            # neutron server from sending network-vif-* events to the nova
            # API server, thus possibly preventing instance spawn.
            if port_detail.get('admin_state_up'):
                LOG.debug("Setting status for %s to UP", device)
                devices_up.append(device)
            else:
                LOG.debug("Setting status for %s to DOWN", device)
                devices_down.append(device)
        if devices_up or devices_down:
            devices_set = self.plugin_rpc.update_device_list(
                self.context, devices_up, devices_down, self.agent_id,
                self.conf.host)
            failed_devices = (devices_set.get('failed_devices_up') +
                devices_set.get('failed_devices_down'))
            if failed_devices:
                LOG.error(_LE("Configuration for devices %s failed!"),
                          failed_devices)
        LOG.info(_LI("Configuration for devices up %(up)s and devices "
                     "down %(down)s completed."),
                 {'up': devices_up, 'down': devices_down})
        return set(failed_devices)

    @staticmethod
    def setup_arp_spoofing_protection(bridge, vif, port_details):
        if not port_details.get('port_security_enabled', True):
            LOG.info(_LI("Skipping ARP spoofing rules for port '%s' because "
                         "it has port security disabled"), vif.port_name)
            bridge.delete_arp_spoofing_protection(port=vif.ofport)
            bridge.set_allowed_macs_for_port(port=vif.ofport, allow_all=True)
            return
        if port_details['device_owner'].startswith(
            n_const.DEVICE_OWNER_NETWORK_PREFIX):
            LOG.debug("Skipping ARP spoofing rules for network owned port "
                      "'%s'.", vif.port_name)
            bridge.delete_arp_spoofing_protection(port=vif.ofport)
            bridge.set_allowed_macs_for_port(port=vif.ofport, allow_all=True)
            return
        # clear any previous flows related to this port in our ARP table
        bridge.delete_arp_spoofing_allow_rules(port=vif.ofport)
        # collect all of the addresses and cidrs that belong to the port
        addresses = {f['ip_address'] for f in port_details['fixed_ips']}
        mac_addresses = {vif.vif_mac}
        if port_details.get('allowed_address_pairs'):
            addresses |= {p['ip_address']
                          for p in port_details['allowed_address_pairs']}
            mac_addresses |= {p['mac_address']
                              for p in port_details['allowed_address_pairs']
                              if p.get('mac_address')}

        bridge.set_allowed_macs_for_port(vif.ofport, mac_addresses)
        ipv6_addresses = {ip for ip in addresses
                          if netaddr.IPNetwork(ip).version == 6}
        # Allow neighbor advertisements for LLA address.
        ipv6_addresses |= {str(ipv6.get_ipv6_addr_by_EUI64(
                               n_const.IPV6_LLA_PREFIX, mac))
                           for mac in mac_addresses}
        if not has_zero_prefixlen_address(ipv6_addresses):
            # Install protection only when prefix is not zero because a /0
            # prefix allows any address anyway and the nd_target can only
            # match on /1 or more.
            bridge.install_icmpv6_na_spoofing_protection(port=vif.ofport,
                ip_addresses=ipv6_addresses)

        ipv4_addresses = {ip for ip in addresses
                          if netaddr.IPNetwork(ip).version == 4}
        if not has_zero_prefixlen_address(ipv4_addresses):
            # Install protection only when prefix is not zero because a /0
            # prefix allows any address anyway and the ARP_SPA can only
            # match on /1 or more.
            bridge.install_arp_spoofing_protection(port=vif.ofport,
                                                   ip_addresses=ipv4_addresses)
        else:
            bridge.delete_arp_spoofing_protection(port=vif.ofport)

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

        :param port: an ovs_lib.VifPort object.
        '''
        # Don't kill a port if it's already dead
        cur_tag = self.int_br.db_get_val("Port", port.port_name, "tag",
                                         log_errors=log_errors)
        if cur_tag and cur_tag != constants.DEAD_VLAN_TAG:
            self.int_br.set_db_attribute("Port", port.port_name, "tag",
                                         constants.DEAD_VLAN_TAG,
                                         log_errors=log_errors)
            self.int_br.drop_port(in_port=port.ofport)

    def setup_integration_br(self):
        '''Setup the integration bridge.

        '''
        # Ensure the integration bridge is created.
        # ovs_lib.OVSBridge.create() will run
        #   ovs-vsctl -- --may-exist add-br BRIDGE_NAME
        # which does nothing if bridge already exists.
        self.int_br.create()
        self.int_br.set_secure_mode()
        self.int_br.setup_controllers(self.conf)

        if self.conf.AGENT.drop_flows_on_start:
            # Delete the patch port between br-int and br-tun if we're deleting
            # the flows on br-int, so that traffic doesn't get flooded over
            # while flows are missing.
            self.int_br.delete_port(self.conf.OVS.int_peer_patch_port)
            self.int_br.delete_flows()
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

    def setup_tunnel_br(self, tun_br_name=None):
        '''(re)initialize the tunnel bridge.

        Creates tunnel bridge, and links it to the integration bridge
        using a patch port.

        :param tun_br_name: the name of the tunnel bridge.
        '''
        if not self.tun_br:
            self.tun_br = self.br_tun_cls(tun_br_name)

        # tun_br.create() won't recreate bridge if it exists, but will handle
        # cases where something like datapath_type has changed
        self.tun_br.create(secure_mode=True)
        self.tun_br.setup_controllers(self.conf)
        if (not self.int_br.port_exists(self.conf.OVS.int_peer_patch_port) or
                self.patch_tun_ofport == ovs_lib.INVALID_OFPORT):
            self.patch_tun_ofport = self.int_br.add_patch_port(
                self.conf.OVS.int_peer_patch_port,
                self.conf.OVS.tun_peer_patch_port)
        if (not self.tun_br.port_exists(self.conf.OVS.tun_peer_patch_port) or
                self.patch_int_ofport == ovs_lib.INVALID_OFPORT):
            self.patch_int_ofport = self.tun_br.add_patch_port(
                self.conf.OVS.tun_peer_patch_port,
                self.conf.OVS.int_peer_patch_port)
        if ovs_lib.INVALID_OFPORT in (self.patch_tun_ofport,
                                      self.patch_int_ofport):
            LOG.error(_LE("Failed to create OVS patch port. Cannot have "
                          "tunneling enabled on this agent, since this "
                          "version of OVS does not support tunnels or patch "
                          "ports. Agent terminated!"))
            sys.exit(1)
        if self.conf.AGENT.drop_flows_on_start:
            self.tun_br.delete_flows()

    def setup_tunnel_br_flows(self):
        '''Setup the tunnel bridge.

        Add all flows to the tunnel bridge.
        '''
        self.tun_br.setup_default_table(self.patch_int_ofport,
                                        self.arp_responder_enabled)

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
            # The bridge already exists, so create won't recreate it, but will
            # handle things like changing the datapath_type
            br.create()
            br.setup_controllers(self.conf)
            if cfg.CONF.AGENT.drop_flows_on_start:
                br.delete_flows()
            br.setup_default_table()
            self.phys_brs[physical_network] = br

            # interconnect physical and integration bridges using veth/patches
            int_if_name = p_utils.get_interface_name(
                bridge, prefix=constants.PEER_INTEGRATION_PREFIX)
            phys_if_name = p_utils.get_interface_name(
                bridge, prefix=constants.PEER_PHYSICAL_PREFIX)
            # Interface type of port for physical and integration bridges must
            # be same, so check only one of them.
            # Not logging error here, as the interface may not exist yet.
            # Type check is done to cleanup wrong interface if any.
            int_type = self.int_br.db_get_val("Interface",
                int_if_name, "type", log_errors=False)
            if self.use_veth_interconnection:
                # Drop ports if the interface types doesn't match the
                # configuration value.
                if int_type == 'patch':
                    self.int_br.delete_port(int_if_name)
                    br.delete_port(phys_if_name)
                device = ip_lib.IPDevice(int_if_name)
                if device.exists():
                    device.link.delete()
                    # Give udev a chance to process its rules here, to avoid
                    # race conditions between commands launched by udev rules
                    # and the subsequent call to ip_wrapper.add_veth
                    utils.execute(['udevadm', 'settle', '--timeout=10'])
                int_veth, phys_veth = ip_wrapper.add_veth(int_if_name,
                                                          phys_if_name)
                int_ofport = self.int_br.add_port(int_veth)
                phys_ofport = br.add_port(phys_veth)
            else:
                # Drop ports if the interface type doesn't match the
                # configuration value
                if int_type == 'veth':
                    self.int_br.delete_port(int_if_name)
                    br.delete_port(phys_if_name)

                # Setup int_br to physical bridge patches.  If they already
                # exist we leave them alone, otherwise we create them but don't
                # connect them until after the drop rules are in place.
                int_ofport = self.int_br.get_port_ofport(int_if_name)
                if int_ofport == ovs_lib.INVALID_OFPORT:
                    int_ofport = self.int_br.add_patch_port(
                        int_if_name, constants.NONEXISTENT_PEER)

                phys_ofport = br.get_port_ofport(phys_if_name)
                if phys_ofport == ovs_lib.INVALID_OFPORT:
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
                                             'options', {'peer': phys_if_name})
                br.set_db_attribute('Interface', phys_if_name,
                                    'options', {'peer': int_if_name})

    def update_stale_ofport_rules(self):
        # ARP spoofing rules and drop-flow upon port-delete
        # use ofport-based rules
        previous = self.vifname_to_ofport_map
        current = self.int_br.get_vif_port_to_ofport_map()

        # if any ofport numbers have changed, re-process the devices as
        # added ports so any rules based on ofport numbers are updated.
        moved_ports = self._get_ofport_moves(current, previous)

        # delete any stale rules based on removed ofports
        ofports_deleted = set(previous.values()) - set(current.values())
        for ofport in ofports_deleted:
            if self.prevent_arp_spoofing:
                self.int_br.delete_arp_spoofing_protection(port=ofport)
            self.int_br.delete_flows(in_port=ofport)
        # store map for next iteration
        self.vifname_to_ofport_map = current
        return moved_ports

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

    def _get_port_info(self, registered_ports, cur_ports,
                       readd_registered_ports):
        port_info = {'current': cur_ports}
        # FIXME(salv-orlando): It's not really necessary to return early
        # if nothing has changed.
        if not readd_registered_ports and cur_ports == registered_ports:
            return port_info

        if readd_registered_ports:
            port_info['added'] = cur_ports
        else:
            port_info['added'] = cur_ports - registered_ports
        # Update port_info with ports not found on the integration bridge
        port_info['removed'] = registered_ports - cur_ports
        return port_info

    def _update_port_info_failed_devices_stats(self, port_info,
                                               failed_devices):
        # remove failed devices that don't need to be retried
        failed_devices['added'] -= port_info['removed']
        failed_devices['removed'] -= port_info['added']

        # Disregard devices that were never noticed by the agent
        port_info['removed'] &= port_info['current']
        # retry failed devices
        port_info['added'] |= failed_devices['added']
        LOG.debug("retrying failed devices %s", failed_devices['added'])
        port_info['removed'] |= failed_devices['removed']
        # Update current ports
        port_info['current'] |= port_info['added']
        port_info['current'] -= port_info['removed']

    def process_ports_events(self, events, registered_ports, ancillary_ports,
                             old_ports_not_ready, failed_devices,
                             failed_ancillary_devices, updated_ports=None):
        port_info = {}
        port_info['added'] = set()
        port_info['removed'] = set()
        port_info['current'] = registered_ports

        ancillary_port_info = {}
        ancillary_port_info['added'] = set()
        ancillary_port_info['removed'] = set()
        ancillary_port_info['current'] = ancillary_ports

        ports_not_ready_yet = set()
        # if a port was added and then removed or viceversa since the agent
        # can't know the order of the operations, check the status of the port
        # to determine if the port was added or deleted
        ports_removed_and_added = [
            p for p in events['added'] if p in events['removed']]
        for p in ports_removed_and_added:
            if ovs_lib.BaseOVS().port_exists(p['name']):
                events['removed'].remove(p)
            else:
                events['added'].remove(p)

        #TODO(rossella_s): scanning the ancillary bridge won't be needed
        # anymore when https://review.openstack.org/#/c/203381 since the bridge
        # id stored in external_ids will be used to identify the bridge the
        # port belongs to
        cur_ancillary_ports = set()
        for bridge in self.ancillary_brs:
            cur_ancillary_ports |= bridge.get_vif_port_set()
        cur_ancillary_ports |= ancillary_port_info['current']

        def _process_port(port, ports, ancillary_ports):
            # check 'iface-id' is set otherwise is not a port
            # the agent should care about
            if 'attached-mac' in port.get('external_ids', []):
                iface_id = self.int_br.portid_from_external_ids(
                    port['external_ids'])
                if iface_id:
                    if port['ofport'] == ovs_lib.UNASSIGNED_OFPORT:
                        LOG.debug("Port %s not ready yet on the bridge",
                                  iface_id)
                        ports_not_ready_yet.add(port['name'])
                        return
                    # check if port belongs to ancillary bridge
                    if iface_id in cur_ancillary_ports:
                        ancillary_ports.add(iface_id)
                    else:
                        ports.add(iface_id)
        if old_ports_not_ready:
            old_ports_not_ready_attrs = self.int_br.get_ports_attributes(
                'Interface', columns=['name', 'external_ids', 'ofport'],
                ports=old_ports_not_ready, if_exists=True)
            now_ready_ports = set(
                [p['name'] for p in old_ports_not_ready_attrs])
            LOG.debug("Ports %s are now ready", now_ready_ports)
            old_ports_not_ready_yet = old_ports_not_ready - now_ready_ports
            removed_ports = set([p['name'] for p in events['removed']])
            old_ports_not_ready_yet -= removed_ports
            LOG.debug("Ports %s were not ready at last iteration and are not "
                      "ready yet", old_ports_not_ready_yet)
            ports_not_ready_yet |= old_ports_not_ready_yet
            events['added'].extend(old_ports_not_ready_attrs)

        for port in events['added']:
            _process_port(port, port_info['added'],
                          ancillary_port_info['added'])
        for port in events['removed']:
            _process_port(port, port_info['removed'],
                          ancillary_port_info['removed'])

        self._update_port_info_failed_devices_stats(port_info, failed_devices)
        self._update_port_info_failed_devices_stats(ancillary_port_info,
                                failed_ancillary_devices)

        if updated_ports is None:
            updated_ports = set()
        updated_ports.update(self.check_changed_vlans())

        if updated_ports:
            # Some updated ports might have been removed in the
            # meanwhile, and therefore should not be processed.
            # In this case the updated port won't be found among
            # current ports.
            updated_ports &= port_info['current']
            port_info['updated'] = updated_ports
        return port_info, ancillary_port_info, ports_not_ready_yet

    def scan_ports(self, registered_ports, sync, updated_ports=None):
        cur_ports = self.int_br.get_vif_port_set()
        self.int_br_device_count = len(cur_ports)
        port_info = self._get_port_info(registered_ports, cur_ports, sync)
        if updated_ports is None:
            updated_ports = set()
        updated_ports.update(self.check_changed_vlans())
        if updated_ports:
            # Some updated ports might have been removed in the
            # meanwhile, and therefore should not be processed.
            # In this case the updated port won't be found among
            # current ports.
            updated_ports &= cur_ports
            if updated_ports:
                port_info['updated'] = updated_ports
        return port_info

    def scan_ancillary_ports(self, registered_ports, sync):
        cur_ports = set()
        for bridge in self.ancillary_brs:
            cur_ports |= bridge.get_vif_port_set()
        return self._get_port_info(registered_ports, cur_ports, sync)

    def check_changed_vlans(self):
        """Return ports which have lost their vlan tag.

        The returned value is a set of port ids of the ports concerned by a
        vlan tag loss.
        """
        port_tags = self.int_br.get_port_tag_dict()
        changed_ports = set()
        for lvm in self.local_vlan_map.values():
            for port in lvm.vif_ports.values():
                if (
                    port.port_name in port_tags
                    and port_tags[port.port_name] != lvm.vlan
                ):
                    LOG.info(
                        _LI("Port '%(port_name)s' has lost "
                            "its vlan tag '%(vlan_tag)d'!"),
                        {'port_name': port.port_name,
                         'vlan_tag': lvm.vlan}
                    )
                    changed_ports.add(port.vif_id)
        return changed_ports

    def treat_vif_port(self, vif_port, port_id, network_id, network_type,
                       physical_network, segmentation_id, admin_state_up,
                       fixed_ips, device_owner, ovs_restarted):
        # When this function is called for a port, the port should have
        # an OVS ofport configured, as only these ports were considered
        # for being treated. If that does not happen, it is a potential
        # error condition of which operators should be aware
        port_needs_binding = True
        if not vif_port.ofport:
            LOG.warning(_LW("VIF port: %s has no ofport configured, "
                            "and might not be able to transmit"),
                        vif_port.vif_id)
        if vif_port:
            if admin_state_up:
                port_needs_binding = self.port_bound(
                    vif_port, network_id, network_type,
                    physical_network, segmentation_id,
                    fixed_ips, device_owner, ovs_restarted)
            else:
                LOG.info(_LI("VIF port: %s admin state up disabled, "
                             "putting on the dead VLAN"), vif_port.vif_id)

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
                                    self.dont_fragment,
                                    self.tunnel_csum)
        if ofport == ovs_lib.INVALID_OFPORT:
            LOG.error(_LE("Failed to set-up %(type)s tunnel port to %(ip)s"),
                      {'type': tunnel_type, 'ip': remote_ip})
            return 0

        self.tun_br_ofports[tunnel_type][remote_ip] = ofport
        # Add flow in default table to resubmit to the right
        # tunneling table (lvid will be set in the latter)
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
        port_name = self.get_tunnel_name(
            network_type, self.local_ip, remote_ip)
        if port_name is None:
            return 0
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
            items = list(self.tun_br_ofports[tunnel_type].items())
            for remote_ip, ofport in items:
                if ofport == tun_ofport:
                    port_name = self.get_tunnel_name(
                        tunnel_type, self.local_ip, remote_ip)
                    br.delete_port(port_name)
                    br.cleanup_tunnel_port(ofport)
                    self.tun_br_ofports[tunnel_type].pop(remote_ip, None)

    def treat_devices_added_or_updated(self, devices, ovs_restarted):
        skipped_devices = []
        need_binding_devices = []
        security_disabled_devices = []
        devices_details_list = (
            self.plugin_rpc.get_devices_details_list_and_failed_devices(
                self.context,
                devices,
                self.agent_id,
                self.conf.host))
        failed_devices = set(devices_details_list.get('failed_devices'))

        devices = devices_details_list.get('devices')
        vif_by_id = self.int_br.get_vifs_by_ids(
            [vif['device'] for vif in devices])
        for details in devices:
            device = details['device']
            LOG.debug("Processing port: %s", device)
            port = vif_by_id.get(device)
            if not port:
                # The port disappeared and cannot be processed
                LOG.info(_LI("Port %s was not found on the integration bridge "
                             "and will therefore not be processed"), device)
                skipped_devices.append(device)
                continue

            if 'port_id' in details:
                LOG.info(_LI("Port %(device)s updated. Details: %(details)s"),
                         {'device': device, 'details': details})
                details['vif_port'] = port
                need_binding = self.treat_vif_port(port, details['port_id'],
                                                   details['network_id'],
                                                   details['network_type'],
                                                   details['physical_network'],
                                                   details['segmentation_id'],
                                                   details['admin_state_up'],
                                                   details['fixed_ips'],
                                                   details['device_owner'],
                                                   ovs_restarted)
                if need_binding:
                    need_binding_devices.append(details)

                port_security = details['port_security_enabled']
                has_sgs = 'security_groups' in details
                if not port_security or not has_sgs:
                    security_disabled_devices.append(device)
                self._update_port_network(details['port_id'],
                                          details['network_id'])
                self.ext_manager.handle_port(self.context, details)
            else:
                LOG.warning(
                    _LW("Device %s not defined on plugin or binding failed"),
                    device)
                if (port and port.ofport != -1):
                    self.port_dead(port)
        return (skipped_devices, need_binding_devices,
                security_disabled_devices, failed_devices)

    def _update_port_network(self, port_id, network_id):
        self._clean_network_ports(port_id)
        self.network_ports[network_id].add(port_id)

    def treat_ancillary_devices_added(self, devices):
        devices_details_list = (
            self.plugin_rpc.get_devices_details_list_and_failed_devices(
                self.context,
                devices,
                self.agent_id,
                self.conf.host))
        failed_devices = set(devices_details_list.get('failed_devices'))
        devices_added = [
            d['device'] for d in devices_details_list.get('devices')]

        # update plugin about port status
        devices_set_up = (
            self.plugin_rpc.update_device_list(self.context,
                                               devices_added,
                                               [],
                                               self.agent_id,
                                               self.conf.host))
        failed_devices |= set(devices_set_up.get('failed_devices_up'))
        LOG.info(_LI("Ancillary Ports %(added)s added, failed devices "
                     "%(failed)s"), {'added': devices,
                                     'failed': failed_devices})
        return failed_devices

    def treat_devices_removed(self, devices):
        self.sg_agent.remove_devices_filter(devices)
        LOG.info(_LI("Ports %s removed"), devices)
        devices_down = self.plugin_rpc.update_device_list(self.context,
                                                          [],
                                                          devices,
                                                          self.agent_id,
                                                          self.conf.host)
        failed_devices = set(devices_down.get('failed_devices_down'))
        LOG.debug("Port removal failed for %s", failed_devices)
        for device in devices:
            self.port_unbound(device)
        return failed_devices

    def treat_ancillary_devices_removed(self, devices):
        LOG.info(_LI("Ancillary ports %s removed"), devices)
        devices_down = self.plugin_rpc.update_device_list(self.context,
                                                          [],
                                                          devices,
                                                          self.agent_id,
                                                          self.conf.host)
        LOG.info(_LI("Devices down  %s "), devices_down)
        failed_devices = set(devices_down.get('failed_devices_down'))
        if failed_devices:
            LOG.debug("Port removal failed for %s", failed_devices)
        for detail in devices_down.get('devices_down'):
            if detail['exists']:
                LOG.info(_LI("Port %s updated."), detail['device'])
                # Nothing to do regarding local networking
            else:
                LOG.debug("Device %s not defined on plugin", detail['device'])
        return failed_devices

    def process_network_ports(self, port_info, ovs_restarted):
        failed_devices = {'added': set(), 'removed': set()}
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
        security_disabled_ports = []
        if devices_added_updated:
            start = time.time()
            (skipped_devices, need_binding_devices,
            security_disabled_ports, failed_devices['added']) = (
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

        # TODO(salv-orlando): Optimize avoiding applying filters
        # unnecessarily, (eg: when there are no IP address changes)
        added_ports = port_info.get('added', set())
        self._add_port_tag_info(need_binding_devices)
        if security_disabled_ports:
            added_ports -= set(security_disabled_ports)
        self.sg_agent.setup_port_filters(added_ports,
                                         port_info.get('updated', set()))
        failed_devices['added'] |= self._bind_devices(need_binding_devices)

        if 'removed' in port_info and port_info['removed']:
            start = time.time()
            failed_devices['removed'] |= self.treat_devices_removed(
                port_info['removed'])
            LOG.debug("process_network_ports - iteration:%(iter_num)d - "
                      "treat_devices_removed completed in %(elapsed).3f",
                      {'iter_num': self.iter_num,
                       'elapsed': time.time() - start})
        return failed_devices

    def process_ancillary_network_ports(self, port_info):
        failed_devices = {'added': set(), 'removed': set()}
        if 'added' in port_info and port_info['added']:
            start = time.time()
            failed_added = self.treat_ancillary_devices_added(
                port_info['added'])
            LOG.debug("process_ancillary_network_ports - iteration: "
                      "%(iter_num)d - treat_ancillary_devices_added "
                      "completed in %(elapsed).3f",
                      {'iter_num': self.iter_num,
                       'elapsed': time.time() - start})
            failed_devices['added'] = failed_added

        if 'removed' in port_info and port_info['removed']:
            start = time.time()
            failed_removed = self.treat_ancillary_devices_removed(
                port_info['removed'])
            failed_devices['removed'] = failed_removed

            LOG.debug("process_ancillary_network_ports - iteration: "
                      "%(iter_num)d - treat_ancillary_devices_removed "
                      "completed in %(elapsed).3f",
                      {'iter_num': self.iter_num,
                       'elapsed': time.time() - start})
        return failed_devices

    @classmethod
    def get_ip_in_hex(cls, ip_address):
        try:
            return '%08x' % netaddr.IPAddress(ip_address, version=4)
        except Exception:
            LOG.warning(_LW("Invalid remote IP: %s"), ip_address)
            return

    def tunnel_sync(self):
        LOG.info(_LI("Configuring tunnel endpoints to other OVS agents"))

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
                            tun_name = self.get_tunnel_name(
                                tunnel_type, self.local_ip, remote_ip)
                            if tun_name is None:
                                continue
                            self._setup_tunnel_port(self.tun_br,
                                                    tun_name,
                                                    tunnel['ip_address'],
                                                    tunnel_type)
        except Exception as e:
            LOG.debug("Unable to sync tunnel IP %(local_ip)s: %(e)s",
                      {'local_ip': self.local_ip, 'e': e})
            return True
        return False

    @classmethod
    def get_tunnel_name(cls, network_type, local_ip, remote_ip):
        remote_ip_hex = cls.get_ip_in_hex(remote_ip)
        if not remote_ip_hex:
            return None
        return '%s-%s' % (network_type, remote_ip_hex)

    def _agent_has_updates(self, polling_manager):
        return (polling_manager.is_polling_required or
                self.updated_ports or
                self.deleted_ports or
                self.sg_agent.firewall_refresh_needed())

    def _port_info_has_changes(self, port_info):
        return (port_info.get('added') or
                port_info.get('removed') or
                port_info.get('updated'))

    def check_ovs_status(self):
        # Check for the canary flow
        status = self.int_br.check_canary_table()
        if status == constants.OVS_RESTARTED:
            LOG.warning(_LW("OVS is restarted. OVSNeutronAgent will reset "
                            "bridges and recover ports."))
        elif status == constants.OVS_DEAD:
            LOG.warning(_LW("OVS is dead. OVSNeutronAgent will keep running "
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

    def get_port_stats(self, port_info, ancillary_port_info):
        port_stats = {
            'regular': {
                'added': len(port_info.get('added', [])),
                'updated': len(port_info.get('updated', [])),
                'removed': len(port_info.get('removed', []))}}
        if self.ancillary_brs:
            port_stats['ancillary'] = {
                'added': len(ancillary_port_info.get('added', [])),
                'removed': len(ancillary_port_info.get('removed', []))}
        return port_stats

    def cleanup_stale_flows(self):
        bridges = [self.int_br]
        bridges.extend(self.phys_brs.values())
        if self.enable_tunneling:
            bridges.append(self.tun_br)
        for bridge in bridges:
            LOG.info(_LI("Cleaning stale %s flows"), bridge.br_name)
            bridge.cleanup_flows()

    def process_port_info(self, start, polling_manager, sync, ovs_restarted,
                       ports, ancillary_ports, updated_ports_copy,
                       consecutive_resyncs, ports_not_ready_yet,
                       failed_devices, failed_ancillary_devices):
        # There are polling managers that don't have get_events, e.g.
        # AlwaysPoll used by windows implementations
        # REVISIT (rossella_s) This needs to be reworked to hide implementation
        # details regarding polling in BasePollingManager subclasses
        if sync or not (hasattr(polling_manager, 'get_events')):
            if sync:
                LOG.info(_LI("Agent out of sync with plugin!"))
                consecutive_resyncs = consecutive_resyncs + 1
                if (consecutive_resyncs >=
                        constants.MAX_DEVICE_RETRIES):
                    LOG.warning(_LW(
                        "Clearing cache of registered ports,"
                        " retries to resync were > %s"),
                             constants.MAX_DEVICE_RETRIES)
                    ports.clear()
                    ancillary_ports.clear()
                    consecutive_resyncs = 0
            else:
                consecutive_resyncs = 0
                # TODO(rossella_s): For implementations that use AlwaysPoll
                # resync if a device failed. This can be improved in future
                sync = (any(failed_devices.values()) or
                    any(failed_ancillary_devices.values()))

            # NOTE(rossella_s) don't empty the queue of events
            # calling polling_manager.get_events() since
            # the agent might miss some event (for example a port
            # deletion)
            reg_ports = (set() if ovs_restarted else ports)
            port_info = self.scan_ports(reg_ports, sync,
                                        updated_ports_copy)
            # Treat ancillary devices if they exist
            if self.ancillary_brs:
                ancillary_port_info = self.scan_ancillary_ports(
                    ancillary_ports, sync)
                LOG.debug("Agent rpc_loop - iteration:%(iter_num)d"
                          " - ancillary port info retrieved. "
                          "Elapsed:%(elapsed).3f",
                          {'iter_num': self.iter_num,
                           'elapsed': time.time() - start})
            else:
                ancillary_port_info = {}

        else:
            consecutive_resyncs = 0
            events = polling_manager.get_events()
            port_info, ancillary_port_info, ports_not_ready_yet = (
                self.process_ports_events(events, ports, ancillary_ports,
                                          ports_not_ready_yet,
                                          failed_devices,
                                          failed_ancillary_devices,
                                          updated_ports_copy))
        return (port_info, ancillary_port_info, consecutive_resyncs,
                ports_not_ready_yet)

    def _remove_devices_not_to_retry(self, failed_devices,
                                     failed_ancillary_devices,
                                     devices_not_to_retry,
                                     ancillary_devices_not_to_retry):
        """This method removes the devices that exceeded the number of retries
           from failed_devices and failed_ancillary_devices

        """
        for event in ['added', 'removed']:
            failed_devices[event] = (
                failed_devices[event] - devices_not_to_retry[event])
            failed_ancillary_devices[event] = (
                failed_ancillary_devices[event] -
                ancillary_devices_not_to_retry[event])

    def _get_devices_not_to_retry(self, failed_devices,
                                  failed_ancillary_devices,
                                  failed_devices_retries_map):
        """Return the devices not to retry and update the retries map"""
        new_failed_devices_retries_map = {}
        devices_not_to_retry = {}
        ancillary_devices_not_to_retry = {}

        def _increase_retries(devices_set):
            devices_not_to_retry = set()
            for dev in devices_set:
                retries = failed_devices_retries_map.get(dev, 0)
                if retries >= constants.MAX_DEVICE_RETRIES:
                    devices_not_to_retry.add(dev)
                    LOG.warning(_LW(
                        "Device %(dev)s failed for %(times)s times and won't "
                        "be retried anymore"), {
                            'dev': dev, 'times': constants.MAX_DEVICE_RETRIES})
                else:
                    new_failed_devices_retries_map[dev] = retries + 1
            return devices_not_to_retry

        for event in ['added', 'removed']:
            devices_not_to_retry[event] = _increase_retries(
                failed_devices[event])
            ancillary_devices_not_to_retry[event] = _increase_retries(
                failed_ancillary_devices[event])

        return (new_failed_devices_retries_map, devices_not_to_retry,
                ancillary_devices_not_to_retry)

    def update_retries_map_and_remove_devs_not_to_retry(
            self, failed_devices, failed_ancillary_devices,
            failed_devices_retries_map):
        (new_failed_devices_retries_map, devices_not_to_retry,
         ancillary_devices_not_to_retry) = self._get_devices_not_to_retry(
            failed_devices, failed_ancillary_devices,
            failed_devices_retries_map)
        self._remove_devices_not_to_retry(
            failed_devices, failed_ancillary_devices, devices_not_to_retry,
            ancillary_devices_not_to_retry)
        return new_failed_devices_retries_map

    def rpc_loop(self, polling_manager=None):
        if not polling_manager:
            polling_manager = polling.get_polling_manager(
                minimize_polling=False)

        sync = False
        ports = set()
        updated_ports_copy = set()
        ancillary_ports = set()
        tunnel_sync = True
        ovs_restarted = False
        consecutive_resyncs = 0
        need_clean_stale_flow = True
        ports_not_ready_yet = set()
        failed_devices = {'added': set(), 'removed': set()}
        failed_ancillary_devices = {'added': set(), 'removed': set()}
        failed_devices_retries_map = {}
        while self._check_and_handle_signal():
            if self.fullsync:
                LOG.info(_LI("rpc_loop doing a full sync."))
                sync = True
                self.fullsync = False
            port_info = {}
            ancillary_port_info = {}
            start = time.time()
            LOG.debug("Agent rpc_loop - iteration:%d started",
                      self.iter_num)
            ovs_status = self.check_ovs_status()
            if ovs_status == constants.OVS_RESTARTED:
                self.setup_integration_br()
                self.setup_physical_bridges(self.bridge_mappings)
                if self.enable_tunneling:
                    self._reset_tunnel_ofports()
                    self.setup_tunnel_br()
                    self.setup_tunnel_br_flows()
                    tunnel_sync = True
                if self.enable_distributed_routing:
                    self.dvr_agent.reset_ovs_parameters(self.int_br,
                                                 self.tun_br,
                                                 self.patch_int_ofport,
                                                 self.patch_tun_ofport)
                    self.dvr_agent.reset_dvr_parameters()
                    self.dvr_agent.setup_dvr_flows()
                # restart the polling manager so that it will signal as added
                # all the current ports
                # REVISIT (rossella_s) Define a method "reset" in
                # BasePollingManager that will be implemented by AlwaysPoll as
                # no action and by InterfacePollingMinimizer as start/stop
                if isinstance(
                    polling_manager, polling.InterfacePollingMinimizer):
                    polling_manager.stop()
                    polling_manager.start()
            elif ovs_status == constants.OVS_DEAD:
                # Agent doesn't apply any operations when ovs is dead, to
                # prevent unexpected failure or crash. Sleep and continue
                # loop in which ovs status will be checked periodically.
                port_stats = self.get_port_stats({}, {})
                self.loop_count_and_wait(start, port_stats)
                continue
            # Notify the plugin of tunnel IP
            if self.enable_tunneling and tunnel_sync:
                try:
                    tunnel_sync = self.tunnel_sync()
                except Exception:
                    LOG.exception(
                            _LE("Error while configuring tunnel endpoints"))
                    tunnel_sync = True
            ovs_restarted |= (ovs_status == constants.OVS_RESTARTED)
            devices_need_retry = (any(failed_devices.values()) or
                any(failed_ancillary_devices.values()) or
                ports_not_ready_yet)
            if (self._agent_has_updates(polling_manager) or sync
                    or devices_need_retry):
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
                    (port_info, ancillary_port_info, consecutive_resyncs,
                     ports_not_ready_yet) = (self.process_port_info(
                            start, polling_manager, sync, ovs_restarted,
                            ports, ancillary_ports, updated_ports_copy,
                            consecutive_resyncs, ports_not_ready_yet,
                            failed_devices, failed_ancillary_devices))
                    sync = False
                    self.process_deleted_ports(port_info)
                    ofport_changed_ports = self.update_stale_ofport_rules()
                    if ofport_changed_ports:
                        port_info.setdefault('updated', set()).update(
                            ofport_changed_ports)
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
                        failed_devices = self.process_network_ports(
                            port_info, ovs_restarted)
                        if need_clean_stale_flow:
                            self.cleanup_stale_flows()
                            need_clean_stale_flow = False
                        LOG.debug("Agent rpc_loop - iteration:%(iter_num)d - "
                                  "ports processed. Elapsed:%(elapsed).3f",
                                  {'iter_num': self.iter_num,
                                   'elapsed': time.time() - start})

                    ports = port_info['current']

                    if self.ancillary_brs:
                        failed_ancillary_devices = (
                            self.process_ancillary_network_ports(
                                ancillary_port_info))
                        LOG.debug("Agent rpc_loop - iteration: "
                                  "%(iter_num)d - ancillary ports "
                                  "processed. Elapsed:%(elapsed).3f",
                                  {'iter_num': self.iter_num,
                                   'elapsed': time.time() - start})
                        ancillary_ports = ancillary_port_info['current']

                    polling_manager.polling_completed()
                    failed_devices_retries_map = (
                        self.update_retries_map_and_remove_devs_not_to_retry(
                            failed_devices, failed_ancillary_devices,
                            failed_devices_retries_map))
                    # Keep this flag in the last line of "try" block,
                    # so we can sure that no other Exception occurred.
                    ovs_restarted = False
                    self._dispose_local_vlan_hints()
                except Exception:
                    LOG.exception(_LE("Error while processing VIF ports"))
                    # Put the ports back in self.updated_port
                    self.updated_ports |= updated_ports_copy
                    sync = True
            port_stats = self.get_port_stats(port_info, ancillary_port_info)
            self.loop_count_and_wait(start, port_stats)

    def daemon_loop(self):
        # Start everything.
        LOG.info(_LI("Agent initialized successfully, now running... "))
        signal.signal(signal.SIGTERM, self._handle_sigterm)
        if hasattr(signal, 'SIGHUP'):
            signal.signal(signal.SIGHUP, self._handle_sighup)
        with polling.get_polling_manager(
            self.minimize_polling,
            self.ovsdb_monitor_respawn_interval) as pm:

            self.rpc_loop(polling_manager=pm)

    def _handle_sigterm(self, signum, frame):
        self.catch_sigterm = True
        if self.quitting_rpc_timeout:
            self.set_rpc_timeout(self.quitting_rpc_timeout)

    def _handle_sighup(self, signum, frame):
        self.catch_sighup = True

    def _check_and_handle_signal(self):
        if self.catch_sigterm:
            LOG.info(_LI("Agent caught SIGTERM, quitting daemon loop."))
            self.run_daemon_loop = False
            self.catch_sigterm = False
        if self.catch_sighup:
            LOG.info(_LI("Agent caught SIGHUP, resetting."))
            self.conf.reload_config_files()
            config.setup_logging()
            LOG.debug('Full set of CONF:')
            self.conf.log_opt_values(LOG, logging.DEBUG)
            self.catch_sighup = False
        return self.run_daemon_loop

    def set_rpc_timeout(self, timeout):
        for rpc_api in (self.plugin_rpc, self.sg_plugin_rpc,
                        self.dvr_plugin_rpc, self.state_rpc):
            rpc_api.client.timeout = timeout

    def _check_agent_configurations(self):
        if (self.enable_distributed_routing and self.enable_tunneling
            and not self.l2_pop):

            raise ValueError(_("DVR deployments for VXLAN/GRE/Geneve "
                               "underlays require L2-pop to be enabled, "
                               "in both the Agent and Server side."))


def validate_local_ip(local_ip):
    """Verify if the ip exists on the agent's host."""
    if not ip_lib.IPWrapper().get_device_by_ip(local_ip):
        LOG.error(_LE("Tunneling can't be enabled with invalid local_ip '%s'."
                      " IP couldn't be found on this host's interfaces."),
                  local_ip)
        raise SystemExit(1)


def validate_tunnel_config(tunnel_types, local_ip):
    """Verify local ip and tunnel config if tunneling is enabled."""
    if not tunnel_types:
        return

    validate_local_ip(local_ip)
    for tun in tunnel_types:
        if tun not in constants.TUNNEL_NETWORK_TYPES:
            LOG.error(_LE('Invalid tunnel type specified: %s'), tun)
            raise SystemExit(1)


def prepare_xen_compute():
    is_xen_compute_host = 'rootwrap-xen-dom0' in cfg.CONF.AGENT.root_helper
    if is_xen_compute_host:
        # Force ip_lib to always use the root helper to ensure that ip
        # commands target xen dom0 rather than domU.
        cfg.CONF.register_opts(ip_lib.OPTS)
        cfg.CONF.set_default('ip_lib_force_root', True)


def main(bridge_classes):
    prepare_xen_compute()
    validate_tunnel_config(cfg.CONF.AGENT.tunnel_types, cfg.CONF.OVS.local_ip)

    try:
        agent = OVSNeutronAgent(bridge_classes, cfg.CONF)
    except (RuntimeError, ValueError) as e:
        LOG.error(_LE("%s Agent terminated!"), e)
        sys.exit(1)
    agent.daemon_loop()
