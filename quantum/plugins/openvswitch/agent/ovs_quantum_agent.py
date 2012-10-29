#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2011 Nicira Networks, Inc.
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
# @author: Somik Behera, Nicira Networks, Inc.
# @author: Brad Hall, Nicira Networks, Inc.
# @author: Dan Wendlandt, Nicira Networks, Inc.
# @author: Dave Lapsley, Nicira Networks, Inc.
# @author: Aaron Rosen, Nicira Networks, Inc.

import logging
import sys
import time

import eventlet

from quantum.agent import rpc as agent_rpc
from quantum.agent.linux import ip_lib
from quantum.agent.linux import ovs_lib
from quantum.agent.linux import utils
from quantum.common import constants as q_const
from quantum.common import config as logging_config
from quantum.common import topics
from quantum.openstack.common import cfg
from quantum.openstack.common import context
from quantum.openstack.common import rpc
from quantum.openstack.common.rpc import dispatcher
from quantum.plugins.openvswitch.common import config
from quantum.plugins.openvswitch.common import constants

logging.basicConfig()
LOG = logging.getLogger(__name__)

# A placeholder for dead vlans.
DEAD_VLAN_TAG = "4095"


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

    def __str__(self):
        return ("lv-id = %s type = %s phys-net = %s phys-id = %s" %
                (self.vlan, self.network_type, self.physical_network,
                 self.segmentation_id))


class Port(object):
    """Represents a quantum port.

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
        except:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.id)


class OVSQuantumAgent(object):
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

    # Lower bound on available vlans.
    MIN_VLAN_TAG = 1

    # Upper bound on available vlans.
    MAX_VLAN_TAG = 4094

    # Set RPC API version to 1.0 by default.
    RPC_API_VERSION = '1.0'

    def __init__(self, integ_br, tun_br, local_ip,
                 bridge_mappings, root_helper,
                 polling_interval, enable_tunneling):
        '''Constructor.

        :param integ_br: name of the integration bridge.
        :param tun_br: name of the tunnel bridge.
        :param local_ip: local IP address of this hypervisor.
        :param bridge_mappings: mappings from phyiscal interface to bridge.
        :param root_helper: utility to use when running shell cmds.
        :param polling_interval: interval (secs) to poll DB.
        :param enable_tunneling: if True enable GRE networks.
        '''
        self.root_helper = root_helper
        self.available_local_vlans = set(
            xrange(OVSQuantumAgent.MIN_VLAN_TAG,
                   OVSQuantumAgent.MAX_VLAN_TAG))
        self.int_br = self.setup_integration_br(integ_br)
        self.setup_physical_bridges(bridge_mappings)
        self.local_vlan_map = {}

        self.polling_interval = polling_interval

        self.enable_tunneling = enable_tunneling
        self.local_ip = local_ip
        self.tunnel_count = 0
        if self.enable_tunneling:
            self.setup_tunnel_br(tun_br)

        self.setup_rpc(integ_br)

    def setup_rpc(self, integ_br):
        mac = utils.get_interface_mac(integ_br)
        self.agent_id = '%s%s' % ('ovs', (mac.replace(":", "")))
        self.topic = topics.AGENT
        self.plugin_rpc = agent_rpc.PluginApi(topics.PLUGIN)

        # RPC network init
        self.context = context.RequestContext('quantum', 'quantum',
                                              is_admin=False)
        # Handle updates from service
        self.dispatcher = self.create_rpc_dispatcher()
        # Define the listening consumers for the agent
        consumers = [[topics.PORT, topics.UPDATE],
                     [topics.NETWORK, topics.DELETE],
                     [constants.TUNNEL, topics.UPDATE]]
        self.connection = agent_rpc.create_consumers(self.dispatcher,
                                                     self.topic,
                                                     consumers)

    def get_net_uuid(self, vif_id):
        for network_id, vlan_mapping in self.local_vlan_map.iteritems():
            if vif_id in vlan_mapping.vif_ports:
                return network_id

    def network_delete(self, context, **kwargs):
        LOG.debug("network_delete received")
        network_id = kwargs.get('network_id')
        LOG.debug("Delete %s", network_id)
        # The network may not be defined on this agent
        lvm = self.local_vlan_map.get(network_id)
        if lvm:
            self.reclaim_local_vlan(network_id, lvm)
        else:
            LOG.debug("Network %s not used on agent.", network_id)

    def port_update(self, context, **kwargs):
        LOG.debug("port_update received")
        port = kwargs.get('port')
        network_type = kwargs.get('network_type')
        segmentation_id = kwargs.get('segmentation_id')
        physical_network = kwargs.get('physical_network')
        vif_port = self.int_br.get_vif_port_by_id(port['id'])
        self.treat_vif_port(vif_port, port['id'], port['network_id'],
                            network_type, physical_network,
                            segmentation_id, port['admin_state_up'])

    def tunnel_update(self, context, **kwargs):
        LOG.debug("tunnel_update received")
        if not self.enable_tunneling:
            return
        tunnel_ip = kwargs.get('tunnel_ip')
        tunnel_id = kwargs.get('tunnel_id')
        if tunnel_ip == self.local_ip:
            return
        tun_name = 'gre-%s' % tunnel_id
        self.tun_br.add_tunnel_port(tun_name, tunnel_ip)

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
        :param network_type: the network type ('gre', 'vlan', 'flat', 'local')
        :param physical_network: the physical network for 'vlan' or 'flat'
        :param segmentation_id: the VID for 'vlan' or tunnel ID for 'tunnel'
        '''

        if not self.available_local_vlans:
            LOG.error("No local VLAN available for net-id=%s", net_uuid)
            return
        lvid = self.available_local_vlans.pop()
        LOG.info("Assigning %s as local vlan for net-id=%s", lvid, net_uuid)
        self.local_vlan_map[net_uuid] = LocalVLANMapping(lvid, network_type,
                                                         physical_network,
                                                         segmentation_id)

        if network_type == constants.TYPE_GRE:
            if self.enable_tunneling:
                # outbound
                self.tun_br.add_flow(priority=4, in_port=self.patch_int_ofport,
                                     dl_vlan=lvid,
                                     actions="set_tunnel:%s,normal" %
                                     segmentation_id)
                # inbound bcast/mcast
                self.tun_br.add_flow(priority=3, tun_id=segmentation_id,
                                     dl_dst=
                                     "01:00:00:00:00:00/01:00:00:00:00:00",
                                     actions="mod_vlan_vid:%s,output:%s" %
                                     (lvid, self.patch_int_ofport))
            else:
                LOG.error("Cannot provision GRE network for net-id=%s "
                          "- tunneling disabled", net_uuid)
        elif network_type == constants.TYPE_FLAT:
            if physical_network in self.phys_brs:
                # outbound
                br = self.phys_brs[physical_network]
                br.add_flow(priority=4,
                            in_port=self.phys_ofports[physical_network],
                            dl_vlan=lvid,
                            actions="strip_vlan,normal")
                # inbound
                self.int_br.add_flow(priority=3,
                                     in_port=
                                     self.int_ofports[physical_network],
                                     dl_vlan=0xffff,
                                     actions="mod_vlan_vid:%s,normal" % lvid)
            else:
                LOG.error("Cannot provision flat network for net-id=%s "
                          "- no bridge for physical_network %s", net_uuid,
                          physical_network)
        elif network_type == constants.TYPE_VLAN:
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
                LOG.error("Cannot provision VLAN network for net-id=%s "
                          "- no bridge for physical_network %s", net_uuid,
                          physical_network)
        elif network_type == constants.TYPE_LOCAL:
            # no flows needed for local networks
            pass
        else:
            LOG.error("Cannot provision unknown network type %s for "
                      "net-id=%s", network_type, net_uuid)

    def reclaim_local_vlan(self, net_uuid, lvm):
        '''Reclaim a local VLAN.

        :param net_uuid: the network uuid associated with this vlan.
        :param lvm: a LocalVLANMapping object that tracks (vlan, lsw_id,
            vif_ids) mapping.'''
        LOG.info("Reclaiming vlan = %s from net-id = %s", lvm.vlan, net_uuid)

        if lvm.network_type == constants.TYPE_GRE:
            if self.enable_tunneling:
                self.tun_br.delete_flows(tun_id=lvm.segmentation_id)
                self.tun_br.delete_flows(dl_vlan=lvm.vlan)
        elif lvm.network_type == constants.TYPE_FLAT:
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
        elif lvm.network_type == constants.TYPE_VLAN:
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
        elif lvm.network_type == constants.TYPE_LOCAL:
            # no flows needed for local networks
            pass
        else:
            LOG.error("Cannot reclaim unknown network type %s for net-id=%s",
                      lvm.network_type, net_uuid)

        del self.local_vlan_map[net_uuid]
        self.available_local_vlans.add(lvm.vlan)

    def port_bound(self, port, net_uuid,
                   network_type, physical_network, segmentation_id):
        '''Bind port to net_uuid/lsw_id and install flow for inbound traffic
        to vm.

        :param port: a ovslib.VifPort object.
        :param net_uuid: the net_uuid this port is to be associated with.
        :param network_type: the network type ('gre', 'vlan', 'flat', 'local')
        :param physical_network: the physical network for 'vlan' or 'flat'
        :param segmentation_id: the VID for 'vlan' or tunnel ID for 'tunnel'
        '''
        if net_uuid not in self.local_vlan_map:
            self.provision_local_vlan(net_uuid, network_type,
                                      physical_network, segmentation_id)
        lvm = self.local_vlan_map[net_uuid]
        lvm.vif_ports[port.vif_id] = port

        if network_type == constants.TYPE_GRE:
            if self.enable_tunneling:
                # inbound unicast
                self.tun_br.add_flow(priority=3, tun_id=segmentation_id,
                                     dl_dst=port.vif_mac,
                                     actions="mod_vlan_vid:%s,normal" %
                                     lvm.vlan)

        self.int_br.set_db_attribute("Port", port.port_name, "tag",
                                     str(lvm.vlan))
        if int(port.ofport) != -1:
            self.int_br.delete_flows(in_port=port.ofport)

    def port_unbound(self, vif_id, net_uuid=None):
        '''Unbind port.

        Removes corresponding local vlan mapping object if this is its last
        VIF.

        :param vif_id: the id of the vif
        :param net_uuid: the net_uuid this port is associated with.'''
        if net_uuid is None:
            net_uuid = self.get_net_uuid(vif_id)

        if not self.local_vlan_map.get(net_uuid):
            LOG.info('port_unbound() net_uuid %s not in local_vlan_map',
                     net_uuid)
            return
        lvm = self.local_vlan_map[net_uuid]
        if lvm.network_type == 'gre':
            if self.enable_tunneling:
                # remove inbound unicast flow
                self.tun_br.delete_flows(tun_id=lvm.segmentation_id,
                                         dl_dst=lvm.vif_ports[vif_id].vif_mac)

        if vif_id in lvm.vif_ports:
            del lvm.vif_ports[vif_id]
        else:
            LOG.info('port_unbound: vif_id %s not in local_vlan_map', vif_id)

        if not lvm.vif_ports:
            self.reclaim_local_vlan(net_uuid, lvm)

    def port_dead(self, port):
        '''Once a port has no binding, put it on the "dead vlan".

        :param port: a ovs_lib.VifPort object.'''
        self.int_br.set_db_attribute("Port", port.port_name, "tag",
                                     DEAD_VLAN_TAG)
        self.int_br.add_flow(priority=2, in_port=port.ofport, actions="drop")

    def setup_integration_br(self, bridge_name):
        '''Setup the integration bridge.

        Create patch ports and remove all existing flows.

        :param bridge_name: the name of the integration bridge.
        :returns: the integration bridge
        '''
        int_br = ovs_lib.OVSBridge(bridge_name, self.root_helper)
        int_br.delete_port("patch-tun")
        int_br.remove_all_flows()
        # switch all traffic using L2 learning
        int_br.add_flow(priority=1, actions="normal")
        return int_br

    def setup_tunnel_br(self, tun_br):
        '''Setup the tunnel bridge.

        Creates tunnel bridge, and links it to the integration bridge
        using a patch port.

        :param tun_br: the name of the tunnel bridge.'''
        self.tun_br = ovs_lib.OVSBridge(tun_br, self.root_helper)
        self.tun_br.reset_bridge()
        self.patch_tun_ofport = self.int_br.add_patch_port("patch-tun",
                                                           "patch-int")
        self.patch_int_ofport = self.tun_br.add_patch_port("patch-int",
                                                           "patch-tun")
        if int(self.patch_tun_ofport) < 0 or int(self.patch_int_ofport) < 0:
            LOG.error("Failed to create OVS patch port. Cannot have tunneling "
                      "enabled on this agent, since this version of OVS does "
                      "not support tunnels or patch ports. "
                      "Agent terminated!")
            exit(1)
        self.tun_br.remove_all_flows()
        self.tun_br.add_flow(priority=1, actions="drop")

    def setup_physical_bridges(self, bridge_mappings):
        '''Setup the physical network bridges.

        Creates phyiscal network bridges and links them to the
        integration bridge using veths.

        :param bridge_mappings: map physical network names to bridge names.'''
        self.phys_brs = {}
        self.int_ofports = {}
        self.phys_ofports = {}
        ip_wrapper = ip_lib.IPWrapper(self.root_helper)
        for physical_network, bridge in bridge_mappings.iteritems():
            LOG.info("Mapping physical network %s to bridge %s",
                     physical_network, bridge)
            # setup physical bridge
            if not ip_lib.device_exists(bridge, self.root_helper):
                LOG.error("Bridge %s for physical network %s does not exist. "
                          "Agent terminated!",
                          bridge, physical_network)
                sys.exit(1)
            br = ovs_lib.OVSBridge(bridge, self.root_helper)
            br.remove_all_flows()
            br.add_flow(priority=1, actions="normal")
            self.phys_brs[physical_network] = br

            # create veth to patch physical bridge with integration bridge
            int_veth_name = constants.VETH_INTEGRATION_PREFIX + bridge
            self.int_br.delete_port(int_veth_name)
            phys_veth_name = constants.VETH_PHYSICAL_PREFIX + bridge
            br.delete_port(phys_veth_name)
            if ip_lib.device_exists(int_veth_name, self.root_helper):
                ip_lib.IPDevice(int_veth_name, self.root_helper).link.delete()
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

    def update_ports(self, registered_ports):
        ports = self.int_br.get_vif_port_set()
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
            if admin_state_up:
                self.port_bound(vif_port, network_id, network_type,
                                physical_network, segmentation_id)
            else:
                self.port_dead(vif_port)
        else:
            LOG.debug("No VIF port for port %s defined on agent.", port_id)

    def treat_devices_added(self, devices):
        resync = False
        for device in devices:
            LOG.info("Port %s added", device)
            try:
                details = self.plugin_rpc.get_device_details(self.context,
                                                             device,
                                                             self.agent_id)
            except Exception as e:
                LOG.debug("Unable to get port details for %s: %s", device, e)
                resync = True
                continue
            port = self.int_br.get_vif_port_by_id(details['device'])
            if 'port_id' in details:
                LOG.info("Port %s updated. Details: %s", device, details)
                self.treat_vif_port(port, details['port_id'],
                                    details['network_id'],
                                    details['network_type'],
                                    details['physical_network'],
                                    details['segmentation_id'],
                                    details['admin_state_up'])
            else:
                LOG.debug("Device %s not defined on plugin", device)
                if (port and int(port.ofport) != -1):
                    self.port_dead(port)
        return resync

    def treat_devices_removed(self, devices):
        resync = False
        for device in devices:
            LOG.info("Attachment %s removed", device)
            try:
                details = self.plugin_rpc.update_device_down(self.context,
                                                             device,
                                                             self.agent_id)
            except Exception as e:
                LOG.debug("port_removed failed for %s: %s", device, e)
                resync = True
                continue
            if details['exists']:
                LOG.info("Port %s updated.", device)
                # Nothing to do regarding local networking
            else:
                LOG.debug("Device %s not defined on plugin", device)
                self.port_unbound(device)
        return resync

    def process_network_ports(self, port_info):
        resync_a = False
        resync_b = False
        if 'added' in port_info:
            resync_a = self.treat_devices_added(port_info['added'])
        if 'removed' in port_info:
            resync_b = self.treat_devices_removed(port_info['removed'])
        # If one of the above opertaions fails => resync with plugin
        return (resync_a | resync_b)

    def tunnel_sync(self):
        resync = False
        try:
            details = self.plugin_rpc.tunnel_sync(self.context, self.local_ip)
            tunnels = details['tunnels']
            for tunnel in tunnels:
                if self.local_ip != tunnel['ip_address']:
                    tun_name = 'gre-%s' % tunnel['id']
                    self.tun_br.add_tunnel_port(tun_name, tunnel['ip_address'])
        except Exception as e:
            LOG.debug("Unable to sync tunnel IP %s: %s", self.local_ip, e)
            resync = True
        return resync

    def rpc_loop(self):
        sync = True
        ports = set()
        tunnel_sync = True

        while True:
            try:
                start = time.time()
                if sync:
                    LOG.info("Agent out of sync with plugin!")
                    ports.clear()
                    sync = False

                # Notify the plugin of tunnel IP
                if self.enable_tunneling and tunnel_sync:
                    LOG.info("Agent tunnel out of sync with plugin!")
                    tunnel_sync = self.tunnel_sync()

                port_info = self.update_ports(ports)

                # notify plugin about port deltas
                if port_info:
                    LOG.debug("Agent loop has new devices!")
                    # If treat devices fails - must resync with plugin
                    sync = self.process_network_ports(port_info)
                    ports = port_info['current']

            except:
                LOG.exception("Error in agent event loop")
                sync = True
                tunnel_sync = True

            # sleep till end of polling interval
            elapsed = (time.time() - start)
            if (elapsed < self.polling_interval):
                time.sleep(self.polling_interval - elapsed)
            else:
                LOG.debug("Loop iteration exceeded interval (%s vs. %s)!",
                          self.polling_interval, elapsed)

    def daemon_loop(self):
        self.rpc_loop()


def parse_bridge_mappings(bridge_mapping_list):
    """Parse a list of physical network to bridge mappings.

    :param bridge_mapping_list: a list of strings of the form
                                '<physical network>:<bridge>'
    :returns: a dict mapping physical networks to bridges
    """
    bridge_mappings = {}
    for mapping in bridge_mapping_list:
        mapping = mapping.strip()
        if not mapping:
            continue
        split_result = [x.strip() for x in mapping.split(':', 1) if x.strip()]
        if len(split_result) != 2:
            raise ValueError('Invalid bridge mapping: %s.' % mapping)
        physical_network, bridge = split_result
        bridge_mappings[physical_network] = bridge
    return bridge_mappings


def create_agent_config_map(config):
    """Create a map of agent config parameters.

    :param config: an instance of cfg.CONF
    :returns: a map of agent configuration parameters
    """
    bridge_mappings = parse_bridge_mappings(config.OVS.bridge_mappings)
    kwargs = dict(
        integ_br=config.OVS.integration_bridge,
        tun_br=config.OVS.tunnel_bridge,
        local_ip=config.OVS.local_ip,
        bridge_mappings=bridge_mappings,
        root_helper=config.AGENT.root_helper,
        polling_interval=config.AGENT.polling_interval,
        enable_tunneling=config.OVS.enable_tunneling,
    )

    if kwargs['enable_tunneling'] and not kwargs['local_ip']:
        msg = 'Tunnelling cannot be enabled without a valid local_ip.'
        raise ValueError(msg)

    return kwargs


def main():
    eventlet.monkey_patch()
    cfg.CONF(args=sys.argv, project='quantum')

    # (TODO) gary - swap with common logging
    logging_config.setup_logging(cfg.CONF)

    try:
        agent_config = create_agent_config_map(cfg.CONF)
    except ValueError as e:
        LOG.error('%s Agent terminated!', e)
        sys.exit(1)

    plugin = OVSQuantumAgent(**agent_config)

    # Start everything.
    LOG.info("Agent initialized successfully, now running... ")
    plugin.daemon_loop()
    sys.exit(0)


if __name__ == "__main__":
    main()
