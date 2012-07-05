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
from sqlalchemy.ext import sqlsoup

from quantum.agent import rpc as agent_rpc
from quantum.agent.linux import ovs_lib
from quantum.agent.linux import utils
from quantum.common import constants
from quantum.common import config as logging_config
from quantum.common import topics
from quantum.openstack.common import cfg
from quantum.openstack.common import context
from quantum.openstack.common import rpc
from quantum.openstack.common.rpc import dispatcher
from quantum.plugins.openvswitch.common import config

logging.basicConfig()
LOG = logging.getLogger(__name__)

# A placeholder for dead vlans.
DEAD_VLAN_TAG = "4095"

# Default interval values
DEFAULT_POLLING_INTERVAL = 2
DEFAULT_RECONNECT_INTERVAL = 2


# A class to represent a VIF (i.e., a port that has 'iface-id' and 'vif-mac'
# attributes set).
class LocalVLANMapping:
    def __init__(self, vlan, lsw_id, vif_ids=None):
        if vif_ids is None:
            vif_ids = []
        self.vlan = vlan
        self.lsw_id = lsw_id
        self.vif_ids = vif_ids

    def __str__(self):
        return "lv-id = %s ls-id = %s" % (self.vlan, self.lsw_id)


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


class OVSRpcCallbacks():

    # Set RPC API version to 1.0 by default.
    RPC_API_VERSION = '1.0'

    def __init__(self, context, int_br, local_ip=None, tun_br=None):
        self.context = context
        self.int_br = int_br
        # Tunneling variables
        self.local_ip = local_ip
        self.tun_br = tun_br

    def network_delete(self, context, **kwargs):
        LOG.debug("network_delete received")
        network_id = kwargs.get('network_id')
        # (TODO) garyk delete the bridge interface
        LOG.debug("Delete %s", network_id)

    def port_update(self, context, **kwargs):
        LOG.debug("port_update received")
        port = kwargs.get('port')
        vif_port = self.int_br.get_vif_port_by_id(port['id'])
        if vif_port:
            if port['admin_state_up']:
                vlan_id = kwargs.get('vlan_id')
                # create the networking for the port
                self.int_br.set_db_attribute("Port", vif_port.port_name,
                                             "tag", str(vlan_id))
                self.int_br.delete_flows(in_port=vif_port.ofport)
            else:
                self.int_br.clear_db_attribute("Port", vif_port.port_name,
                                               "tag")

    def tunnel_update(self, context, **kwargs):
        LOG.debug("tunnel_update received")
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


class OVSQuantumAgent(object):

    def __init__(self, integ_br, root_helper, polling_interval,
                 reconnect_interval, rpc):
        self.root_helper = root_helper
        self.setup_integration_br(integ_br)
        self.polling_interval = polling_interval
        self.reconnect_interval = reconnect_interval
        self.rpc = rpc
        if rpc:
            self.setup_rpc(integ_br)

    def setup_rpc(self, integ_br):
        mac = utils.get_interface_mac(integ_br)
        self.agent_id = '%s' % (mac.replace(":", ""))
        self.topic = topics.AGENT
        self.plugin_rpc = agent_rpc.PluginApi(topics.PLUGIN)

        # RPC network init
        self.context = context.RequestContext('quantum', 'quantum',
                                              is_admin=False)
        # Handle updates from service
        self.callbacks = OVSRpcCallbacks(self.context, self.int_br)
        self.dispatcher = self.callbacks.create_rpc_dispatcher()
        # Define the listening consumers for the agent
        consumers = [[topics.PORT, topics.UPDATE],
                     [topics.NETWORK, topics.DELETE]]
        self.connection = agent_rpc.create_consumers(self.dispatcher,
                                                     self.topic,
                                                     consumers)

    def port_bound(self, port, vlan_id):
        self.int_br.set_db_attribute("Port", port.port_name,
                                     "tag", str(vlan_id))
        self.int_br.delete_flows(in_port=port.ofport)

    def port_unbound(self, port, still_exists):
        if still_exists:
            self.int_br.clear_db_attribute("Port", port.port_name, "tag")

    def setup_integration_br(self, integ_br):
        self.int_br = ovs_lib.OVSBridge(integ_br, self.root_helper)
        self.int_br.remove_all_flows()
        # switch all traffic using L2 learning
        self.int_br.add_flow(priority=1, actions="normal")

    def db_loop(self, db_connection_url):
        '''Main processing loop for Non-Tunneling Agent.

        :param options: database information - in the event need to reconnect
        '''
        self.local_vlan_map = {}
        old_local_bindings = {}
        old_vif_ports = {}
        db_connected = False

        while True:
            if not db_connected:
                time.sleep(self.reconnect_interval)
                db = sqlsoup.SqlSoup(db_connection_url)
                db_connected = True
                LOG.info("Connecting to database \"%s\" on %s" %
                         (db.engine.url.database, db.engine.url.host))

            all_bindings = {}
            try:
                ports = db.ports.all()
            except Exception, e:
                LOG.info("Unable to get port bindings! Exception: %s" % e)
                db_connected = False
                continue

            for port in ports:
                all_bindings[port.id] = port

            vlan_bindings = {}
            try:
                vlan_binds = db.vlan_bindings.all()
            except Exception, e:
                LOG.info("Unable to get vlan bindings! Exception: %s" % e)
                db_connected = False
                continue

            for bind in vlan_binds:
                vlan_bindings[bind.network_id] = bind.vlan_id

            new_vif_ports = {}
            new_local_bindings = {}
            vif_ports = self.int_br.get_vif_ports()
            for p in vif_ports:
                new_vif_ports[p.vif_id] = p
                if p.vif_id in all_bindings:
                    net_id = all_bindings[p.vif_id].network_id
                    new_local_bindings[p.vif_id] = net_id
                else:
                    # no binding, put him on the 'dead vlan'
                    self.int_br.set_db_attribute("Port", p.port_name, "tag",
                                                 DEAD_VLAN_TAG)
                    self.int_br.add_flow(priority=2,
                                         in_port=p.ofport,
                                         actions="drop")

                old_b = old_local_bindings.get(p.vif_id, None)
                new_b = new_local_bindings.get(p.vif_id, None)

                if old_b != new_b:
                    if old_b is not None:
                        LOG.info("Removing binding to net-id = %s for %s"
                                 % (old_b, str(p)))
                        self.port_unbound(p, True)
                        if p.vif_id in all_bindings:
                            all_bindings[p.vif_id].status = (
                                constants.PORT_STATUS_DOWN)
                    if new_b is not None:
                        # If we don't have a binding we have to stick it on
                        # the dead vlan
                        net_id = all_bindings[p.vif_id].network_id
                        vlan_id = vlan_bindings.get(net_id, DEAD_VLAN_TAG)
                        self.port_bound(p, vlan_id)
                        if p.vif_id in all_bindings:
                            all_bindings[p.vif_id].status = (
                                constants.PORT_STATUS_ACTIVE)
                        LOG.info(("Adding binding to net-id = %s "
                                  "for %s on vlan %s") %
                                 (new_b, str(p), vlan_id))

            for vif_id in old_vif_ports:
                if vif_id not in new_vif_ports:
                    LOG.info("Port Disappeared: %s" % vif_id)
                    if vif_id in old_local_bindings:
                        old_b = old_local_bindings[vif_id]
                        self.port_unbound(old_vif_ports[vif_id], False)
                    if vif_id in all_bindings:
                        all_bindings[vif_id].status = (
                            constants.PORT_STATUS_DOWN)

            old_vif_ports = new_vif_ports
            old_local_bindings = new_local_bindings
            try:
                db.commit()
            except Exception, e:
                LOG.info("Unable to commit to database! Exception: %s" % e)
                db.rollback()
                old_local_bindings = {}
                old_vif_ports = {}

            time.sleep(self.polling_interval)

    def update_ports(self, registered_ports):
        ports = self.int_br.get_vif_port_set()
        if ports == registered_ports:
            return
        added = ports - registered_ports
        removed = registered_ports - ports
        return {'current': ports,
                'added': added,
                'removed': removed}

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
            if 'port_id' in details:
                LOG.info("Port %s updated. Details: %s", device, details)
                port = self.int_br.get_vif_port_by_id(details['port_id'])
                if port:
                    if details['admin_state_up']:
                        self.port_bound(port, details['vlan_id'])
                    else:
                        self.port_unbound(port, True)
            else:
                LOG.debug("Device %s not defined on plugin", device)
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
            if details['exists']:
                LOG.info("Port %s updated.", device)
                # Nothing to do regarding local networking
            else:
                LOG.debug("Device %s not defined on plugin", device)
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

    def rpc_loop(self):
        sync = True
        ports = set()

        while True:
            start = time.time()
            if sync:
                LOG.info("Agent out of sync with plugin!")
                ports.clear()
                sync = False

            port_info = self.update_ports(ports)

            # notify plugin about port deltas
            if port_info:
                LOG.debug("Agent loop has new devices!")
                # If treat devices fails - indicates must resync with plugin
                sync = self.process_network_ports(port_info)
                ports = port_info['current']

            # sleep till end of polling interval
            elapsed = (time.time() - start)
            if (elapsed < self.polling_interval):
                time.sleep(self.polling_interval - elapsed)
            else:
                LOG.debug("Loop iteration exceeded interval (%s vs. %s)!",
                          self.polling_interval, elapsed)

    def daemon_loop(self, db_connection_url):
        if self.rpc:
            self.rpc_loop()
        else:
            self.db_loop(db_connection_url)


class OVSQuantumTunnelAgent(object):
    '''Implements OVS-based tunneling.

    Two local bridges are created: an integration bridge (defaults to 'br-int')
    and a tunneling bridge (defaults to 'br-tun').

    All VM VIFs are plugged into the integration bridge. VMs for a given tenant
    share a common "local" VLAN (i.e. not propagated externally). The VLAN id
    of this local VLAN is mapped to a Logical Switch (LS) identifier and is
    used to differentiate tenant traffic on inter-HV tunnels.

    A mesh of tunnels is created to other Hypervisors in the cloud. These
    tunnels originate and terminate on the tunneling bridge of each hypervisor.

    Port patching is done to connect local VLANs on the integration bridge
    to inter-hypervisor tunnels on the tunnel bridge.
    '''

    # Lower bound on available vlans.
    MIN_VLAN_TAG = 1

    # Upper bound on available vlans.
    MAX_VLAN_TAG = 4094

    def __init__(self, integ_br, tun_br, local_ip, root_helper,
                 polling_interval, reconnect_interval, rpc):
        '''Constructor.

        :param integ_br: name of the integration bridge.
        :param tun_br: name of the tunnel bridge.
        :param local_ip: local IP address of this hypervisor.
        :param root_helper: utility to use when running shell cmds.
        :param polling_interval: interval (secs) to poll DB.
        :param reconnect_internal: retry interval (secs) on DB error.
        :param rpc: if True use RPC interface to interface with plugin.
        '''
        self.root_helper = root_helper
        self.available_local_vlans = set(
            xrange(OVSQuantumTunnelAgent.MIN_VLAN_TAG,
                   OVSQuantumTunnelAgent.MAX_VLAN_TAG))
        self.setup_integration_br(integ_br)
        self.local_vlan_map = {}

        self.polling_interval = polling_interval
        self.reconnect_interval = reconnect_interval

        self.local_ip = local_ip
        self.tunnel_count = 0
        self.setup_tunnel_br(tun_br)
        self.rpc = rpc
        if rpc:
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
        self.callbacks = OVSRpcCallbacks(self.context, self.int_br,
                                         self.local_ip, self.tun_br)
        self.dispatcher = self.callbacks.create_rpc_dispatcher()
        # Define the listening consumers for the agent
        consumers = [[topics.PORT, topics.UPDATE],
                     [topics.NETWORK, topics.DELETE],
                     [config.TUNNEL, topics.UPDATE]]
        self.connection = agent_rpc.create_consumers(self.dispatcher,
                                                     self.topic,
                                                     consumers)

    def provision_local_vlan(self, net_uuid, lsw_id):
        '''Provisions a local VLAN.

        :param net_uuid: the uuid of the network associated with this vlan.
        :param lsw_id: the logical switch id of this vlan.'''
        if not self.available_local_vlans:
            raise Exception("No local VLANs available for ls-id = %s" % lsw_id)
        lvid = self.available_local_vlans.pop()
        LOG.info("Assigning %s as local vlan for net-id=%s" % (lvid, net_uuid))
        self.local_vlan_map[net_uuid] = LocalVLANMapping(lvid, lsw_id)

        # outbound
        self.tun_br.add_flow(priority=4, in_port=self.patch_int_ofport,
                             dl_vlan=lvid,
                             actions="set_tunnel:%s,normal" % lsw_id)
        # inbound bcast/mcast
        self.tun_br.add_flow(priority=3, tun_id=lsw_id,
                             dl_dst="01:00:00:00:00:00/01:00:00:00:00:00",
                             actions="mod_vlan_vid:%s,output:%s" %
                             (lvid, self.patch_int_ofport))

    def reclaim_local_vlan(self, net_uuid, lvm):
        '''Reclaim a local VLAN.

        :param net_uuid: the network uuid associated with this vlan.
        :param lvm: a LocalVLANMapping object that tracks (vlan, lsw_id,
            vif_ids) mapping.'''
        LOG.info("reclaming vlan = %s from net-id = %s" % (lvm.vlan, net_uuid))
        self.tun_br.delete_flows(tun_id=lvm.lsw_id)
        self.tun_br.delete_flows(dl_vlan=lvm.vlan)
        del self.local_vlan_map[net_uuid]
        self.available_local_vlans.add(lvm.vlan)

    def port_bound(self, port, net_uuid, lsw_id):
        '''Bind port to net_uuid/lsw_id and install flow for inbound traffic
        to vm.

        :param port: a ovslib.VifPort object.
        :param net_uuid: the net_uuid this port is to be associated with.
        :param lsw_id: the logical switch this port is to be associated with.
        '''
        if net_uuid not in self.local_vlan_map:
            self.provision_local_vlan(net_uuid, lsw_id)
        lvm = self.local_vlan_map[net_uuid]
        lvm.vif_ids.append(port.vif_id)

        # inbound unicast
        self.tun_br.add_flow(priority=3, tun_id=lsw_id, dl_dst=port.vif_mac,
                             actions="mod_vlan_vid:%s,normal" % lvm.vlan)

        self.int_br.set_db_attribute("Port", port.port_name, "tag",
                                     str(lvm.vlan))
        if int(port.ofport) != -1:
            self.int_br.delete_flows(in_port=port.ofport)

    def port_unbound(self, port, net_uuid):
        '''Unbind port.

        Removes corresponding local vlan mapping object if this is its last
        VIF.

        :param port: a ovslib.VifPort object.
        :param net_uuid: the net_uuid this port is associated with.'''
        if net_uuid not in self.local_vlan_map:
            LOG.info('port_unbound() net_uuid %s not in local_vlan_map' %
                     net_uuid)
            return
        lvm = self.local_vlan_map[net_uuid]

        if port.vif_id in lvm.vif_ids:
            lvm.vif_ids.remove(port.vif_id)
        else:
            LOG.info('port_unbound: vid_id %s not in list' % port.vif_id)

        if not lvm.vif_ids:
            self.reclaim_local_vlan(net_uuid, lvm)

    def port_dead(self, port):
        '''Once a port has no binding, put it on the "dead vlan".

        :param port: a ovs_lib.VifPort object.'''
        self.int_br.set_db_attribute("Port", port.port_name, "tag",
                                     DEAD_VLAN_TAG)
        self.int_br.add_flow(priority=2, in_port=port.ofport, actions="drop")

    def setup_integration_br(self, integ_br):
        '''Setup the integration bridge.

        Create patch ports and remove all existing flows.

        :param integ_br: the name of the integration bridge.'''
        self.int_br = ovs_lib.OVSBridge(integ_br, self.root_helper)
        self.int_br.delete_port("patch-tun")
        self.patch_tun_ofport = self.int_br.add_patch_port("patch-tun",
                                                           "patch-int")
        self.int_br.remove_all_flows()
        # switch all traffic using L2 learning
        self.int_br.add_flow(priority=1, actions="normal")

    def setup_tunnel_br(self, tun_br):
        '''Setup the tunnel bridge.

        Creates tunnel bridge, and links it to the integration bridge
        using a patch port.

        :param tun_br: the name of the tunnel bridge.'''
        self.tun_br = ovs_lib.OVSBridge(tun_br, self.root_helper)
        self.tun_br.reset_bridge()
        self.patch_int_ofport = self.tun_br.add_patch_port("patch-int",
                                                           "patch-tun")
        self.tun_br.remove_all_flows()
        self.tun_br.add_flow(priority=1, actions="drop")

    def manage_tunnels(self, tunnel_ips, old_tunnel_ips, db):
        if self.local_ip in tunnel_ips:
            tunnel_ips.remove(self.local_ip)
        else:
            db.tunnel_ips.insert(ip_address=self.local_ip)

        new_tunnel_ips = tunnel_ips - old_tunnel_ips
        if new_tunnel_ips:
            LOG.info("adding tunnels to: %s" % new_tunnel_ips)
            for ip in new_tunnel_ips:
                tun_name = "gre-" + str(self.tunnel_count)
                self.tun_br.add_tunnel_port(tun_name, ip)
                self.tunnel_count += 1

    def rollback_until_success(self, db):
        while True:
            time.sleep(self.reconnect_interval)
            try:
                db.rollback()
                break
            except:
                LOG.exception("Problem connecting to database")

    def db_loop(self, db_connection_url):
        '''Main processing loop for Tunneling Agent.

        :param options: database information - in the event need to reconnect
        '''
        old_local_bindings = {}
        old_vif_ports = {}
        old_tunnel_ips = set()

        db = sqlsoup.SqlSoup(db_connection_url)
        LOG.info("Connecting to database \"%s\" on %s" %
                 (db.engine.url.database, db.engine.url.host))

        while True:
            try:
                all_bindings = dict((p.id, Port(p))
                                    for p in db.ports.all())
                all_bindings_vif_port_ids = set(all_bindings)
                lsw_id_bindings = dict((bind.network_id, bind.vlan_id)
                                       for bind in db.vlan_bindings.all())

                tunnel_ips = set(x.ip_address for x in db.tunnel_ips.all())
                self.manage_tunnels(tunnel_ips, old_tunnel_ips, db)

                # Get bindings from OVS bridge.
                vif_ports = self.int_br.get_vif_ports()
                new_vif_ports = dict([(p.vif_id, p) for p in vif_ports])
                new_vif_ports_ids = set(new_vif_ports.keys())

                old_vif_ports_ids = set(old_vif_ports.keys())
                dead_vif_ports_ids = (new_vif_ports_ids -
                                      all_bindings_vif_port_ids)
                dead_vif_ports = [new_vif_ports[p] for p in dead_vif_ports_ids]
                disappeared_vif_ports_ids = (old_vif_ports_ids -
                                             new_vif_ports_ids)
                new_local_bindings_ids = (all_bindings_vif_port_ids.
                                          intersection(new_vif_ports_ids))
                new_local_bindings = dict([(p, all_bindings.get(p))
                                           for p in new_vif_ports_ids])
                new_bindings = set(
                    (p, old_local_bindings.get(p),
                     new_local_bindings.get(p)) for p in new_vif_ports_ids)
                changed_bindings = set([b for b in new_bindings
                                        if b[2] != b[1]])

                LOG.debug('all_bindings: %s', all_bindings)
                LOG.debug('lsw_id_bindings: %s', lsw_id_bindings)
                LOG.debug('new_vif_ports_ids: %s', new_vif_ports_ids)
                LOG.debug('dead_vif_ports_ids: %s', dead_vif_ports_ids)
                LOG.debug('old_vif_ports_ids: %s', old_vif_ports_ids)
                LOG.debug('new_local_bindings_ids: %s',
                          new_local_bindings_ids)
                LOG.debug('new_local_bindings: %s', new_local_bindings)
                LOG.debug('new_bindings: %s', new_bindings)
                LOG.debug('changed_bindings: %s', changed_bindings)

                # Take action.
                for p in dead_vif_ports:
                    LOG.info("No quantum binding for port " + str(p)
                             + "putting on dead vlan")
                    self.port_dead(p)

                for b in changed_bindings:
                    port_id, old_port, new_port = b
                    p = new_vif_ports[port_id]
                    if old_port:
                        old_net_uuid = old_port.network_id
                        LOG.info("Removing binding to net-id = " +
                                 old_net_uuid + " for " + str(p)
                                 + " added to dead vlan")
                        self.port_unbound(p, old_net_uuid)
                        if p.vif_id in all_bindings:
                            all_bindings[p.vif_id].status = (
                                constants.PORT_STATUS_DOWN)
                        if not new_port:
                            self.port_dead(p)

                    if new_port:
                        new_net_uuid = new_port.network_id
                        if new_net_uuid not in lsw_id_bindings:
                            LOG.warn("No ls-id binding found for net-id '%s'" %
                                     new_net_uuid)
                            continue

                        lsw_id = lsw_id_bindings[new_net_uuid]
                        self.port_bound(p, new_net_uuid, lsw_id)
                        all_bindings[p.vif_id].status = (
                            constants.PORT_STATUS_ACTIVE)
                        LOG.info("Port %s on net-id = %s bound to %s " % (
                                 str(p), new_net_uuid,
                                 str(self.local_vlan_map[new_net_uuid])))

                for vif_id in disappeared_vif_ports_ids:
                    LOG.info("Port Disappeared: " + vif_id)
                    if vif_id in all_bindings:
                        all_bindings[vif_id].status = (
                            constants.PORT_STATUS_DOWN)
                    old_port = old_local_bindings.get(vif_id)
                    if old_port:
                        self.port_unbound(old_vif_ports[vif_id],
                                          old_port.network_id)
                # commit any DB changes and expire
                # data loaded from the database
                db.commit()

                # sleep and re-initialize state for next pass
                time.sleep(self.polling_interval)
                old_tunnel_ips = tunnel_ips
                old_vif_ports = new_vif_ports
                old_local_bindings = new_local_bindings

            except:
                LOG.exception("Main-loop Exception:")
                self.rollback_until_success(db)

    def update_ports(self, registered_ports):
        ports = self.int_br.get_vif_port_set()
        if ports == registered_ports:
            return
        added = ports - registered_ports
        removed = registered_ports - ports
        return {'current': ports,
                'added': added,
                'removed': removed}

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
            if 'port_id' in details:
                LOG.info("Port %s updated. Details: %s", device, details)
                port = self.int_br.get_vif_port_by_id(details['port_id'])
                if port:
                    if details['admin_state_up']:
                        self.port_bound(port, details['network_id'],
                                        details['vlan_id'])
                    else:
                        self.port_unbound(port, details['network_id'])
            else:
                LOG.debug("Device %s not defined on plugin", device)
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
            if details['exists']:
                LOG.info("Port %s updated.", device)
                # Nothing to do regarding local networking
            else:
                LOG.debug("Device %s not defined on plugin", device)
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
            start = time.time()
            if sync:
                LOG.info("Agent out of sync with plugin!")
                ports.clear()
                sync = False

            # Notify the plugin of tunnel IP
            if tunnel_sync:
                LOG.info("Agent tunnel out of sync with plugin!")
                tunnel_sync = self.tunnel_sync()

            port_info = self.update_ports(ports)

            # notify plugin about port deltas
            if port_info:
                LOG.debug("Agent loop has new devices!")
                # If treat devices fails - indicates must resync with plugin
                sync = self.process_network_ports(port_info)
                ports = port_info['current']

            # sleep till end of polling interval
            elapsed = (time.time() - start)
            if (elapsed < self.polling_interval):
                time.sleep(self.polling_interval - elapsed)
            else:
                LOG.debug("Loop iteration exceeded interval (%s vs. %s)!",
                          self.polling_interval, elapsed)

    def daemon_loop(self, db_connection_url):
        if self.rpc:
            self.rpc_loop()
        else:
            self.db_loop(db_connection_url)


def main():
    cfg.CONF(args=sys.argv, project='quantum')

    # (TODO) gary - swap with common logging
    logging_config.setup_logging(cfg.CONF)

    # Determine which agent type to use.
    enable_tunneling = cfg.CONF.OVS.enable_tunneling
    integ_br = cfg.CONF.OVS.integration_bridge
    db_connection_url = cfg.CONF.DATABASE.sql_connection
    polling_interval = cfg.CONF.AGENT.polling_interval
    reconnect_interval = cfg.CONF.DATABASE.reconnect_interval
    root_helper = cfg.CONF.AGENT.root_helper
    rpc = cfg.CONF.AGENT.rpc

    if enable_tunneling:
        # Get parameters for OVSQuantumTunnelAgent
        tun_br = cfg.CONF.OVS.tunnel_bridge
        # Mandatory parameter.
        local_ip = cfg.CONF.OVS.local_ip
        plugin = OVSQuantumTunnelAgent(integ_br, tun_br, local_ip, root_helper,
                                       polling_interval, reconnect_interval,
                                       rpc)
    else:
        # Get parameters for OVSQuantumAgent.
        plugin = OVSQuantumAgent(integ_br, root_helper, polling_interval,
                                 reconnect_interval, rpc)

    # Start everything.
    plugin.daemon_loop(db_connection_url)

    sys.exit(0)

if __name__ == "__main__":
    eventlet.monkey_patch()
    main()
