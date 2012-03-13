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

import ConfigParser
import logging as LOG
import shlex
import sys
import time
import signal

from optparse import OptionParser
from sqlalchemy.ext.sqlsoup import SqlSoup
from subprocess import *


# Global constants.
OP_STATUS_UP = "UP"
OP_STATUS_DOWN = "DOWN"

# A placeholder for dead vlans.
DEAD_VLAN_TAG = "4095"

REFRESH_INTERVAL = 2


# A class to represent a VIF (i.e., a port that has 'iface-id' and 'vif-mac'
# attributes set).
class VifPort:
    def __init__(self, port_name, ofport, vif_id, vif_mac, switch):
        self.port_name = port_name
        self.ofport = ofport
        self.vif_id = vif_id
        self.vif_mac = vif_mac
        self.switch = switch

    def __str__(self):
        return "iface-id=" + self.vif_id + ", vif_mac=" + \
          self.vif_mac + ", port_name=" + self.port_name + \
          ", ofport=" + self.ofport + ", bridge name = " + self.switch.br_name


class OVSBridge:
    def __init__(self, br_name, root_helper):
        self.br_name = br_name
        self.root_helper = root_helper

    def run_cmd(self, args):
        cmd = shlex.split(self.root_helper) + args
        LOG.debug("## running command: " + " ".join(cmd))
        p = Popen(cmd, stdout=PIPE)
        retval = p.communicate()[0]
        if p.returncode == -(signal.SIGALRM):
            LOG.debug("## timeout running command: " + " ".join(cmd))
        return retval

    def run_vsctl(self, args):
        full_args = ["ovs-vsctl", "--timeout=2"] + args
        return self.run_cmd(full_args)

    def reset_bridge(self):
        self.run_vsctl(["--", "--if-exists", "del-br", self.br_name])
        self.run_vsctl(["add-br", self.br_name])

    def delete_port(self, port_name):
        self.run_vsctl(["--", "--if-exists", "del-port", self.br_name,
          port_name])

    def set_db_attribute(self, table_name, record, column, value):
        args = ["set", table_name, record, "%s=%s" % (column, value)]
        self.run_vsctl(args)

    def clear_db_attribute(self, table_name, record, column):
        args = ["clear", table_name, record, column]
        self.run_vsctl(args)

    def run_ofctl(self, cmd, args):
        full_args = ["ovs-ofctl", cmd, self.br_name] + args
        return self.run_cmd(full_args)

    def remove_all_flows(self):
        self.run_ofctl("del-flows", [])

    def get_port_ofport(self, port_name):
        return self.db_get_val("Interface", port_name, "ofport")

    def add_flow(self, **dict):
        if "actions" not in dict:
            raise Exception("must specify one or more actions")
        if "priority" not in dict:
            dict["priority"] = "0"

        flow_str = "priority=%s" % dict["priority"]
        if "match" in dict:
            flow_str += "," + dict["match"]
        flow_str += ",actions=%s" % (dict["actions"])
        self.run_ofctl("add-flow", [flow_str])

    def delete_flows(self, **dict):
        all_args = []
        if "priority" in dict:
            all_args.append("priority=%s" % dict["priority"])
        if "match" in dict:
            all_args.append(dict["match"])
        if "actions" in dict:
            all_args.append("actions=%s" % (dict["actions"]))
        flow_str = ",".join(all_args)
        self.run_ofctl("del-flows", [flow_str])

    def add_tunnel_port(self, port_name, remote_ip):
        self.run_vsctl(["add-port", self.br_name, port_name])
        self.set_db_attribute("Interface", port_name, "type", "gre")
        self.set_db_attribute("Interface", port_name, "options", "remote_ip=" +
            remote_ip)
        self.set_db_attribute("Interface", port_name, "options", "in_key=flow")
        self.set_db_attribute("Interface", port_name, "options",
            "out_key=flow")
        return self.get_port_ofport(port_name)

    def add_patch_port(self, local_name, remote_name):
        self.run_vsctl(["add-port", self.br_name, local_name])
        self.set_db_attribute("Interface", local_name, "type", "patch")
        self.set_db_attribute("Interface", local_name, "options", "peer=" +
                              remote_name)
        return self.get_port_ofport(local_name)

    def db_get_map(self, table, record, column):
        str = self.run_vsctl(["get", table, record, column]).rstrip("\n\r")
        return self.db_str_to_map(str)

    def db_get_val(self, table, record, column):
        return self.run_vsctl(["get", table, record, column]).rstrip("\n\r")

    def db_str_to_map(self, full_str):
        list = full_str.strip("{}").split(", ")
        ret = {}
        for e in list:
            if e.find("=") == -1:
                continue
            arr = e.split("=")
            ret[arr[0]] = arr[1].strip("\"")
        return ret

    def get_port_name_list(self):
        res = self.run_vsctl(["list-ports", self.br_name])
        return res.split("\n")[0:-1]

    def get_port_stats(self, port_name):
        return self.db_get_map("Interface", port_name, "statistics")

    def get_xapi_iface_id(self, xs_vif_uuid):
        return self.run_cmd(
                        ["xe",
                        "vif-param-get",
                        "param-name=other-config",
                        "param-key=nicira-iface-id",
                        "uuid=%s" % xs_vif_uuid]).strip()

    # returns a VIF object for each VIF port
    def get_vif_ports(self):
        edge_ports = []
        port_names = self.get_port_name_list()
        for name in port_names:
            external_ids = self.db_get_map("Interface", name, "external_ids")
            ofport = self.db_get_val("Interface", name, "ofport")
            if "iface-id" in external_ids and "attached-mac" in external_ids:
                p = VifPort(name, ofport, external_ids["iface-id"],
                            external_ids["attached-mac"], self)
                edge_ports.append(p)
            elif "xs-vif-uuid" in external_ids and \
                 "attached-mac" in external_ids:
                # if this is a xenserver and iface-id is not automatically
                # synced to OVS from XAPI, we grab it from XAPI directly
                iface_id = self.get_xapi_iface_id(external_ids["xs-vif-uuid"])
                p = VifPort(name, ofport, iface_id,
                            external_ids["attached-mac"], self)
                edge_ports.append(p)

        return edge_ports


class LocalVLANMapping:
    def __init__(self, vlan, lsw_id, vif_ids=None):
        if vif_ids is None:
            vif_ids = []
        self.vlan = vlan
        self.lsw_id = lsw_id
        self.vif_ids = vif_ids

    def __str__(self):
        return "lv-id = %s ls-id = %s" % (self.vlan, self.lsw_id)


class OVSQuantumAgent(object):

    def __init__(self, integ_br, root_helper):
        self.root_helper = root_helper
        self.setup_integration_br(integ_br)

    def port_bound(self, port, vlan_id):
        self.int_br.set_db_attribute("Port", port.port_name, "tag",
                str(vlan_id))
        self.int_br.delete_flows(match="in_port=%s" % port.ofport)

    def port_unbound(self, port, still_exists):
        if still_exists:
            self.int_br.clear_db_attribute("Port", port.port_name, "tag")

    def setup_integration_br(self, integ_br):
        self.int_br = OVSBridge(integ_br, self.root_helper)
        self.int_br.remove_all_flows()
        # switch all traffic using L2 learning
        self.int_br.add_flow(priority=1, actions="normal")

    def daemon_loop(self, db):
        self.local_vlan_map = {}
        old_local_bindings = {}
        old_vif_ports = {}

        while True:

            all_bindings = {}
            try:
                ports = db.ports.all()
            except:
                ports = []
            for port in ports:
                all_bindings[port.interface_id] = port

            vlan_bindings = {}
            try:
                vlan_binds = db.vlan_bindings.all()
            except:
                vlan_binds = []
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
                           match="in_port=%s" % p.ofport, actions="drop")

                old_b = old_local_bindings.get(p.vif_id, None)
                new_b = new_local_bindings.get(p.vif_id, None)

                if old_b != new_b:
                    if old_b is not None:
                        LOG.info("Removing binding to net-id = %s for %s"
                          % (old_b, str(p)))
                        self.port_unbound(p, True)
                        if p.vif_id in all_bindings:
                            all_bindings[p.vif_id].op_status = OP_STATUS_DOWN
                    if new_b is not None:
                        # If we don't have a binding we have to stick it on
                        # the dead vlan
                        net_id = all_bindings[p.vif_id].network_id
                        vlan_id = vlan_bindings.get(net_id, DEAD_VLAN_TAG)
                        self.port_bound(p, vlan_id)
                        if p.vif_id in all_bindings:
                            all_bindings[p.vif_id].op_status = OP_STATUS_UP
                        LOG.info("Adding binding to net-id = %s " \
                             "for %s on vlan %s" % (new_b, str(p), vlan_id))

            for vif_id in old_vif_ports:
                if vif_id not in new_vif_ports:
                    LOG.info("Port Disappeared: %s" % vif_id)
                    if vif_id in old_local_bindings:
                        old_b = old_local_bindings[vif_id]
                        self.port_unbound(old_vif_ports[vif_id], False)
                    if vif_id in all_bindings:
                        all_bindings[vif_id].op_status = OP_STATUS_DOWN

            old_vif_ports = new_vif_ports
            old_local_bindings = new_local_bindings
            db.commit()
            time.sleep(REFRESH_INTERVAL)


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

    def __init__(self, integ_br, tun_br, remote_ip_file, local_ip,
                 root_helper):
        '''Constructor.

        :param integ_br: name of the integration bridge.
        :param tun_br: name of the tunnel bridge.
        :param remote_ip_file: name of file containing list of hypervisor IPs.
        :param local_ip: local IP address of this hypervisor.'''
        self.root_helper = root_helper
        self.available_local_vlans = set(
            xrange(OVSQuantumTunnelAgent.MIN_VLAN_TAG,
                   OVSQuantumTunnelAgent.MAX_VLAN_TAG))
        self.setup_integration_br(integ_br)
        self.local_vlan_map = {}
        self.setup_tunnel_br(tun_br, remote_ip_file, local_ip)

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
        self.tun_br.add_flow(priority=4, match="in_port=%s,dl_vlan=%s" %
                            (self.patch_int_ofport, lvid),
                             actions="set_tunnel:%s,normal" % (lsw_id))

        # inbound
        self.tun_br.add_flow(priority=3, match="tun_id=%s" % lsw_id,
                             actions="mod_vlan_vid:%s,output:%s" % (lvid,
                             self.patch_int_ofport))

    def reclaim_local_vlan(self, net_uuid, lvm):
        '''Reclaim a local VLAN.

        :param net_uuid: the network uuid associated with this vlan.
        :param lvm: a LocalVLANMapping object that tracks (vlan, lsw_id,
            vif_ids) mapping.'''
        LOG.info("reclaming vlan = %s from net-id = %s" % (lvm.vlan, net_uuid))
        self.tun_br.delete_flows(match="tun_id=%s" % lvm.lsw_id)
        self.tun_br.delete_flows(match="dl_vlan=%s" % lvm.vlan)
        del self.local_vlan_map[net_uuid]
        self.available_local_vlans.add(lvm.vlan)

    def port_bound(self, port, net_uuid, lsw_id):
        '''Bind port to net_uuid/lsw_id.

        :param port: a VifPort object.
        :param net_uuid: the net_uuid this port is to be associated with.
        :param lsw_id: the logical switch this port is to be associated with.
        '''
        if net_uuid not in self.local_vlan_map:
            self.provision_local_vlan(net_uuid, lsw_id)
        lvm = self.local_vlan_map[net_uuid]
        lvm.vif_ids.append(port.vif_id)

        self.int_br.set_db_attribute("Port", port.port_name, "tag",
                                     str(lvm.vlan))
        self.int_br.delete_flows(match="in_port=%s" % port.ofport)

    def port_unbound(self, port, net_uuid):
        '''Unbind port.

        Removes corresponding local vlan mapping object if this is its last
        VIF.

        :param port: a VifPort object.
        :param net_uuid: the net_uuid this port is associated with.'''
        if net_uuid not in self.local_vlan_map:
            LOG.info('port_unbound() net_uuid %s not in local_vlan_map'
                     % net_uuid)
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

        :param port: a VifPort object.'''
        self.int_br.set_db_attribute("Port", port.port_name, "tag",
                                     DEAD_VLAN_TAG)
        self.int_br.add_flow(priority=2,
                             match="in_port=%s" % port.ofport, actions="drop")

    def setup_integration_br(self, integ_br):
        '''Setup the integration bridge.

        Create patch ports and remove all existing flows.

        :param integ_br: the name of the integration bridge.'''
        self.int_br = OVSBridge(integ_br, self.root_helper)
        self.int_br.delete_port("patch-tun")
        self.patch_tun_ofport = self.int_br.add_patch_port("patch-tun",
                                                           "patch-int")
        self.int_br.remove_all_flows()
        # switch all traffic using L2 learning
        self.int_br.add_flow(priority=1, actions="normal")

    def setup_tunnel_br(self, tun_br, remote_ip_file, local_ip):
        '''Setup the tunnel bridge.

        Reads in list of IP addresses. Creates GRE tunnels to each of these
        addresses and then clears out existing flows. local_ip is the address
        of the local node. A tunnel is not created to this IP address.

        :param tun_br: the name of the tunnel bridge.
        :param remote_ip_file: path to file that contains list of destination
            IP addresses.
        :param local_ip: the ip address of this node.'''
        self.tun_br = OVSBridge(tun_br, self.root_helper)
        self.tun_br.reset_bridge()
        self.patch_int_ofport = self.tun_br.add_patch_port("patch-int",
                                                           "patch-tun")
        try:
            with open(remote_ip_file, 'r') as f:
                remote_ip_list = f.readlines()
                clean_ips = (x.rstrip() for x in remote_ip_list)
                tunnel_ips = (x for x in clean_ips if x != local_ip and x)
                for i, remote_ip in enumerate(tunnel_ips):
                    self.tun_br.add_tunnel_port("gre-" + str(i), remote_ip)
        except Exception, e:
            LOG.error("Error configuring tunnels: '%s' %s"
                      % (remote_ip_file, str(e)))
            raise

        self.tun_br.remove_all_flows()
        # default drop
        self.tun_br.add_flow(priority=1, actions="drop")

    def get_db_port_bindings(self, db):
        '''Get database port bindings from central Quantum database.

        The central quantum database 'ovs_quantum' resides on the openstack
        mysql server.

        :returns: a dictionary containing port bindings.'''
        ports = []
        try:
            ports = db.ports.all()
        except Exception, e:
            LOG.info("Exception accessing db.ports: %s" % e)

        return dict([(port.interface_id, port) for port in ports])

    def get_db_vlan_bindings(self, db):
        '''Get database vlan bindings from central Quantum database.

        The central quantum database 'ovs_quantum' resides on the openstack
        mysql server.

        :returns: a dictionary containing vlan bindings.'''
        lsw_id_binds = []
        try:
            lsw_id_binds.extend(db.vlan_bindings.all())
        except Exception, e:
            LOG.info("Exception accessing db.vlan_bindings: %s" % e)

        return dict([(bind.network_id, bind.vlan_id)
            for bind in lsw_id_binds])

    def daemon_loop(self, db):
        '''Main processing loop (not currently used).

        :param db: reference to database layer.
        '''
        old_local_bindings = {}
        old_vif_ports = {}

        while True:
            # Get bindings from db.
            all_bindings = self.get_db_port_bindings(db)
            all_bindings_vif_port_ids = set(all_bindings.keys())
            lsw_id_bindings = self.get_db_vlan_bindings(db)

            # Get bindings from OVS bridge.
            vif_ports = self.int_br.get_vif_ports()
            new_vif_ports = dict([(p.vif_id, p) for p in vif_ports])
            new_vif_ports_ids = set(new_vif_ports.keys())

            old_vif_ports_ids = set(old_vif_ports.keys())
            dead_vif_ports_ids = new_vif_ports_ids - all_bindings_vif_port_ids
            dead_vif_ports = [new_vif_ports[p] for p in dead_vif_ports_ids]
            disappeared_vif_ports_ids = old_vif_ports_ids - new_vif_ports_ids
            new_local_bindings_ids = all_bindings_vif_port_ids.intersection(
                new_vif_ports_ids)
            new_local_bindings = dict([(p, all_bindings.get(p))
                for p in new_vif_ports_ids])
            new_bindings = set((p, old_local_bindings.get(p),
                new_local_bindings.get(p)) for p in new_vif_ports_ids)
            changed_bindings = set([b for b in new_bindings
                if b[2] != b[1]])

            LOG.debug('all_bindings: %s' % all_bindings)
            LOG.debug('lsw_id_bindings: %s' % lsw_id_bindings)
            LOG.debug('old_vif_ports_ids: %s' % old_vif_ports_ids)
            LOG.debug('dead_vif_ports_ids: %s' % dead_vif_ports_ids)
            LOG.debug('old_vif_ports_ids: %s' % old_vif_ports_ids)
            LOG.debug('new_local_bindings_ids: %s' % new_local_bindings_ids)
            LOG.debug('new_local_bindings: %s' % new_local_bindings)
            LOG.debug('new_bindings: %s' % new_bindings)
            LOG.debug('changed_bindings: %s' % changed_bindings)

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
                    if not new_port:
                        self.port_dead(p)

                if new_port:
                    new_net_uuid = new_port.network_id
                    if new_net_uuid not in lsw_id_bindings:
                        LOG.warn("No ls-id binding found for net-id '%s'" %
                            new_net_uuid)
                        continue

                    lsw_id = lsw_id_bindings[new_net_uuid]
                    try:
                        self.port_bound(p, new_net_uuid, lsw_id)
                        LOG.info("Port " + str(p) + " on net-id = "
                                 + new_net_uuid + " bound to " +
                                 str(self.local_vlan_map[new_net_uuid]))
                    except Exception, e:
                        LOG.info("Unable to bind Port " + str(p) +
                            " on netid = " + new_net_uuid + " to "
                            + str(self.local_vlan_map[new_net_uuid]))

            for vif_id in disappeared_vif_ports_ids:
                LOG.info("Port Disappeared: " + vif_id)
                old_port = old_local_bindings.get(vif_id)
                if old_port:
                    try:
                        self.port_unbound(old_vif_ports[vif_id],
                                          old_port.network_id)
                    except Exception:
                        LOG.info("Unable to unbind Port " + str(p) +
                                 " on net-id = " + old_port.network_uuid)

            old_vif_ports = new_vif_ports
            old_local_bindings = new_local_bindings
            time.sleep(REFRESH_INTERVAL)


def main():
    usagestr = "%prog [OPTIONS] <config file>"
    parser = OptionParser(usage=usagestr)
    parser.add_option("-v", "--verbose", dest="verbose",
      action="store_true", default=False, help="turn on verbose logging")

    options, args = parser.parse_args()

    if options.verbose:
        LOG.basicConfig(level=LOG.DEBUG)
    else:
        LOG.basicConfig(level=LOG.WARN)

    if len(args) != 1:
        parser.print_help()
        sys.exit(1)

    config_file = args[0]
    config = ConfigParser.ConfigParser()
    try:
        config.read(config_file)
    except Exception, e:
        LOG.error("Unable to parse config file \"%s\": %s"
                  % (config_file, str(e)))
        raise e

    # Determine which agent type to use.
    enable_tunneling = False
    try:
        enable_tunneling = config.getboolean("OVS", "enable-tunneling")
    except Exception, e:
        pass

    # Get common parameters.
    try:
        integ_br = config.get("OVS", "integration-bridge")
        if not len(integ_br):
            raise Exception('Empty integration-bridge in configuration file.')

        db_connection_url = config.get("DATABASE", "sql_connection")
        if not len(db_connection_url):
            raise Exception('Empty db_connection_url in configuration file.')

        root_helper = config.get("AGENT", "root_helper")

    except Exception, e:
        LOG.error("Error parsing common params in config_file: '%s': %s"
                  % (config_file, str(e)))
        sys.exit(1)

    if enable_tunneling:
        # Get parameters for OVSQuantumTunnelAgent
        try:
            # Mandatory parameter.
            tun_br = config.get("OVS", "tunnel-bridge")
            if not len(tun_br):
                raise Exception('Empty tunnel-bridge in configuration file.')

            # Mandatory parameter.
            remote_ip_file = config.get("OVS", "remote-ip-file")
            if not len(remote_ip_file):
                raise Exception('Empty remote-ip-file in configuration file.')

            # Mandatory parameter.
            remote_ip_file = config.get("OVS", "remote-ip-file")
            local_ip = config.get("OVS", "local-ip")
            if not len(local_ip):
                raise Exception('Empty local-ip in configuration file.')
        except Exception, e:
            LOG.error("Error parsing tunnel params in config_file: '%s': %s"
                      % (config_file, str(e)))
            sys.exit(1)

        plugin = OVSQuantumTunnelAgent(integ_br, tun_br, remote_ip_file,
                                       local_ip, root_helper)
    else:
        # Get parameters for OVSQuantumAgent.
        plugin = OVSQuantumAgent(integ_br, root_helper)

    # Start everything.
    options = {"sql_connection": db_connection_url}
    db = SqlSoup(options["sql_connection"])
    LOG.info("Connecting to database \"%s\" on %s" %
             (db.engine.url.database, db.engine.url.host))

    plugin.daemon_loop(db)

    sys.exit(0)

if __name__ == "__main__":
    main()
