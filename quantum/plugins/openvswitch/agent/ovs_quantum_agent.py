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

import ConfigParser
import logging as LOG
import MySQLdb
import os
import sys
import time

from optparse import OptionParser
from subprocess import *


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
    def __init__(self, br_name):
        self.br_name = br_name

    def run_cmd(self, args):
        # LOG.debug("## running command: " + " ".join(args))
        return Popen(args, stdout=PIPE).communicate()[0]

    def run_vsctl(self, args):
        full_args = ["ovs-vsctl"] + args
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

    # this is a hack that should go away once nova properly reports bindings
    # to quantum.  We have this here for now as it lets us work with
    # unmodified nova
    def xapi_get_port(self, name):
        external_ids = self.db_get_map("Interface", name, "external_ids")
        if "attached-mac" not in external_ids:
            return None
        vm_uuid = external_ids.get("xs-vm-uuid", "")
        if len(vm_uuid) == 0:
            return None
        LOG.debug("iface-id not set, got xs-vm-uuid: %s" % vm_uuid)
        res = os.popen("xe vm-list uuid=%s params=name-label --minimal" \
                                    % vm_uuid).readline().strip()
        if len(res) == 0:
            return None
        external_ids["iface-id"] = res
        LOG.info("Setting interface \"%s\" iface-id to \"%s\"" % (name, res))
        self.set_db_attribute("Interface", name,
                  "external-ids:iface-id", res)
        ofport = self.db_get_val("Interface", name, "ofport")
        return VifPort(name, ofport, external_ids["iface-id"],
                        external_ids["attached-mac"], self)

    # returns a VIF object for each VIF port
    def get_vif_ports(self):
        edge_ports = []
        port_names = self.get_port_name_list()
        for name in port_names:
            external_ids = self.db_get_map("Interface", name, "external_ids")
            if "xs-vm-uuid" in external_ids:
                p = xapi_get_port(name)
                if p is not None:
                    edge_ports.append(p)
            elif "iface-id" in external_ids and "attached-mac" in external_ids:
                ofport = self.db_get_val("Interface", name, "ofport")
                p = VifPort(name, ofport, external_ids["iface-id"],
                            external_ids["attached-mac"], self)
                edge_ports.append(p)
        return edge_ports


class OVSQuantumAgent:

    def __init__(self, integ_br):
        self.setup_integration_br(integ_br)

    def port_bound(self, port, vlan_id):
        self.int_br.set_db_attribute("Port", port.port_name, "tag",
                                                       str(vlan_id))
        self.int_br.delete_flows(match="in_port=%s" % port.ofport)

    def port_unbound(self, port, still_exists):
        if still_exists:
            self.int_br.clear_db_attribute("Port", port.port_name, "tag")

    def setup_integration_br(self, integ_br):
        self.int_br = OVSBridge(integ_br)
        self.int_br.remove_all_flows()
        # switch all traffic using L2 learning
        self.int_br.add_flow(priority=1, actions="normal")

    def daemon_loop(self, conn):
        self.local_vlan_map = {}
        old_local_bindings = {}
        old_vif_ports = {}

        while True:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM ports where state = 'ACTIVE'")
            rows = cursor.fetchall()
            cursor.close()
            all_bindings = {}
            for r in rows:
                all_bindings[r[2]] = r[1]

            cursor = conn.cursor()
            cursor.execute("SELECT * FROM vlan_bindings")
            rows = cursor.fetchall()
            cursor.close()
            vlan_bindings = {}
            for r in rows:
                vlan_bindings[r[1]] = r[0]

            new_vif_ports = {}
            new_local_bindings = {}
            vif_ports = self.int_br.get_vif_ports()
            for p in vif_ports:
                new_vif_ports[p.vif_id] = p
                if p.vif_id in all_bindings:
                    new_local_bindings[p.vif_id] = all_bindings[p.vif_id]
                else:
                    # no binding, put him on the 'dead vlan'
                    self.int_br.set_db_attribute("Port", p.port_name, "tag",
                              "4095")
                    self.int_br.add_flow(priority=2,
                           match="in_port=%s" % p.ofport, actions="drop")

                old_b = old_local_bindings.get(p.vif_id, None)
                new_b = new_local_bindings.get(p.vif_id, None)

                if old_b != new_b:
                    if old_b is not None:
                        LOG.info("Removing binding to net-id = %s for %s"
                          % (old_b, str(p)))
                        self.port_unbound(p, True)
                    if new_b is not None:
                        # If we don't have a binding we have to stick it on
                        # the dead vlan
                        vlan_id = vlan_bindings.get(all_bindings[p.vif_id],
                          "4095")
                        self.port_bound(p, vlan_id)
                        LOG.info("Adding binding to net-id = %s " \
                             "for %s on vlan %s" % (new_b, str(p), vlan_id))
            for vif_id in old_vif_ports.keys():
                if vif_id not in new_vif_ports:
                    LOG.info("Port Disappeared: %s" % vif_id)
                    if vif_id in old_local_bindings:
                        old_b = old_local_bindings[vif_id]
                        self.port_unbound(old_vif_ports[vif_id], False)

            old_vif_ports = new_vif_ports
            old_local_bindings = new_local_bindings
            time.sleep(2)

if __name__ == "__main__":
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
        LOG.error("Unable to parse config file \"%s\": %s" % (config_file,
          str(e)))

    integ_br = config.get("OVS", "integration-bridge")

    db_name = config.get("DATABASE", "name")
    db_user = config.get("DATABASE", "user")
    db_pass = config.get("DATABASE", "pass")
    db_host = config.get("DATABASE", "host")
    conn = None
    try:
        LOG.info("Connecting to database \"%s\" on %s" % (db_name, db_host))
        conn = MySQLdb.connect(host=db_host, user=db_user,
          passwd=db_pass, db=db_name)
        plugin = OVSQuantumAgent(integ_br)
        plugin.daemon_loop(conn)
    finally:
        if conn:
            conn.close()

    sys.exit(0)
