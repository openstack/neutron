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

import re

from quantum.agent.linux import utils
from quantum.openstack.common import jsonutils
from quantum.openstack.common import log as logging

LOG = logging.getLogger(__name__)


class VifPort:
    def __init__(self, port_name, ofport, vif_id, vif_mac, switch):
        self.port_name = port_name
        self.ofport = ofport
        self.vif_id = vif_id
        self.vif_mac = vif_mac
        self.switch = switch

    def __str__(self):
        return ("iface-id=" + self.vif_id + ", vif_mac=" +
                self.vif_mac + ", port_name=" + self.port_name +
                ", ofport=" + str(self.ofport) + ", bridge_name =" +
                self.switch.br_name)


class OVSBridge:
    def __init__(self, br_name, root_helper):
        self.br_name = br_name
        self.root_helper = root_helper
        self.re_id = self.re_compile_id()

    def re_compile_id(self):
        external = 'external_ids\s*'
        mac = 'attached-mac="(?P<vif_mac>([a-fA-F\d]{2}:){5}([a-fA-F\d]{2}))"'
        iface = 'iface-id="(?P<vif_id>[^"]+)"'
        name = 'name\s*:\s"(?P<port_name>[^"]*)"'
        port = 'ofport\s*:\s(?P<ofport>-?\d+)'
        _re = ('%(external)s:\s{ ( %(mac)s,? | %(iface)s,? | . )* }'
               ' \s+ %(name)s \s+ %(port)s' % locals())
        return re.compile(_re, re.M | re.X)

    def run_vsctl(self, args):
        full_args = ["ovs-vsctl", "--timeout=2"] + args
        try:
            return utils.execute(full_args, root_helper=self.root_helper)
        except Exception, e:
            LOG.error(_("Unable to execute %(cmd)s. Exception: %(exception)s"),
                      {'cmd': full_args, 'exception': e})

    def reset_bridge(self):
        self.run_vsctl(["--", "--if-exists", "del-br", self.br_name])
        self.run_vsctl(["add-br", self.br_name])

    def add_port(self, port_name):
        self.run_vsctl(["--", "--may-exist", "add-port", self.br_name,
                        port_name])
        return self.get_port_ofport(port_name)

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
        try:
            return utils.execute(full_args, root_helper=self.root_helper)
        except Exception, e:
            LOG.error(_("Unable to execute %(cmd)s. Exception: %(exception)s"),
                      {'cmd': full_args, 'exception': e})

    def count_flows(self):
        flow_list = self.run_ofctl("dump-flows", []).split("\n")[1:]
        return len(flow_list) - 1

    def remove_all_flows(self):
        self.run_ofctl("del-flows", [])

    def get_port_ofport(self, port_name):
        return self.db_get_val("Interface", port_name, "ofport")

    def get_datapath_id(self):
        return self.db_get_val('Bridge',
                               self.br_name, 'datapath_id').strip('"')

    def _build_flow_expr_arr(self, **kwargs):
        flow_expr_arr = []
        is_delete_expr = kwargs.get('delete', False)
        if not is_delete_expr:
            prefix = ("hard_timeout=%s,idle_timeout=%s,priority=%s" %
                     (kwargs.get('hard_timeout', '0'),
                      kwargs.get('idle_timeout', '0'),
                      kwargs.get('priority', '1')))
            flow_expr_arr.append(prefix)
        elif 'priority' in kwargs:
            raise Exception(_("Cannot match priority on flow deletion"))

        in_port = ('in_port' in kwargs and ",in_port=%s" %
                   kwargs['in_port'] or '')
        dl_type = ('dl_type' in kwargs and ",dl_type=%s" %
                   kwargs['dl_type'] or '')
        dl_vlan = ('dl_vlan' in kwargs and ",dl_vlan=%s" %
                   kwargs['dl_vlan'] or '')
        dl_src = 'dl_src' in kwargs and ",dl_src=%s" % kwargs['dl_src'] or ''
        dl_dst = 'dl_dst' in kwargs and ",dl_dst=%s" % kwargs['dl_dst'] or ''
        nw_src = 'nw_src' in kwargs and ",nw_src=%s" % kwargs['nw_src'] or ''
        nw_dst = 'nw_dst' in kwargs and ",nw_dst=%s" % kwargs['nw_dst'] or ''
        tun_id = 'tun_id' in kwargs and ",tun_id=%s" % kwargs['tun_id'] or ''
        proto = 'proto' in kwargs and ",%s" % kwargs['proto'] or ''
        ip = ('nw_src' in kwargs or 'nw_dst' in kwargs) and ',ip' or ''
        match = (in_port + dl_type + dl_vlan + dl_src + dl_dst +
                (ip or proto) + nw_src + nw_dst + tun_id)
        if match:
            match = match[1:]  # strip leading comma
            flow_expr_arr.append(match)
        return flow_expr_arr

    def add_flow(self, **kwargs):
        if "actions" not in kwargs:
            raise Exception(_("Must specify one or more actions"))
        if "priority" not in kwargs:
            kwargs["priority"] = "0"

        flow_expr_arr = self._build_flow_expr_arr(**kwargs)
        flow_expr_arr.append("actions=%s" % (kwargs["actions"]))
        flow_str = ",".join(flow_expr_arr)
        self.run_ofctl("add-flow", [flow_str])

    def delete_flows(self, **kwargs):
        kwargs['delete'] = True
        flow_expr_arr = self._build_flow_expr_arr(**kwargs)
        if "actions" in kwargs:
            flow_expr_arr.append("actions=%s" % (kwargs["actions"]))
        flow_str = ",".join(flow_expr_arr)
        self.run_ofctl("del-flows", [flow_str])

    def add_tunnel_port(self, port_name, remote_ip):
        self.run_vsctl(["add-port", self.br_name, port_name])
        self.set_db_attribute("Interface", port_name, "type", "gre")
        self.set_db_attribute("Interface", port_name, "options:remote_ip",
                              remote_ip)
        self.set_db_attribute("Interface", port_name, "options:in_key", "flow")
        self.set_db_attribute("Interface", port_name, "options:out_key",
                              "flow")
        return self.get_port_ofport(port_name)

    def add_patch_port(self, local_name, remote_name):
        self.run_vsctl(["add-port", self.br_name, local_name])
        self.set_db_attribute("Interface", local_name, "type", "patch")
        self.set_db_attribute("Interface", local_name, "options:peer",
                              remote_name)
        return self.get_port_ofport(local_name)

    def db_get_map(self, table, record, column):
        output = self.run_vsctl(["get", table, record, column])
        if output:
            str = output.rstrip("\n\r")
            return self.db_str_to_map(str)
        return {}

    def db_get_val(self, table, record, column):
        output = self.run_vsctl(["get", table, record, column])
        if output:
            return output.rstrip("\n\r")

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
        if res:
            return res.strip().split("\n")
        return []

    def get_port_stats(self, port_name):
        return self.db_get_map("Interface", port_name, "statistics")

    def get_xapi_iface_id(self, xs_vif_uuid):
        args = ["xe", "vif-param-get", "param-name=other-config",
                "param-key=nicira-iface-id", "uuid=%s" % xs_vif_uuid]
        try:
            return utils.execute(args, root_helper=self.root_helper).strip()
        except Exception, e:
            LOG.error(_("Unable to execute %(cmd)s. Exception: %(exception)s"),
                      {'cmd': args, 'exception': e})

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
            elif ("xs-vif-uuid" in external_ids and
                  "attached-mac" in external_ids):
                # if this is a xenserver and iface-id is not automatically
                # synced to OVS from XAPI, we grab it from XAPI directly
                iface_id = self.get_xapi_iface_id(external_ids["xs-vif-uuid"])
                p = VifPort(name, ofport, iface_id,
                            external_ids["attached-mac"], self)
                edge_ports.append(p)

        return edge_ports

    def get_vif_port_set(self):
        port_names = self.get_port_name_list()
        edge_ports = set()
        args = ['--format=json', '--', '--columns=name,external_ids',
                'list', 'Interface']
        result = self.run_vsctl(args)
        if not result:
            return edge_ports
        for row in jsonutils.loads(result)['data']:
            name = row[0]
            if name not in port_names:
                continue
            external_ids = dict(row[1][1])
            if "iface-id" in external_ids and "attached-mac" in external_ids:
                edge_ports.add(external_ids['iface-id'])
            elif ("xs-vif-uuid" in external_ids and
                  "attached-mac" in external_ids):
                # if this is a xenserver and iface-id is not automatically
                # synced to OVS from XAPI, we grab it from XAPI directly
                iface_id = self.get_xapi_iface_id(external_ids["xs-vif-uuid"])
                edge_ports.add(iface_id)
        return edge_ports

    def get_vif_port_by_id(self, port_id):
        args = ['--', '--columns=external_ids,name,ofport',
                'find', 'Interface',
                'external_ids:iface-id="%s"' % port_id]
        result = self.run_vsctl(args)
        if not result:
            return
        match = self.re_id.search(result)
        try:
            vif_mac = match.group('vif_mac')
            vif_id = match.group('vif_id')
            port_name = match.group('port_name')
            ofport = int(match.group('ofport'))
            return VifPort(port_name, ofport, vif_id, vif_mac, self)
        except Exception, e:
            LOG.info(_("Unable to parse regex results. Exception: %s"), e)
            return

    def delete_ports(self, all_ports=False):
        if all_ports:
            port_names = self.get_port_name_list()
        else:
            port_names = (port.port_name for port in self.get_vif_ports())

        for port_name in port_names:
            self.delete_port(port_name)


def get_bridge_for_iface(root_helper, iface):
    args = ["ovs-vsctl", "--timeout=2", "iface-to-br", iface]
    try:
        return utils.execute(args, root_helper=root_helper).strip()
    except Exception, e:
        LOG.exception(_("Interface %(iface)s not found. Exception: %(e)s"),
                      locals())
        return None


def get_bridges(root_helper):
    args = ["ovs-vsctl", "--timeout=2", "list-br"]
    try:
        return utils.execute(args, root_helper=root_helper).strip().split("\n")
    except Exception, e:
        LOG.exception(_("Unable to retrieve bridges. Exception: %s"), e)
        return []
