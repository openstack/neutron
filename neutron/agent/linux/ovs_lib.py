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

from oslo.config import cfg

from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.openstack.common import jsonutils
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants as p_const
#  TODO(JLH) Should we remove the explicit include of the ovs plugin here
from neutron.plugins.openvswitch.common import constants

# Default timeout for ovs-vsctl command
DEFAULT_OVS_VSCTL_TIMEOUT = 10
OPTS = [
    cfg.IntOpt('ovs_vsctl_timeout',
               default=DEFAULT_OVS_VSCTL_TIMEOUT,
               help=_('Timeout in seconds for ovs-vsctl commands')),
]
cfg.CONF.register_opts(OPTS)

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
                ", ofport=" + str(self.ofport) + ", bridge_name=" +
                self.switch.br_name)


class BaseOVS(object):

    def __init__(self, root_helper):
        self.root_helper = root_helper
        self.vsctl_timeout = cfg.CONF.ovs_vsctl_timeout

    def run_vsctl(self, args, check_error=False):
        full_args = ["ovs-vsctl", "--timeout=%d" % self.vsctl_timeout] + args
        try:
            return utils.execute(full_args, root_helper=self.root_helper)
        except Exception as e:
            LOG.error(_("Unable to execute %(cmd)s. Exception: %(exception)s"),
                      {'cmd': full_args, 'exception': e})
            if check_error:
                raise

    def add_bridge(self, bridge_name):
        self.run_vsctl(["--", "--may-exist", "add-br", bridge_name])
        return OVSBridge(bridge_name, self.root_helper)

    def delete_bridge(self, bridge_name):
        self.run_vsctl(["--", "--if-exists", "del-br", bridge_name])

    def bridge_exists(self, bridge_name):
        try:
            self.run_vsctl(['br-exists', bridge_name], check_error=True)
        except RuntimeError as e:
            if 'Exit code: 2\n' in str(e):
                return False
            raise
        return True

    def get_bridge_name_for_port_name(self, port_name):
        try:
            return self.run_vsctl(['port-to-br', port_name], check_error=True)
        except RuntimeError as e:
            if 'Exit code: 1\n' not in str(e):
                raise

    def port_exists(self, port_name):
        return bool(self.get_bridge_name_for_port_name(port_name))


class OVSBridge(BaseOVS):
    def __init__(self, br_name, root_helper):
        super(OVSBridge, self).__init__(root_helper)
        self.br_name = br_name
        self.re_id = self.re_compile_id()
        self.defer_apply_flows = False
        self.deferred_flows = {'add': '', 'mod': '', 'del': ''}

    def re_compile_id(self):
        external = 'external_ids\s*'
        mac = 'attached-mac="(?P<vif_mac>([a-fA-F\d]{2}:){5}([a-fA-F\d]{2}))"'
        iface = 'iface-id="(?P<vif_id>[^"]+)"'
        name = 'name\s*:\s"(?P<port_name>[^"]*)"'
        port = 'ofport\s*:\s(?P<ofport>-?\d+)'
        _re = ('%(external)s:\s{ ( %(mac)s,? | %(iface)s,? | . )* }'
               ' \s+ %(name)s \s+ %(port)s' % {'external': external,
                                               'mac': mac,
                                               'iface': iface, 'name': name,
                                               'port': port})
        return re.compile(_re, re.M | re.X)

    def create(self):
        self.add_bridge(self.br_name)

    def destroy(self):
        self.delete_bridge(self.br_name)

    def reset_bridge(self):
        self.destroy()
        self.create()

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

    def run_ofctl(self, cmd, args, process_input=None):
        full_args = ["ovs-ofctl", cmd, self.br_name] + args
        try:
            return utils.execute(full_args, root_helper=self.root_helper,
                                 process_input=process_input)
        except Exception as e:
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

        table = ('table' in kwargs and ",table=%s" %
                 kwargs['table'] or '')
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
        match = (table + in_port + dl_type + dl_vlan + dl_src + dl_dst +
                (proto or ip) + nw_src + nw_dst + tun_id)
        if match:
            match = match[1:]  # strip leading comma
            flow_expr_arr.append(match)
        return flow_expr_arr

    def add_or_mod_flow_str(self, **kwargs):
        if "actions" not in kwargs:
            raise Exception(_("Must specify one or more actions"))
        if "priority" not in kwargs:
            kwargs["priority"] = "0"

        flow_expr_arr = self._build_flow_expr_arr(**kwargs)
        flow_expr_arr.append("actions=%s" % (kwargs["actions"]))
        flow_str = ",".join(flow_expr_arr)
        return flow_str

    def add_flow(self, **kwargs):
        flow_str = self.add_or_mod_flow_str(**kwargs)
        if self.defer_apply_flows:
            self.deferred_flows['add'] += flow_str + '\n'
        else:
            self.run_ofctl("add-flow", [flow_str])

    def mod_flow(self, **kwargs):
        flow_str = self.add_or_mod_flow_str(**kwargs)
        if self.defer_apply_flows:
            self.deferred_flows['mod'] += flow_str + '\n'
        else:
            self.run_ofctl("mod-flows", [flow_str])

    def delete_flows(self, **kwargs):
        kwargs['delete'] = True
        flow_expr_arr = self._build_flow_expr_arr(**kwargs)
        if "actions" in kwargs:
            flow_expr_arr.append("actions=%s" % (kwargs["actions"]))
        flow_str = ",".join(flow_expr_arr)
        if self.defer_apply_flows:
            self.deferred_flows['del'] += flow_str + '\n'
        else:
            self.run_ofctl("del-flows", [flow_str])

    def defer_apply_on(self):
        LOG.debug(_('defer_apply_on'))
        self.defer_apply_flows = True

    def defer_apply_off(self):
        LOG.debug(_('defer_apply_off'))
        for action, flows in self.deferred_flows.items():
            if flows:
                LOG.debug(_('Applying following deferred flows '
                            'to bridge %s'), self.br_name)
                for line in flows.splitlines():
                    LOG.debug(_('%(action)s: %(flow)s'),
                              {'action': action, 'flow': line})
                self.run_ofctl('%s-flows' % action, ['-'], flows)
        self.defer_apply_flows = False
        self.deferred_flows = {'add': '', 'mod': '', 'del': ''}

    def add_tunnel_port(self, port_name, remote_ip, local_ip,
                        tunnel_type=p_const.TYPE_GRE,
                        vxlan_udp_port=constants.VXLAN_UDP_PORT):
        vsctl_command = ["--", "--may-exist", "add-port", self.br_name,
                         port_name]
        vsctl_command.extend(["--", "set", "Interface", port_name,
                              "type=%s" % tunnel_type])
        if tunnel_type == p_const.TYPE_VXLAN:
            # Only set the VXLAN UDP port if it's not the default
            if vxlan_udp_port != constants.VXLAN_UDP_PORT:
                vsctl_command.append("options:dst_port=%s" % vxlan_udp_port)
        vsctl_command.extend(["options:remote_ip=%s" % remote_ip,
                              "options:local_ip=%s" % local_ip,
                              "options:in_key=flow",
                              "options:out_key=flow"])
        self.run_vsctl(vsctl_command)
        return self.get_port_ofport(port_name)

    def add_patch_port(self, local_name, remote_name):
        self.run_vsctl(["add-port", self.br_name, local_name,
                        "--", "set", "Interface", local_name,
                        "type=patch", "options:peer=%s" % remote_name])
        return self.get_port_ofport(local_name)

    def db_get_map(self, table, record, column):
        output = self.run_vsctl(["get", table, record, column])
        if output:
            output_str = output.rstrip("\n\r")
            return self.db_str_to_map(output_str)
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
        except Exception as e:
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
        except Exception as e:
            LOG.info(_("Unable to parse regex results. Exception: %s"), e)
            return

    def delete_ports(self, all_ports=False):
        if all_ports:
            port_names = self.get_port_name_list()
        else:
            port_names = (port.port_name for port in self.get_vif_ports())

        for port_name in port_names:
            self.delete_port(port_name)

    def get_local_port_mac(self):
        """Retrieve the mac of the bridge's local port."""
        address = ip_lib.IPDevice(self.br_name, self.root_helper).link.address
        if address:
            return address
        else:
            msg = _('Unable to determine mac address for %s') % self.br_name
            raise Exception(msg)


def get_bridge_for_iface(root_helper, iface):
    args = ["ovs-vsctl", "--timeout=%d" % cfg.CONF.ovs_vsctl_timeout,
            "iface-to-br", iface]
    try:
        return utils.execute(args, root_helper=root_helper).strip()
    except Exception:
        LOG.exception(_("Interface %s not found."), iface)
        return None


def get_bridges(root_helper):
    args = ["ovs-vsctl", "--timeout=%d" % cfg.CONF.ovs_vsctl_timeout,
            "list-br"]
    try:
        return utils.execute(args, root_helper=root_helper).strip().split("\n")
    except Exception as e:
        LOG.exception(_("Unable to retrieve bridges. Exception: %s"), e)
        return []


def get_installed_ovs_usr_version(root_helper):
    args = ["ovs-vsctl", "--version"]
    try:
        cmd = utils.execute(args, root_helper=root_helper)
        ver = re.findall("\d+\.\d+", cmd)[0]
        return ver
    except Exception:
        LOG.exception(_("Unable to retrieve OVS userspace version."))


def get_installed_ovs_klm_version():
    args = ["modinfo", "openvswitch"]
    try:
        cmd = utils.execute(args)
        for line in cmd.split('\n'):
            if 'version: ' in line and not 'srcversion' in line:
                ver = re.findall("\d+\.\d+", line)
                return ver[0]
    except Exception:
        LOG.exception(_("Unable to retrieve OVS kernel module version."))


def get_bridge_external_bridge_id(root_helper, bridge):
    args = ["ovs-vsctl", "--timeout=2", "br-get-external-id",
            bridge, "bridge-id"]
    try:
        return utils.execute(args, root_helper=root_helper).strip()
    except Exception:
        LOG.exception(_("Bridge %s not found."), bridge)
        return None
