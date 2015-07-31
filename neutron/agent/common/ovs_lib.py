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
import itertools
import operator

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils
import retrying
import six
import uuid

from neutron.agent.common import utils
from neutron.agent.linux import ip_lib
from neutron.agent.ovsdb import api as ovsdb
from neutron.common import exceptions
from neutron.i18n import _LE, _LI, _LW
from neutron.plugins.common import constants as p_const

# Default timeout for ovs-vsctl command
DEFAULT_OVS_VSCTL_TIMEOUT = 10

# Special return value for an invalid OVS ofport
INVALID_OFPORT = -1
UNASSIGNED_OFPORT = []

# OVS bridge fail modes
FAILMODE_SECURE = 'secure'
FAILMODE_STANDALONE = 'standalone'

OPTS = [
    cfg.IntOpt('ovs_vsctl_timeout',
               default=DEFAULT_OVS_VSCTL_TIMEOUT,
               help=_('Timeout in seconds for ovs-vsctl commands')),
]
cfg.CONF.register_opts(OPTS)

LOG = logging.getLogger(__name__)


def _ofport_result_pending(result):
    """Return True if ovs-vsctl indicates the result is still pending."""
    # ovs-vsctl can return '[]' for an ofport that has not yet been assigned
    try:
        int(result)
        return False
    except (ValueError, TypeError):
        return True


def _ofport_retry(fn):
    """Decorator for retrying when OVS has yet to assign an ofport.

    The instance's vsctl_timeout is used as the max waiting time. This relies
    on the fact that instance methods receive self as the first argument.
    """
    @six.wraps(fn)
    def wrapped(*args, **kwargs):
        self = args[0]
        new_fn = retrying.retry(
            retry_on_result=_ofport_result_pending,
            stop_max_delay=self.vsctl_timeout * 1000,
            wait_exponential_multiplier=10,
            wait_exponential_max=1000,
            retry_on_exception=lambda _: False)(fn)
        return new_fn(*args, **kwargs)
    return wrapped


class VifPort(object):
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

    def __init__(self):
        self.vsctl_timeout = cfg.CONF.ovs_vsctl_timeout
        self.ovsdb = ovsdb.API.get(self)

    def add_bridge(self, bridge_name):
        self.ovsdb.add_br(bridge_name).execute()
        br = OVSBridge(bridge_name)
        # Don't return until vswitchd sets up the internal port
        br.get_port_ofport(bridge_name)
        return br

    def delete_bridge(self, bridge_name):
        self.ovsdb.del_br(bridge_name).execute()

    def bridge_exists(self, bridge_name):
        return self.ovsdb.br_exists(bridge_name).execute()

    def port_exists(self, port_name):
        cmd = self.ovsdb.db_get('Port', port_name, 'name')
        return bool(cmd.execute(check_error=False, log_errors=False))

    def get_bridge_for_iface(self, iface):
        return self.ovsdb.iface_to_br(iface).execute()

    def get_bridges(self):
        return self.ovsdb.list_br().execute(check_error=True)

    def get_bridge_external_bridge_id(self, bridge):
        return self.ovsdb.br_get_external_id(bridge, 'bridge-id').execute()

    def set_db_attribute(self, table_name, record, column, value,
                         check_error=False, log_errors=True):
        self.ovsdb.db_set(table_name, record, (column, value)).execute(
            check_error=check_error, log_errors=log_errors)

    def clear_db_attribute(self, table_name, record, column):
        self.ovsdb.db_clear(table_name, record, column).execute()

    def db_get_val(self, table, record, column, check_error=False,
                   log_errors=True):
        return self.ovsdb.db_get(table, record, column).execute(
            check_error=check_error, log_errors=log_errors)

    def db_list(self, table, records=None, columns=None,
                check_error=True, log_errors=True, if_exists=False):
        return (self.ovsdb.db_list(table, records=records, columns=columns,
                                   if_exists=if_exists).
                execute(check_error=check_error, log_errors=log_errors))


class OVSBridge(BaseOVS):
    def __init__(self, br_name):
        super(OVSBridge, self).__init__()
        self.br_name = br_name

    def set_controller(self, controllers):
        self.ovsdb.set_controller(self.br_name,
                                  controllers).execute(check_error=True)

    def del_controller(self):
        self.ovsdb.del_controller(self.br_name).execute(check_error=True)

    def get_controller(self):
        return self.ovsdb.get_controller(self.br_name).execute(
            check_error=True)

    def _set_bridge_fail_mode(self, mode):
        self.ovsdb.set_fail_mode(self.br_name, mode).execute(check_error=True)

    def set_secure_mode(self):
        self._set_bridge_fail_mode(FAILMODE_SECURE)

    def set_standalone_mode(self):
        self._set_bridge_fail_mode(FAILMODE_STANDALONE)

    def set_protocols(self, protocols):
        self.set_db_attribute('Bridge', self.br_name, 'protocols', protocols,
                              check_error=True)

    def create(self):
        self.ovsdb.add_br(self.br_name).execute()
        # Don't return until vswitchd sets up the internal port
        self.get_port_ofport(self.br_name)

    def destroy(self):
        self.delete_bridge(self.br_name)

    def reset_bridge(self, secure_mode=False):
        with self.ovsdb.transaction() as txn:
            txn.add(self.ovsdb.del_br(self.br_name))
            txn.add(self.ovsdb.add_br(self.br_name))
            if secure_mode:
                txn.add(self.ovsdb.set_fail_mode(self.br_name,
                                                 FAILMODE_SECURE))

    def add_port(self, port_name, *interface_attr_tuples):
        with self.ovsdb.transaction() as txn:
            txn.add(self.ovsdb.add_port(self.br_name, port_name))
            if interface_attr_tuples:
                txn.add(self.ovsdb.db_set('Interface', port_name,
                                          *interface_attr_tuples))
        return self.get_port_ofport(port_name)

    def replace_port(self, port_name, *interface_attr_tuples):
        """Replace existing port or create it, and configure port interface."""
        with self.ovsdb.transaction() as txn:
            txn.add(self.ovsdb.del_port(port_name))
            txn.add(self.ovsdb.add_port(self.br_name, port_name,
                                        may_exist=False))
            if interface_attr_tuples:
                txn.add(self.ovsdb.db_set('Interface', port_name,
                                          *interface_attr_tuples))
        # Don't return until the port has been assigned by vswitchd
        self.get_port_ofport(port_name)

    def delete_port(self, port_name):
        self.ovsdb.del_port(port_name, self.br_name).execute()

    def run_ofctl(self, cmd, args, process_input=None):
        full_args = ["ovs-ofctl", cmd, self.br_name] + args
        try:
            return utils.execute(full_args, run_as_root=True,
                                 process_input=process_input)
        except Exception as e:
            LOG.error(_LE("Unable to execute %(cmd)s. Exception: "
                          "%(exception)s"),
                      {'cmd': full_args, 'exception': e})

    def count_flows(self):
        flow_list = self.run_ofctl("dump-flows", []).split("\n")[1:]
        return len(flow_list) - 1

    def remove_all_flows(self):
        self.run_ofctl("del-flows", [])

    @_ofport_retry
    def _get_port_ofport(self, port_name):
        return self.db_get_val("Interface", port_name, "ofport")

    def get_port_ofport(self, port_name):
        """Get the port's assigned ofport, retrying if not yet assigned."""
        ofport = INVALID_OFPORT
        try:
            ofport = self._get_port_ofport(port_name)
        except retrying.RetryError as e:
            LOG.exception(_LE("Timed out retrieving ofport on port %(pname)s. "
                              "Exception: %(exception)s"),
                          {'pname': port_name, 'exception': e})
        return ofport

    def get_datapath_id(self):
        return self.db_get_val('Bridge',
                               self.br_name, 'datapath_id')

    def do_action_flows(self, action, kwargs_list):
        flow_strs = [_build_flow_expr_str(kw, action) for kw in kwargs_list]
        self.run_ofctl('%s-flows' % action, ['-'], '\n'.join(flow_strs))

    def add_flow(self, **kwargs):
        self.do_action_flows('add', [kwargs])

    def mod_flow(self, **kwargs):
        self.do_action_flows('mod', [kwargs])

    def delete_flows(self, **kwargs):
        self.do_action_flows('del', [kwargs])

    def dump_flows_for_table(self, table):
        retval = None
        flow_str = "table=%s" % table
        flows = self.run_ofctl("dump-flows", [flow_str])
        if flows:
            retval = '\n'.join(item for item in flows.splitlines()
                               if 'NXST' not in item)
        return retval

    def deferred(self, **kwargs):
        return DeferredOVSBridge(self, **kwargs)

    def add_tunnel_port(self, port_name, remote_ip, local_ip,
                        tunnel_type=p_const.TYPE_GRE,
                        vxlan_udp_port=p_const.VXLAN_UDP_PORT,
                        dont_fragment=True):
        attrs = [('type', tunnel_type)]
        # TODO(twilson) This is an OrderedDict solely to make a test happy
        options = collections.OrderedDict()
        vxlan_uses_custom_udp_port = (
            tunnel_type == p_const.TYPE_VXLAN and
            vxlan_udp_port != p_const.VXLAN_UDP_PORT
        )
        if vxlan_uses_custom_udp_port:
            options['dst_port'] = vxlan_udp_port
        options['df_default'] = str(dont_fragment).lower()
        options['remote_ip'] = remote_ip
        options['local_ip'] = local_ip
        options['in_key'] = 'flow'
        options['out_key'] = 'flow'
        attrs.append(('options', options))

        return self.add_port(port_name, *attrs)

    def add_patch_port(self, local_name, remote_name):
        attrs = [('type', 'patch'),
                 ('options', {'peer': remote_name})]
        return self.add_port(local_name, *attrs)

    def get_iface_name_list(self):
        # get the interface name list for this bridge
        return self.ovsdb.list_ifaces(self.br_name).execute(check_error=True)

    def get_port_name_list(self):
        # get the port name list for this bridge
        return self.ovsdb.list_ports(self.br_name).execute(check_error=True)

    def get_port_stats(self, port_name):
        return self.db_get_val("Interface", port_name, "statistics")

    def get_xapi_iface_id(self, xs_vif_uuid):
        args = ["xe", "vif-param-get", "param-name=other-config",
                "param-key=nicira-iface-id", "uuid=%s" % xs_vif_uuid]
        try:
            return utils.execute(args, run_as_root=True).strip()
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Unable to execute %(cmd)s. "
                              "Exception: %(exception)s"),
                          {'cmd': args, 'exception': e})

    # returns a VIF object for each VIF port
    def get_vif_ports(self):
        edge_ports = []
        port_names = self.get_port_name_list()
        port_info = self.db_list(
            'Interface', columns=['name', 'external_ids', 'ofport'])
        by_name = {x['name']: x for x in port_info}
        for name in port_names:
            if not by_name.get(name):
                #NOTE(dprince): some ports (like bonds) won't have all
                # these attributes so we skip them entirely
                continue
            external_ids = by_name[name]['external_ids']
            ofport = by_name[name]['ofport']
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

    def get_vif_port_to_ofport_map(self):
        port_names = self.get_port_name_list()
        results = self.db_list(
            'Interface', port_names, ['name', 'external_ids', 'ofport'],
            if_exists=True)
        port_map = {}
        for r in results:
            # fall back to basic interface name
            key = self.portid_from_external_ids(r['external_ids']) or r['name']
            try:
                port_map[key] = int(r['ofport'])
            except TypeError:
                # port doesn't yet have an ofport entry so we ignore it
                pass
        return port_map

    def get_vif_port_set(self):
        edge_ports = set()
        port_names = self.get_port_name_list()
        results = self.db_list(
            'Interface', port_names, ['name', 'external_ids', 'ofport'],
            if_exists=True)
        for result in results:
            if result['ofport'] == UNASSIGNED_OFPORT:
                LOG.warn(_LW("Found not yet ready openvswitch port: %s"),
                         result['name'])
            elif result['ofport'] == INVALID_OFPORT:
                LOG.warn(_LW("Found failed openvswitch port: %s"),
                         result['name'])
            elif 'attached-mac' in result['external_ids']:
                port_id = self.portid_from_external_ids(result['external_ids'])
                if port_id:
                    edge_ports.add(port_id)
        return edge_ports

    def portid_from_external_ids(self, external_ids):
        if 'iface-id' in external_ids:
            return external_ids['iface-id']
        if 'xs-vif-uuid' in external_ids:
            iface_id = self.get_xapi_iface_id(
                external_ids['xs-vif-uuid'])
            return iface_id

    def get_port_tag_dict(self):
        """Get a dict of port names and associated vlan tags.

        e.g. the returned dict is of the following form::

            {u'int-br-eth2': [],
             u'patch-tun': [],
             u'qr-76d9e6b6-21': 1,
             u'tapce5318ff-78': 1,
             u'tape1400310-e6': 1}

        The TAG ID is only available in the "Port" table and is not available
        in the "Interface" table queried by the get_vif_port_set() method.

        """
        port_names = self.get_port_name_list()
        results = self.db_list('Port', port_names, ['name', 'tag'],
                               if_exists=True)
        return {p['name']: p['tag'] for p in results}

    def get_vifs_by_ids(self, port_ids):
        interface_info = self.db_list(
            "Interface", columns=["name", "external_ids", "ofport"])
        by_id = {x['external_ids'].get('iface-id'): x for x in interface_info}
        intfs_on_bridge = self.ovsdb.list_ports(self.br_name).execute(
            check_error=True)
        result = {}
        for port_id in port_ids:
            result[port_id] = None
            if (port_id not in by_id or
                    by_id[port_id]['name'] not in intfs_on_bridge):
                LOG.info(_LI("Port %(port_id)s not present in bridge "
                             "%(br_name)s"),
                         {'port_id': port_id, 'br_name': self.br_name})
                continue
            pinfo = by_id[port_id]
            if not self._check_ofport(port_id, pinfo):
                continue
            mac = pinfo['external_ids'].get('attached-mac')
            result[port_id] = VifPort(pinfo['name'], pinfo['ofport'],
                                      port_id, mac, self)
        return result

    @staticmethod
    def _check_ofport(port_id, port_info):
        if port_info['ofport'] in [UNASSIGNED_OFPORT, INVALID_OFPORT]:
            LOG.warn(_LW("ofport: %(ofport)s for VIF: %(vif)s is not a"
                         " positive integer"),
                     {'ofport': port_info['ofport'], 'vif': port_id})
            return False
        return True

    def get_vif_port_by_id(self, port_id):
        ports = self.ovsdb.db_find(
            'Interface', ('external_ids', '=', {'iface-id': port_id}),
            ('external_ids', '!=', {'attached-mac': ''}),
            columns=['external_ids', 'name', 'ofport']).execute()
        for port in ports:
            if self.br_name != self.get_bridge_for_iface(port['name']):
                continue
            if not self._check_ofport(port_id, port):
                continue
            mac = port['external_ids'].get('attached-mac')
            return VifPort(port['name'], port['ofport'], port_id, mac, self)
        LOG.info(_LI("Port %(port_id)s not present in bridge %(br_name)s"),
                 {'port_id': port_id, 'br_name': self.br_name})

    def delete_ports(self, all_ports=False):
        if all_ports:
            port_names = self.get_port_name_list()
        else:
            port_names = (port.port_name for port in self.get_vif_ports())

        for port_name in port_names:
            self.delete_port(port_name)

    def get_local_port_mac(self):
        """Retrieve the mac of the bridge's local port."""
        address = ip_lib.IPDevice(self.br_name).link.address
        if address:
            return address
        else:
            msg = _('Unable to determine mac address for %s') % self.br_name
            raise Exception(msg)

    def set_controllers_connection_mode(self, connection_mode):
        """Set bridge controllers connection mode.

        :param connection_mode: "out-of-band" or "in-band"
        """
        attr = [('connection_mode', connection_mode)]
        controllers = self.db_get_val('Bridge', self.br_name, 'controller')
        controllers = [controllers] if isinstance(
            controllers, uuid.UUID) else controllers
        with self.ovsdb.transaction(check_error=True) as txn:
            for controller_uuid in controllers:
                txn.add(self.ovsdb.db_set('Controller',
                                          controller_uuid, *attr))

    def __enter__(self):
        self.create()
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        self.destroy()


class DeferredOVSBridge(object):
    '''Deferred OVSBridge.

    This class wraps add_flow, mod_flow and delete_flows calls to an OVSBridge
    and defers their application until apply_flows call in order to perform
    bulk calls. It wraps also ALLOWED_PASSTHROUGHS calls to avoid mixing
    OVSBridge and DeferredOVSBridge uses.
    This class can be used as a context, in such case apply_flows is called on
    __exit__ except if an exception is raised.
    This class is not thread-safe, that's why for every use a new instance
    must be implemented.
    '''
    ALLOWED_PASSTHROUGHS = 'add_port', 'add_tunnel_port', 'delete_port'

    def __init__(self, br, full_ordered=False,
                 order=('add', 'mod', 'del')):
        '''Constructor.

        :param br: wrapped bridge
        :param full_ordered: Optional, disable flow reordering (slower)
        :param order: Optional, define in which order flow are applied
        '''

        self.br = br
        self.full_ordered = full_ordered
        self.order = order
        if not self.full_ordered:
            self.weights = dict((y, x) for x, y in enumerate(self.order))
        self.action_flow_tuples = []

    def __getattr__(self, name):
        if name in self.ALLOWED_PASSTHROUGHS:
            return getattr(self.br, name)
        raise AttributeError(name)

    def add_flow(self, **kwargs):
        self.action_flow_tuples.append(('add', kwargs))

    def mod_flow(self, **kwargs):
        self.action_flow_tuples.append(('mod', kwargs))

    def delete_flows(self, **kwargs):
        self.action_flow_tuples.append(('del', kwargs))

    def apply_flows(self):
        action_flow_tuples = self.action_flow_tuples
        self.action_flow_tuples = []
        if not action_flow_tuples:
            return

        if not self.full_ordered:
            action_flow_tuples.sort(key=lambda af: self.weights[af[0]])

        grouped = itertools.groupby(action_flow_tuples,
                                    key=operator.itemgetter(0))
        itemgetter_1 = operator.itemgetter(1)
        for action, action_flow_list in grouped:
            flows = list(map(itemgetter_1, action_flow_list))
            self.br.do_action_flows(action, flows)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is None:
            self.apply_flows()
        else:
            LOG.exception(_LE("OVS flows could not be applied on bridge %s"),
                          self.br.br_name)


def _build_flow_expr_str(flow_dict, cmd):
    flow_expr_arr = []
    actions = None

    if cmd == 'add':
        flow_expr_arr.append("hard_timeout=%s" %
                             flow_dict.pop('hard_timeout', '0'))
        flow_expr_arr.append("idle_timeout=%s" %
                             flow_dict.pop('idle_timeout', '0'))
        flow_expr_arr.append("priority=%s" %
                             flow_dict.pop('priority', '1'))
    elif 'priority' in flow_dict:
        msg = _("Cannot match priority on flow deletion or modification")
        raise exceptions.InvalidInput(error_message=msg)

    if cmd != 'del':
        if "actions" not in flow_dict:
            msg = _("Must specify one or more actions on flow addition"
                    " or modification")
            raise exceptions.InvalidInput(error_message=msg)
        actions = "actions=%s" % flow_dict.pop('actions')

    for key, value in six.iteritems(flow_dict):
        if key == 'proto':
            flow_expr_arr.append(value)
        else:
            flow_expr_arr.append("%s=%s" % (key, str(value)))

    if actions:
        flow_expr_arr.append(actions)

    return ','.join(flow_expr_arr)
