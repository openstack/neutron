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
import itertools
import operator
import random
import time
import uuid

from neutron_lib import constants as p_const
from neutron_lib import exceptions
from neutron_lib.services.qos import constants as qos_constants
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import uuidutils
from ovsdbapp.backend.ovs_idl import idlutils

import debtcollector
import tenacity

from neutron._i18n import _
from neutron.agent.common import ip_lib
from neutron.agent.common import utils
from neutron.agent.ovsdb import impl_idl
from neutron.common import _constants as common_constants
from neutron.common import utils as common_utils
from neutron.conf.agent import ovs_conf
from neutron.plugins.ml2.drivers.openvswitch.agent.common \
    import constants

UINT64_BITMASK = (1 << 64) - 1

# Special return value for an invalid OVS ofport
INVALID_OFPORT = -1
UNASSIGNED_OFPORT = []

# OVS bridge fail modes
FAILMODE_SECURE = 'secure'
FAILMODE_STANDALONE = 'standalone'

# special values for cookies
COOKIE_ANY = object()

ovs_conf.register_ovs_agent_opts()

LOG = logging.getLogger(__name__)

OVS_DEFAULT_CAPS = {
    'datapath_types': [],
    'iface_types': [],
}

# It's default queue, all packets not tagged with 'set_queue' will go through
# this one
QOS_DEFAULT_QUEUE = 0

_SENTINEL = object()

CTRL_RATE_LIMIT_MIN = 100
CTRL_BURST_LIMIT_MIN = 25

# TODO(slaweq): move this to neutron_lib.constants
TYPE_GRE_IP6 = 'ip6gre'


def _ovsdb_result_pending(result):
    """Return True if ovsdb indicates the result is still pending."""
    # ovsdb can return '[]' for an ofport that has not yet been assigned
    return result == []


def _ovsdb_retry(fn):
    """Decorator for retrying when OVS has yet to assign an ofport.

    The instance's ovsdb_timeout is used as the max waiting time. This relies
    on the fact that instance methods receive self as the first argument.
    """
    @functools.wraps(fn)
    def wrapped(*args, **kwargs):
        self = args[0]
        new_fn = tenacity.retry(
            reraise=True,
            retry=tenacity.retry_if_result(_ovsdb_result_pending),
            wait=tenacity.wait_exponential(multiplier=0.02, max=1),
            stop=tenacity.stop_after_delay(
                self.ovsdb_timeout))(fn)
        return new_fn(*args, **kwargs)
    return wrapped


def get_gre_tunnel_port_type(remote_ip, local_ip):
    if (common_utils.get_ip_version(remote_ip) == p_const.IP_VERSION_6 or
            common_utils.get_ip_version(local_ip) == p_const.IP_VERSION_6):
        return TYPE_GRE_IP6
    return p_const.TYPE_GRE


class VifPort(object):
    def __init__(self, port_name, ofport, vif_id, vif_mac, switch):
        self.port_name = port_name
        self.ofport = ofport
        self.vif_id = vif_id
        self.vif_mac = vif_mac
        self.switch = switch

    def __str__(self):
        return ("iface-id=%s, vif_mac=%s, port_name=%s, ofport=%s, "
                "bridge_name=%s") % (
                    self.vif_id, self.vif_mac,
                    self.port_name, self.ofport,
                    self.switch.br_name)


class BaseOVS(object):

    def __init__(self):
        self.ovsdb = impl_idl.api_factory()
        self._hw_offload = None

    @property
    def ovsdb_timeout(self):
        return self.ovsdb.ovsdb_connection.timeout

    def add_bridge(self, bridge_name,
                   datapath_type=constants.OVS_DATAPATH_SYSTEM):
        br = OVSBridge(bridge_name, datapath_type=datapath_type)
        br.create()
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

    def get_bridge_external_bridge_id(self, bridge, check_error=False,
                                      log_errors=True):
        return self.ovsdb.br_get_external_id(bridge, 'bridge-id').execute(
            check_error=check_error, log_errors=log_errors)

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

    @property
    def config(self):
        """A dict containing the only row from the root Open_vSwitch table

        This row contains several columns describing the Open vSwitch install
        and the system on which it is installed. Useful keys include:
            datapath_types: a list of supported datapath types
            iface_types: a list of supported interface types
            ovs_version: the OVS version
        """
        return self.ovsdb.db_list("Open_vSwitch").execute()[0]

    @property
    def capabilities(self):
        _cfg = self.config
        return {k: _cfg.get(k, OVS_DEFAULT_CAPS[k]) for k in OVS_DEFAULT_CAPS}

    @property
    def is_hw_offload_enabled(self):
        if self._hw_offload is None:
            self._hw_offload = self.config.get('other_config',
                                   {}).get('hw-offload', '').lower() == 'true'
        return self._hw_offload


# Map from version string to on-the-wire protocol version encoding:
OF_PROTOCOL_TO_VERSION = {
    constants.OPENFLOW10: 1,
    constants.OPENFLOW11: 2,
    constants.OPENFLOW12: 3,
    constants.OPENFLOW13: 4,
    constants.OPENFLOW14: 5,
    constants.OPENFLOW15: 6,
}


def version_from_protocol(protocol):
    if protocol not in OF_PROTOCOL_TO_VERSION:
        raise Exception(_("unknown OVS protocol string, cannot compare: "
                          "%(protocol)s, (known: %(known)s)") %
                        {'protocol': protocol,
                         'known': list(OF_PROTOCOL_TO_VERSION)})
    return OF_PROTOCOL_TO_VERSION[protocol]


class OVSBridge(BaseOVS):
    def __init__(self, br_name, datapath_type=constants.OVS_DATAPATH_SYSTEM):
        super(OVSBridge, self).__init__()
        self.br_name = br_name
        self.datapath_type = datapath_type
        self._default_cookie = generate_random_cookie()
        self._highest_protocol_needed = constants.OPENFLOW10
        self._min_bw_qos_id = uuidutils.generate_uuid()
        # TODO(jlibosva): Revert initial_protocols once launchpad bug 1852221
        #                 is fixed and new openvswitch containing the fix is
        #                 released.
        self.initial_protocols = {
            constants.OPENFLOW10, constants.OPENFLOW13, constants.OPENFLOW14}
        self.initial_protocols.add(self._highest_protocol_needed)

    @property
    def default_cookie(self):
        return self._default_cookie

    def set_agent_uuid_stamp(self, val):
        self._default_cookie = val

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

    def add_protocols(self, *protocols):
        self.ovsdb.db_add('Bridge', self.br_name,
                          'protocols', *protocols).execute(check_error=True)

    def use_at_least_protocol(self, protocol):
        """Calls to ovs-ofctl will use a protocol version >= 'protocol'"""
        self.add_protocols(protocol)
        self._highest_protocol_needed = max(self._highest_protocol_needed,
                                            protocol,
                                            key=version_from_protocol)
        self.initial_protocols.add(self._highest_protocol_needed)

    def set_igmp_snooping_state(self, state):
        state = bool(state)
        other_config = {
            'mcast-snooping-disable-flood-unregistered': 'false'}
        with self.ovsdb.transaction() as txn:
            txn.add(
                self.ovsdb.db_set('Bridge', self.br_name,
                                  ('mcast_snooping_enable', state)))
            txn.add(
                self.ovsdb.db_set('Bridge', self.br_name,
                                  ('other_config', other_config)))

    def set_igmp_snooping_flood(self, port_name, state):
        state = str(state)
        other_config = {
            'mcast-snooping-flood-reports': state,
            'mcast-snooping-flood': state}
        self.ovsdb.db_set(
            'Port', port_name,
            ('other_config', other_config)).execute(
                check_error=True, log_errors=True)

    def create(self, secure_mode=False):
        other_config = {
            'mac-table-size': str(cfg.CONF.OVS.bridge_mac_table_size)}
        with self.ovsdb.transaction() as txn:
            txn.add(
                self.ovsdb.add_br(self.br_name,
                                  datapath_type=self.datapath_type))
            # the ovs-ofctl commands below in run_ofctl use OF10, so we
            # need to ensure that this version is enabled ; we could reuse
            # add_protocols, but doing ovsdb.db_add avoids doing two
            # transactions
            txn.add(
                self.ovsdb.db_add('Bridge', self.br_name,
                                  'protocols',
                                  *self.initial_protocols))
            txn.add(
                self.ovsdb.db_set('Bridge', self.br_name,
                                  ('other_config', other_config)))
            if secure_mode:
                txn.add(self.ovsdb.set_fail_mode(self.br_name,
                                                 FAILMODE_SECURE))

    def destroy(self):
        self.delete_bridge(self.br_name)

    def add_port(self, port_name, *interface_attr_tuples):
        with self.ovsdb.transaction() as txn:
            txn.add(self.ovsdb.add_port(self.br_name, port_name))
            if interface_attr_tuples:
                txn.add(self.ovsdb.db_set('Interface', port_name,
                                          *interface_attr_tuples))
        return self.get_port_ofport(port_name)

    def replace_port(self, port_name, *interface_attr_tuples):
        """Replace existing port or create it, and configure port interface."""

        # NOTE(xiaohhui): If del_port is inside the transaction, there will
        # only be one command for replace_port. This will cause the new port
        # not be found by system, which will lead to Bug #1519926.
        self.ovsdb.del_port(port_name).execute()
        with self.ovsdb.transaction() as txn:
            txn.add(self.ovsdb.add_port(self.br_name, port_name,
                                        may_exist=False))
            # NOTE(mangelajo): Port is added to dead vlan (4095) by default
            # until it's handled by the neutron-openvswitch-agent. Otherwise it
            # becomes a trunk port on br-int (receiving traffic for all vlans),
            # and also triggers issues on ovs-vswitchd related to the
            # datapath flow revalidator thread, see lp#1767422
            txn.add(self.ovsdb.db_set(
                    'Port', port_name, ('tag', constants.DEAD_VLAN_TAG)))

            # TODO(mangelajo): We could accept attr tuples for the Port too
            # but, that could potentially break usage of this function in
            # stable branches (where we need to backport).
            # https://review.opendev.org/#/c/564825/4/neutron/agent/common/
            # ovs_lib.py@289
            if interface_attr_tuples:
                txn.add(self.ovsdb.db_set('Interface', port_name,
                                          *interface_attr_tuples))

    def delete_port(self, port_name):
        self.ovsdb.del_port(port_name, self.br_name).execute()

    def run_ofctl(self, cmd, args, process_input=None):
        debtcollector.deprecate("Use of run_ofctl is "
            "deprecated", removal_version='V')
        full_args = ["ovs-ofctl", cmd,
                     "-O", self._highest_protocol_needed,
                     self.br_name] + args
        # TODO(kevinbenton): This error handling is really brittle and only
        # detects one specific type of failure. The callers of this need to
        # be refactored to expect errors so we can re-raise and they can
        # take appropriate action based on the type of error.
        for i in range(1, 11):
            try:
                return utils.execute(full_args, run_as_root=True,
                                     process_input=process_input)
            except Exception as e:
                if "failed to connect to socket" in str(e):
                    LOG.debug("Failed to connect to OVS. Retrying "
                              "in 1 second. Attempt: %s/10", i)
                    time.sleep(1)
                    continue
                LOG.error("Unable to execute %(cmd)s. Exception: "
                          "%(exception)s",
                          {'cmd': full_args, 'exception': e})
                break

    def count_flows(self):
        flow_list = self.run_ofctl("dump-flows", []).split("\n")[1:]
        return len(flow_list) - 1

    def remove_all_flows(self):
        self.run_ofctl("del-flows", [])

    @_ovsdb_retry
    def _get_port_val(self, port_name, port_val):
        return self.db_get_val("Interface", port_name, port_val)

    def get_port_ofport(self, port_name):
        """Get the port's assigned ofport, retrying if not yet assigned."""
        ofport = INVALID_OFPORT
        try:
            ofport = self._get_port_val(port_name, "ofport")
        except tenacity.RetryError:
            LOG.exception("Timed out retrieving ofport on port %s.",
                          port_name)
        return ofport

    @_ovsdb_retry
    def _get_datapath_id(self):
        return self.db_get_val('Bridge', self.br_name, 'datapath_id')

    def get_datapath_id(self):
        try:
            return self._get_datapath_id()
        except tenacity.RetryError:
            # if ovs fails to find datapath_id then something is likely to be
            # broken here
            LOG.exception("Timed out retrieving datapath_id on bridge %s.",
                          self.br_name)
            raise RuntimeError(_('No datapath_id on bridge %s') % self.br_name)

    def do_action_flows(self, action, kwargs_list, use_bundle=False):
        # we can't mix strict and non-strict, so we'll use the first kw
        # and check against other kw being different
        strict = kwargs_list[0].get('strict', False)

        for kw in kwargs_list:
            if action == 'del':
                if kw.get('cookie') == COOKIE_ANY:
                    # special value COOKIE_ANY was provided, unset
                    # cookie to match flows whatever their cookie is
                    kw.pop('cookie')
                    if kw.get('cookie_mask'):  # non-zero cookie mask
                        raise Exception(_("cookie=COOKIE_ANY but cookie_mask "
                                          "set to %s") % kw.get('cookie_mask'))
                elif 'cookie' in kw:
                    # a cookie was specified, use it
                    kw['cookie'] = check_cookie_mask(kw['cookie'])
                else:
                    # nothing was specified about cookies, use default
                    kw['cookie'] = "%d/-1" % self._default_cookie
            else:
                if 'cookie' not in kw:
                    kw['cookie'] = self._default_cookie

            if action in ('mod', 'del'):
                if kw.pop('strict', False) != strict:
                    msg = ("cannot mix 'strict' and not 'strict' in a batch "
                           "call")
                    raise exceptions.InvalidInput(error_message=msg)
            else:
                if kw.pop('strict', False):
                    msg = "cannot use 'strict' with 'add' action"
                    raise exceptions.InvalidInput(error_message=msg)

        extra_param = ["--strict"] if strict else []

        if action == 'del' and {} in kwargs_list:
            # the 'del' case simplifies itself if kwargs_list has at least
            # one item that matches everything
            self.run_ofctl('%s-flows' % action, [])
        else:
            flow_strs = [_build_flow_expr_str(kw, action, strict)
                         for kw in kwargs_list]
            LOG.debug("Processing %d OpenFlow rules.", len(flow_strs))
            if use_bundle:
                extra_param.append('--bundle')

            step = common_constants.AGENT_RES_PROCESSING_STEP
            for i in range(0, len(flow_strs), step):
                self.run_ofctl('%s-flows' % action, extra_param + ['-'],
                               '\n'.join(flow_strs[i:i + step]))

    def add_flow(self, **kwargs):
        self.do_action_flows('add', [kwargs])

    def mod_flow(self, **kwargs):
        self.do_action_flows('mod', [kwargs])

    def delete_flows(self, **kwargs):
        self.do_action_flows('del', [kwargs])

    def dump_flows_for_table(self, table):
        return self.dump_flows_for(table=table)

    def dump_flows_for(self, **kwargs):
        retval = None
        if "cookie" in kwargs:
            kwargs["cookie"] = check_cookie_mask(str(kwargs["cookie"]))
        flow_str = ",".join("=".join([key, str(val)])
                            for key, val in kwargs.items())

        flows = self.run_ofctl("dump-flows", [flow_str])
        if flows:
            retval = '\n'.join(item for item in flows.splitlines()
                               if is_a_flow_line(item))
        return retval

    def dump_all_flows(self):
        return [f for f in self.run_ofctl("dump-flows", []).splitlines()
                if is_a_flow_line(f)]

    def deferred(self, *args, **kwargs):
        return DeferredOVSBridge(self, *args, **kwargs)

    def add_tunnel_port(self, port_name, remote_ip, local_ip,
                        tunnel_type=p_const.TYPE_GRE,
                        vxlan_udp_port=p_const.VXLAN_UDP_PORT,
                        dont_fragment=True,
                        tunnel_csum=False,
                        tos=None):
        if tunnel_type == p_const.TYPE_GRE:
            tunnel_type = get_gre_tunnel_port_type(remote_ip, local_ip)
        attrs = [('type', tunnel_type)]
        # TODO(twilson) This is an OrderedDict solely to make a test happy
        options = collections.OrderedDict()
        vxlan_uses_custom_udp_port = (
            tunnel_type == p_const.TYPE_VXLAN and
            vxlan_udp_port != p_const.VXLAN_UDP_PORT
        )
        if vxlan_uses_custom_udp_port:
            options['dst_port'] = str(vxlan_udp_port)
        options['df_default'] = str(dont_fragment).lower()
        options['remote_ip'] = remote_ip
        options['local_ip'] = local_ip
        options['in_key'] = 'flow'
        options['out_key'] = 'flow'
        # NOTE(moshele): pkt_mark is not upported when using ovs hw-offload,
        # therefore avoid clear mark on encapsulating packets when it's
        # enabled
        if not self.is_hw_offload_enabled:
            options['egress_pkt_mark'] = '0'
        if tunnel_csum:
            options['csum'] = str(tunnel_csum).lower()
        if tos:
            options['tos'] = str(tos)
        if tunnel_type == TYPE_GRE_IP6:
            # NOTE(slaweq) According to the OVS documentation L3 GRE tunnels
            # over IPv6 are not supported.
            options['packet_type'] = 'legacy_l2'
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

    def get_ports_attributes(self, table, columns=None, ports=None,
                             check_error=True, log_errors=True,
                             if_exists=False):
        port_names = ports or self.get_port_name_list()
        if not port_names:
            return []
        return (self.ovsdb.db_list(table, port_names, columns=columns,
                                   if_exists=if_exists).
                execute(check_error=check_error, log_errors=log_errors))

    # returns a VIF object for each VIF port
    def get_vif_ports(self, ofport_filter=None):
        edge_ports = []
        port_info = self.get_ports_attributes(
            'Interface', columns=['name', 'external_ids', 'ofport'],
            if_exists=True)
        for port in port_info:
            name = port['name']
            external_ids = port['external_ids']
            ofport = port['ofport']
            if ofport_filter and ofport in ofport_filter:
                continue
            if "iface-id" in external_ids and "attached-mac" in external_ids:
                p = VifPort(name, ofport, external_ids["iface-id"],
                            external_ids["attached-mac"], self)
                edge_ports.append(p)

        return edge_ports

    def get_vif_port_to_ofport_map(self):
        results = self.get_ports_attributes(
            'Interface', columns=['name', 'external_ids', 'ofport'],
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
        results = self.get_ports_attributes(
            'Interface', columns=['name', 'external_ids', 'ofport'],
            if_exists=True)
        for result in results:
            if result['ofport'] == UNASSIGNED_OFPORT:
                LOG.warning("Found not yet ready openvswitch port: %s",
                            result['name'])
            elif result['ofport'] == INVALID_OFPORT:
                LOG.warning("Found failed openvswitch port: %s",
                            result['name'])
            elif 'attached-mac' in result['external_ids']:
                port_id = self.portid_from_external_ids(result['external_ids'])
                if port_id:
                    edge_ports.add(port_id)
        return edge_ports

    def portid_from_external_ids(self, external_ids):
        if 'iface-id' in external_ids:
            return external_ids['iface-id']

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
        results = self.get_ports_attributes(
            'Port', columns=['name', 'tag'], if_exists=True)
        return {p['name']: p['tag'] for p in results}

    def get_vifs_by_ids(self, port_ids):
        interface_info = self.get_ports_attributes(
            "Interface", columns=["name", "external_ids", "ofport"],
            if_exists=True)
        by_id = {x['external_ids'].get('iface-id'): x for x in interface_info}
        result = {}
        for port_id in port_ids:
            result[port_id] = None
            if port_id not in by_id:
                LOG.info("Port %(port_id)s not present in bridge "
                         "%(br_name)s",
                         {'port_id': port_id, 'br_name': self.br_name})
                continue
            pinfo = by_id[port_id]
            mac = pinfo['external_ids'].get('attached-mac')
            result[port_id] = VifPort(pinfo['name'], pinfo['ofport'],
                                      port_id, mac, self)
        return result

    def get_vif_port_by_id(self, port_id):
        ports = self.ovsdb.db_find(
            'Interface', ('external_ids', '=', {'iface-id': port_id}),
            ('external_ids', '!=', {'attached-mac': ''}),
            columns=['external_ids', 'name', 'ofport']).execute()
        for port in ports:
            if self.br_name != self.get_bridge_for_iface(port['name']):
                continue
            mac = port['external_ids'].get('attached-mac')
            return VifPort(port['name'], port['ofport'], port_id, mac, self)
        LOG.info("Port %(port_id)s not present in bridge %(br_name)s",
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
        self.set_controller_field('connection_mode', connection_mode)

    def set_controllers_inactivity_probe(self, interval):
        """Set bridge controllers inactivity probe interval.

        :param interval: inactivity_probe value in seconds.
        """
        self.set_controller_field('inactivity_probe', interval * 1000)

    def _set_egress_bw_limit_for_port(self, port_name, max_kbps,
                                      max_burst_kbps, check_error=True):
        with self.ovsdb.transaction(check_error=check_error) as txn:
            txn.add(self.ovsdb.db_set('Interface', port_name,
                                      ('ingress_policing_rate', max_kbps)))
            txn.add(self.ovsdb.db_set('Interface', port_name,
                                      ('ingress_policing_burst',
                                       max_burst_kbps)))

    def create_egress_bw_limit_for_port(self, port_name, max_kbps,
                                        max_burst_kbps):
        self._set_egress_bw_limit_for_port(
            port_name, max_kbps, max_burst_kbps)

    def get_egress_bw_limit_for_port(self, port_name):

        max_kbps = self.db_get_val('Interface', port_name,
                                   'ingress_policing_rate')
        max_burst_kbps = self.db_get_val('Interface', port_name,
                                         'ingress_policing_burst')

        max_kbps = max_kbps or None
        max_burst_kbps = max_burst_kbps or None

        return max_kbps, max_burst_kbps

    def delete_egress_bw_limit_for_port(self, port_name):
        if not self.port_exists(port_name):
            return
        self._set_egress_bw_limit_for_port(port_name, 0, 0, check_error=False)

    def find_qos(self, port_name):
        qos = self.ovsdb.db_find(
            'QoS',
            ('external_ids', '=', {'id': port_name}),
            columns=['_uuid', 'other_config']).execute(check_error=True)
        if qos:
            return qos[0]

    def find_queue(self, port_name, queue_type):
        queues = self.ovsdb.db_find(
            'Queue',
            ('external_ids', '=', {'id': port_name,
                                   'queue_type': str(queue_type)}),
            columns=['_uuid', 'other_config']).execute(check_error=True)
        if queues:
            return queues[0]

    def _update_bw_limit_queue(self, txn, port_name, queue_uuid, queue_type,
                               other_config):
        if queue_uuid:
            txn.add(self.ovsdb.db_set(
                'Queue', queue_uuid,
                ('other_config', other_config)))
        else:
            external_ids = {'id': port_name,
                            'queue_type': str(queue_type)}
            queue_uuid = txn.add(
                self.ovsdb.db_create(
                    'Queue', external_ids=external_ids,
                    other_config=other_config))
        return queue_uuid

    def _update_bw_limit_profile(self, txn, port_name, qos_uuid,
                                 queue_uuid, queue_type, qos_other_config):
        queues = {queue_type: queue_uuid}
        if qos_uuid:
            txn.add(self.ovsdb.db_set(
                'QoS', qos_uuid, ('queues', queues)))
            txn.add(self.ovsdb.db_set(
                'QoS', qos_uuid, ('other_config', qos_other_config)))
        else:
            external_ids = {'id': port_name}
            qos_uuid = txn.add(
                self.ovsdb.db_create(
                    'QoS', external_ids=external_ids,
                    type='linux-htb',
                    queues=queues,
                    other_config=qos_other_config))
        return qos_uuid

    def _update_bw_limit_profile_dpdk(self, txn, port_name, qos_uuid,
                                      other_config):
        if qos_uuid:
            txn.add(self.ovsdb.db_set(
                'QoS', qos_uuid, ('other_config', other_config)))
        else:
            external_ids = {'id': port_name}
            qos_uuid = txn.add(
                self.ovsdb.db_create(
                    'QoS', external_ids=external_ids, type='egress-policer',
                    other_config=other_config))
        return qos_uuid

    def _update_ingress_bw_limit_for_port(
            self, port_name, max_bw_in_bits, max_burst_in_bits):
        qos_other_config = {
            'max-rate': str(max_bw_in_bits)
        }
        queue_other_config = {
            'max-rate': str(max_bw_in_bits),
            'burst': str(max_burst_in_bits),
        }
        qos = self.find_qos(port_name)
        queue = self.find_queue(port_name, QOS_DEFAULT_QUEUE)
        qos_uuid = qos['_uuid'] if qos else None
        queue_uuid = queue['_uuid'] if queue else None
        with self.ovsdb.transaction(check_error=True) as txn:
            queue_uuid = self._update_bw_limit_queue(
                txn, port_name, queue_uuid, QOS_DEFAULT_QUEUE,
                queue_other_config
            )

            qos_uuid = self._update_bw_limit_profile(
                txn, port_name, qos_uuid, queue_uuid, QOS_DEFAULT_QUEUE,
                qos_other_config
            )

            txn.add(self.ovsdb.db_set(
                'Port', port_name, ('qos', qos_uuid)))

    def _update_ingress_bw_limit_for_dpdk_port(
            self, port_name, max_bw_in_bits, max_burst_in_bits):
        # cir and cbs should be set in bytes instead of bits
        qos_other_config = {
            'cir': str(max_bw_in_bits / 8),
            'cbs': str(max_burst_in_bits / 8)
        }
        qos = self.find_qos(port_name)
        qos_uuid = qos['_uuid'] if qos else None
        with self.ovsdb.transaction(check_error=True) as txn:
            qos_uuid = self._update_bw_limit_profile_dpdk(
                txn, port_name, qos_uuid, qos_other_config)
            txn.add(self.ovsdb.db_set(
                'Port', port_name, ('qos', qos_uuid)))

    def update_ingress_bw_limit_for_port(self, port_name, max_kbps,
                                         max_burst_kbps):
        max_bw_in_bits = max_kbps * p_const.SI_BASE
        max_burst_in_bits = max_burst_kbps * p_const.SI_BASE
        port_type = self._get_port_val(port_name, "type")
        if port_type in constants.OVS_DPDK_PORT_TYPES:
            self._update_ingress_bw_limit_for_dpdk_port(
                port_name, max_bw_in_bits, max_burst_in_bits)
        else:
            self._update_ingress_bw_limit_for_port(
                port_name, max_bw_in_bits, max_burst_in_bits)

    def get_ingress_bw_limit_for_port(self, port_name):
        max_kbps = None
        qos_max_kbps = None
        queue_max_kbps = None
        max_burst_kbit = None

        qos_res = self.find_qos(port_name)
        if qos_res:
            other_config = qos_res['other_config']
            max_bw_in_bits = other_config.get('max-rate')
            if max_bw_in_bits is not None:
                qos_max_kbps = int(max_bw_in_bits) / p_const.SI_BASE

        queue_res = self.find_queue(port_name, QOS_DEFAULT_QUEUE)
        if queue_res:
            other_config = queue_res['other_config']
            max_bw_in_bits = other_config.get('max-rate')
            if max_bw_in_bits is not None:
                queue_max_kbps = int(max_bw_in_bits) / p_const.SI_BASE
            max_burst_in_bits = other_config.get('burst')
            if max_burst_in_bits is not None:
                max_burst_kbit = (
                    int(max_burst_in_bits) / p_const.SI_BASE)

        if qos_max_kbps == queue_max_kbps:
            max_kbps = qos_max_kbps
        else:
            LOG.warning("qos max-rate %(qos_max_kbps)s is not equal to "
                        "queue max-rate %(queue_max_kbps)s",
                        {'qos_max_kbps': qos_max_kbps,
                         'queue_max_kbps': queue_max_kbps})
        return max_kbps, max_burst_kbit

    def get_ingress_bw_limit_for_dpdk_port(self, port_name):
        max_kbps = None
        max_burst_kbit = None
        res = self.find_qos(port_name)
        if res:
            other_config = res['other_config']
            max_bw_in_bytes = other_config.get("cir")
            if max_bw_in_bytes is not None:
                max_kbps = common_utils.bits_to_kilobits(
                    common_utils.bytes_to_bits(int(float(max_bw_in_bytes))),
                    p_const.SI_BASE)
            max_burst_in_bytes = other_config.get("cbs")
            if max_burst_in_bytes is not None:
                max_burst_kbit = common_utils.bits_to_kilobits(
                    common_utils.bytes_to_bits(int(float(max_burst_in_bytes))),
                    p_const.SI_BASE)
        return max_kbps, max_burst_kbit

    def delete_ingress_bw_limit_for_port(self, port_name):
        self.ovsdb.db_clear('Port', port_name,
                            'qos').execute(check_error=False)
        qos = self.find_qos(port_name)
        queue = self.find_queue(port_name, QOS_DEFAULT_QUEUE)
        with self.ovsdb.transaction(check_error=True) as txn:
            if qos:
                txn.add(self.ovsdb.db_destroy('QoS', qos['_uuid']))
            if queue:
                txn.add(self.ovsdb.db_destroy('Queue', queue['_uuid']))

    def set_controller_field(self, field, value):
        attr = [(field, value)]
        controllers = self.db_get_val('Bridge', self.br_name, 'controller')
        controllers = [controllers] if isinstance(
            controllers, uuid.UUID) else controllers
        with self.ovsdb.transaction(check_error=True) as txn:
            for controller_uuid in controllers:
                txn.add(self.ovsdb.db_set(
                    'Controller', controller_uuid, *attr))

    def set_controller_rate_limit(self, controller_rate_limit):
        """Set bridge controller_rate_limit

        :param controller_rate_limit: at least 100
        """
        if controller_rate_limit < CTRL_RATE_LIMIT_MIN:
            LOG.info("rate limit's value must be at least 100")
            controller_rate_limit = CTRL_RATE_LIMIT_MIN
        self.set_controller_field(
            'controller_rate_limit', controller_rate_limit)

    def set_controller_burst_limit(self, controller_burst_limit):
        """Set bridge controller_burst_limit

        :param controller_burst_limit: at least 25
        """
        if controller_burst_limit < CTRL_BURST_LIMIT_MIN:
            LOG.info("burst limit's value must be at least 25")
            controller_burst_limit = CTRL_BURST_LIMIT_MIN
        self.set_controller_field(
            'controller_burst_limit', controller_burst_limit)

    def set_datapath_id(self, datapath_id):
        dpid_cfg = {'datapath-id': datapath_id}
        self.set_db_attribute('Bridge', self.br_name, 'other_config', dpid_cfg,
                              check_error=True)

    def get_egress_min_bw_for_port(self, port_id):
        queue = self._find_queue(port_id)
        if not queue:
            return

        min_bps = queue['other_config'].get('min-rate')
        return int(int(min_bps) / 1000) if min_bps else None

    def _set_queue_for_minimum_bandwidth(self, queue_num):
        # reg4 is used to memoize if queue was set or not. If it is first visit
        # to table 0 for a packet (i.e. reg4 == 0), set queue and memoize (i.e.
        # load 1 to reg4), then goto table 0 again. The packet will be handled
        # as usual when the second visit to table 0.
        self.add_flow(
            table=constants.LOCAL_SWITCHING,
            in_port=queue_num,
            reg4=0,
            priority=200,
            actions=("set_queue:%s,load:1->NXM_NX_REG4[0],"
                     "resubmit(,%s)" % (queue_num, constants.LOCAL_SWITCHING)))

    def _unset_queue_for_minimum_bandwidth(self, queue_num):
        self.delete_flows(
            table=constants.LOCAL_SWITCHING,
            in_port=queue_num,
            reg4=0)

    def update_minimum_bandwidth_queue(self, port_id, egress_port_names,
                                       queue_num, min_kbps):
        queue_num = int(queue_num)
        queue_id = self._update_queue(port_id, queue_num, min_kbps=min_kbps)
        qos_id, qos_queues = self._find_qos()
        if qos_queues:
            qos_queues[queue_num] = queue_id
        else:
            qos_queues = {queue_num: queue_id}
        qos_id = self._update_qos(
            qos_id=qos_id, queues=qos_queues)
        for egress_port_name in egress_port_names:
            self._set_port_qos(egress_port_name, qos_id=qos_id)
        self._set_queue_for_minimum_bandwidth(queue_num)
        return qos_id

    def delete_minimum_bandwidth_queue(self, port_id):
        queue = self._find_queue(port_id)
        if not queue:
            return
        queue_num = int(queue['external_ids']['queue-num'])
        self._unset_queue_for_minimum_bandwidth(queue_num)
        qos_id, qos_queues = self._find_qos()
        if not qos_queues:
            return
        if queue_num in qos_queues.keys():
            qos_queues.pop(queue_num)
            self._update_qos(
                qos_id=qos_id, queues=qos_queues)
            self._delete_queue(queue['_uuid'])

    def clear_minimum_bandwidth_qos(self):
        qoses = self._list_qos(
            qos_type=qos_constants.RULE_TYPE_MINIMUM_BANDWIDTH)

        for qos in qoses:
            qos_id = qos['_uuid']
            queues = {num: queue.uuid
                      for num, queue in qos['queues'].items()}
            ports = self.ovsdb.db_find(
                'Port',
                ('qos', '=', qos_id),
                colmuns=['name']).execute(check_error=True)
            for port in ports:
                self._set_port_qos(port['name'])
            self.ovsdb.db_destroy('QoS', qos_id).execute(check_error=True)
            for queue_uuid in queues.values():
                self._delete_queue(queue_uuid)

    def _update_queue(self, port_id, queue_num, max_kbps=None,
                      max_burst_kbps=None, min_kbps=None):
        other_config = {}
        if max_kbps:
            other_config['max-rate'] = str(max_kbps * 1000)
        if max_burst_kbps:
            other_config['burst'] = str(max_burst_kbps * 1000)
        if min_kbps:
            other_config['min-rate'] = str(min_kbps * 1000)

        queue = self._find_queue(port_id)
        if queue and queue['_uuid']:
            if queue['other_config'] != other_config:
                self.set_db_attribute('Queue', queue['_uuid'], 'other_config',
                                      other_config, check_error=True)
        else:
            # NOTE(ralonsoh): "external_ids" is a map of string-string pairs
            external_ids = {
                'port': str(port_id),
                'type': str(qos_constants.RULE_TYPE_MINIMUM_BANDWIDTH),
                'queue-num': str(queue_num)}
            self.ovsdb.db_create(
                'Queue', other_config=other_config,
                external_ids=external_ids).execute(check_error=True)
            queue = self._find_queue(port_id)
        return queue['_uuid']

    def _find_queue(self, port_id, _type=None):
        # NOTE(ralonsoh): in ovsdb native library, '{>=}' operator is not
        # implemented yet. This is a workaround: list all queues and compare
        # the external_ids key needed.
        _type = _type or qos_constants.RULE_TYPE_MINIMUM_BANDWIDTH
        queues = self._list_queues(port=port_id, _type=_type)
        if queues:
            return queues[0]
        return None

    def _list_queues(self, _type=None, port=None):
        queues = self.ovsdb.db_list(
            'Queue',
            columns=['_uuid', 'external_ids', 'other_config']).execute(
            check_error=True)
        if port:
            queues = [queue for queue in queues
                      if queue['external_ids'].get('port') == str(port)]
        if _type:
            queues = [queue for queue in queues
                      if queue['external_ids'].get('type') == str(_type)]
        return queues

    def _delete_queue(self, queue_id):
        try:
            self.ovsdb.db_destroy('Queue', queue_id).execute(check_error=True)
        except idlutils.RowNotFound:
            LOG.info('OVS Queue %s was already deleted', queue_id)
        except RuntimeError as exc:
            with excutils.save_and_reraise_exception():
                if 'referential integrity violation' not in str(exc):
                    return
                qos_regs = self._list_qos()
                qos_uuids = []
                for qos_reg in qos_regs:
                    queue_nums = [num for num, q in qos_reg['queues'].items()
                                  if q.uuid == queue_id]
                    if queue_nums:
                        qos_uuids.append(str(qos_reg['_uuid']))
                LOG.error('Queue %(queue)s was still in use by the following '
                          'QoS rules: %(qoses)s',
                          {'queue': str(queue_id),
                           'qoses': ', '.join(sorted(qos_uuids))})

    def _update_qos(self, qos_id=None, queues=None):
        queues = queues or {}
        if not qos_id:
            external_ids = {'id': self._min_bw_qos_id,
                            '_type': qos_constants.RULE_TYPE_MINIMUM_BANDWIDTH}
            self.ovsdb.db_create(
                'QoS',
                type='linux-htb',
                queues=queues,
                external_ids=external_ids).execute(check_error=True)
            qos_id, _ = self._find_qos()
        else:
            self.clear_db_attribute('QoS', qos_id, 'queues')
            if queues:
                self.set_db_attribute('QoS', qos_id, 'queues', queues,
                                      check_error=True)
        return qos_id

    def _list_qos(self, _id=None, qos_type=None):
        external_ids = {}
        if _id:
            external_ids['id'] = _id
        if qos_type:
            external_ids['_type'] = qos_type
        if external_ids:
            return self.ovsdb.db_find(
                'QoS',
                ('external_ids', '=', external_ids),
                colmuns=['_uuid', 'queues']).execute(check_error=True)

        return self.ovsdb.db_find(
            'QoS', colmuns=['_uuid', 'queues']).execute(check_error=True)

    def _find_qos(self):
        qos_regs = self._list_qos(_id=self._min_bw_qos_id)
        if qos_regs:
            queues = {num: queue.uuid
                      for num, queue in qos_regs[0]['queues'].items()}
            return qos_regs[0]['_uuid'], queues
        return None, None

    def _set_port_qos(self, port_name, qos_id=None):
        if qos_id:
            self.set_db_attribute('Port', port_name, 'qos', qos_id,
                                  check_error=True)
        else:
            self.clear_db_attribute('Port', port_name, 'qos')

    def get_bridge_ports(self, port_type=None):
        port_names = self.get_port_name_list() + [self.br_name]
        ports = self.get_ports_attributes('Interface',
                                          ports=port_names,
                                          columns=['name', 'type'],
                                          if_exists=True) or []
        if port_type is None:
            return ports
        elif not isinstance(port_type, list):
            port_type = [port_type]
        return [port['name'] for port in ports if port['type'] in port_type]

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
                 order=('add', 'mod', 'del'), use_bundle=False):
        '''Constructor.

        :param br: wrapped bridge
        :param full_ordered: Optional, disable flow reordering (slower)
        :param order: Optional, define in which order flow are applied
        :param use_bundle: Optional, a bool whether --bundle should be passed
                           to all ofctl commands. Default is set to False.
        '''

        self.br = br
        self.full_ordered = full_ordered
        self.order = order
        if not self.full_ordered:
            self.weights = dict((y, x) for x, y in enumerate(self.order))
        self.action_flow_tuples = []
        self.use_bundle = use_bundle

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
            self.br.do_action_flows(action, flows, self.use_bundle)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is None:
            self.apply_flows()
        else:
            LOG.exception("OVS flows could not be applied on bridge %s",
                          self.br.br_name)


def _build_flow_expr_str(flow_dict, cmd, strict):
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
        if not strict:
            msg = _("Cannot match priority on flow deletion or modification "
                    "without 'strict'")
            raise exceptions.InvalidInput(error_message=msg)

    if cmd != 'del':
        if "actions" not in flow_dict:
            msg = _("Must specify one or more actions on flow addition"
                    " or modification")
            raise exceptions.InvalidInput(error_message=msg)
        actions = "actions=%s" % flow_dict.pop('actions')

    for key, value in flow_dict.items():
        if key == 'proto':
            flow_expr_arr.append(value)
        else:
            flow_expr_arr.append("%s=%s" % (key, str(value)))

    if actions:
        flow_expr_arr.append(actions)

    return ','.join(flow_expr_arr)


def generate_random_cookie():
    # The OpenFlow spec forbids use of -1
    return random.randrange(UINT64_BITMASK)


def check_cookie_mask(cookie):
    cookie = str(cookie)
    if '/' not in cookie:
        return cookie + '/-1'
    else:
        return cookie


def is_a_flow_line(line):
    # this is used to filter out from ovs-ofctl dump-flows the lines that
    # are not flow descriptions but mere indications of the type of openflow
    # message that was used ; e.g.:
    #
    # # ovs-ofctl dump-flows br-int
    # NXST_FLOW reply (xid=0x4):
    #  cookie=0xb7dff131a697c6a5, duration=2411726.809s, table=0, ...
    #  cookie=0xb7dff131a697c6a5, duration=2411726.786s, table=23, ...
    #  cookie=0xb7dff131a697c6a5, duration=2411726.760s, table=24, ...
    #
    return 'NXST' not in line and 'OFPST' not in line
