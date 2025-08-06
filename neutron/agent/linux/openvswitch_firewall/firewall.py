# Copyright 2015
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
import contextlib
import copy
import itertools
import re
import time

import netaddr
from neutron_lib.agent.common import constants as agent_consts
from neutron_lib.callbacks import events as callbacks_events
from neutron_lib.callbacks import registry as callbacks_registry
from neutron_lib.callbacks import resources as callbacks_resources
from neutron_lib import constants as lib_const
from neutron_lib.plugins.ml2 import ovs_constants as ovs_consts
from neutron_lib.plugins import utils as p_utils
from neutron_lib.utils import helpers
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import netutils

from neutron._i18n import _
from neutron.agent.common import ovs_lib
from neutron.agent import firewall
from neutron.agent.linux import ip_conntrack
from neutron.agent.linux.openvswitch_firewall import constants as ovsfw_consts
from neutron.agent.linux.openvswitch_firewall import exceptions
from neutron.agent.linux.openvswitch_firewall import iptables
from neutron.agent.linux.openvswitch_firewall import rules
from neutron.common import utils as n_utils

LOG = logging.getLogger(__name__)
CONJ_ID_REGEX = re.compile(r"conj_id=(\d+),")


def _replace_register(flow_params, register_number, register_value):
    """Replace value from flows to given register number

    'register_value' key in dictionary will be replaced by register number
    given by 'register_number'

    :param flow_params: Dictionary containing defined flows
    :param register_number: The number of register where value will be stored
    :param register_value: Key to be replaced by register number

    """
    try:
        reg_port = flow_params[register_value]
        del flow_params[register_value]
        flow_params[f'reg{register_number:d}'] = reg_port
    except KeyError:
        pass


def create_reg_numbers(flow_params):
    """Replace reg_(port|net) values with defined register numbers"""
    _replace_register(
        flow_params, agent_consts.REG_PORT, agent_consts.PORT_REG_NAME)
    _replace_register(
        flow_params, agent_consts.REG_NET, agent_consts.NET_REG_NAME)
    _replace_register(
        flow_params, agent_consts.REG_REMOTE_GROUP,
        agent_consts.REMOTE_GROUP_REG_NAME)


def get_segmentation_id_from_other_config(bridge, port_name):
    """Return segmentation_id stored in OVSDB other_config metadata.

    :param bridge: OVSBridge instance where port is.
    :param port_name: Name of the port.
    """
    try:
        other_config = bridge.db_get_val(
            'Port', port_name, 'other_config')
        network_type = other_config.get('network_type')
        if lib_const.TYPE_VLAN == network_type:
            return int(other_config.get('segmentation_id'))
    except (TypeError, ValueError):
        pass


def get_network_type_from_other_config(bridge, port_name):
    """Return network_type stored in OVSDB other_config metadata.

    :param bridge: OVSBridge instance where port is.
    :param port_name: Name of the port.
    """
    other_config = bridge.db_get_val('Port', port_name, 'other_config')
    return other_config.get('network_type')


def get_physical_network_from_other_config(bridge, port_name):
    """Return physical_network stored in OVSDB other_config metadata.

    :param bridge: OVSBridge instance where port is.
    :param port_name: Name of the port.
    """
    other_config = bridge.db_get_val('Port', port_name, 'other_config')
    return other_config.get('physical_network')


def get_tag_from_other_config(bridge, port_name):
    """Return tag stored in OVSDB other_config metadata.

    :param bridge: OVSBridge instance where port is.
    :param port_name: Name of the port.
    :raises OVSFWTagNotFound: In case tag cannot be found in OVSDB.
    """
    other_config = None
    try:
        other_config = bridge.db_get_val(
            'Port', port_name, 'other_config')
        return int(other_config['tag'])
    except (KeyError, TypeError, ValueError):
        raise exceptions.OVSFWTagNotFound(
            port_name=port_name, other_config=other_config)


class SecurityGroup:
    def __init__(self, id_):
        self.id = id_
        self.raw_rules = []
        self.remote_rules = []
        self.members = {}
        self.ports = set()

    def update_rules(self, rules):
        """Separate raw and remote rules.
        If a rule has a protocol field, it is normalized to a number
        here in order to ease later processing.
        """
        self.raw_rules = []
        self.remote_rules = []
        for rule in copy.deepcopy(rules):
            protocol = rule.get('protocol')
            if protocol is not None:
                if protocol.isdigit():
                    rule['protocol'] = int(protocol)
                elif (rule.get('ethertype') == lib_const.IPv6 and
                      protocol == lib_const.PROTO_NAME_ICMP):
                    rule['protocol'] = lib_const.PROTO_NUM_IPV6_ICMP
                else:
                    rule['protocol'] = lib_const.IP_PROTOCOL_MAP.get(
                        protocol, protocol)
            if 'remote_group_id' in rule or 'remote_address_group_id' in rule:
                self.remote_rules.append(rule)
            else:
                self.raw_rules.append(rule)

    def get_ethertype_filtered_addresses(self, ethertype):
        return self.members.get(ethertype, [])


class OFPort:
    def __init__(self, port_dict, ovs_port, vlan_tag, segment_id=None,
                 network_type=None, physical_network=None):
        self.id = port_dict['device']
        self.vlan_tag = vlan_tag
        self.segment_id = segment_id
        self.mac = ovs_port.vif_mac
        self.lla_address = str(netutils.get_ipv6_addr_by_EUI64(
            lib_const.IPv6_LLA_PREFIX, self.mac))
        self.ofport = ovs_port.ofport
        self.sec_groups = []
        self.fixed_ips = port_dict.get('fixed_ips', [])
        self.neutron_port_dict = port_dict.copy()
        self.allowed_pairs_v4 = self._get_allowed_pairs(port_dict, version=4)
        self.allowed_pairs_v6 = self._get_allowed_pairs(port_dict, version=6)
        self.network_type = network_type
        self.physical_network = physical_network

    @staticmethod
    def _get_allowed_pairs(port_dict, version):
        aap_dict = port_dict.get('allowed_address_pairs', set())
        return {(aap['mac_address'], aap['ip_address']) for aap in aap_dict
                if netaddr.IPNetwork(aap['ip_address']).version == version}

    @property
    def all_allowed_macs(self):
        macs = {item[0] for item in self.allowed_pairs_v4.union(
            self.allowed_pairs_v6)}
        macs.add(self.mac)
        return macs

    @property
    def ipv4_addresses(self):
        return [ip_addr for ip_addr in self.fixed_ips
                if netaddr.IPAddress(ip_addr).version == 4]

    @property
    def ipv6_addresses(self):
        return [ip_addr for ip_addr in self.fixed_ips
                if netaddr.IPAddress(ip_addr).version == 6]

    def update(self, port_dict):
        self.allowed_pairs_v4 = self._get_allowed_pairs(port_dict,
                                                        version=4)
        self.allowed_pairs_v6 = self._get_allowed_pairs(port_dict,
                                                        version=6)
        # Neighbour discovery uses LLA
        self.allowed_pairs_v6.add((self.mac, self.lla_address))
        self.fixed_ips = port_dict.get('fixed_ips', [])
        self.neutron_port_dict = port_dict.copy()


class SGPortMap:
    def __init__(self):
        self.ports = {}
        self.sec_groups = {}
        # Maps port_id to ofport number
        self.unfiltered = {}

    def get_sg(self, sg_id):
        return self.sec_groups.get(sg_id, None)

    def get_or_create_sg(self, sg_id):
        try:
            sec_group = self.sec_groups[sg_id]
        except KeyError:
            sec_group = SecurityGroup(sg_id)
            self.sec_groups[sg_id] = sec_group
        return sec_group

    def delete_sg(self, sg_id):
        del self.sec_groups[sg_id]

    def create_port(self, port, port_dict):
        self.ports[port.id] = port
        self.update_port(port, port_dict)

    def update_port(self, port, port_dict):
        for sec_group in self.sec_groups.values():
            sec_group.ports.discard(port)

        port.sec_groups = [self.get_or_create_sg(sg_id)
                           for sg_id in port_dict['security_groups']]
        for sec_group in port.sec_groups:
            sec_group.ports.add(port)
        port.update(port_dict)

    def remove_port(self, port):
        for sec_group in port.sec_groups:
            sec_group.ports.discard(port)
        del self.ports[port.id]

    def update_rules(self, sg_id, rules):
        sec_group = self.get_or_create_sg(sg_id)
        sec_group.update_rules(rules)

    def update_members(self, sg_id, members):
        sec_group = self.get_or_create_sg(sg_id)
        sec_group.members = members


class ConjIdMap:
    """Handle conjunction ID allocations and deallocations."""

    CONJ_ID_BLOCK_SIZE = 8
    MAX_CONJ_ID = 2 ** 32 - 8

    def __new__(cls, int_br):
        if not hasattr(cls, '_instance'):
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, int_br):
        self.id_map = collections.defaultdict(self._conj_id_factory)
        # Stores the set of conjunction IDs used for each unique tuple
        # (sg_id, remote_id, direction, ethertype). Each tuple
        # can have up to 8 conjunction IDs (see ConjIPFlowManager.add()).
        self.id_map_group = collections.defaultdict(set)
        self.id_free = collections.deque()
        self._max_id = self._init_max_id(int_br)

    def _init_max_id(self, int_br):
        """Read the maximum conjunction ID number in the integration bridge

        This method will dump all integration bridge flows, parse them and
        return the maximum conjunction ID number. By default, "int_br" is a
        ``OVSAgentBridge`` instance, using "os-ken" library to access to the OF
        rules.
        If not, "int_br" will default to a ``OVSBridge`` instance. The CLI
        command "ovs-ofctl" will be used instead.

        :param int_br: ``OVSAgentBridge`` or ``OVSBridge`` instance.
        :returns: The maximum conjunction ID number in the integration bridge
        """
        conj_id_max = 0
        try:
            for flow in itertools.chain(
                    *[int_br.dump_flows(table)
                      for table in ovs_consts.OVS_FIREWALL_TABLES]):
                conj_id_max = max(conj_id_max, flow.match.get('conj_id', 0))
        except AttributeError:  # br_int is a ``OVSBridge`` instance.
            flows_iter = itertools.chain(
                *[int_br.dump_flows_for_table(table)
                  for table in ovs_consts.OVS_FIREWALL_TABLES])
            conj_ids = CONJ_ID_REGEX.findall(" | ".join(flows_iter))
            try:
                conj_id_max = max(int(conj_id) for conj_id in conj_ids)
            except ValueError:
                conj_id_max = 0

        max_id = conj_id_max - conj_id_max % self.CONJ_ID_BLOCK_SIZE
        return self._next_max_id(max_id)

    def _next_max_id(self, max_id):
        max_id += self.CONJ_ID_BLOCK_SIZE
        if max_id >= self.MAX_CONJ_ID:
            max_id = 0
        return max_id

    def _conj_id_factory(self):
        # If there is any freed ID, use one.
        if self.id_free:
            return self.id_free.popleft()
        # Allocate new one. It must be divisible by 8. (See the next function.)
        self._max_id = self._next_max_id(self._max_id)
        return self._max_id

    def get_conj_id(self, sg_id, remote_id, direction, ethertype):
        """Return a conjunction ID specified by the arguments.
        Allocate one if necessary.  The returned ID is divisible by 8
        (CONJ_ID_BLOCK_SIZE), as there are 4 priority levels
        (see rules.flow_priority_offset) and 2 conjunction IDs are needed per
        priority.
        """
        if direction not in [lib_const.EGRESS_DIRECTION,
                             lib_const.INGRESS_DIRECTION]:
            raise ValueError(_("Invalid direction '%s'") % direction)
        if ethertype not in [lib_const.IPv4, lib_const.IPv6]:
            raise ValueError(_("Invalid ethertype '%s'") % ethertype)

        return self.id_map[(sg_id, remote_id, direction, ethertype)]

    def delete_sg(self, sg_id):
        """Free all conj_ids associated with the sg_id and
        return a list of (remote_sg_id, conj_id), which are no longer
        in use.
        """
        result = set()
        for k in list(self.id_map.keys()):
            if sg_id in k[0:2]:
                conj_id = self.id_map.pop(k)
                result.add((k[1], conj_id))
                self.id_free.append(conj_id)

        # If the remote_sg_id is removed, the tuple (sg_id, remote_sg_id,
        # direction, ethertype) no longer exists; the conjunction IDs assigned
        # to this tuple should be removed too.
        for k in list(self.id_map_group.keys()):
            if sg_id in k[0:2]:
                conj_id_groups = self.id_map_group.pop(k, [])
                for conj_id in conj_id_groups:
                    result.add((k[1], conj_id))

        return result


class ConjIPFlowManager:
    """Manage conj_id allocation and remote securitygroups derived
    conjunction flows.

    Flows managed by this class is of form:

        nw_src=10.2.3.4,reg_net=0xf00 actions=conjunction(123,1/2)

    These flows are managed per network and are usually per remote_group_id,
    but flows from different remote_group need to be merged on shared networks,
    where the complexity arises and this manager is needed.

    """

    def __init__(self, driver):
        self.conj_id_map = ConjIdMap(driver.int_br.br)
        self.driver = driver
        # The following two are dict of dicts and are indexed like:
        #     self.x[vlan_tag][(direction, ethertype)]
        self.conj_ids = collections.defaultdict(dict)
        self.flow_state = collections.defaultdict(
            lambda: collections.defaultdict(dict))

    def _build_addr_conj_id_map(self, ethertype, sg_ag_conj_id_map):
        """Build a map of addr -> list of conj_ids."""
        addr_to_conj = collections.defaultdict(list)
        for remote_id, conj_id_set in sg_ag_conj_id_map.items():
            remote_group = self.driver.sg_port_map.get_sg(remote_id)
            if not remote_group or not remote_group.members:
                LOG.debug('No member for security group or'
                          'address group %s', remote_id)
                continue
            for addr in remote_group.get_ethertype_filtered_addresses(
                    ethertype):
                addr_to_conj[addr].extend(conj_id_set)
        return addr_to_conj

    def _update_flows_for_vlan_subr(self, direction, ethertype, vlan_tag,
                                    flow_state, addr_to_conj,
                                    conj_id_to_remove, ofport):
        """Do the actual flow updates for given direction and ethertype."""
        conj_id_to_remove = conj_id_to_remove or []
        # Delete any current flow related to any deleted IP address, before
        # creating the flows for the current IPs.
        self.driver.delete_flows_for_flow_state(
            flow_state, addr_to_conj, direction, ethertype, vlan_tag)
        for conj_id_set in conj_id_to_remove:
            # Remove any remaining flow with remote SG/AG ID conj_id_to_remove
            for (current_ip, current_mac), conj_ids in flow_state.items():
                conj_ids_to_remove = conj_id_set & set(conj_ids)
                self.driver.delete_flow_for_ip_and_mac(
                    current_ip, current_mac, direction, ethertype,
                    vlan_tag, conj_ids_to_remove)

        # NOTE(hangyang): Handle add/delete overlapped IPs among
        # remote security groups and remote address groups
        removed_ips = {
            str(netaddr.IPNetwork(addr).cidr)
            for addr, _ in set(flow_state) - set(addr_to_conj)
        }
        ip_to_conj = collections.defaultdict(set)
        for (addr, mac), conj_ids in addr_to_conj.items():
            # Addresses from remote security groups have mac addresses,
            # others from remote address groups have not.
            ip_to_conj[str(netaddr.IPNetwork(addr).cidr)].update(conj_ids)

        for addr, mac in addr_to_conj:
            ip_cidr = str(netaddr.IPNetwork(addr).cidr)
            # When the overlapped IP in remote security group and remote
            # address group have different conjunction ids but with the
            # same priority offset, we need to combine the conj_ids together
            # before create flows otherwise flows will be overridden in the
            # creation sequence.
            conj_ids = list(ip_to_conj[ip_cidr])
            conj_ids.sort()
            if (flow_state.get((addr, mac)) == conj_ids and
                    ip_cidr not in removed_ips):
                # When there are IP overlaps among remote security groups
                # and remote address groups, removal of the overlapped ips
                # from one remote group will also delete the flows for the
                # other groups because the non-strict delete method cannot
                # match flow priority or actions for different conjunction
                # ids, therefore we need to recreate the affected flows.
                continue
            for flow in rules.create_flows_for_ip_address_and_mac(
                    addr, mac, direction, ethertype, vlan_tag, conj_ids):
                self.driver._add_flow(flow_group_id=ofport, **flow)

    def update_flows_for_vlan(self, vlan_tag, ofport, conj_id_to_remove=None):
        """Install action=conjunction(conj_id, 1/2) flows,
        which depend on IP addresses of remote_group_id or
        remote_address_group_id.
        """
        for (direction, ethertype), sg_ag_conj_id_map in (
                self.conj_ids[vlan_tag].items()):
            # TODO(toshii): optimize when remote_groups have
            # no address overlaps.
            addr_to_conj = self._build_addr_conj_id_map(
                ethertype, sg_ag_conj_id_map)
            self._update_flows_for_vlan_subr(
                direction, ethertype, vlan_tag,
                self.flow_state[vlan_tag][(direction, ethertype)],
                addr_to_conj, conj_id_to_remove, ofport)
            self.flow_state[vlan_tag][(direction, ethertype)] = addr_to_conj

    def add(self, vlan_tag, sg_id, remote_id, direction, ethertype,
            priority_offset):
        """Get conj_id specified by the arguments
        and notify the manager that
        (remote_id, direction, ethertype, conj_id) flows need
        to be populated on the vlan_tag network.

        A caller must call update_flows_for_vlan to have the change in effect.

        """
        conj_id = self.conj_id_map.get_conj_id(
            sg_id, remote_id, direction, ethertype) + priority_offset * 2

        if (direction, ethertype) not in self.conj_ids[vlan_tag]:
            self.conj_ids[vlan_tag][(direction, ethertype)] = (
                collections.defaultdict(set))
        self.conj_ids[vlan_tag][(direction, ethertype)][remote_id].add(
            conj_id)

        conj_id_tuple = (sg_id, remote_id, direction, ethertype)
        self.conj_id_map.id_map_group[conj_id_tuple].add(conj_id)
        return conj_id

    def sg_removed(self, sg_id):
        """Handle SG removal events.

        Free all conj_ids associated with the sg_id removed and clean up
        obsolete entries from the self.conj_ids map.  Unlike the add
        method, it also updates flows.
        If a SG is removed, both sg_id and remote_sg_id should be removed from
        the "vlan_conj_id_map".
        """
        id_set = self.conj_id_map.delete_sg(sg_id)
        unused_dict = collections.defaultdict(set)
        for remote_sg_id, conj_id in id_set:
            unused_dict[remote_sg_id].add(conj_id)

        for vlan_tag, vlan_conj_id_map in self.conj_ids.items():
            update = False
            conj_id_to_remove = []
            for sg_conj_id_map in vlan_conj_id_map.values():
                for remote_sg_id, unused in unused_dict.items():
                    if (remote_sg_id in sg_conj_id_map and
                            sg_conj_id_map[remote_sg_id] & unused):
                        if remote_sg_id == sg_id:
                            conj_id_to_remove.append(
                                sg_conj_id_map[remote_sg_id] & unused)
                        sg_conj_id_map[remote_sg_id] -= unused
                        if not sg_conj_id_map[remote_sg_id]:
                            del sg_conj_id_map[remote_sg_id]
                        update = True

            if update:
                self.update_flows_for_vlan(vlan_tag, None,
                                           conj_id_to_remove=conj_id_to_remove)


class OVSFirewallDriver(firewall.FirewallDriver):
    REQUIRED_PROTOCOLS = [
        ovs_consts.OPENFLOW10,
        ovs_consts.OPENFLOW11,
        ovs_consts.OPENFLOW12,
        ovs_consts.OPENFLOW13,
        ovs_consts.OPENFLOW14,
    ]

    provides_arp_spoofing_protection = True

    def __init__(self, integration_bridge):
        """Initialize object

        :param integration_bridge: Bridge on which openflow rules will be
                                   applied

        """
        self.permitted_ethertypes = n_utils.parse_permitted_ethertypes(
            cfg.CONF.SECURITYGROUP.permitted_ethertypes)
        self.int_br = self.initialize_bridge(integration_bridge)
        self._initialize_sg()
        self._update_cookie = None
        self._deferred = False
        self.iptables_helper = iptables.Helper(self.int_br.br)
        self.iptables_helper.load_driver_if_needed()
        self.ipconntrack = ip_conntrack.OvsIpConntrackManager()
        self._initialize_firewall()

        callbacks_registry.subscribe(
            self._init_firewall_callback,
            callbacks_resources.AGENT,
            callbacks_events.OVS_RESTARTED)

    def _init_firewall_callback(self, resource, event, trigger, payload=None):
        LOG.info("Reinitialize Openvswitch firewall after OVS restart.")
        self._initialize_sg()
        self._initialize_firewall()

    def _initialize_sg(self):
        self.sg_port_map = SGPortMap()
        self.conj_ip_manager = ConjIPFlowManager(self)
        self.sg_to_delete = set()

    def _initialize_firewall(self):
        self._drop_all_unmatched_flows()
        self._initialize_common_flows()
        self._initialize_third_party_tables()

    @contextlib.contextmanager
    def update_cookie_context(self):
        try:
            self._update_cookie = self.int_br.br.request_cookie()
            yield
        finally:
            self.int_br.br.unset_cookie(self._update_cookie)
            self._update_cookie = None

    def security_group_updated(self, action_type, sec_group_ids,
                               device_ids=None):
        """The current driver doesn't make use of this method.

        It exists here to avoid NotImplementedError raised from the parent
        class's method.
        """

    def _accept_flow(self, **flow):
        for f in rules.create_accept_flows(flow):
            self._add_flow(**f)

    def _add_flow(self, flow_group_id=None, **kwargs):
        """Add a new flow.

        Most of the port related flows will have the parameters "reg_port" or
        "in_port". If no "flow_group_id" is defined, "in_port" or "reg_port"
        will be used instead (those parameters store the port "ofport"). The
        flow group ID will be used to commit all flows related to a port in
        the same transaction (for deferred OVS bridge implementation only).
        """
        flow_group_id = (flow_group_id or
                         kwargs.get('in_port') or
                         kwargs.get('reg_port'))
        dl_type = kwargs.get('dl_type')
        create_reg_numbers(kwargs)
        if isinstance(dl_type, int):
            kwargs['dl_type'] = f"0x{dl_type:04x}"
        if self._update_cookie:
            kwargs['cookie'] = self._update_cookie
        if self._deferred:
            self.int_br.add_flow(flow_group_id=flow_group_id, **kwargs)
        else:
            self.int_br.br.add_flow(**kwargs)

    def _delete_flows(self, **kwargs):
        create_reg_numbers(kwargs)
        deferred = kwargs.pop('deferred', self._deferred)
        if deferred:
            self.int_br.delete_flows(**kwargs)
        else:
            self.int_br.br.delete_flows(**kwargs)

    @staticmethod
    def initialize_bridge(int_br):
        int_br.add_protocols(*OVSFirewallDriver.REQUIRED_PROTOCOLS)
        return int_br.deferred(full_ordered=True, use_bundle=True)

    def _drop_all_unmatched_flows(self):
        for table in ovs_consts.OVS_FIREWALL_TABLES:
            self.int_br.br.add_flow(table=table, priority=0, actions='drop')

    def _initialize_common_flows(self):
        # Remove conntrack information from tracked packets
        self._add_flow(
            table=ovs_consts.BASE_EGRESS_TABLE,
            priority=110,
            ct_state=ovsfw_consts.OF_STATE_TRACKED,
            actions='ct_clear,'
                    'resubmit(,%d)' % ovs_consts.BASE_EGRESS_TABLE,
        )

        if cfg.CONF.AGENT.explicitly_egress_direct:
            self._add_flow(
                table=ovs_consts.TRANSIENT_TABLE,
                priority=2,
                actions='resubmit(,%d)' % (
                    ovs_consts.ACCEPTED_EGRESS_TRAFFIC_NORMAL_TABLE)
            )

    def _initialize_third_party_tables(self):
        self.int_br.br.add_flow(
            table=ovs_consts.ACCEPTED_EGRESS_TRAFFIC_NORMAL_TABLE,
            priority=1,
            actions='normal')
        self.int_br.br.add_flow(
            table=ovs_consts.ACCEPTED_EGRESS_TRAFFIC_TABLE,
            priority=1,
            actions='resubmit(,%d)' % (
                ovs_consts.ACCEPTED_EGRESS_TRAFFIC_NORMAL_TABLE)
        )
        for table in (ovs_consts.ACCEPTED_INGRESS_TRAFFIC_TABLE,
                      ovs_consts.DROPPED_TRAFFIC_TABLE):
            self.int_br.br.add_flow(
                table=table, priority=0, actions='drop')

    def get_ovs_port(self, port_id):
        ovs_port = self.int_br.br.get_vif_port_by_id(port_id)
        if not ovs_port or ovs_port.ofport in (ovs_lib.UNASSIGNED_OFPORT,
                                               ovs_lib.INVALID_OFPORT):
            raise exceptions.OVSFWPortNotFound(port_id=port_id)
        return ovs_port

    def get_ovs_ports(self, port_ids):
        return self.int_br.br.get_vifs_by_ids(port_ids)

    def _get_port_vlan_tag(self, port_name):
        return get_tag_from_other_config(self.int_br.br, port_name)

    def _get_port_segmentation_id(self, port_name):
        return get_segmentation_id_from_other_config(
            self.int_br.br, port_name)

    def _get_port_network_type(self, port_name):
        return get_network_type_from_other_config(
            self.int_br.br, port_name)

    def _get_port_physical_network(self, port_name):
        return get_physical_network_from_other_config(
            self.int_br.br, port_name)

    def _delete_invalid_conntrack_entries_for_port(self, port, of_port):
        port['of_port'] = of_port
        for ethertype in [lib_const.IPv4, lib_const.IPv6]:
            self.ipconntrack.delete_conntrack_state_by_remote_ips(
                [port], ethertype, set(), mark=ovsfw_consts.CT_MARK_INVALID)

    def get_ofport(self, port):
        port_id = port['device']
        return self.sg_port_map.ports.get(port_id)

    def _create_of_port(self, port, ovs_port):
        # Should always try to get the local vlan tag from
        # the OVSDB Port other_config, since the ovs-agent's
        # LocalVlanManager always allocated/updated it and then
        # set_db_attribute to Port other_config before this.
        port_vlan_id = self._get_port_vlan_tag(ovs_port.port_name)
        segment_id = self._get_port_segmentation_id(
            ovs_port.port_name)
        network_type = self._get_port_network_type(
            ovs_port.port_name)
        physical_network = self._get_port_physical_network(
            ovs_port.port_name)
        return OFPort(port, ovs_port, port_vlan_id,
                      segment_id,
                      network_type, physical_network)

    def get_or_create_ofport(self, port):
        """Get ofport specified by port['device'], checking and reflecting
        ofport changes.
        If ofport is nonexistent, create and return one.
        """
        port_id = port['device']
        ovs_port = self.get_ovs_port(port_id)
        try:
            of_port = self.sg_port_map.ports[port_id]
        except KeyError:
            of_port = self._create_of_port(port, ovs_port)
            self.sg_port_map.create_port(of_port, port)
        else:
            if of_port.ofport != ovs_port.ofport:
                self.sg_port_map.remove_port(of_port)
                of_port = self._create_of_port(port, ovs_port)
                self.sg_port_map.create_port(of_port, port)
            else:
                self.sg_port_map.update_port(of_port, port)

        return of_port

    def is_port_managed(self, port):
        return port['device'] in self.sg_port_map.ports

    def prepare_port_filter(self, port):
        self.iptables_helper.cleanup_port(port)
        if not firewall.port_sec_enabled(port):
            self._initialize_egress_no_port_security(port['device'])
            return

        try:
            old_of_port = self.get_ofport(port)
            of_port = self.get_or_create_ofport(port)
            if old_of_port:
                LOG.info("Initializing port %s that was already initialized.",
                         port['device'])
                self._update_flows_for_port(of_port, old_of_port)
            else:
                self._set_port_filters(of_port)
            self._delete_invalid_conntrack_entries_for_port(port, of_port)
        except exceptions.OVSFWPortNotFound as not_found_error:
            LOG.info("port %(port_id)s does not exist in ovsdb: %(err)s.",
                     {'port_id': port['device'],
                      'err': not_found_error})
        except exceptions.OVSFWTagNotFound as tag_not_found:
            LOG.info("Tag was not found for port %(port_id)s: %(err)s.",
                     {'port_id': port['device'],
                      'err': tag_not_found})

    def update_port_filter(self, port):
        """Update rules for given port

        Current existing filtering rules are removed and new ones are generated
        based on current loaded security group rules and members.

        """
        if not firewall.port_sec_enabled(port):
            self.remove_port_filter(port)
            self._initialize_egress_no_port_security(port['device'])
            return
        if not self.is_port_managed(port):
            try:
                self._remove_egress_no_port_security(port['device'])
            except exceptions.OVSFWPortNotHandled as e:
                LOG.debug(e)
            else:
                self.prepare_port_filter(port)
                return
        try:
            # Make sure delete old allowed_address_pair MACs because
            # allowed_address_pair MACs will be updated in
            # self.get_or_create_ofport(port)
            old_of_port = self.get_ofport(port)
            of_port = self.get_or_create_ofport(port)
            if old_of_port:
                self._update_flows_for_port(of_port, old_of_port)
            else:
                self._set_port_filters(of_port)

            self._delete_invalid_conntrack_entries_for_port(port, of_port)

        except exceptions.OVSFWPortNotFound as not_found_error:
            LOG.info("port %(port_id)s does not exist in ovsdb: %(err)s.",
                     {'port_id': port['device'],
                      'err': not_found_error})
            # If port doesn't exist in ovsdb, lets ensure that there are no
            # leftovers
            self.remove_port_filter(port)
        except exceptions.OVSFWTagNotFound as tag_not_found:
            LOG.info("Tag was not found for port %(port_id)s: %(err)s.",
                     {'port_id': port['device'],
                      'err': tag_not_found})

    def _set_port_filters(self, of_port):
        self.initialize_port_flows(of_port)
        self.add_flows_from_rules(of_port)

    def _update_flows_for_port(self, of_port, old_of_port):
        with self.update_cookie_context():
            self._set_port_filters(of_port)
        self.delete_all_port_flows(old_of_port)
        # Rewrite update cookie with default cookie
        self._set_port_filters(of_port)

    def remove_port_filter(self, port):
        """Remove port from firewall

        All flows related to this port are removed from ovs. Port is also
        removed from ports managed by this firewall.

        """
        if self.is_port_managed(port):
            of_port = self.get_ofport(port)
            self.delete_all_port_flows(of_port)
            self.sg_port_map.remove_port(of_port)
            for sec_group in of_port.sec_groups:
                self._schedule_sg_deletion_maybe(sec_group.id)

    def update_security_group_rules(self, sg_id, rules):
        self.sg_port_map.update_rules(sg_id, rules)

    def update_security_group_members(self, sg_id, member_ips):
        self.sg_port_map.update_members(sg_id, member_ips)
        if not member_ips:
            self._schedule_sg_deletion_maybe(sg_id)

    def _schedule_sg_deletion_maybe(self, sg_id):
        """Schedule possible deletion of the given SG.

        This function must be called when the number of ports
        associated to sg_id drops to zero, as it isn't possible
        to know SG deletions from agents due to RPC API design.
        """
        sec_group = self.sg_port_map.get_or_create_sg(sg_id)
        if not sec_group.members or not sec_group.ports:
            self.sg_to_delete.add(sg_id)

    def _cleanup_stale_sg(self):
        sg_to_delete = self.sg_to_delete
        self.sg_to_delete = set()

        for sg_id in sg_to_delete:
            sec_group = self.sg_port_map.get_sg(sg_id)
            if sec_group.members or sec_group.ports:
                # sec_group is still in use
                continue

            self.conj_ip_manager.sg_removed(sg_id)
            self.sg_port_map.delete_sg(sg_id)

    def process_trusted_ports(self, port_ids):
        """Pass packets from these ports directly to ingress pipeline."""
        ovs_ports = self.get_ovs_ports(port_ids)
        for port_id in port_ids:
            self._initialize_egress_no_port_security(port_id,
                                                     ovs_ports=ovs_ports)
            # yield to let other threads proceed
            time.sleep(0)

    def remove_trusted_ports(self, port_ids):
        for port_id in port_ids:
            try:
                self._remove_egress_no_port_security(port_id)
            except exceptions.OVSFWPortNotHandled as e:
                LOG.debug(e)

    def filter_defer_apply_on(self):
        self._deferred = True

    def filter_defer_apply_off(self):
        if self._deferred:
            self._cleanup_stale_sg()
            self.int_br.apply_flows()
            self._deferred = False

    @property
    def ports(self):
        return {id_: port.neutron_port_dict
                for id_, port in self.sg_port_map.ports.items()}

    def install_physical_direct_flow(self, mac, segment_id,
                                     ofport, local_vlan, network_type):
        actions = ('set_field:{:d}->reg{:d},'
                   'set_field:{:d}->reg{:d},').format(
                       ofport,
                       agent_consts.REG_PORT,
                       # This always needs the local vlan.
                       local_vlan,
                       agent_consts.REG_NET)
        if network_type == lib_const.TYPE_VLAN:
            actions += 'strip_vlan,resubmit(,{:d})'.format(
                ovs_consts.BASE_INGRESS_TABLE)
            self._add_flow(
                flow_group_id=ofport,
                table=ovs_consts.TRANSIENT_TABLE,
                priority=90,
                dl_dst=mac,
                dl_vlan='0x%x' % segment_id,
                actions=actions)
        elif network_type == lib_const.TYPE_FLAT:
            # If the port belong to flat network, we need match vlan_tci and
            # needn't pop vlan
            actions += 'resubmit(,{:d})'.format(
                ovs_consts.BASE_INGRESS_TABLE)
            self._add_flow(
                flow_group_id=ofport,
                table=ovs_consts.TRANSIENT_TABLE,
                priority=90,
                dl_dst=mac,
                vlan_tci=ovs_consts.FLAT_VLAN_TCI,
                actions=actions)

    def delete_physical_direct_flow(self, mac, segment_id):
        if segment_id:
            self._delete_flows(table=ovs_consts.TRANSIENT_TABLE,
                               dl_dst=mac,
                               dl_vlan=segment_id)
        else:
            self._delete_flows(table=ovs_consts.TRANSIENT_TABLE,
                               dl_dst=mac,
                               vlan_tci=ovs_consts.FLAT_VLAN_TCI)

    def initialize_port_flows(self, port):
        """Set base flows for port

        :param port: OFPort instance

        """
        # Identify egress flow
        self._add_flow(
            table=ovs_consts.TRANSIENT_TABLE,
            priority=100,
            in_port=port.ofport,
            actions='set_field:{:d}->reg{:d},'
                    'set_field:{:d}->reg{:d},'
                    'resubmit(,{:d})'.format(
                        port.ofport,
                        agent_consts.REG_PORT,
                        port.vlan_tag,
                        agent_consts.REG_NET,
                        ovs_consts.BASE_EGRESS_TABLE)
        )

        # Identify ingress flows
        for mac_addr in port.all_allowed_macs:
            self.install_physical_direct_flow(
                mac_addr, port.segment_id, port.ofport,
                port.vlan_tag, port.network_type)

            self._add_flow(
                flow_group_id=port.ofport,
                table=ovs_consts.TRANSIENT_TABLE,
                priority=90,
                dl_dst=mac_addr,
                dl_vlan='0x%x' % port.vlan_tag,
                actions='set_field:{:d}->reg{:d},'
                        'set_field:{:d}->reg{:d},'
                        'strip_vlan,resubmit(,{:d})'.format(
                            port.ofport,
                            agent_consts.REG_PORT,
                            port.vlan_tag,
                            agent_consts.REG_NET,
                            ovs_consts.BASE_INGRESS_TABLE),
            )

        self._initialize_egress(port)
        self._initialize_ingress(port)

    def _initialize_egress_ipv6_icmp(self, port, allowed_pairs):
        allowed_pairs = allowed_pairs.union({(port.mac, port.lla_address)})
        for mac_addr, ip_addr in allowed_pairs:
            for icmp_type in firewall.ICMPV6_ALLOWED_EGRESS_TYPES:
                self._add_flow(
                    table=ovs_consts.BASE_EGRESS_TABLE,
                    priority=95,
                    in_port=port.ofport,
                    reg_port=port.ofport,
                    dl_type=lib_const.ETHERTYPE_IPV6,
                    nw_proto=lib_const.PROTO_NUM_IPV6_ICMP,
                    icmp_type=icmp_type,
                    dl_src=mac_addr,
                    ipv6_src=ip_addr,
                    actions='resubmit(,%d)' % (
                        ovs_consts.ACCEPTED_EGRESS_TRAFFIC_NORMAL_TABLE)
                )
            for icmp_type in firewall.ICMPV6_RESTRICTED_EGRESS_TYPES:
                self._add_flow(
                    table=ovs_consts.BASE_EGRESS_TABLE,
                    priority=95,
                    in_port=port.ofport,
                    reg_port=port.ofport,
                    dl_type=lib_const.ETHERTYPE_IPV6,
                    nw_proto=lib_const.PROTO_NUM_IPV6_ICMP,
                    icmp_type=icmp_type,
                    nd_target=ip_addr,
                    actions='resubmit(,%d)' % (
                        ovs_consts.ACCEPTED_EGRESS_TRAFFIC_NORMAL_TABLE)
                )

    def _initialize_egress_no_port_security(self, port_id, ovs_ports=None):
        try:
            if ovs_ports is not None:
                ovs_port = ovs_ports.get(port_id)
                if not ovs_port:
                    raise exceptions.OVSFWPortNotFound(port_id=port_id)
            else:
                ovs_port = self.get_ovs_port(port_id)
            vlan_tag = self._get_port_vlan_tag(ovs_port.port_name)
        except exceptions.OVSFWTagNotFound:
            # It's a patch port, don't set anything
            return
        except exceptions.OVSFWPortNotFound as not_found_e:
            LOG.error("Initializing unfiltered port %(port_id)s that does not "
                      "exist in ovsdb: %(err)s.",
                      {'port_id': port_id,
                       'err': not_found_e})
            return
        self.sg_port_map.unfiltered[port_id] = (ovs_port, vlan_tag)
        self._add_flow(
            table=ovs_consts.TRANSIENT_TABLE,
            priority=100,
            in_port=ovs_port.ofport,
            actions='set_field:%d->reg%d,'
                    'set_field:%d->reg%d,'
                    'resubmit(,%d)' % (
                        ovs_port.ofport,
                        agent_consts.REG_PORT,
                        vlan_tag,
                        agent_consts.REG_NET,
                        ovs_consts.ACCEPT_OR_INGRESS_TABLE)
        )
        self._add_flow(
            table=ovs_consts.ACCEPT_OR_INGRESS_TABLE,
            priority=80,
            reg_port=ovs_port.ofport,
            actions='resubmit(,%d)' % (
                ovs_consts.ACCEPTED_EGRESS_TRAFFIC_NORMAL_TABLE)
        )

        tunnel_direct_info = {
            "network_type": self._get_port_network_type(ovs_port.port_name),
            "physical_network": self._get_port_physical_network(
                ovs_port.port_name)
        }
        self.install_accepted_egress_direct_flow(
            ovs_port.vif_mac, vlan_tag, ovs_port.ofport,
            tunnel_direct_info=tunnel_direct_info)

    def _remove_egress_no_port_security(self, port_id):
        try:
            ovs_port, vlan_tag = self.sg_port_map.unfiltered[port_id]
        except KeyError:
            raise exceptions.OVSFWPortNotHandled(port_id=port_id)

        self._delete_flows(
            table=ovs_consts.TRANSIENT_TABLE,
            in_port=ovs_port.ofport
        )
        self._delete_flows(
            table=ovs_consts.ACCEPT_OR_INGRESS_TABLE,
            reg_port=ovs_port.ofport
        )

        self.delete_accepted_egress_direct_flow(
            ovs_port.vif_mac, vlan_tag)

        del self.sg_port_map.unfiltered[port_id]

    def _initialize_egress(self, port):
        """Identify egress traffic and send it to egress base"""

        # Apply mac/ip pairs for IPv4
        allowed_mac_ipv4_pairs = port.allowed_pairs_v4.union(
            {(port.mac, ip_addr) for ip_addr in port.ipv4_addresses})
        for mac_addr, ip_addr in allowed_mac_ipv4_pairs:
            self._add_flow(
                table=ovs_consts.BASE_EGRESS_TABLE,
                priority=95,
                in_port=port.ofport,
                reg_port=port.ofport,
                dl_src=mac_addr,
                dl_type=lib_const.ETHERTYPE_ARP,
                arp_spa=ip_addr,
                actions='resubmit(,%d)' % (
                    ovs_consts.ACCEPTED_EGRESS_TRAFFIC_NORMAL_TABLE)
            )
            self._add_flow(
                table=ovs_consts.BASE_EGRESS_TABLE,
                priority=95,
                reg_port=port.ofport,
                dl_type=lib_const.ETHERTYPE_RARP,
                in_port=port.ofport,
                dl_src=mac_addr,
                actions='resubmit(,%d)' % (
                    ovs_consts.ACCEPTED_EGRESS_TRAFFIC_NORMAL_TABLE)
            )
            self._add_flow(
                table=ovs_consts.BASE_EGRESS_TABLE,
                priority=65,
                reg_port=port.ofport,
                dl_type=lib_const.ETHERTYPE_IP,
                in_port=port.ofport,
                dl_src=mac_addr,
                nw_src=ip_addr,
                actions='ct(table={:d},zone=NXM_NX_REG{:d}[0..15])'.format(
                    ovs_consts.RULES_EGRESS_TABLE,
                    agent_consts.REG_NET)
            )

        # Apply mac/ip pairs for IPv6
        allowed_mac_ipv6_pairs = port.allowed_pairs_v6.union(
            {(port.mac, ip_addr) for ip_addr in port.ipv6_addresses})
        self._initialize_egress_ipv6_icmp(port, allowed_mac_ipv6_pairs)
        for mac_addr, ip_addr in allowed_mac_ipv6_pairs:
            self._add_flow(
                table=ovs_consts.BASE_EGRESS_TABLE,
                priority=65,
                reg_port=port.ofport,
                in_port=port.ofport,
                dl_type=lib_const.ETHERTYPE_IPV6,
                dl_src=mac_addr,
                ipv6_src=ip_addr,
                actions='ct(table={:d},zone=NXM_NX_REG{:d}[0..15])'.format(
                    ovs_consts.RULES_EGRESS_TABLE,
                    agent_consts.REG_NET)
            )

        # DHCP discovery
        additional_ipv4_filters = [
            {"dl_src": mac, "nw_src": ip}
            for mac, ip in (*allowed_mac_ipv4_pairs,
                            (port.mac, '0.0.0.0'),)]
        additional_ipv6_filters = [
            {"dl_src": mac, "ipv6_src": ip}
            for mac, ip in allowed_mac_ipv6_pairs]
        for dl_type, src_port, dst_port, filters_list in (
                (lib_const.ETHERTYPE_IP, 68, 67, additional_ipv4_filters),
                (lib_const.ETHERTYPE_IPV6, 546, 547, additional_ipv6_filters)):
            for additional_filters in filters_list:
                self._add_flow(
                    table=ovs_consts.BASE_EGRESS_TABLE,
                    priority=80,
                    reg_port=port.ofport,
                    in_port=port.ofport,
                    dl_type=dl_type,
                    **additional_filters,
                    nw_proto=lib_const.PROTO_NUM_UDP,
                    tp_src=src_port,
                    tp_dst=dst_port,
                    actions='resubmit(,{:d})'.format(
                        ovs_consts.ACCEPT_OR_INGRESS_TABLE)
                )
        # Ban dhcp service running on an instance
        for dl_type, src_port, dst_port in (
                (lib_const.ETHERTYPE_IP, 67, 68),
                (lib_const.ETHERTYPE_IPV6, 547, 546)):
            self._add_flow(
                table=ovs_consts.BASE_EGRESS_TABLE,
                priority=70,
                in_port=port.ofport,
                reg_port=port.ofport,
                dl_type=dl_type,
                nw_proto=lib_const.PROTO_NUM_UDP,
                tp_src=src_port,
                tp_dst=dst_port,
                actions='resubmit(,%d)' % ovs_consts.DROPPED_TRAFFIC_TABLE
            )

        # Drop Router Advertisements from instances
        self._add_flow(
            table=ovs_consts.BASE_EGRESS_TABLE,
            priority=70,
            in_port=port.ofport,
            reg_port=port.ofport,
            dl_type=lib_const.ETHERTYPE_IPV6,
            nw_proto=lib_const.PROTO_NUM_IPV6_ICMP,
            icmp_type=lib_const.ICMPV6_TYPE_RA,
            actions='resubmit(,%d)' % ovs_consts.DROPPED_TRAFFIC_TABLE
        )

        # Allow custom ethertypes
        for permitted_ethertype in self.permitted_ethertypes:
            action = ('resubmit(,%d)' %
                      ovs_consts.ACCEPTED_EGRESS_TRAFFIC_NORMAL_TABLE)
            self._add_flow(
                table=ovs_consts.BASE_EGRESS_TABLE,
                priority=95,
                dl_type=permitted_ethertype,
                reg_port=port.ofport,
                actions=action)

        # Drop all remaining egress connections
        self._add_flow(
            table=ovs_consts.BASE_EGRESS_TABLE,
            priority=10,
            in_port=port.ofport,
            reg_port=port.ofport,
            actions='ct_clear,'
                    'resubmit(,%d)' % ovs_consts.DROPPED_TRAFFIC_TABLE
        )

        # Fill in accept_or_ingress table by checking that traffic is ingress
        # and if not, accept it
        for mac_addr in port.all_allowed_macs:
            self._add_flow(
                flow_group_id=port.ofport,
                table=ovs_consts.ACCEPT_OR_INGRESS_TABLE,
                priority=100,
                dl_dst=mac_addr,
                reg_net=port.vlan_tag,
                actions='set_field:{:d}->reg{:d},resubmit(,{:d})'.format(
                    port.ofport,
                    agent_consts.REG_PORT,
                    ovs_consts.BASE_INGRESS_TABLE),
            )
        for ethertype in [lib_const.ETHERTYPE_IP, lib_const.ETHERTYPE_IPV6]:
            self._add_flow(
                table=ovs_consts.ACCEPT_OR_INGRESS_TABLE,
                priority=90,
                dl_type=ethertype,
                reg_port=port.ofport,
                ct_state=ovsfw_consts.OF_STATE_NEW_NOT_ESTABLISHED,
                actions='ct(commit,zone=NXM_NX_REG{:d}[0..15]),'
                        'resubmit(,{:d})'.format(
                            agent_consts.REG_NET,
                            ovs_consts.ACCEPTED_EGRESS_TRAFFIC_TABLE)
            )
        self._add_flow(
            table=ovs_consts.ACCEPT_OR_INGRESS_TABLE,
            priority=80,
            reg_port=port.ofport,
            actions='resubmit(,%d)' % (
                ovs_consts.ACCEPTED_EGRESS_TRAFFIC_NORMAL_TABLE)
        )

        tunnel_direct_info = {"network_type": port.network_type,
                              "physical_network": port.physical_network}
        self.install_accepted_egress_direct_flow(
            port.mac, port.vlan_tag, port.ofport,
            tunnel_direct_info=tunnel_direct_info)

    def install_accepted_egress_direct_flow(self, mac, vlan_tag, dst_port,
                                            tunnel_direct_info=None):
        if not cfg.CONF.AGENT.explicitly_egress_direct:
            return

        # Prevent flood for accepted egress traffic
        # For packets from internal ports or VM ports.
        self._add_flow(
            flow_group_id=dst_port,
            table=ovs_consts.ACCEPTED_EGRESS_TRAFFIC_NORMAL_TABLE,
            priority=12,
            dl_dst=mac,
            reg_net=vlan_tag,
            actions=f'output:{dst_port:d}'
        )
        # For packets from patch ports.
        self._add_flow(
            flow_group_id=dst_port,
            table=ovs_consts.ACCEPTED_EGRESS_TRAFFIC_NORMAL_TABLE,
            priority=12,
            dl_dst=mac,
            dl_vlan=vlan_tag,
            actions=f'strip_vlan,output:{dst_port:d}'
        )

        # The former flow may not match, that means the destination port is
        # not in this host. So, we direct the packet to mapped bridge(s).
        if tunnel_direct_info:
            patch_ofport = ovs_lib.INVALID_OFPORT
            if tunnel_direct_info["network_type"] in (
                    lib_const.TYPE_VXLAN, lib_const.TYPE_GRE,
                    lib_const.TYPE_GENEVE):
                # Some ports like router internal gateway will not install
                # the l2pop related flows, so we will transmit the ARP request
                # packet to tunnel bridge use NORMAL action as usual.
                port_name = cfg.CONF.OVS.int_peer_patch_port
                patch_ofport = self.int_br.br.get_port_ofport(port_name)
            elif tunnel_direct_info["network_type"] == lib_const.TYPE_VLAN:
                physical_network = tunnel_direct_info["physical_network"]
                if not physical_network:
                    return
                bridge_mappings = helpers.parse_mappings(
                    cfg.CONF.OVS.bridge_mappings)
                bridge = bridge_mappings.get(physical_network)
                port_name = p_utils.get_interface_name(
                    bridge, prefix=ovs_consts.PEER_INTEGRATION_PREFIX)
                patch_ofport = self.int_br.br.get_port_ofport(port_name)

            if patch_ofport is not ovs_lib.INVALID_OFPORT:
                self._add_flow(
                    flow_group_id=dst_port,
                    table=ovs_consts.ACCEPTED_EGRESS_TRAFFIC_NORMAL_TABLE,
                    priority=10,
                    dl_src=mac,
                    dl_dst="00:00:00:00:00:00/01:00:00:00:00:00",
                    reg_net=vlan_tag,
                    actions='mod_vlan_vid:{:d},output:{:d}'.format(
                        vlan_tag,
                        patch_ofport)
                )

    def delete_accepted_egress_direct_flow(self, mac, vlan_tag):
        self._delete_flows(
            table=ovs_consts.ACCEPTED_EGRESS_TRAFFIC_NORMAL_TABLE,
            dl_dst=mac,
            reg_net=vlan_tag)

        self._delete_flows(
            table=ovs_consts.ACCEPTED_EGRESS_TRAFFIC_NORMAL_TABLE,
            dl_src=mac,
            reg_net=vlan_tag)

        self._delete_flows(
            table=ovs_consts.ACCEPTED_EGRESS_TRAFFIC_NORMAL_TABLE,
            dl_dst=mac,
            dl_vlan=vlan_tag
        )

    def _initialize_tracked_egress(self, port):
        # Drop invalid packets
        self._add_flow(
            flow_group_id=port.ofport,
            table=ovs_consts.RULES_EGRESS_TABLE,
            priority=50,
            ct_state=ovsfw_consts.OF_STATE_INVALID,
            actions='resubmit(,%d)' % ovs_consts.DROPPED_TRAFFIC_TABLE
        )
        # Drop traffic for removed sg rules
        self._add_flow(
            table=ovs_consts.RULES_EGRESS_TABLE,
            priority=50,
            reg_port=port.ofport,
            ct_mark=ovsfw_consts.CT_MARK_INVALID,
            actions='resubmit(,%d)' % ovs_consts.DROPPED_TRAFFIC_TABLE
        )

        for state in (
                ovsfw_consts.OF_STATE_ESTABLISHED_REPLY,
                ovsfw_consts.OF_STATE_RELATED,
        ):
            self._add_flow(
                table=ovs_consts.RULES_EGRESS_TABLE,
                priority=50,
                ct_state=state,
                ct_mark=ovsfw_consts.CT_MARK_NORMAL,
                reg_port=port.ofport,
                ct_zone=port.vlan_tag,
                actions='resubmit(,%d)' % (
                    ovs_consts.ACCEPTED_EGRESS_TRAFFIC_NORMAL_TABLE)
            )
        self._add_flow(
            table=ovs_consts.RULES_EGRESS_TABLE,
            priority=40,
            reg_port=port.ofport,
            ct_state=ovsfw_consts.OF_STATE_NOT_ESTABLISHED,
            actions='resubmit(,%d)' % ovs_consts.DROPPED_TRAFFIC_TABLE
        )
        for ethertype in [lib_const.ETHERTYPE_IP, lib_const.ETHERTYPE_IPV6]:
            self._add_flow(
                table=ovs_consts.RULES_EGRESS_TABLE,
                priority=40,
                dl_type=ethertype,
                reg_port=port.ofport,
                ct_state=ovsfw_consts.OF_STATE_ESTABLISHED,
                actions="ct(commit,zone=NXM_NX_REG{:d}[0..15],"
                        "exec(set_field:{:s}->ct_mark))".format(
                            agent_consts.REG_NET,
                            ovsfw_consts.CT_MARK_INVALID)
            )

    def _initialize_ingress_ipv6_icmp(self, port):
        # NOTE(ralonsoh): "ICMPV6_TYPE_RA" was removed from
        # "ICMPV6_ALLOWED_INGRESS_TYPES" because of a bug in the iptables
        # firewall. This rule was added in "_add_ingress_ra_rule". However,
        # the OVS firewall does not use port["security_group_rules"].
        for icmp_type in (firewall.ICMPV6_ALLOWED_INGRESS_TYPES +
                          (lib_const.ICMPV6_TYPE_RA, )):
            self._add_flow(
                table=ovs_consts.BASE_INGRESS_TABLE,
                priority=100,
                reg_port=port.ofport,
                dl_type=lib_const.ETHERTYPE_IPV6,
                nw_proto=lib_const.PROTO_NUM_IPV6_ICMP,
                icmp_type=icmp_type,
                actions=f'output:{port.ofport:d}'
            )

    def _initialize_ingress(self, port):
        # Allow incoming ARPs
        self._add_flow(
            table=ovs_consts.BASE_INGRESS_TABLE,
            priority=100,
            dl_type=lib_const.ETHERTYPE_ARP,
            reg_port=port.ofport,
            actions=f'output:{port.ofport:d}'
        )

        # Allow custom ethertypes
        for permitted_ethertype in self.permitted_ethertypes:
            self._add_flow(
                table=ovs_consts.BASE_INGRESS_TABLE,
                priority=100,
                dl_type=permitted_ethertype,
                reg_port=port.ofport,
                actions=f'output:{port.ofport:d}')

        self._initialize_ingress_ipv6_icmp(port)

        # DHCP offers
        for dl_type, src_port, dst_port in (
                (lib_const.ETHERTYPE_IP, 67, 68),
                (lib_const.ETHERTYPE_IPV6, 547, 546)):
            self._add_flow(
                table=ovs_consts.BASE_INGRESS_TABLE,
                priority=95,
                reg_port=port.ofport,
                dl_type=dl_type,
                nw_proto=lib_const.PROTO_NUM_UDP,
                tp_src=src_port,
                tp_dst=dst_port,
                actions=f'output:{port.ofport:d}'
            )

        # Track untracked
        for dl_type in (lib_const.ETHERTYPE_IP, lib_const.ETHERTYPE_IPV6):
            self._add_flow(
                table=ovs_consts.BASE_INGRESS_TABLE,
                priority=90,
                reg_port=port.ofport,
                dl_type=dl_type,
                ct_state=ovsfw_consts.OF_STATE_NOT_TRACKED,
                actions='ct(table={:d},zone=NXM_NX_REG{:d}[0..15])'.format(
                    ovs_consts.RULES_INGRESS_TABLE,
                    agent_consts.REG_NET)
            )
        self._add_flow(
            table=ovs_consts.BASE_INGRESS_TABLE,
            ct_state=ovsfw_consts.OF_STATE_TRACKED,
            priority=80,
            reg_port=port.ofport,
            actions=f'resubmit(,{ovs_consts.RULES_INGRESS_TABLE:d})'
        )

    def _initialize_tracked_ingress(self, port):
        # Drop invalid packets
        self._add_flow(
            flow_group_id=port.ofport,
            table=ovs_consts.RULES_INGRESS_TABLE,
            priority=50,
            ct_state=ovsfw_consts.OF_STATE_INVALID,
            actions='resubmit(,%d)' % ovs_consts.DROPPED_TRAFFIC_TABLE
        )
        # Drop traffic for removed sg rules
        self._add_flow(
            table=ovs_consts.RULES_INGRESS_TABLE,
            priority=50,
            reg_port=port.ofport,
            ct_mark=ovsfw_consts.CT_MARK_INVALID,
            actions='resubmit(,%d)' % ovs_consts.DROPPED_TRAFFIC_TABLE
        )

        # NOTE: The OUTPUT action is used instead of NORMAL action to reduce
        # cpu utilization, but it causes the datapath rule to be flood rule.
        # This is due to mac learning not happened on ingress traffic.
        # While this is ok for no offload case, in ovs offload flood rule
        # is not offloaded. Therefore, we change the action to be NORMAL in
        # offload case. In case the explicitly_egress_direct is used the
        # pipeline don't contain action NORMAL so we don't have flood rule
        # issue.
        actions = f'output:{port.ofport:d}'
        if (self.int_br.br.is_hw_offload_enabled and
                not cfg.CONF.AGENT.explicitly_egress_direct):
            actions = f'mod_vlan_vid:{port.vlan_tag:d},normal'
        # Allow established and related connections
        for state in (ovsfw_consts.OF_STATE_ESTABLISHED_REPLY,
                      ovsfw_consts.OF_STATE_RELATED):
            self._add_flow(
                table=ovs_consts.RULES_INGRESS_TABLE,
                priority=50,
                reg_port=port.ofport,
                ct_state=state,
                ct_mark=ovsfw_consts.CT_MARK_NORMAL,
                ct_zone=port.vlan_tag,
                actions=actions
            )
        self._add_flow(
            table=ovs_consts.RULES_INGRESS_TABLE,
            priority=40,
            reg_port=port.ofport,
            ct_state=ovsfw_consts.OF_STATE_NOT_ESTABLISHED,
            actions='resubmit(,%d)' % ovs_consts.DROPPED_TRAFFIC_TABLE
        )
        for ethertype in [lib_const.ETHERTYPE_IP, lib_const.ETHERTYPE_IPV6]:
            self._add_flow(
                table=ovs_consts.RULES_INGRESS_TABLE,
                priority=40,
                dl_type=ethertype,
                reg_port=port.ofport,
                ct_state=ovsfw_consts.OF_STATE_ESTABLISHED,
                actions="ct(commit,zone=NXM_NX_REG{:d}[0..15],"
                        "exec(set_field:{:s}->ct_mark))".format(
                            agent_consts.REG_NET,
                            ovsfw_consts.CT_MARK_INVALID)
            )

    def _add_non_ip_conj_flows(self, port):
        """Install conjunction flows that don't depend on IP address of remote
        groups, which consist of actions=conjunction(conj_id, 2/2) flows and
        actions=accept flows.

        The remaining part is done by ConjIPFlowManager.
        """
        port_rules = collections.defaultdict(list)
        for sec_group_id, rule in (
                self._create_remote_rules_generator_for_port(port)):
            direction = rule['direction']
            ethertype = rule['ethertype']
            protocol = rule.get('protocol')
            priority_offset = rules.flow_priority_offset(rule)

            if rule.get('remote_group_id'):
                remote_type = 'security group'
                remote_id = rule.get('remote_group_id')
            else:
                remote_type = 'address group'
                remote_id = rule.get('remote_address_group_id')
            conj_id = self.conj_ip_manager.add(port.vlan_tag, sec_group_id,
                                               remote_id,
                                               direction, ethertype,
                                               priority_offset)
            LOG.debug("Created conjunction %(conj_id)s for SG %(sg_id)s "
                      "referencing remote %(remote_type)s ID %(remote_id)s "
                      "on port %(port_id)s.",
                      {'conj_id': conj_id,
                       'sg_id': sec_group_id,
                       'remote_type': remote_type,
                       'remote_id': remote_id,
                       'port_id': port.id})

            rule1 = rule.copy()
            rule1.pop('remote_group_id', None)
            rule1.pop('remote_address_group_id', None)
            port_rules_key = (direction, ethertype, protocol)
            port_rules[port_rules_key].append((rule1, conj_id))

        for (direction, ethertype, protocol), rule_conj_list in (
                port_rules.items()):
            all_conj_ids = set()
            for rule, conj_id in rule_conj_list:
                all_conj_ids.add(conj_id)

            if protocol in [lib_const.PROTO_NUM_SCTP,
                            lib_const.PROTO_NUM_TCP,
                            lib_const.PROTO_NUM_UDP]:
                rule_conj_list = rules.merge_port_ranges(rule_conj_list)
            else:
                rule_conj_list = rules.merge_common_rules(rule_conj_list)

            for rule, conj_ids in rule_conj_list:
                flows = rules.create_flows_from_rule_and_port(
                    rule, port, conjunction=True)
                for flow in rules.substitute_conjunction_actions(
                        flows, 2, conj_ids):
                    self._add_flow(**flow)

            # Install accept flows and store conj_id to reg7 for future process
            for conj_id in all_conj_ids:
                for flow in rules.create_conj_flows(
                        port, conj_id, direction, ethertype):
                    flow['actions'] = "set_field:{:d}->reg{:d},{:s}".format(
                        flow['conj_id'],
                        agent_consts.REG_REMOTE_GROUP,
                        flow['actions']
                    )
                    self._add_flow(**flow)

    def add_flows_from_rules(self, port):
        self._initialize_tracked_ingress(port)
        self._initialize_tracked_egress(port)
        LOG.debug('Creating flow rules for port %s that is port %d in OVS',
                  port.id, port.ofport)
        for rule in self._create_rules_generator_for_port(port):
            # NOTE(toshii): A better version of merge_common_rules and
            # its friend should be applied here in order to avoid
            # overlapping flows.
            flows = rules.create_flows_from_rule_and_port(rule, port)
            LOG.debug("RULGEN: Rules generated for flow %s are %s",
                      rule, flows)
            for flow in flows:
                self._accept_flow(**flow)

        self._add_non_ip_conj_flows(port)

        self.conj_ip_manager.update_flows_for_vlan(port.vlan_tag,
                                                   port.ofport)

    def _create_rules_generator_for_port(self, port):
        for sec_group in port.sec_groups:
            yield from sec_group.raw_rules

    def _create_remote_rules_generator_for_port(self, port):
        for sec_group in port.sec_groups:
            for rule in sec_group.remote_rules:
                yield sec_group.id, rule

    def delete_all_port_flows(self, port):
        """Delete all flows for given port"""
        for mac_addr in port.all_allowed_macs:
            self._delete_flows(table=ovs_consts.TRANSIENT_TABLE,
                               dl_dst=mac_addr,
                               dl_vlan=port.vlan_tag)
            self.delete_physical_direct_flow(mac_addr, port.segment_id)
            self._delete_flows(table=ovs_consts.ACCEPT_OR_INGRESS_TABLE,
                               dl_dst=mac_addr, reg_net=port.vlan_tag)

        self.delete_accepted_egress_direct_flow(
            port.mac, port.vlan_tag)
        self._delete_flows(table=ovs_consts.TRANSIENT_TABLE,
                           in_port=port.ofport)
        self._delete_flows(reg_port=port.ofport)

    def delete_flows_for_flow_state(
            self, flow_state, addr_to_conj, direction, ethertype, vlan_tag):
        # Remove rules for deleted IPs and action=conjunction(conj_id, 1/2)
        removed_ips = set(flow_state.keys()) - set(addr_to_conj.keys())
        for removed_ip, removed_mac in removed_ips:
            conj_ids = flow_state[(removed_ip, removed_mac)]
            self.delete_flow_for_ip_and_mac(
                removed_ip, removed_mac, direction,
                ethertype, vlan_tag, conj_ids)

        if not cfg.CONF.AGENT.explicitly_egress_direct:
            return

        for ip, mac in removed_ips:
            # Generate deletion template with bogus conj_id.
            self.delete_flow_for_ip_and_mac(
                ip, mac, direction, ethertype, vlan_tag, [0])

    def delete_flow_for_ip_and_mac(self, ip, mac, direction, ethertype,
                                   vlan_tag, conj_ids):
        for flow in rules.create_flows_for_ip_address_and_mac(
                ip, mac, direction, ethertype, vlan_tag, conj_ids):
            # The following del statements are partly for
            # complying the OpenFlow spec. It forbids the use of
            # these field in non-strict delete flow messages, and
            # the actions field is bogus anyway.
            del flow['actions']
            del flow['priority']
            # NOTE(hangyang) If cookie is not set then _delete_flows will
            # use the OVSBridge._default_cookie to filter the flows but that
            # will not match with the ip flow's cookie so OVS won't actually
            # delete the flow
            flow['cookie'] = ovs_lib.COOKIE_ANY
            self._delete_flows(**flow)
