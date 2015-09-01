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

import netaddr
from oslo_log import log as logging

from neutron._i18n import _, _LE
from neutron.agent import firewall
from neutron.agent.linux.openvswitch_firewall import constants as ovsfw_consts
from neutron.agent.linux.openvswitch_firewall import rules
from neutron.common import constants
from neutron.common import exceptions
from neutron.plugins.ml2.drivers.openvswitch.agent.common import constants \
        as ovs_consts

LOG = logging.getLogger(__name__)


class OVSFWPortNotFound(exceptions.NeutronException):
    message = _("Port %(port_id)s is not managed by this agent. ")


class SecurityGroup(object):
    def __init__(self, id_):
        self.id = id_
        self.raw_rules = []
        self.remote_rules = []
        self.members = {}
        self.ports = set()

    def update_rules(self, rules):
        """Separate raw and remote rules."""
        self.raw_rules = [rule for rule in rules
                          if 'remote_group_id' not in rule]
        self.remote_rules = [rule for rule in rules
                             if 'remote_group_id' in rule]

    def get_ethertype_filtered_addresses(self, ethertype,
                                         exclude_addresses=None):
        exclude_addresses = set(exclude_addresses) or set()
        group_addresses = set(self.members.get(ethertype, []))
        return list(group_addresses - exclude_addresses)


class OFPort(object):
    def __init__(self, port_dict, ovs_port):
        self.id = port_dict['device']
        self.mac = ovs_port.vif_mac
        self.ofport = ovs_port.ofport
        self.sec_groups = list()
        self.fixed_ips = port_dict.get('fixed_ips', [])
        self.neutron_port_dict = port_dict.copy()
        self.allowed_pairs_v4 = self._get_allowed_pairs(port_dict, version=4)
        self.allowed_pairs_v6 = self._get_allowed_pairs(port_dict, version=6)

    @staticmethod
    def _get_allowed_pairs(port_dict, version):
        aap_dict = port_dict.get('allowed_address_pairs', set())
        return {(aap['mac_address'], aap['ip_address']) for aap in aap_dict
                if netaddr.IPAddress(aap['ip_address']).version == version}

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
        self.fixed_ips = port_dict.get('fixed_ips', [])
        self.neutron_port_dict = port_dict.copy()


class SGPortMap(object):
    def __init__(self):
        self.ports = {}
        self.sec_groups = {}

    def get_or_create_sg(self, sg_id):
        try:
            sec_group = self.sec_groups[sg_id]
        except KeyError:
            sec_group = SecurityGroup(sg_id)
            self.sec_groups[sg_id] = sec_group
        return sec_group

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


class OVSFirewallDriver(firewall.FirewallDriver):
    REQUIRED_PROTOCOLS = ",".join([
        ovs_consts.OPENFLOW10,
        ovs_consts.OPENFLOW11,
        ovs_consts.OPENFLOW12,
        ovs_consts.OPENFLOW13,
        ovs_consts.OPENFLOW14,
    ])

    provides_arp_spoofing_protection = True

    def __init__(self, integration_bridge):
        """Initialize object

        :param integration_bridge: Bridge on which openflow rules will be
                                   applied

        """
        self.int_br = self.initialize_bridge(integration_bridge)
        self.sg_port_map = SGPortMap()
        self._deferred = False
        self._drop_all_unmatched_flows()

    def apply_port_filter(self, port):
        """We never call this method

        It exists here to override abstract method of parent abstract class.
        """

    def security_group_updated(self, action_type, sec_group_ids,
                               device_ids=None):
        """This method is obsolete

        The current driver only supports enhanced rpc calls into security group
        agent. This method is never called from that place.
        """

    def _add_flow(self, **kwargs):
        dl_type = kwargs.get('dl_type')
        if isinstance(dl_type, int):
            kwargs['dl_type'] = "0x{:04x}".format(dl_type)
        if self._deferred:
            self.int_br.add_flow(**kwargs)
        else:
            self.int_br.br.add_flow(**kwargs)

    def _delete_flows(self, **kwargs):
        if self._deferred:
            self.int_br.delete_flows(**kwargs)
        else:
            self.int_br.br.delete_flows(**kwargs)

    @staticmethod
    def initialize_bridge(int_br):
        int_br.set_protocols(OVSFirewallDriver.REQUIRED_PROTOCOLS)
        return int_br.deferred(full_ordered=True)

    def _drop_all_unmatched_flows(self):
        for table in ovs_consts.OVS_FIREWALL_TABLES:
            self.int_br.br.add_flow(table=table, priority=0, actions='drop')

    def get_or_create_ofport(self, port):
        port_id = port['device']
        try:
            of_port = self.sg_port_map.ports[port_id]
        except KeyError:
            ovs_port = self.int_br.br.get_vif_port_by_id(port_id)
            if not ovs_port:
                raise OVSFWPortNotFound(port_id=port_id)
            of_port = OFPort(port, ovs_port)
            self.sg_port_map.create_port(of_port, port)
        else:
            self.sg_port_map.update_port(of_port, port)

        return of_port

    def is_port_managed(self, port):
        return port['device'] in self.sg_port_map.ports

    def prepare_port_filter(self, port):
        if not firewall.port_sec_enabled(port):
            return
        port_exists = self.is_port_managed(port)
        of_port = self.get_or_create_ofport(port)
        if port_exists:
            LOG.error(_LE("Initializing port %s that was already "
                          "initialized."),
                      port['device'])
            self.delete_all_port_flows(of_port)
        self.initialize_port_flows(of_port)
        self.add_flows_from_rules(of_port)

    def update_port_filter(self, port):
        """Update rules for given port

        Current existing filtering rules are removed and new ones are generated
        based on current loaded security group rules and members.

        """
        if not firewall.port_sec_enabled(port):
            self.remove_port_filter(port)
            return
        elif not self.is_port_managed(port):
            self.prepare_port_filter(port)
            return
        of_port = self.get_or_create_ofport(port)
        # TODO(jlibosva): Handle firewall blink
        self.delete_all_port_flows(of_port)
        self.initialize_port_flows(of_port)
        self.add_flows_from_rules(of_port)

    def remove_port_filter(self, port):
        """Remove port from firewall

        All flows related to this port are removed from ovs. Port is also
        removed from ports managed by this firewall.

        """
        if self.is_port_managed(port):
            of_port = self.get_or_create_ofport(port)
            self.delete_all_port_flows(of_port)
            self.sg_port_map.remove_port(of_port)

    def update_security_group_rules(self, sg_id, rules):
        self.sg_port_map.update_rules(sg_id, rules)

    def update_security_group_members(self, sg_id, member_ips):
        self.sg_port_map.update_members(sg_id, member_ips)

    def filter_defer_apply_on(self):
        self._deferred = True

    def filter_defer_apply_off(self):
        if self._deferred:
            self.int_br.apply_flows()
            self._deferred = False

    @property
    def ports(self):
        return {id_: port.neutron_port_dict
                for id_, port in self.sg_port_map.ports.items()}

    def initialize_port_flows(self, port):
        """Set base flows for port

        :param port: OFPort instance

        """
        # Identify egress flow
        self._add_flow(
            table=ovs_consts.LOCAL_SWITCHING,
            priority=100,
            in_port=port.ofport,
            actions='set_field:{:d}->reg5,resubmit(,{:d})'.format(
                port.ofport, ovs_consts.BASE_EGRESS_TABLE)
        )

        # Identify ingress flows after egress filtering
        self._add_flow(
            table=ovs_consts.LOCAL_SWITCHING,
            priority=90,
            dl_dst=port.mac,
            actions='set_field:{:d}->reg5,resubmit(,{:d})'.format(
                port.ofport, ovs_consts.BASE_INGRESS_TABLE),
        )

        self._initialize_egress(port)
        self._initialize_ingress(port)

    def _initialize_egress(self, port):
        """Identify egress traffic and send it to egress base"""

        # Apply mac/ip pairs for IPv4
        allowed_pairs = port.allowed_pairs_v4.union(
            {(port.mac, ip_addr) for ip_addr in port.ipv4_addresses})
        for mac_addr, ip_addr in allowed_pairs:
            self._add_flow(
                table=ovs_consts.BASE_EGRESS_TABLE,
                priority=95,
                in_port=port.ofport,
                reg5=port.ofport,
                dl_src=mac_addr,
                dl_type=constants.ETHERTYPE_ARP,
                arp_spa=ip_addr,
                actions='normal'
            )
            self._add_flow(
                table=ovs_consts.BASE_EGRESS_TABLE,
                priority=65,
                reg5=port.ofport,
                ct_state=ovsfw_consts.OF_STATE_NOT_TRACKED,
                dl_type=constants.ETHERTYPE_IP,
                in_port=port.ofport,
                dl_src=mac_addr,
                nw_src=ip_addr,
                actions='ct(table={:d},zone=NXM_NX_REG5[0..15])'.format(
                    ovs_consts.RULES_EGRESS_TABLE)
            )

        # Apply mac/ip pairs for IPv6
        allowed_pairs = port.allowed_pairs_v6.union(
            {(port.mac, ip_addr) for ip_addr in port.ipv6_addresses})
        for mac_addr, ip_addr in allowed_pairs:
            self._add_flow(
                table=ovs_consts.BASE_EGRESS_TABLE,
                priority=95,
                in_port=port.ofport,
                reg5=port.ofport,
                dl_type=constants.ETHERTYPE_IPV6,
                nw_proto=constants.PROTO_NUM_IPV6_ICMP,
                icmp_type=constants.ICMPV6_TYPE_NA,
                actions='normal'
            )
            self._add_flow(
                table=ovs_consts.BASE_EGRESS_TABLE,
                priority=65,
                reg5=port.ofport,
                in_port=port.ofport,
                ct_state=ovsfw_consts.OF_STATE_NOT_TRACKED,
                dl_type=constants.ETHERTYPE_IPV6,
                dl_src=mac_addr,
                ipv6_src=ip_addr,
                actions='ct(table={:d},zone=NXM_NX_REG5[0..15])'.format(
                    ovs_consts.RULES_EGRESS_TABLE)
            )

        # DHCP discovery
        for dl_type, src_port, dst_port in (
                (constants.ETHERTYPE_IP, 68, 67),
                (constants.ETHERTYPE_IPV6, 546, 547)):
            self._add_flow(
                table=ovs_consts.BASE_EGRESS_TABLE,
                priority=80,
                reg5=port.ofport,
                in_port=port.ofport,
                dl_type=dl_type,
                nw_proto=constants.PROTO_NUM_UDP,
                tp_src=src_port,
                tp_dst=dst_port,
                actions='resubmit(,{:d})'.format(
                    ovs_consts.ACCEPT_OR_INGRESS_TABLE)
            )
        # Ban dhcp service running on an instance
        for dl_type, src_port, dst_port in (
                (constants.ETHERTYPE_IP, 67, 68),
                (constants.ETHERTYPE_IPV6, 547, 546)):
            self._add_flow(
                table=ovs_consts.BASE_EGRESS_TABLE,
                priority=70,
                in_port=port.ofport,
                reg5=port.ofport,
                dl_type=dl_type,
                nw_proto=constants.PROTO_NUM_UDP,
                tp_src=src_port,
                tp_dst=dst_port,
                actions='drop'
            )

        # Drop all remaining not tracked egress connections
        self._add_flow(
            table=ovs_consts.BASE_EGRESS_TABLE,
            priority=10,
            ct_state=ovsfw_consts.OF_STATE_NOT_TRACKED,
            in_port=port.ofport,
            reg5=port.ofport,
            actions='drop'
        )

        # Fill in accept_or_ingress table by checking that traffic is ingress
        # and if not, accept it
        self._add_flow(
            table=ovs_consts.ACCEPT_OR_INGRESS_TABLE,
            priority=100,
            dl_dst=port.mac,
            actions='set_field:{:d}->reg5,resubmit(,{:d})'.format(
                port.ofport, ovs_consts.BASE_INGRESS_TABLE),
        )
        self._add_flow(
            table=ovs_consts.ACCEPT_OR_INGRESS_TABLE,
            priority=90,
            reg5=port.ofport,
            in_port=port.ofport,
            actions='ct(commit,zone=NXM_NX_REG5[0..15]),normal'
        )

    def _initialize_tracked_egress(self, port):
        self._add_flow(
            table=ovs_consts.RULES_EGRESS_TABLE,
            priority=90,
            ct_state=ovsfw_consts.OF_STATE_INVALID,
            actions='drop',
        )
        for state in (
            ovsfw_consts.OF_STATE_ESTABLISHED,
            ovsfw_consts.OF_STATE_RELATED,
        ):
            self._add_flow(
                table=ovs_consts.RULES_EGRESS_TABLE,
                priority=80,
                ct_state=state,
                reg5=port.ofport,
                ct_zone=port.ofport,
                actions='normal'
            )

    def _initialize_ingress(self, port):
        # Allow incoming ARPs
        self._add_flow(
            table=ovs_consts.BASE_INGRESS_TABLE,
            priority=100,
            dl_type=constants.ETHERTYPE_ARP,
            reg5=port.ofport,
            dl_dst=port.mac,
            actions='output:{:d}'.format(port.ofport),
        )
        # Neighbor soliciation
        self._add_flow(
            table=ovs_consts.BASE_INGRESS_TABLE,
            priority=100,
            reg5=port.ofport,
            dl_dst=port.mac,
            dl_type=constants.ETHERTYPE_IPV6,
            nw_proto=constants.PROTO_NUM_IPV6_ICMP,
            icmp_type=constants.ICMPV6_TYPE_NC,
            actions='output:{:d}'.format(port.ofport),
        )
        # DHCP offers
        for dl_type, src_port, dst_port in (
                (constants.ETHERTYPE_IP, 67, 68),
                (constants.ETHERTYPE_IPV6, 547, 546)):
            self._add_flow(
                table=ovs_consts.BASE_INGRESS_TABLE,
                priority=95,
                reg5=port.ofport,
                dl_type=dl_type,
                nw_proto=constants.PROTO_NUM_UDP,
                tp_src=src_port,
                tp_dst=dst_port,
                actions='output:{:d}'.format(port.ofport),
            )

        # Track untracked
        for dl_type in (constants.ETHERTYPE_IP, constants.ETHERTYPE_IPV6):
            self._add_flow(
                table=ovs_consts.BASE_INGRESS_TABLE,
                priority=90,
                reg5=port.ofport,
                dl_type=dl_type,
                ct_state=ovsfw_consts.OF_STATE_NOT_TRACKED,
                actions='ct(table={:d},zone=NXM_NX_REG5[0..15])'.format(
                    ovs_consts.RULES_INGRESS_TABLE)
            )
        self._add_flow(
            table=ovs_consts.BASE_INGRESS_TABLE,
            priority=80,
            reg5=port.ofport,
            dl_dst=port.mac,
            actions='resubmit(,{:d})'.format(ovs_consts.RULES_INGRESS_TABLE)
        )

    def _initialize_tracked_ingress(self, port):
        # Drop invalid packets
        self._add_flow(
            table=ovs_consts.RULES_INGRESS_TABLE,
            priority=100,
            ct_state=ovsfw_consts.OF_STATE_INVALID,
            actions='drop'
        )
        # Allow established and related connections
        for state in (ovsfw_consts.OF_STATE_ESTABLISHED,
                      ovsfw_consts.OF_STATE_RELATED):
            self._add_flow(
                table=ovs_consts.RULES_INGRESS_TABLE,
                priority=80,
                dl_dst=port.mac,
                reg5=port.ofport,
                ct_state=state,
                ct_zone=port.ofport,
                actions='output:{:d}'.format(port.ofport)
            )

    def add_flows_from_rules(self, port):
        self._initialize_tracked_ingress(port)
        self._initialize_tracked_egress(port)
        LOG.debug('Creating flow rules for port %s that is port %d in OVS',
                  port.id, port.ofport)
        rules_generator = self.create_rules_generator_for_port(port)
        for rule in rules_generator:
            flows = rules.create_flows_from_rule_and_port(rule, port)
            LOG.debug("RULGEN: Rules generated for flow %s are %s",
                      rule, flows)
            for flow in flows:
                self._add_flow(**flow)

    def create_rules_generator_for_port(self, port):
        for sec_group in port.sec_groups:
            for rule in sec_group.raw_rules:
                yield rule
            for rule in sec_group.remote_rules:
                remote_group = self.sg_port_map.sec_groups[
                    rule['remote_group_id']]
                for ip_addr in remote_group.get_ethertype_filtered_addresses(
                        rule['ethertype'], port.fixed_ips):
                    yield rules.create_rule_for_ip_address(ip_addr, rule)

    def delete_all_port_flows(self, port):
        """Delete all flows for given port"""
        self._delete_flows(table=ovs_consts.LOCAL_SWITCHING, dl_dst=port.mac)
        self._delete_flows(table=ovs_consts.LOCAL_SWITCHING,
                           in_port=port.ofport)
        self._delete_flows(reg5=port.ofport)
        self._delete_flows(table=ovs_consts.ACCEPT_OR_INGRESS_TABLE,
                           dl_dst=port.mac)
