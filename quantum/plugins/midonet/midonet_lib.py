# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (C) 2012 Midokura Japan K.K.
# Copyright (C) 2013 Midokura PTE LTD
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
#
# @author: Tomoe Sugihara, Midokura Japan KK
# @author: Ryu Ishimoto, Midokura Japan KK


from quantum.openstack.common import log as logging


LOG = logging.getLogger(__name__)

PREFIX = 'OS_SG_'
SUFFIX_IN = '_IN'
SUFFIX_OUT = '_OUT'
OS_ROUTER_IN_CHAIN_NAME_FORMAT = 'OS_ROUTER_IN_%s'
OS_ROUTER_OUT_CHAIN_NAME_FORMAT = 'OS_ROUTER_OUT_%s'
NAME_IDENTIFIABLE_PREFIX_LEN = len(PREFIX) + 36  # 36 = length of uuid


def sg_label(sg_id, sg_name):
    """Construct the security group ID used as chain identifier in MidoNet."""
    return PREFIX + str(sg_id) + '_' + sg_name

port_group_name = sg_label


def chain_names(sg_id, sg_name):
    """Get inbound and outbound chain names."""
    prefix = sg_label(sg_id, sg_name)
    in_chain_name = prefix + SUFFIX_IN
    out_chain_name = prefix + SUFFIX_OUT
    return {'in': in_chain_name, 'out': out_chain_name}


class ChainManager:

    def __init__(self, mido_api):
        self.mido_api = mido_api

    def create_for_sg(self, tenant_id, sg_id, sg_name):
        """Create a new chain for security group.

        Creating a security group creates a pair of chains in MidoNet, one for
        inbound and the other for outbound.
        """
        LOG.debug(_("ChainManager.create_for_sg called: "
                    "tenant_id=%(tenant_id)s sg_id=%(sg_id)s "
                    "sg_name=%(sg_name)s "),
                  {'tenant_id': tenant_id, 'sg_id': sg_id, 'sg_name': sg_name})

        cnames = chain_names(sg_id, sg_name)
        self.mido_api.add_chain().tenant_id(tenant_id).name(
            cnames['in']).create()
        self.mido_api.add_chain().tenant_id(tenant_id).name(
            cnames['out']).create()

    def delete_for_sg(self, tenant_id, sg_id, sg_name):
        """Delete a chain mapped to a security group.

        Delete a SG means deleting all the chains (inbound and outbound)
        associated with the SG in MidoNet.
        """
        LOG.debug(_("ChainManager.delete_for_sg called: "
                    "tenant_id=%(tenant_id)s sg_id=%(sg_id)s "
                    "sg_name=%(sg_name)s "),
                  {'tenant_id': tenant_id, 'sg_id': sg_id, 'sg_name': sg_name})

        cnames = chain_names(sg_id, sg_name)
        chains = self.mido_api.get_chains({'tenant_id': tenant_id})
        for c in chains:
            if c.get_name() == cnames['in'] or c.get_name() == cnames['out']:
                LOG.debug(_('ChainManager.delete_for_sg: deleting chain=%r'),
                          c)
                c.delete()

    def get_router_chains(self, tenant_id, router_id):
        """Get router chains.

        Returns a dictionary that has in/out chain resources key'ed with 'in'
        and 'out' respectively, given the tenant_id and the router_id passed
        in in the arguments.
        """
        LOG.debug(_("ChainManager.get_router_chains called: "
                    "tenant_id=%(tenant_id)s router_id=%(router_id)s"),
                  {'tenant_id': tenant_id, 'router_id': router_id})

        router_chain_names = self._get_router_chain_names(router_id)
        chains = {}
        for c in self.mido_api.get_chains({'tenant_id': tenant_id}):
            if c.get_name() == router_chain_names['in']:
                chains['in'] = c
            elif c.get_name() == router_chain_names['out']:
                chains['out'] = c
        return chains

    def create_router_chains(self, tenant_id, router_id):
        """Create a new chain on a router.

        Creates chains for the router and returns the same dictionary as
        get_router_chains() returns.
        """
        LOG.debug(_("ChainManager.create_router_chains called: "
                    "tenant_id=%(tenant_id)s router_id=%(router_id)s"),
                  {'tenant_id': tenant_id, 'router_id': router_id})

        chains = {}
        router_chain_names = self._get_router_chain_names(router_id)
        chains['in'] = self.mido_api.add_chain().tenant_id(tenant_id).name(
            router_chain_names['in']).create()

        chains['out'] = self.mido_api.add_chain().tenant_id(tenant_id).name(
            router_chain_names['out']).create()
        return chains

    def get_sg_chains(self, tenant_id, sg_id):
        """Get a list of chains mapped to a security group."""
        LOG.debug(_("ChainManager.get_sg_chains called: "
                    "tenant_id=%(tenant_id)s sg_id=%(sg_id)s"),
                  {'tenant_id': tenant_id, 'sg_id': sg_id})

        cnames = chain_names(sg_id, sg_name='')
        chain_name_prefix_for_id = cnames['in'][:NAME_IDENTIFIABLE_PREFIX_LEN]
        chains = {}

        for c in self.mido_api.get_chains({'tenant_id': tenant_id}):
            if c.get_name().startswith(chain_name_prefix_for_id):
                if c.get_name().endswith(SUFFIX_IN):
                    chains['in'] = c
                if c.get_name().endswith(SUFFIX_OUT):
                    chains['out'] = c
        assert 'in' in chains
        assert 'out' in chains
        return chains

    def _get_router_chain_names(self, router_id):
        LOG.debug(_("ChainManager.get_router_chain_names called: "
                    "router_id=%(router_id)s"), {'router_id': router_id})

        in_name = OS_ROUTER_IN_CHAIN_NAME_FORMAT % router_id
        out_name = OS_ROUTER_OUT_CHAIN_NAME_FORMAT % router_id
        router_chain_names = {'in': in_name, 'out': out_name}
        return router_chain_names


class PortGroupManager:

    def __init__(self, mido_api):
        self.mido_api = mido_api

    def create(self, tenant_id, sg_id, sg_name):
        LOG.debug(_("PortGroupManager.create called: "
                    "tenant_id=%(tenant_id)s sg_id=%(sg_id)s "
                    "sg_name=%(sg_name)s"),
                  {'tenant_id': tenant_id, 'sg_id': sg_id, 'sg_name': sg_name})
        pg_name = port_group_name(sg_id, sg_name)
        self.mido_api.add_port_group().tenant_id(tenant_id).name(
            pg_name).create()

    def delete(self, tenant_id, sg_id, sg_name):
        LOG.debug(_("PortGroupManager.delete called: "
                    "tenant_id=%(tenant_id)s sg_id=%(sg_id)s "
                    "sg_name=%(sg_name)s"),
                  {'tenant_id': tenant_id, 'sg_id': sg_id, 'sg_name': sg_name})
        pg_name = port_group_name(sg_id, sg_name)
        pgs = self.mido_api.get_port_groups({'tenant_id': tenant_id})
        for pg in pgs:
            if pg.get_name() == pg_name:
                LOG.debug(_("PortGroupManager.delete: deleting pg=%r"), pg)
                pg.delete()

    def get_for_sg(self, tenant_id, sg_id):
        LOG.debug(_("PortGroupManager.get_for_sg called: "
                    "tenant_id=%(tenant_id)s sg_id=%(sg_id)s"),
                  {'tenant_id': tenant_id, 'sg_id': sg_id})

        pg_name_prefix = port_group_name(
            sg_id, sg_name='')[:NAME_IDENTIFIABLE_PREFIX_LEN]
        port_groups = self.mido_api.get_port_groups({'tenant_id': tenant_id})
        for pg in port_groups:
            if pg.get_name().startswith(pg_name_prefix):
                LOG.debug(_("PortGroupManager.get_for_sg exiting: pg=%r"), pg)
                return pg
        return None


class RuleManager:

    OS_SG_KEY = 'os_sg_rule_id'

    def __init__(self, mido_api):
        self.mido_api = mido_api
        self.chain_manager = ChainManager(mido_api)
        self.pg_manager = PortGroupManager(mido_api)

    def _properties(self, os_sg_rule_id):
        return {self.OS_SG_KEY: str(os_sg_rule_id)}

    def create_for_sg_rule(self, rule):
        LOG.debug(_("RuleManager.create_for_sg_rule called: rule=%r"), rule)

        direction = rule['direction']
        protocol = rule['protocol']
        port_range_max = rule['port_range_max']
        rule_id = rule['id']
        security_group_id = rule['security_group_id']
        remote_group_id = rule['remote_group_id']
        remote_ip_prefix = rule['remote_ip_prefix']  # watch out. not validated
        tenant_id = rule['tenant_id']
        port_range_min = rule['port_range_min']

        # construct a corresponding rule
        tp_src_start = tp_src_end = None
        tp_dst_start = tp_dst_end = None
        nw_src_address = None
        nw_src_length = None
        port_group_id = None

        # handle source
        if not remote_ip_prefix is None:
            nw_src_address, nw_src_length = remote_ip_prefix.split('/')
        elif not remote_group_id is None:  # security group as a srouce
            source_pg = self.pg_manager.get_for_sg(tenant_id, remote_group_id)
            port_group_id = source_pg.get_id()
        else:
            raise Exception(_("Don't know what to do with rule=%r"), rule)

        # dst ports
        tp_dst_start, tp_dst_end = port_range_min, port_range_max

        # protocol
        if protocol == 'tcp':
            nw_proto = 6
        elif protocol == 'udp':
            nw_proto = 17
        elif protocol == 'icmp':
            nw_proto = 1
            # extract type and code from reporposed fields
            icmp_type = rule['from_port']
            icmp_code = rule['to_port']

            # translate -1(wildcard in OS) to midonet wildcard
            if icmp_type == -1:
                icmp_type = None
            if icmp_code == -1:
                icmp_code = None

            # set data for midonet rule
            tp_src_start = tp_src_end = icmp_type
            tp_dst_start = tp_dst_end = icmp_code

        chains = self.chain_manager.get_sg_chains(tenant_id, security_group_id)
        chain = None
        if direction == 'egress':
            chain = chains['in']
        elif direction == 'ingress':
            chain = chains['out']
        else:
            raise Exception(_("Don't know what to do with rule=%r"), rule)

        # create an accept rule
        properties = self._properties(rule_id)
        LOG.debug(_("RuleManager.create_for_sg_rule: adding accept rule "
                    "%(rule_id) in portgroup %(port_group_id)s"),
                  {'rule_id': rule_id, 'port_group_id': port_group_id})
        chain.add_rule().port_group(port_group_id).type('accept').nw_proto(
            nw_proto).nw_src_address(nw_src_address).nw_src_length(
                nw_src_length).tp_src_start(tp_src_start).tp_src_end(
                    tp_src_end).tp_dst_start(tp_dst_start).tp_dst_end(
                        tp_dst_end).properties(properties).create()

    def delete_for_sg_rule(self, rule):
        LOG.debug(_("RuleManager.delete_for_sg_rule called: rule=%r"), rule)

        tenant_id = rule['tenant_id']
        security_group_id = rule['security_group_id']
        rule_id = rule['id']

        properties = self._properties(rule_id)
        # search for the chains to find the rule to delete
        chains = self.chain_manager.get_sg_chains(tenant_id, security_group_id)
        for c in chains['in'], chains['out']:
            rules = c.get_rules()
            for r in rules:
                if r.get_properties() == properties:
                    LOG.debug(_("RuleManager.delete_for_sg_rule: deleting "
                                "rule %r"), r)
                    r.delete()
