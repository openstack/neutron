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

import netaddr

from neutron_lib import constants as const
from neutron_lib import exceptions as n_exceptions
from oslo_config import cfg

from neutron._i18n import _
from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils

# Convert the protocol number from integer to strings because that's
# how Neutron will pass it to us
PROTOCOL_NAME_TO_NUM_MAP = {k: str(v) for k, v in
                            const.IP_PROTOCOL_MAP.items()}
# Create a map from protocol numbers to names
PROTOCOL_NUM_TO_NAME_MAP = {v: k for k, v in
                            PROTOCOL_NAME_TO_NUM_MAP.items()}

# Group of transport protocols supported
TRANSPORT_PROTOCOLS = (const.PROTO_NAME_TCP,
                       const.PROTO_NAME_UDP,
                       const.PROTO_NAME_SCTP,
                       PROTOCOL_NAME_TO_NUM_MAP[const.PROTO_NAME_TCP],
                       PROTOCOL_NAME_TO_NUM_MAP[const.PROTO_NAME_UDP],
                       PROTOCOL_NAME_TO_NUM_MAP[const.PROTO_NAME_SCTP])

# Group of versions of the ICMP protocol supported
ICMP_PROTOCOLS = (const.PROTO_NAME_ICMP,
                  const.PROTO_NAME_IPV6_ICMP,
                  const.PROTO_NAME_IPV6_ICMP_LEGACY,
                  PROTOCOL_NAME_TO_NUM_MAP[const.PROTO_NAME_ICMP],
                  PROTOCOL_NAME_TO_NUM_MAP[const.PROTO_NAME_IPV6_ICMP],
                  PROTOCOL_NAME_TO_NUM_MAP[const.PROTO_NAME_IPV6_ICMP_LEGACY])


class ProtocolNotSupported(n_exceptions.NeutronException):
    message = _('The protocol "%(protocol)s" is not supported. Valid '
                'protocols are: %(valid_protocols)s; or protocol '
                'numbers ranging from 0 to 255.')


def is_sg_enabled():
    return cfg.CONF.SECURITYGROUP.enable_security_group


def acl_direction(r, port=None, port_group=None):
    if r['direction'] == const.INGRESS_DIRECTION:
        portdir = 'outport'
    else:
        portdir = 'inport'

    if port:
        return '%s == "%s"' % (portdir, port['id'])
    return '%s == @%s' % (portdir, port_group)


def acl_ethertype(r):
    match = ''
    ip_version = None
    icmp = None
    if r['ethertype'] == const.IPv4:
        match = ' && ip4'
        ip_version = 'ip4'
        icmp = 'icmp4'
    elif r['ethertype'] == const.IPv6:
        match = ' && ip6'
        ip_version = 'ip6'
        icmp = 'icmp6'
    return match, ip_version, icmp


def acl_remote_ip_prefix(r, ip_version):
    if not r['remote_ip_prefix']:
        return ''
    src_or_dst = 'src' if r['direction'] == const.INGRESS_DIRECTION else 'dst'
    return ' && %s.%s == %s' % (ip_version, src_or_dst,
                                r['remote_ip_prefix'])


def _get_protocol_number(protocol):
    if protocol is None:
        return
    try:
        protocol = int(protocol)
        if 0 <= protocol <= 255:
            return str(protocol)
    except (ValueError, TypeError):
        protocol = PROTOCOL_NAME_TO_NUM_MAP.get(protocol)
        if protocol is not None:
            return protocol

    raise ProtocolNotSupported(
        protocol=protocol, valid_protocols=', '.join(PROTOCOL_NAME_TO_NUM_MAP))


def acl_protocol_and_ports(r, icmp):
    match = ''
    protocol = _get_protocol_number(r.get('protocol'))
    if protocol is None:
        return match

    min_port = r.get('port_range_min')
    max_port = r.get('port_range_max')
    if protocol in TRANSPORT_PROTOCOLS:
        protocol = PROTOCOL_NUM_TO_NAME_MAP[protocol]
        match += ' && %s' % protocol
        if min_port is not None and min_port == max_port:
            match += ' && %s.dst == %d' % (protocol, min_port)
        else:
            if min_port is not None:
                match += ' && %s.dst >= %d' % (protocol, min_port)
            if max_port is not None:
                match += ' && %s.dst <= %d' % (protocol, max_port)
    elif protocol in ICMP_PROTOCOLS:
        protocol = icmp
        match += ' && %s' % protocol
        if min_port is not None:
            match += ' && %s.type == %d' % (protocol, min_port)
        if max_port is not None:
            match += ' && %s.code == %d' % (protocol, max_port)
    else:
        match += ' && ip.proto == %s' % protocol

    return match


def add_acls_for_drop_port_group(pg_name):
    acl_list = []
    for direction, p in (('from-lport', 'inport'),
                         ('to-lport', 'outport')):
        acl = {"port_group": pg_name,
               "priority": ovn_const.ACL_PRIORITY_DROP,
               "action": ovn_const.ACL_ACTION_DROP,
               "log": False,
               "name": [],
               "severity": [],
               "direction": direction,
               "match": '%s == @%s && ip' % (p, pg_name)}
        acl_list.append(acl)
    return acl_list


def drop_all_ip_traffic_for_port(port):
    acl_list = []
    for direction, p in (('from-lport', 'inport'),
                         ('to-lport', 'outport')):
        lswitch = utils.ovn_name(port['network_id'])
        lport = port['id']
        acl = {"lswitch": lswitch, "lport": lport,
               "priority": ovn_const.ACL_PRIORITY_DROP,
               "action": ovn_const.ACL_ACTION_DROP,
               "log": False,
               "name": [],
               "severity": [],
               "direction": direction,
               "match": '%s == "%s" && ip' % (p, port['id']),
               "external_ids": {'neutron:lport': port['id']}}
        acl_list.append(acl)
    return acl_list


def add_sg_rule_acl_for_port(port, r, match):
    dir_map = {const.INGRESS_DIRECTION: 'to-lport',
               const.EGRESS_DIRECTION: 'from-lport'}
    acl = {"lswitch": utils.ovn_name(port['network_id']),
           "lport": port['id'],
           "priority": ovn_const.ACL_PRIORITY_ALLOW,
           "action": ovn_const.ACL_ACTION_ALLOW_RELATED,
           "log": False,
           "name": [],
           "severity": [],
           "direction": dir_map[r['direction']],
           "match": match,
           "external_ids": {'neutron:lport': port['id'],
                            ovn_const.OVN_SG_RULE_EXT_ID_KEY: r['id']}}
    return acl


def add_sg_rule_acl_for_port_group(port_group, r, match):
    dir_map = {const.INGRESS_DIRECTION: 'to-lport',
               const.EGRESS_DIRECTION: 'from-lport'}
    acl = {"port_group": port_group,
           "priority": ovn_const.ACL_PRIORITY_ALLOW,
           "action": ovn_const.ACL_ACTION_ALLOW_RELATED,
           "log": False,
           "name": [],
           "severity": [],
           "direction": dir_map[r['direction']],
           "match": match,
           ovn_const.OVN_SG_RULE_EXT_ID_KEY: r['id']}
    return acl


def add_acl_dhcp(port, subnet, ovn_dhcp=True):
    # Allow DHCP requests for OVN native DHCP service, while responses are
    # allowed in ovn-northd.
    # Allow both DHCP requests and responses to pass for other DHCP services.
    # We do this even if DHCP isn't enabled for the subnet
    acl_list = []
    if not ovn_dhcp:
        acl = {"lswitch": utils.ovn_name(port['network_id']),
               "lport": port['id'],
               "priority": ovn_const.ACL_PRIORITY_ALLOW,
               "action": ovn_const.ACL_ACTION_ALLOW,
               "log": False,
               "name": [],
               "severity": [],
               "direction": 'to-lport',
               "match": ('outport == "%s" && ip4 && ip4.src == %s && '
                         'udp && udp.src == 67 && udp.dst == 68'
                         ) % (port['id'], subnet['cidr']),
               "external_ids": {'neutron:lport': port['id']}}
        acl_list.append(acl)
    acl = {"lswitch": utils.ovn_name(port['network_id']),
           "lport": port['id'],
           "priority": ovn_const.ACL_PRIORITY_ALLOW,
           "action": ovn_const.ACL_ACTION_ALLOW,
           "log": False,
           "name": [],
           "severity": [],
           "direction": 'from-lport',
           "match": ('inport == "%s" && ip4 && '
                     'ip4.dst == {255.255.255.255, %s} && '
                     'udp && udp.src == 68 && udp.dst == 67'
                     ) % (port['id'], subnet['cidr']),
           "external_ids": {'neutron:lport': port['id']}}
    acl_list.append(acl)
    return acl_list


def _get_subnet_from_cache(plugin, admin_context, subnet_cache, subnet_id):
    if subnet_id in subnet_cache:
        return subnet_cache[subnet_id]
    else:
        subnet = plugin.get_subnet(admin_context, subnet_id)
        if subnet:
            subnet_cache[subnet_id] = subnet
        return subnet


def _get_sg_ports_from_cache(plugin, admin_context, sg_ports_cache, sg_id):
    if sg_id in sg_ports_cache:
        return sg_ports_cache[sg_id]
    else:
        filters = {'security_group_id': [sg_id]}
        sg_ports = plugin._get_port_security_group_bindings(
            admin_context, filters)
        if sg_ports:
            sg_ports_cache[sg_id] = sg_ports
        return sg_ports


def _get_sg_from_cache(plugin, admin_context, sg_cache, sg_id):
    if sg_id in sg_cache:
        return sg_cache[sg_id]
    else:
        sg = plugin.get_security_group(admin_context, sg_id)
        if sg:
            sg_cache[sg_id] = sg
        return sg


def acl_remote_group_id(r, ip_version, ovn=None):
    if not r['remote_group_id']:
        return ''

    src_or_dst = 'src' if r['direction'] == const.INGRESS_DIRECTION else 'dst'
    if (ovn and ovn.is_port_groups_supported()):
        addrset_name = utils.ovn_pg_addrset_name(r['remote_group_id'],
                                                 ip_version)
    else:
        addrset_name = utils.ovn_addrset_name(r['remote_group_id'],
                                              ip_version)
    return ' && %s.%s == $%s' % (ip_version, src_or_dst, addrset_name)


def _add_sg_rule_acl_for_port(port, r):
    # Update the match based on which direction this rule is for (ingress
    # or egress).
    match = acl_direction(r, port)

    # Update the match for IPv4 vs IPv6.
    ip_match, ip_version, icmp = acl_ethertype(r)
    match += ip_match

    # Update the match if an IPv4 or IPv6 prefix was specified.
    match += acl_remote_ip_prefix(r, ip_version)

    # Update the match if remote group id was specified.
    match += acl_remote_group_id(r, ip_version)

    # Update the match for the protocol (tcp, udp, icmp) and port/type
    # range if specified.
    match += acl_protocol_and_ports(r, icmp)

    # Finally, create the ACL entry for the direction specified.
    return add_sg_rule_acl_for_port(port, r, match)


def _add_sg_rule_acl_for_port_group(port_group, r, ovn):
    # Update the match based on which direction this rule is for (ingress
    # or egress).
    match = acl_direction(r, port_group=port_group)

    # Update the match for IPv4 vs IPv6.
    ip_match, ip_version, icmp = acl_ethertype(r)
    match += ip_match

    # Update the match if an IPv4 or IPv6 prefix was specified.
    match += acl_remote_ip_prefix(r, ip_version)

    # Update the match if remote group id was specified.
    match += acl_remote_group_id(r, ip_version, ovn)

    # Update the match for the protocol (tcp, udp, icmp) and port/type
    # range if specified.
    match += acl_protocol_and_ports(r, icmp)

    # Finally, create the ACL entry for the direction specified.
    return add_sg_rule_acl_for_port_group(port_group, r, match)


def _acl_columns_name_severity_supported(nb_idl):
    columns = list(nb_idl._tables['ACL'].columns)
    return ('name' in columns) and ('severity' in columns)


def add_acls_for_sg_port_group(ovn, security_group, txn):
    for r in security_group['security_group_rules']:
        acl = _add_sg_rule_acl_for_port_group(
            utils.ovn_port_group_name(security_group['id']), r, ovn)
        txn.add(ovn.pg_acl_add(**acl))


def update_acls_for_security_group(plugin,
                                   admin_context,
                                   ovn,
                                   security_group_id,
                                   security_group_rule,
                                   sg_ports_cache=None,
                                   is_add_acl=True):

    # Skip ACLs if security groups aren't enabled
    if not is_sg_enabled():
        return

    # Check if ACL log name and severity supported or not
    keep_name_severity = _acl_columns_name_severity_supported(ovn)

    # If we're using a Port Group for this SG, just update it.
    # Otherwise, keep the old behavior.
    if (ovn.is_port_groups_supported() and
            not ovn.get_address_set(security_group_id)):
        acl = _add_sg_rule_acl_for_port_group(
            utils.ovn_port_group_name(security_group_id),
            security_group_rule, ovn)
        # Remove ACL log name and severity if not supported
        if is_add_acl:
            if not keep_name_severity:
                acl.pop('name')
                acl.pop('severity')
            ovn.pg_acl_add(**acl).execute(check_error=True)
        else:
            ovn.pg_acl_del(acl['port_group'], acl['direction'],
                           acl['priority'], acl['match']).execute(
                check_error=True)
        return

    # Get the security group ports.
    sg_ports_cache = sg_ports_cache or {}
    sg_ports = _get_sg_ports_from_cache(plugin,
                                        admin_context,
                                        sg_ports_cache,
                                        security_group_id)

    # ACLs associated with a security group may span logical switches
    sg_port_ids = [binding['port_id'] for binding in sg_ports]
    sg_port_ids = list(set(sg_port_ids))
    port_list = plugin.get_ports(admin_context,
                                 filters={'id': sg_port_ids})
    if not port_list:
        return

    acl_new_values_dict = {}
    update_port_list = []

    # NOTE(lizk): We can directly locate the affected acl records,
    # so no need to compare new acl values with existing acl objects.
    for port in port_list:
        # Skip trusted port
        if utils.is_lsp_trusted(port):
            continue

        update_port_list.append(port)
        acl = _add_sg_rule_acl_for_port(port, security_group_rule)
        # Remove lport and lswitch since we don't need them
        acl.pop('lport')
        acl.pop('lswitch')
        # Remove ACL log name and severity if not supported,
        if not keep_name_severity:
            acl.pop('name')
            acl.pop('severity')
        acl_new_values_dict[port['id']] = acl

    if not update_port_list:
        return
    lswitch_names = {p['network_id'] for p in update_port_list}

    ovn.update_acls(list(lswitch_names),
                    iter(update_port_list),
                    acl_new_values_dict,
                    need_compare=False,
                    is_add_acl=is_add_acl).execute(check_error=True)


def add_acls(plugin, admin_context, port, sg_cache, subnet_cache, ovn):
    acl_list = []

    # Skip ACLs if security groups aren't enabled
    if not is_sg_enabled():
        return acl_list

    sec_groups = utils.get_lsp_security_groups(port)
    if not sec_groups:
        # If it is a trusted port or port security is disabled, allow all
        # traffic. So don't add any ACLs.
        if utils.is_lsp_trusted(port) or not utils.is_port_security_enabled(
                port):
            return acl_list

        # if port security is enabled, drop all traffic.
        return drop_all_ip_traffic_for_port(port)

    # Drop all IP traffic to and from the logical port by default.
    acl_list += drop_all_ip_traffic_for_port(port)

    # Add DHCP ACLs.
    port_subnet_ids = set()
    for ip in port['fixed_ips']:
        if netaddr.IPNetwork(ip['ip_address']).version != 4:
            continue
        subnet = _get_subnet_from_cache(plugin,
                                        admin_context,
                                        subnet_cache,
                                        ip['subnet_id'])
        # Ignore duplicate DHCP ACLs for the subnet.
        if subnet['id'] not in port_subnet_ids:
            acl_list += add_acl_dhcp(port, subnet, True)
            port_subnet_ids.add(subnet['id'])

    # We create an ACL entry for each rule on each security group applied
    # to this port.
    for sg_id in sec_groups:
        sg = _get_sg_from_cache(plugin,
                                admin_context,
                                sg_cache,
                                sg_id)
        for r in sg['security_group_rules']:
            acl = _add_sg_rule_acl_for_port(port, r)
            acl_list.append(acl)

    # Remove ACL log name and severity if not supported,
    if not _acl_columns_name_severity_supported(ovn):
        for acl in acl_list:
            acl.pop('name')
            acl.pop('severity')

    return acl_list


def acl_port_ips(port):
    # Skip ACLs if security groups aren't enabled
    if not is_sg_enabled():
        return {'ip4': [], 'ip6': []}

    ip_list = [x['ip_address'] for x in port.get('fixed_ips', [])]
    ip_list.extend(utils.get_allowed_address_pairs_ip_addresses(port))
    return utils.sort_ips_by_version(ip_list)


def filter_acl_dict(acl, extra_fields=None):
    if extra_fields is None:
        extra_fields = []
    extra_fields.extend(ovn_const.ACL_EXPECTED_COLUMNS_NBDB)
    return {k: acl[k] for k in extra_fields}
